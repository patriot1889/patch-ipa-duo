"""Local, trusted adapter manifests and executable transforms."""
from dataclasses import dataclass
from pathlib import Path
import copy
import json
import subprocess
import sys

from .bundles import is_bundle_id
from .errors import Problem

BARS = {'default', 'top', 'side'}
PROTECTED = {'CFBundleIdentifier', 'CFBundleExecutable', 'CFBundleVersion', 'CFBundleShortVersionString',
             'CFBundleSupportedPlatforms', 'MinimumOSVersion', 'UIDeviceFamily', 'UIRequiredDeviceCapabilities',
             'DTSDKName', 'DTPlatformVersion'}


def require(ok, message):
    if not ok:
        raise Problem(message)


def string_list(value):
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


def small_regular(path):
    require(path.is_file() and path.stat().st_size <= 1024 * 1024, f'Missing or oversized adapter resource: {path}.')
    return path


@dataclass
class Adapter:
    data: dict
    directory: Path
    supported: bool = False
    forced: bool = False

    @property
    def name(self):
        return self.data['name']

    @property
    def operations(self):
        return self.data.get('operations')

    def require_support(self):
        require(self.supported, f'Adapter {self.name} does not support this app version/build. No output produced.')
        require(self.operations is not None, self.data.get('patchUnavailableReason', 'Adapter patch operations are unavailable.'))

    def resource(self, relative, suffix):
        from .archive import safe_component
        require(isinstance(relative, str) and relative.endswith(suffix)
                and all(safe_component(p) for p in relative.split('/')),
                f'Adapter resource must be a {suffix} file within its package.')
        result = (self.directory / relative).resolve()
        require(self.directory in result.parents, 'Adapter source escapes its package.')
        return small_regular(result)


def load_adapters(directory):
    from .archive import safe_component
    if not directory.exists():
        return []
    require(directory.is_dir(), f'Adapter path must be a directory: {directory}.')
    result, identifiers = [], set()
    for entry in sorted(directory.iterdir()):
        if entry.name.startswith('.'):
            continue
        package = entry.is_dir()
        if not package and entry.suffix != '.json':
            continue
        path = entry / 'adapter.json' if package else entry
        if package and not path.exists():
            continue
        try:
            data = json.loads(small_regular(path).read_text(encoding='utf-8'))
        except (ValueError, UnicodeError) as error:
            raise Problem(f'Invalid adapter descriptor {path.name}: {error}') from error
        require(isinstance(data, dict), f'Invalid adapter descriptor {path.name}.')
        adapter = Adapter(data, path.parent.resolve())
        ops = adapter.operations
        names = [data.get('bundleIdentifier')] + data.get('aliases', []) if isinstance(data.get('aliases'), list) else []
        builds = data.get('supportedBuilds')
        bars = data.get('supportedFullModeBars')
        require(data.get('schemaVersion') == (1 if ops is None else 2)
                and entry.name == (str(data.get('bundleIdentifier')) if package else str(data.get('bundleIdentifier')) + '.json')
                and names and all(is_bundle_id(n) for n in names) and len(set(names)) == len(names)
                and isinstance(data.get('name'), str) and data['name'].strip()
                and string_list(data.get('plannedChanges'))
                and isinstance(builds, list) and builds
                and all(isinstance(b, dict) and isinstance(b.get('version'), str) and b['version']
                        and isinstance(b.get('build'), str) and b['build'] for b in builds)
                and string_list(bars) and bars and len(set(bars)) == len(bars) and set(bars) <= BARS
                and data.get('fullModeDefaultBars') in bars,
                f'Invalid adapter metadata or bundle-identifier filename: {path.name}.')
        if ops is None:
            require(isinstance(data.get('patchUnavailableReason'), str) and data['patchUnavailableReason'].strip(),
                    'Inspection-only adapter must explain why patching is unavailable.')
        else:
            require(package and data.get('patchUnavailableReason') is None and isinstance(ops, dict), 'Invalid adapter operations.')
            require(type(ops.get('enableIPhone')) is bool and isinstance(ops.get('setPlist'), dict)
                    and all(string_list(ops.get(key)) for key in ('removePlistKeys', 'requiresAbsentPlistKeys', 'requiredExecutableStrings')),
                    'Invalid adapter plist operations.')
            require(not PROTECTED.intersection(set(ops['removePlistKeys']) | set(ops['setPlist'])), 'Adapter changes protected plist keys.')
            # JSON values must also be representable by plistlib (no nulls).
            def valid_plist(value):
                return (type(value) in (str, int, float, bool)
                        or isinstance(value, list) and all(valid_plist(v) for v in value)
                        or isinstance(value, dict) and all(isinstance(k, str) and valid_plist(v) for k, v in value.items()))
            require(valid_plist(ops['setPlist']), 'Invalid adapter plist values.')
            libraries = ops.get('libraries')
            require(isinstance(libraries, list) and len(libraries) <= 8, 'Invalid adapter libraries.')
            used = set()
            for library in libraries:
                require(isinstance(library, dict), 'Invalid adapter library.')
                name = library.get('fileName')
                require(isinstance(name, str) and safe_component(name) and '/' not in name
                        and name.endswith('.dylib') and name.casefold() != 'ipapatcherbars.dylib'
                        and name.casefold() not in used, 'Invalid adapter library name.')
                used.add(name.casefold())
                adapter.resource(library.get('source'), '.m')
            require(all(value and '\0' not in value for value in ops['requiredExecutableStrings']), 'Invalid adapter required strings.')
            transform = ops.get('executableTransform')
            if transform is not None:
                require(isinstance(transform, dict), 'Invalid adapter transform.')
                adapter.resource(transform.get('source'), '.py')
        require(not identifiers.intersection(names), 'Multiple adapters claim the same bundle identifier.')
        identifiers.update(names)
        result.append(adapter)
    return result


def select_adapter(info, adapters, forced=None):
    selected = next((item for item in adapters if (item.data['bundleIdentifier'] == forced if forced
                    else info['CFBundleIdentifier'] in [item.data['bundleIdentifier']] + item.data['aliases'])), None)
    if forced and selected is None:
        raise Problem(f'Requested adapter {forced} was not found in the adapters directory. Use its canonical bundle identifier.')
    if selected:
        selected = copy.copy(selected)
        selected.supported = any(b['version'] == info.get('CFBundleShortVersionString') and b['build'] == info.get('CFBundleVersion')
                                 for b in selected.data['supportedBuilds'])
        selected.forced = bool(forced)
    return selected


def configure_info(info, adapter):
    result = copy.deepcopy(info)
    if adapter and adapter.operations:
        ops = adapter.operations
        for key in ops['requiresAbsentPlistKeys']:
            require(key not in info, f'Adapter requires an original app without {key}. Use an unpatched input IPA.')
        for key in ops['removePlistKeys']:
            result.pop(key, None)
        result.update(copy.deepcopy(ops['setPlist']))
    return result


def validate_executable(executable, adapter):
    from .macho import slices
    if not adapter or not adapter.operations or not adapter.operations['requiredExecutableStrings']:
        return
    with executable.open('rb') as stream:
        for part in slices(executable):
            stream.seek(part.offset)
            data = stream.read(part.size)
            for value in adapter.operations['requiredExecutableStrings']:
                require(value.encode() + b'\0' in data, f'Adapter executable preflight failed: required string {value} is missing in a Mach-O slice.')


def transform_executable(executable, adapter, libraries, work):
    from .macho import architectures
    if not adapter or not adapter.operations or not adapter.operations.get('executableTransform'):
        return
    source = adapter.resource(adapter.operations['executableTransform'].get('source'), '.py')
    request = work / 'adapter-transform-request.json'
    request.write_text(json.dumps({'schemaVersion': 1, 'executable': str(executable), 'injectedLibraries': libraries}), encoding='utf-8')
    result = subprocess.run([sys.executable, str(source), str(request)], capture_output=True, text=True, encoding='utf-8', errors='replace')
    require(result.returncode == 0, f'Adapter executable transformation failed: {result.stderr.strip()}')
    print('Adapter transformation: ' + result.stdout.strip())
    architectures(executable)
