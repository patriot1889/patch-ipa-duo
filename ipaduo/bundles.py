"""Validate bundle layout before modifying any executable."""
from dataclasses import dataclass
from pathlib import Path
import plistlib
import re
from xml.parsers.expat import ExpatError

from .errors import Problem

MACH_MAGICS = {b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf',
               b'\xbf\xba\xfe\xca', b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
               b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'}


def is_bundle_id(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*', value) is not None


def read_plist(path):
    if path.stat().st_size > 4 * 1024 * 1024:
        raise Problem(f'Bundle Info.plist is too large: {path.name}.')
    try:
        info = plistlib.loads(path.read_bytes())
    except (ValueError, TypeError, ExpatError, plistlib.InvalidFileException) as error:
        raise Problem(f'Invalid Info.plist: {error}') from error
    if not isinstance(info, dict):
        raise Problem('Expected a property-list dictionary.')
    return info


@dataclass
class Bundle:
    path: str
    id: str
    executable: str
    file_type: int


def bundle(path, package_type, root, files):
    from .archive import safe_component
    if path + '/Info.plist' not in files:
        raise Problem(f'Missing Info.plist in {path}.')
    info = read_plist(root / path / 'Info.plist')
    identifier, executable = info.get('CFBundleIdentifier'), info.get('CFBundleExecutable')
    if (not is_bundle_id(identifier) or not isinstance(executable, str)
            or '/' in executable or not safe_component(executable)
            or executable.lower() in {'embedded.mobileprovision', '_codesignature', 'coderesources'}
            or path + '/' + executable not in files):
        raise Problem(f'Bundle has a missing, invalid or reserved identifier or executable in {path}.')
    if info.get('CFBundlePackageType', package_type) != package_type:
        raise Problem(f'Unexpected CFBundlePackageType in {path}.')
    if info.get('CFBundleSupportedPlatforms', ['iPhoneOS']) != ['iPhoneOS']:
        raise Problem(f'Bundle in {path} was not built for iOS device.')
    return Bundle(path, identifier, path + '/' + executable, 6 if package_type == 'FMWK' else 2)


def code_items(app_path: str, root: Path, dirs: set[str], files: set[str]):
    app = bundle(app_path, 'APPL', root, files)
    prefix = app_path + '/PlugIns/'
    extensions = [bundle(path, 'XPC!', root, files) for path in sorted(dirs)
                  if path.startswith(prefix) and '/' not in path[len(prefix):] and path.endswith('.appex')]
    if any(not item.id.startswith(app.id + '.') for item in extensions):
        raise Problem('Extension bundle identifiers must start with the app identifier plus a dot.')
    if len({item.id for item in extensions}) != len(extensions):
        raise Problem('The IPA contains extensions with duplicate bundle identifiers.')
    ordered, allowed = [], {app_path}
    for item in extensions + [app]:
        allowed.add(item.path)
        prefix = item.path + '/Frameworks/'
        for name in sorted(files):
            if name.startswith(prefix) and '/' not in name[len(prefix):] and name.endswith('.dylib'):
                ordered.append(Bundle(name, '', name, 6))
        for path in sorted(dirs):
            if path.startswith(prefix) and '/' not in path[len(prefix):] and path.endswith('.framework'):
                if path + '/Versions' in dirs:
                    raise Problem(f'Versioned frameworks are unsupported in IPA mode: {path}.')
                allowed.add(path)
                ordered.append(bundle(path, 'FMWK', root, files))
        ordered.append(item)
    for path in sorted(dirs - allowed):
        if Path(path).suffix.lower() in {'.app', '.appex', '.framework', '.xpc', '.plugin', '.systemextension', '.kext'}:
            raise Problem(f'Unsupported nested code bundle: {path}.')
    known = {item.executable for item in ordered}
    for path in sorted(files - known):
        with (root / path).open('rb') as stream:
            if stream.read(4) in MACH_MAGICS:
                raise Problem(f'Unsupported Mach-O location: {path}.')
    return ordered
