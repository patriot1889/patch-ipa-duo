"""Cross-platform command line and transactional patch pipeline."""
from pathlib import Path
import os
import plistlib
import re
import sys
import tempfile
import unittest

from .errors import Problem
from .archive import Archive, write_archive
from .bundles import bundle, code_items, is_bundle_id, read_plist
from .adapters import load_adapters, select_adapter, configure_info, validate_executable, transform_executable
from . import macho, native

ROOT = Path(__file__).resolve().parent.parent
USAGE = '''Usage:
  patch-ipa-duo inspect INPUT.ipa [--adapter BUNDLE_IDENTIFIER]
  patch-ipa-duo patch INPUT.ipa --output OUTPUT.ipa
      [--display full|reserved-side] [--bars default|side|top] [--enable-iphone]
      [--adapter BUNDLE_IDENTIFIER]
  patch-ipa-duo --self-test

Python 3.10+; macOS and Windows. Native hooks use bundled iOS libraries.
Rebuild native/prebuilt on macOS with tools/build_native.py after source changes.
Output requires separate signing. Existing output files are never overwritten.
'''


def visible(value):
    import unicodedata
    return ''.join('?' if unicodedata.category(c) in ('Cc', 'Cf') else c for c in str(value))


def report(value):
    print(visible(value))


def parse(args):
    if len(args) < 2 or args[0] not in ('inspect', 'patch') or args[1].startswith('--'):
        raise Problem(USAGE)
    result = dict(inspect=args[0] == 'inspect', input=Path(args[1]).absolute(), output=None,
                  display='full', bars='default', enable_iphone=False, adapter=None)
    seen, index = set(), 2
    while index < len(args):
        flag = args[index]
        if flag in seen or result['inspect'] and flag != '--adapter':
            raise Problem(f'Unexpected or repeated option: {flag}.')
        seen.add(flag)
        if flag == '--enable-iphone':
            result['enable_iphone'] = True
            index += 1
            continue
        if flag not in ('--output', '--display', '--bars', '--adapter') or index + 1 >= len(args):
            raise Problem(f'Unknown option or missing value: {flag}.')
        value = args[index + 1]
        if value.startswith('--'):
            raise Problem(f'Missing value for {flag}.')
        if flag == '--adapter' and not is_bundle_id(value):
            raise Problem('--adapter requires a canonical bundle identifier, not a file path.')
        result[flag[2:]] = Path(value).absolute() if flag == '--output' else value
        index += 2
    if result['display'] not in ('full', 'reserved-side') or result['bars'] not in ('default', 'side', 'top'):
        raise Problem('Invalid display or bars option.\n' + USAGE)
    if not result['inspect'] and result['output'] is None:
        raise Problem('patch requires --output OUTPUT.ipa.')
    if result['display'] == 'reserved-side' and result['bars'] == 'top':
        raise Problem('--bars top requires --display full.')
    return result


def has_scene(info):
    manifest = info.get('UIApplicationSceneManifest')
    config = manifest.get('UISceneConfigurations') if isinstance(manifest, dict) else None
    scenes = config.get('UIWindowSceneSessionRoleApplication') if isinstance(config, dict) else None
    return isinstance(scenes, list) and bool(scenes) and all(isinstance(s, dict) and bool(s) for s in scenes)


def resolve(info, records, options, adapter):
    if adapter:
        adapter.require_support()
    updated = configure_info(info, adapter)
    if not has_scene(updated):
        raise Problem('App has no existing application scene configuration; a compatibility adapter is required. Scene configuration was not fabricated.')
    sdk = 27 << 16 if options['display'] == 'reserved-side' else max((27 << 16) | (1 << 8), *(r.sdk for r in records))
    if any(r.minimum > sdk for r in records):
        raise Problem(f'The selected SDK {macho.version(sdk)} is below the executable minimum OS; cannot preserve the deployment target.')
    minimum = info.get('MinimumOSVersion')
    if minimum is not None:
        if not isinstance(minimum, str) or re.fullmatch(r'\d+(?:\.\d+){0,2}', minimum) is None:
            raise Problem('Invalid MinimumOSVersion metadata.')
        parts = [int(x) for x in minimum.split('.')]
        parts += [0] * (3 - len(parts))
        if tuple(parts) > (sdk >> 16, sdk >> 8 & 255, sdk & 255):
            raise Problem(f'The selected SDK {macho.version(sdk)} is below MinimumOSVersion {minimum}.')
    families = info.get('UIDeviceFamily')
    if not isinstance(families, list) or not families or any(type(x) is not int or x not in (1, 2) for x in families):
        raise Problem('Expected iPhone/iPad UIDeviceFamily metadata.')
    if options['enable_iphone'] and 1 not in families:
        updated['UIDeviceFamily'] = [1] + families
    updated['DTSDKName'] = 'iphoneos' + macho.version(sdk)
    updated['DTPlatformVersion'] = macho.version(sdk)
    return updated, sdk


def ensure_output_available(output):
    try:
        output.lstat()
    except FileNotFoundError:
        return
    raise Problem(f'Output already exists or cannot be inspected: {output}.')


def patch_command(args, adapter_directory=None):
    options = parse(args)
    output = options['output']
    if output:
        ensure_output_available(output)
        if not output.parent.is_dir():
            raise Problem('Output parent must be an existing writable directory.')
    with tempfile.TemporaryDirectory(prefix='patch-ipa-duo-') as temporary:
        work = Path(temporary)
        with Archive(options['input']) as archive:
            dirs, files, app_path = archive.validate_layout()
            archive.extract(work)
            executable_paths = {e.path for e in archive.entries if e.executable and not e.directory and e.path != 'iTunesArtwork'}
        ordered = code_items(app_path, work, dirs, files)
        for item in ordered:
            macho.architectures(work / item.executable, file_type=item.file_type)
        app = bundle(app_path, 'APPL', work, files)
        info_path = work / app_path / 'Info.plist'
        executable = work / app.executable
        info = read_plist(info_path)
        adapter = select_adapter(info, load_adapters(adapter_directory if adapter_directory is not None else ROOT / 'adapters'), options['adapter'])
        records = macho.sdk_records(executable)
        report(f'App: {app.id}; executable: {Path(app.executable).name}')
        report('Executable SDK: ' + ', '.join(macho.version(r.sdk) for r in records)
               + '; minimum OS: ' + ', '.join(macho.version(r.minimum) for r in records))
        report(f'Plist SDK: {info.get("DTSDKName", "absent")}; platform version: {info.get("DTPlatformVersion", "absent")}')
        report(f'Device families: {info.get("UIDeviceFamily", "absent")}; application scene: {"present" if has_scene(info) else "absent"}')
        status = 'unsupported version/build' if adapter and not adapter.supported else 'patch supported' if adapter and adapter.operations else 'inspection only'
        report(f'Adapter: {adapter.name + " (" + adapter.data["bundleIdentifier"] + "; " + status + ")" if adapter else "generic"}')
        if adapter:
            report('Adapter selection: ' + ('forced by --adapter' if adapter.forced else 'automatic from bundle identifier'))
        if options['inspect']:
            report(f'Scene manifest: {info.get("UIApplicationSceneManifest", "absent")}')
            if adapter:
                report(f'Adapter full-mode bars: default={adapter.data["fullModeDefaultBars"]}; supported={", ".join(adapter.data["supportedFullModeBars"])}')
                report('Adapter changes: ' + ' '.join(adapter.data['plannedChanges']))
                report('Adapter status: ' + ('No supported build matches this app version/build.' if not adapter.supported
                                            else adapter.data.get('patchUnavailableReason', 'Patch operations available.')))
            report('Top/side hooks use bundled iOS libraries; runtime compatibility still requires device testing.')
            return
        if adapter:
            adapter.require_support()
            if options['display'] == 'full':
                if options['bars'] == 'default':
                    options['bars'] = adapter.data['fullModeDefaultBars']
                if options['bars'] not in adapter.data['supportedFullModeBars']:
                    raise Problem(f'Adapter {adapter.name} does not support --bars {options["bars"]}.')
            options['enable_iphone'] |= adapter.operations['enableIPhone']
        validate_executable(executable, adapter)
        updated, sdk = resolve(info, records, options, adapter)
        bar_path = app_path + '/Frameworks/' + native.BAR_NAME
        inject_bars = options['display'] == 'full' and options['bars'] != 'default'
        if options['display'] == 'reserved-side' and bar_path in files:
            raise Problem('Input already contains a bar hook. Use the original IPA for reserved-side system placement.')
        adapter_libraries = adapter.operations['libraries'] if adapter else []
        library_names = [lib['fileName'] for lib in adapter_libraries] + ([native.BAR_NAME] if inject_bars else [])
        for name in library_names:
            path = app_path + '/Frameworks/' + name
            if path.casefold() in {p.casefold() for p in files | dirs}:
                raise Problem('Injected-library output path already exists. Use the original IPA to patch again.')
        load_paths = ['@executable_path/Frameworks/' + name for name in library_names]
        plan = macho.injection_plan(executable, load_paths) if load_paths else []
        bars = 'system' if options['display'] == 'reserved-side' else 'existing' if options['bars'] == 'default' else options['bars']
        report(f'Resolved: display={options["display"]}, bars={bars}, SDK={macho.version(sdk)}, families={updated["UIDeviceFamily"]}')
        if any(r.sdk > sdk for r in records):
            report('Warning: linked SDK downgraded; deployment target preserved.')
        macho.patch_sdk(executable, sdk)
        for library in adapter_libraries:
            path = app_path + '/Frameworks/' + library['fileName']
            target = work / path
            target.parent.mkdir(parents=True, exist_ok=True)
            native.obtain(executable, adapter.resource(library['source'], '.m'),
                          '@executable_path/Frameworks/' + library['fileName'], [],
                          adapter.data['bundleIdentifier'] + '/' + library['fileName'], target, work)
            executable_paths.add(path)
            report('Added adapter library: ' + library['fileName'])
        if inject_bars:
            target = work / bar_path
            target.parent.mkdir(parents=True, exist_ok=True)
            native.obtain(executable, ROOT / 'native/IPAPatcherBars.m', native.BAR_LOAD,
                          ['PATCH_TOP=' + ('1' if options['bars'] == 'top' else '0')],
                          'bars/' + options['bars'], target, work)
            executable_paths.add(bar_path)
            report(f'Injected UIKit hook: {options["bars"]}. Best effort on iOS 27.1+; sign the new dylib with the app.')
        if load_paths:
            macho.inject(executable, plan, load_paths)
        transform_executable(executable, adapter, load_paths, work)
        info_path.write_bytes(plistlib.dumps(updated, fmt=plistlib.FMT_BINARY, sort_keys=False))
        if any(r.sdk != sdk for r in macho.sdk_records(executable)):
            raise Problem('SDK verification failed.')
        with tempfile.TemporaryDirectory(prefix='.ipaduo-', dir=output.parent) as staged:
            archive_path = Path(staged) / 'patched.ipa'
            write_archive(work, archive_path, executable_paths)
            with Archive(archive_path) as checked:
                checked.validate_layout()
                checked.validate_all()
            # Atomic create-if-absent: never overwrite even if a file appears during patching.
            try:
                os.link(archive_path, output)
            except OSError as error:
                raise Problem(f'Could not publish without overwriting output (filesystem must support hard links): {error}') from error
        report(f'Patched IPA written to {output}. Requires separate signing before installation; original signature hashes are stale.')


def main(args=None):
    args = list(sys.argv[1:] if args is None else args)
    try:
        if args in (['--help'], ['-h']):
            print(USAGE)
        elif args == ['--self-test']:
            suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            if not result.wasSuccessful() or result.testsRun == 0:
                return 1
            print('Patcher self-tests passed.')
        else:
            patch_command(args)
        return 0
    except (Problem, OSError, ValueError, TypeError, OverflowError) as error:
        print('Error: ' + visible(error), file=sys.stderr)
        return 1
