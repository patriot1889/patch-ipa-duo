"""Build iOS libraries on macOS, or consume verified portable build artifacts."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

from .errors import Problem
from . import macho

ROOT = Path(__file__).resolve().parent.parent
PREBUILT = ROOT / 'native' / 'prebuilt'
BAR_NAME = 'IPAPatcherBars.dylib'
BAR_LOAD = '@executable_path/Frameworks/' + BAR_NAME


def run(args):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result.returncode:
        raise Problem('Native-library build failed: ' + '\n'.join(result.stderr.splitlines()[-8:]))
    return result.stdout.strip()


def fingerprint(source, load_path, defines):
    value = source.read_bytes().replace(b'\r\n', b'\n') + b'\0' + load_path.encode() + b'\0' + '\0'.join(defines).encode()
    return hashlib.sha256(value).hexdigest()


def build(source, load_path, defines, targets, output, work):
    if sys.platform != 'darwin' or shutil.which('xcrun') is None:
        raise Problem('A compatible prebuilt iOS library is missing. Build native bundles on macOS with '
                      'Python tools/build_native.py, then copy native/prebuilt with the project to Windows.')
    built = []
    for architecture, minimum in targets:
        library = work / f'{output.stem}-{architecture}.dylib'
        run(['xcrun', '--sdk', 'iphoneos', 'clang', '-dynamiclib', '-fobjc-arc', '-fblocks',
             '-target', f'{architecture}-apple-ios{macho.version(minimum)}', '-framework', 'UIKit',
             '-Werror', '-Wl,-adhoc_codesign', '-install_name', load_path, source, '-o', library]
            + ['-D' + value for value in defines])
        macho.architectures(library, file_type=6)
        built.append(library)
    if len(built) == 1:
        shutil.copyfile(built[0], output)
    else:
        run(['xcrun', 'lipo', '-create', *built, '-output', output])


def targets_for(executable, file_type=2):
    # SDK records and slices follow file order, while architectures() is sorted.
    targets = []
    with executable.open('rb') as stream:
        for part, record in zip(macho.slices(executable, file_type=file_type), macho.sdk_records(executable, file_type=file_type)):
            stream.seek(part.offset + 8)
            subtype = int.from_bytes(stream.read(4), 'little') & 0xffffff
            targets.append(('arm64e' if subtype == 2 else 'arm64', record.minimum))
    return targets


def validate_library(library, executable, load_path):
    macho.validate_dylib(library, executable, load_path)


def obtain(executable, source, load_path, defines, key, output, work):
    manifest_path = PREBUILT / 'manifest.json'
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            item = manifest['libraries'][key]
            artifact = (PREBUILT / item['file']).resolve()
            if PREBUILT.resolve() not in artifact.parents:
                raise Problem('Native artifact escapes its bundle directory.')
            if item['sourceHash'] != fingerprint(source, load_path, defines):
                raise Problem('Prebuilt iOS library is stale; rebuild native bundles after changing their sources.')
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != item['sha256']:
                raise Problem('Prebuilt iOS library checksum mismatch.')
            requirements = dict(targets_for(executable))
            available = dict(targets_for(artifact, file_type=6))
            if all(arch in available and available[arch] <= minimum for arch, minimum in requirements.items()):
                macho.select_architectures(artifact, output, macho.architectures(executable))
                validate_library(output, executable, load_path)
                return
            # Older deployment targets can still be built locally with Xcode.
            # Windows fails explicitly when its bundled artifact is incompatible.
        except KeyError:
            pass  # A new local adapter may not have a prebuilt artifact yet.
        except (ValueError, TypeError) as error:
            raise Problem(f'Invalid native-library manifest: {error}') from error
    build(source, load_path, defines, targets_for(executable), output, work)
    validate_library(output, executable, load_path)


def build_bundles(destination=PREBUILT):
    from .adapters import load_adapters
    specs = [
        ('bars/top', ROOT / 'native/IPAPatcherBars.m', BAR_LOAD, ['PATCH_TOP=1']),
        ('bars/side', ROOT / 'native/IPAPatcherBars.m', BAR_LOAD, ['PATCH_TOP=0']),
    ]
    for adapter in load_adapters(ROOT / 'adapters'):
        for item in (adapter.operations or {}).get('libraries', []):
            specs.append((adapter.data['bundleIdentifier'] + '/' + item['fileName'],
                          adapter.resource(item['source'], '.m'), '@executable_path/Frameworks/' + item['fileName'], []))
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {'schemaVersion': 1, 'libraries': {}}
    with tempfile.TemporaryDirectory(prefix='ipaduo-build-') as temporary:
        work = Path(temporary)
        for key, source, load_path, defines in specs:
            relative = key + '.dylib' if key.startswith('bars/') else key
            output = work / 'combined.dylib'
            minimum = (12 if key.startswith('bars/') else 15) << 16
            build(source, load_path, defines, [('arm64', minimum), ('arm64e', minimum)], output, work)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(output, target)
            manifest['libraries'][key] = {'file': relative, 'sourceHash': fingerprint(source, load_path, defines),
                                          'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
            print(f'Built {relative}')
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
