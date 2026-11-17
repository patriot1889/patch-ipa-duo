# IPA Patcher for Duo

`patch-ipa-duo` adapts decrypted iOS app packages for Duo on macOS and Windows
using Python. It updates SDK metadata and offers options for iPhone support
and system bar placement. Adapters provide additional compatibility changes for
supported app builds.

**Patched output must be re-signed before installation.** Patching changes the
app's existing signatures. A successful patch confirms structural checks, not
that the app will launch or display correctly on your device.

## Requirements

- Python 3.10 or newer. The patcher uses only the standard library; no pip packages
  are needed. macOS's bundled Python may be too old, so check your interpreter.
- A decrypted iOS device `.ipa` that you are authorized to modify. The tool does
  not decrypt apps or build Simulator versions.
- Keep `ipaduo/`, `adapters/` and `native/` beside the entry-point scripts. The
  included `native/prebuilt/` libraries support arm64 and arm64e on either host.
- An existing, writable output directory on a filesystem that supports hard links
  (for example NTFS on Windows or APFS on macOS). FAT/exFAT output is unsupported.

**Windows (PowerShell):**

```powershell
py -3 --version
py -3 .\patch-ipa-duo.py --help
py -3 .\patch-ipa-duo.py inspect "C:\Users\You\Downloads\MyApp.ipa"
py -3 .\patch-ipa-duo.py patch "C:\Users\You\Downloads\MyApp.ipa" --output "MyApp-duo.ipa"
```

If the Python launcher is unavailable, use `python` with Python 3.10+ installed.
No Xcode, Swift, Unix ZIP command or WSL is needed for the bundled patch modes.

**macOS:** use `python3 patch-ipa-duo.py` with Python 3.10+, or run
`./patch-ipa-duo` when `python3` on your PATH meets that requirement. The original
Swift implementation is retained as `patch-ipa-duo.swift` for comparison.

## Native library bundles

Top/side bars and SQ MixPad use prebuilt **iOS** dylibs; these run inside the
patched iOS app, regardless of which desktop OS creates the IPA. The patcher
selects the executable's architectures and verifies artifact/source checksums,
install names and deployment targets before injection. Generic metadata changes
and the default Plex adapter require no injected libraries.

The bundled bar hooks target iOS 12 or later; SQ MixPad libraries target iOS 15
or later. An executable with an older minimum OS cannot use an incompatible
bundle. On macOS the patcher can build a compatible library using Xcode; on
Windows it reports a missing-compatible-bundle error without publishing output.
Missing bundles can also be built automatically on macOS. Stale or corrupt
bundles are rejected and must be rebuilt.

To rebuild distributable bundles after changing native source or adding an
adapter, use macOS with full Xcode and an iPhoneOS SDK of 27.1 or later:

```sh
python3 tools/build_native.py
```

Distribute the resulting `native/prebuilt/` directory with the rest of the
project. It includes both bar modes and all adapter libraries, plus a checksum
manifest. Bundles do not contain Apple SDK files. New libraries still need to be
signed with the patched app before installation.

## Quick start

1. Download and extract the project, or clone the repository. Open Terminal in
   the project folder. Keep `adapters/` beside `patch-ipa-duo` if you want to use
   the included adapters.

2. Check that the tool runs:

   ```sh
   chmod +x ./patch-ipa-duo
   ./patch-ipa-duo --help
   ```

3. Inspect your original IPA. Replace the example path with your own; keep quotes
   around paths containing spaces.

   ```sh
   ./patch-ipa-duo inspect "$HOME/Downloads/MyApp.ipa"
   ```

   Inspection reports the app identifier, SDK and minimum OS metadata, device
   families, scene configuration, and any selected adapter. Read the selected
   adapter's README before proceeding. Inspection alone does not guarantee that
   patching is supported.

4. Create a new output in the current folder:

   ```sh
   ./patch-ipa-duo patch "$HOME/Downloads/MyApp.ipa" --output "MyApp-duo.ipa"
   ```

   This uses full-display mode and the selected adapter's defaults, if any.
   Without an adapter, it preserves existing device families and bar behavior.
   The original IPA is preserved. Choose a different filename if the output
   already exists.

On success, the tool prints `Patched IPA written to …` and creates the new IPA.
The result requires re-signing before installation. Device launch, resizing and
bar placement still need testing on the target device.

## Options

```text
./patch-ipa-duo inspect INPUT.ipa [--adapter BUNDLE_IDENTIFIER]
./patch-ipa-duo patch INPUT.ipa --output OUTPUT.ipa [OPTIONS]
```

| Option | Behavior |
|---|---|
| `--display full` | Default. Sets executable and plist SDK metadata to at least 27.1, retaining a newer executable SDK. |
| `--display reserved-side` | Sets SDK metadata to 27.0. Reports SDK downgrades and rejects a minimum OS above 27.0. Uses system bar placement. |
| `--bars default` | Default. Preserves existing bars for generic patching; an adapter may select its own default. |
| `--bars top` | Requests horizontal system bars in full mode by injecting a UIKit hook. Unsupported in reserved-side mode. |
| `--bars side` | Requests automatic system placement, including side bars where supported. Injects a UIKit hook in full mode; reserved-side mode uses system placement without this hook. |
| `--enable-iphone` | Adds iPhone support to device-family metadata while retaining existing families. Does not guarantee a usable iPhone layout. |
| `--adapter BUNDLE_IDENTIFIER` | Selects an installed adapter by its canonical identifier. Does not change the app's bundle identifier or bypass supported-build checks. |

Options must not repeat. `inspect` accepts only `--adapter`; the other options
apply to `patch`. Adapter requirements and defaults can affect the resulting
changes.

Examples, each starting from the original IPA and producing a separate output:

```sh
./patch-ipa-duo patch "MyApp.ipa" --output "MyApp-iphone.ipa" --enable-iphone
./patch-ipa-duo patch "MyApp.ipa" --output "MyApp-top.ipa" --bars top
./patch-ipa-duo patch "MyApp.ipa" --output "MyApp-side.ipa" --bars side
./patch-ipa-duo patch "MyApp.ipa" --output "MyApp-reserved.ipa" --display reserved-side
```

## Supported inputs and limits

Generic patching requires an existing application scene configuration and valid
iPhone/iPad device-family metadata. Legacy apps without an application scene
need a compatible adapter. Updating SDK metadata does not rebuild the app or
change its minimum OS version.

The archive must contain one app under `Payload/`. Supported code includes
arm64/arm64e device executables, universal binaries, flat frameworks, dylibs and
ordinary app extensions. Encrypted binaries, Simulator builds, unsupported
architectures, ZIP64 archives, links and unsupported nested bundles such as
Watch apps or App Clips are rejected. Paths must also be valid on Windows:
reserved device names, trailing dots/spaces and characters such as `:` or `\`
are rejected on both hosts. Extra top-level content such as `SwiftSupport/` is
unsupported. Optional top-level `iTunesArtwork` is validated
and omitted from the output.

Full-mode bar overrides inject `Frameworks/IPAPatcherBars.dylib`.
The included build bundles are used on both desktop platforms.
Every executable architecture needs sufficient zeroed Mach-O header padding;
the tool fails rather than moving existing code or data. The hook takes effect
on iOS 27.1 or later and is best effort for standard UIKit bars. Custom-drawn
bars and runtime-generated controller classes may not follow it. Always start
from the original IPA when changing bar mode; an existing injected hook is not
replaced or removed automatically.

Archive validation covers entry paths, layout, checksums and embedded executable
structure. The output ZIP is checked again before publication. Signing metadata
and entitlements are retained, except where an adapter explicitly changes them;
existing signatures become stale. These checks do not verify runtime
compatibility or installation eligibility.

## Adapters

Adapter packages live in `adapters/<bundle-identifier>/` beside the script. Each
package's README documents supported builds, changes, prerequisites and tests.
Browse the [adapters directory](adapters/) for available packages.

Both commands select an adapter automatically from the app's
`CFBundleIdentifier`. Matching apps with unsupported builds fail instead of
silently using the generic path. For a renamed app, `--adapter` selects a
package without changing the app's identifier; version and build checks still
apply. A missing requested adapter is an error.

Adapter discovery follows the installed Python module location and works
from other working directories. The directory is optional for generic patching.
Each package owns its `adapter.json`, native source, validation rules, plist
changes, defaults and tests. Legacy inspection-only
`<bundle-identifier>.json` descriptors are also supported.

## Troubleshooting

| Problem | What to check |
|---|---|
| Python is too old or the script cannot run | Install Python 3.10+; on Windows run `py -3 patch-ipa-duo.py`, on macOS use a suitable `python3`. |
| Missing, stale or corrupt native library | Keep the full `native/` directory with the project, or rebuild bundles on macOS with `python3 tools/build_native.py`. |
| Xcode fallback cannot build a library | Select full Xcode with a suitable iPhoneOS SDK; ordinary patching with compatible bundles does not need Xcode. |
| Output already exists or cannot be published | Choose a new filename in an existing writable directory on a filesystem supporting hard links. |
| No application scene configuration | Check whether an adapter supports the app and exact build. Generic patching cannot add the missing compatibility support. |
| Unsupported adapter build or missing adapter | Check its README and identifier. `--adapter` does not bypass build checks. |
| Insufficient header padding or an existing injected library | Start with the original IPA. Bar modes cannot replace an existing injection; insufficient space prevents injection. |
| Patched app does not install or display correctly | Re-sign the output appropriately and test on the intended device. Structural validation does not establish runtime compatibility. |

## Verification and exit codes

Run the portable regression suite on either host without Xcode or an input IPA:

```sh
python3 patch-ipa-duo.py --self-test
```

On Windows use `py -3 patch-ipa-duo.py --self-test`. Tests cover archive validation,
portable ZIP permissions, Mach-O parsing, SDK changes, prebuilt hook selection,
adapter selection, resource preservation and safe output publication. Success
ends with `Patcher self-tests passed.` GitHub Actions is configured to run the
suite on macOS and Windows with Python 3.10 and 3.14.

Adapter READMEs describe production-archive tests and additional native/runtime
tests. Some native tests still require macOS and Xcode. The original Swift
self-tests remain available through `xcrun swift patch-ipa-duo.swift --self-test`.
The optional large-resource regression uses a temporary 2.1 GB file. On macOS:

```sh
IPADUO_LARGE_TESTS=1 python3 -m unittest discover -s tests -p test_large_archive.py
```

On PowerShell, set `$env:IPADUO_LARGE_TESTS = '1'` before running the equivalent
`py -3 -m unittest discover -s tests -p test_large_archive.py` command.
Actual installation, rendering and hardware operation require signed device tests.

Exit status `0` means the requested operation succeeded; `1` means an argument,
validation, build or output error. Errors are printed to standard error.

## Acknowledgements

patch-ipa-duo was developed independently, with research and inspiration from several projects exploring iPad application compatibility and iOS device behaviour.

Special thanks to:

- **[DuoSDK](https://www.reddit.com/r/sideloaded/comments/1xvhqh4/release_experimental_duo_sdk_remove_the_black/)** — For its research into SDK-version handling and application compatibility through LaunchServices.
- **[TrollPad](https://github.com/khanhduytran0/TrollPad)** — For exploring iPad-style functionality and device interface identity on iPhones.
- **[iPadify by Guilherme Rambo](https://repo.packix.com/package/codes.rambo.ipadify)** — For pioneering work enabling iPad-specific functionality on iPhones.

These projects provided valuable technical references during development.

Acknowledgement does not imply affiliation with or endorsement by the original developers.