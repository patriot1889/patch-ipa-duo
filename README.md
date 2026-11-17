# IPA Patcher for Duo

`patch-ipa-duo` is a macOS command-line tool for adapting decrypted iOS app
packages for Duo. It updates SDK metadata and offers options for iPhone support
and system bar placement. Adapters provide additional compatibility changes for
supported app builds.

**Patched output must be re-signed before installation.** Patching changes the
app's existing signatures. A successful patch confirms structural checks, not
that the app will launch or display correctly on your device.

## Requirements

- macOS with Xcode's Swift toolchain selected for command-line use.
- A decrypted iOS device `.ipa` that you are authorized to modify. The tool does
  not decrypt apps or build Simulator versions.
- Full Xcode with an iPhoneOS SDK of 27.1 or later for full-mode bar overrides
  and self-tests. Native adapters also need full Xcode; check their READMEs for
  SDK versions and additional tools.
- An existing, writable output directory on a filesystem that supports hard links
  for publishing the result without overwriting files.

Check the selected developer tools in Terminal:

```sh
xcode-select -p
xcrun swift --version
```

For native library injection or self-tests, also check the selected iPhoneOS SDK:

```sh
xcrun --sdk iphoneos --show-sdk-version
```

If the SDK is missing or too old, install a suitable Xcode version and select it
under **Xcode → Settings → Locations → Command Line Tools**. Some adapters also
use Python 3; their READMEs list their requirements.

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
Watch apps or App Clips are rejected. Extra top-level content such as
`SwiftSupport/` is unsupported. Optional top-level `iTunesArtwork` is validated
and omitted from the output.

Full-mode bar overrides compile and inject `Frameworks/IPAPatcherBars.dylib`.
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

Adapter discovery follows the script location, including symlinks, and works
from other working directories. The directory is optional for generic patching.
Each package owns its `adapter.json`, native source, validation rules, plist
changes, defaults and tests. Legacy inspection-only
`<bundle-identifier>.json` descriptors are also supported.

## Troubleshooting

| Problem | What to check |
|---|---|
| Permission denied when running the script | Run `chmod +x ./patch-ipa-duo`, or use `xcrun swift patch-ipa-duo` followed by the same arguments. |
| Swift or iPhoneOS SDK cannot be found | Check the developer-tool commands above and select the appropriate Xcode installation. |
| Output already exists or cannot be inspected | Use a new output filename and an existing, writable parent directory. |
| No application scene configuration | Check whether an adapter supports the app and exact build. Generic patching cannot add the missing compatibility support. |
| Unsupported adapter build or missing adapter | Check its README and identifier. `--adapter` does not bypass build checks. |
| Insufficient header padding or an existing injected library | Start with the original IPA. A different bar mode cannot replace a previous injection; insufficient space prevents injection. |
| Patched app does not install or display correctly | Re-sign the output appropriately and test on the intended device. Structural validation does not establish runtime compatibility. |

## Verification and exit codes

```sh
./patch-ipa-duo --self-test
```

Self-tests use temporary fixtures and require Xcode with an iPhoneOS SDK of
27.1 or later. They exercise archive validation, adapter selection, SDK changes,
bar-hook compilation and injection, and safe failure cases without a device or
signing credentials. Success ends with `Patcher self-tests passed.` Adapter
READMEs describe additional tests for their supported apps.

Exit status `0` means the requested operation succeeded; `1` means an argument,
validation, build or output error. Errors are printed to standard error.
