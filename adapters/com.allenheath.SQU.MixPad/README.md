# SQ MixPad adapter

Supports `com.allenheath.SQU.MixPad`, version `1.60.1`, build `1.60.1.92418`
(the app marketed as 1.6.1). All adapter-specific rules and source live here.
The main patcher supplies shared archive validation, prebuilt-library selection
(or macOS source compilation), SDK changes and dylib injection.

Run these commands from the repository root. On Windows replace
`./patch-ipa-duo` with `py -3 .\patch-ipa-duo.py`:

```sh
./patch-ipa-duo inspect com.allenheath.SQU.MixPad-1.6.1.ipa
./patch-ipa-duo inspect MyApp.ipa --adapter com.allenheath.SQU.MixPad
./patch-ipa-duo patch com.allenheath.SQU.MixPad-1.6.1.ipa --output MixPad-top.ipa
./patch-ipa-duo patch com.allenheath.SQU.MixPad-1.6.1.ipa --output MixPad-side.ipa --bars side
./patch-ipa-duo patch com.allenheath.SQU.MixPad-1.6.1.ipa --output MixPad-reserved.ipa --display reserved-side
```

Automatic selection uses the original bundle identifier. A renamed copy can use
`--adapter com.allenheath.SQU.MixPad`; this retains the copy's identifier:

```sh
./patch-ipa-duo patch MyApp.ipa --output MyApp-adapted.ipa --adapter com.allenheath.SQU.MixPad
```

Version, build and executable preflight checks still apply.

The adapter sets `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace`
to expose the app's entire `Documents` directory in Files under
**On My iPhone/iPad > SQ MixPad** (the displayed name may differ after signing).
This follows [Apple's local file-sharing configuration](https://developer.apple.com/documentation/fileprovider#Share-files-locally).
The supported executable already resolves its saved-show directory to
`Documents/Shows/SHOWS` and its working show to `Documents/CurrentShow`, so no path
redirection or migration is needed. Static tracing confirms that its show-path
builder calls Qt's Documents lookup, which resolves to
`NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)`.

After installing a signed build, launch MixPad and save an offline show to create
its folder structure. Close MixPad before copying complete show folders into
`Shows/SHOWS` through Files, then reopen MixPad to check its offline show list.
Saved show folders use the name `SHOW` followed by four digits, such as
`SHOW0000`; use a free number and include `SHOW.DAT` and all other contents.
Keep the complete folder and its contents together; avoid replacing `CurrentShow`
directly. This adds local folder access; opening a show by tapping it in Files
still depends on MixPad's existing document handling. The Files-access build
was signed, installed and launched on a physical Duo, and the user confirmed
that the workflow works.

The manifest enables iPhone while retaining iPad support, removes
`UIRequiresFullScreen`, and adds a single application scene using
`MixPadSceneDelegate`. Full mode defaults to top bars and accepts side placement.
Reserved-side mode keeps system bar placement and rejects `--bars top`. The source-built
`com.allenheath.SQU.MixPad.dylib` is injected in both display modes. The generic
bar hook is additionally injected for full-mode top/side requests.

`scene.m` attaches Qt's existing `QUIWindow` to UIKit's scene rather than creating
replacement content. It handles windows created before or after scene connection,
including windows that Qt already attached to a compatibility scene. It remembers
Qt's visibility request, hides before migrating between scenes, and restores that
request after attachment. Root-view loading happens after scene attachment;
an unloaded or wrapped desktop must not exclude the launch window.
The bridge updates window geometry and fits the largest visible `QUIView` within the main
`QIOSDesktopManagerView`. It retains the original Qt method implementations and
keeps popup/native-window geometry separate. Disconnect clears scene associations
so the same Qt UI can reconnect. iOS 26+ uses effective scene geometry, with a
coordinate-space fallback on older systems.

Requirements: Python 3.10+, a decrypted supported device IPA, the included
`native/prebuilt/` bundles, and enough zeroed Mach-O header padding. Patching
works on macOS and Windows; rebuilding the libraries requires macOS with Xcode
and an iPhoneOS SDK of 27.1 or later. The manifest declares
the required Qt class strings and rejects an existing scene manifest. Always
start with an unpatched archive. Signing with a development identity remains a
separate step; linker ad-hoc seals on new dylibs do not authorize installation.

`discovery.m` builds `SQFind.dylib`. The adapter-owned `patch-executable.py`
redirects the main executable's chained `_sendmsg` import from libSystem to
`_sq_find` in that library. It preserves chained pointer indices, addends and
unrelated imports. Both XML and DER signing metadata lose the root
`com.apple.developer.networking.multicast` entitlement; every other entitlement
is preserved. Entitlement digests are updated without moving executable data.
Code-page/CMS signatures remain stale after patching and must be replaced during
separate signing. No extra multicast-stripping argument is needed at that step.

Only an IPv4 UDP `SQ Find` packet to `255.255.255.255:51320` is converted. The
wrapper enumerates usable local interfaces, respects the socket's bound address
and interface, and probes each subnet's host range, capped at the interface's
own `/24` for wider networks. It skips the interface address, network and
broadcast addresses, loopback/point-to-point interfaces, and `/31` or `/32`
ranges. There is no broadcast fallback. All other calls retain their original
send path; probes retain the original socket, flags, payload and ancillary data.
Discovery outside that bounded IPv4 range remains unsupported by this change.

Run the adapter-specific production-archive checks from the repository root:

```sh
python3 adapters/com.allenheath.SQU.MixPad/test_adapter.py com.allenheath.SQU.MixPad-1.6.1.ipa
python3 adapters/com.allenheath.SQU.MixPad/test_discovery.py
python3 adapters/com.allenheath.SQU.MixPad/test_executable.py
```

The production-archive test runs the Python patcher and verifies top, side,
reserved-side and forced-adapter outputs, SDK/minimum OS metadata, plist changes, load commands,
input/resource/code preservation, import redirection, XML/DER entitlement removal
and safe failures. `test_discovery.py` runs mocked socket tests with sanitizers
and builds both device architectures; it sends no network traffic.
`test_executable.py` checks all supported import formats, fat slices, DER
preservation and codesign readback using temporary ad-hoc fixtures.
On Windows use `py -3` instead of `python3`; `test_adapter.py` is portable.
The socket/native and codesign tests require macOS and Xcode. To compare the
original implementation, pass `--patcher patch-ipa-duo.swift` to `test_adapter.py`.
`--keep-output NEW_DIRECTORY`
retains the artifacts for review.

The adapter also owns `runtime-tests.m` and `runtime-tests-Info.plist`, a UIKit
simulator host with fake Qt classes. Build them with `scene.m` and run the test
app to exercise lifecycle, geometry, reentrant layout and popup isolation. Results
are written to the app's `Documents/adapter-test-result.json`. These tests exercise
the bridge with real UIKit; they do not run the device IPA's Qt binary. Actual
SQ MixPad launch, fold/unfold behavior and mixer operation still require a signed
device test.

To build and run that host, from this adapter directory:

```sh
mkdir -p /tmp/SQAdapterRuntimeTests.app
cp runtime-tests-Info.plist /tmp/SQAdapterRuntimeTests.app/Info.plist
xcrun --sdk iphonesimulator clang -target arm64-apple-ios15.0-simulator \
  -fobjc-arc -fblocks -framework UIKit -Werror -Wl,-adhoc_codesign \
  scene.m runtime-tests.m -o /tmp/SQAdapterRuntimeTests.app/SQAdapterRuntimeTests
xcodebuildmcp simulator boot --simulator-id "$SIMULATOR_UUID"
xcodebuildmcp simulator install --simulator-id "$SIMULATOR_UUID" --app-path /tmp/SQAdapterRuntimeTests.app
xcodebuildmcp simulator launch-app --simulator-id "$SIMULATOR_UUID" --bundle-id com.ipaduo.SQAdapterRuntimeTests
```

The launch tool reports the runtime log, which includes every check and the exact
result JSON path. A native scene dialog test verifies that activation and queued
attachment retries preserve its key focus and that Qt recovers focus afterward.
The host also covers a deferred/nested desktop and migration from another real
`UIWindowScene`. These cases fail against the earlier adapter and pass with the
black-screen fix. Set `MIXPAD_SCENE_DEBUG=1` in the app's launch environment to
log window selection, scene association, root-view class and visibility state.

The black-screen regression was reproduced on the physical Duo: Qt's visible
window initially belonged to a compatibility scene, and the earlier adapter
rejected it because its scene differed from the application scene. The repaired
bridge migrates that same window, preserving visibility. Device diagnostics
confirmed the migration and the interface was visually confirmed after reinstall.
The expanded host passes 41 checks; the previous bridge fails 14 of the earlier
37-check regression set.
