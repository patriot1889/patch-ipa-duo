# Plex adapter

Supports `com.plexapp.plex`, version `2026.22.0`, build `2211`.

Run these commands from the repository root:

```sh
./patch-ipa-duo inspect com.plexapp.plex-2026.22.0.ipa
./patch-ipa-duo patch com.plexapp.plex-2026.22.0.ipa --output Plex-duo.ipa
```

Automatic selection uses the original bundle identifier. To select this adapter
for a renamed copy, add `--adapter com.plexapp.plex` to `inspect` or `patch`.
The copy's bundle identifier is retained; version and build checks still apply.

The default full-display patch updates the main executable and plist SDK
metadata to at least 27.1, retaining a newer executable SDK and preserving the
app and extension bundle identifiers. It uses Plex's existing application scenes
and leaves device families unchanged.

The adapter declares `_airplay._tcp` in `NSBonjourServices` alongside the
configured Plex and Google Cast services. Vizbee uses this service for a
temporary Bonjour registration to check Local Network access before opening the
Cast picker.

Full mode defaults to existing system bar behavior (`--bars default`). Explicit
`--bars top` and `--bars side` requests use the generic UIKit bar hook. The
adapter supplies no native libraries or executable transformation of its own.

Use a decrypted supported device IPA. Explicit bar overrides require a selected
Xcode iPhoneOS SDK 27.1 or later and sufficient Mach-O header padding. Patched
output retains stale signatures and is not ready for device installation.
Structural validation does not verify launch, display behavior or casting on a
physical device.
