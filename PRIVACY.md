# Privacy Policy

*Effective November 15, 2026*

## Overview

This Privacy Policy describes how onekash labs ("we," "us," or "our") handles information in
connection with the KashPass mobile application ("the App"). KashPass opens a KeePass vault file
you choose, on your device. Nothing is sent to us.

This policy applies to every version of KashPass, however you install it.

## Data Collection

We do not collect any personal data. KashPass has no internet access: it does not request
Android's network permission and contains no networking code. It sends no telemetry, analytics,
crash reports or usage statistics to onekash labs or anyone else. It contains no analytics,
advertising or tracking code or SDKs.

There are no user accounts, no registration and no servers. We have no way to access, retrieve or
view your data.

## Your Vault

Your vault stays where you keep it, for example in a cloud storage app or on your phone. KashPass opens it
through the Android file picker and saves your changes back to the same file. The storage app that
holds the file syncs it under its own terms; KashPass never contacts it over
the network itself.

Your vault is decrypted only in memory, while it is unlocked. Locking, turning the screen off, or
leaving the app for longer than the lock timeout drops the decrypted vault and its key.

## Data Stored on Device

KashPass stores only the following, in its private storage on your device:

- Which vault file and key file you chose (their locations and names, never their contents), and
  the security settings last seen for the vault, so a weakened or replaced file can be refused.
- Encrypted copies of your vault, kept when you open it and before and after each save, so a bad
  save can be undone or a damaged file read. They are the vault file's own encrypted bytes; you
  choose how many to keep.
- If you turn on fingerprint or face unlock: your master password in hashed form, encrypted with a
  key held by Android's Keystore that only your biometric can unlock. It is deleted when you turn
  biometric unlock off. Adding a new fingerprint or face makes Android disable that key at once,
  and KashPass deletes it the next time its lock screen appears.
- App settings, such as how many backup copies to keep, and a record that a save is in progress.

Decrypted entries, passwords, key-file contents and your master password are never written to
disk or to logs.

## Clipboard

When you copy a value, KashPass marks it as sensitive, so Android hides it from clipboard previews,
and clears it 30 seconds later.

## Permissions

KashPass declares two permissions:

- Biometric, for optional fingerprint or face unlock.
- Hide overlay windows, to stop other apps drawing over KashPass's screens.

Neither is used to collect, transmit or share personal data.

## Security

- KashPass's screens cannot be captured in screenshots, screen recordings or
  the recent-apps preview.
- Nothing KashPass stores is included in Android backup or device-to-device
  transfer.
- The source code is public for anyone to audit:
  [github.com/OneKashLabs/KashPass](https://github.com/OneKashLabs/KashPass).

## Retention & Deletion

Everything is stored on your device, so you control it. To remove KashPass's data:

- Turn off biometric unlock in Settings.
- Clear the app's data in Android's system settings.
- Uninstall the App.

Your vault file is yours and stays where you keep it; uninstalling KashPass does not delete it.
We hold no data, so nothing remains on our side.

## Children's Privacy

KashPass is not directed at children under the age of 13. We do not collect personal data from
any user, including children.

## Changes to This Policy

We may update this policy to reflect changes in the App or applicable regulations. Material
changes will be noted in the App's release notes.

## Contact

Questions about this policy:

- Email: [privacy@onekash.org](mailto:privacy@onekash.org)
- GitHub: [KashPass issues](https://github.com/OneKashLabs/KashPass/issues)
