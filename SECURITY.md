# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/OneKashLabs/KashPass/security/advisories/new). Don't open a public issue or disclose the vulnerability before it is fixed.

Never attach a real vault, key file or password. A vault made for the report with a throwaway password is enough.

Include:

- what the vulnerability is and what it affects (opening or saving a vault, key derivation, biometric unlock, the clipboard, backups, and so on)
- steps to reproduce
- the impact
- a suggested fix, if you have one

We acknowledge reports within a few days, assess the severity, fix confirmed vulnerabilities, and disclose them once fixed. Reporters are credited in the release notes unless they prefer not to be.

## Scope

This policy covers the KashPass Android app and this repository. KashPass handles:

- vault contents (entries, passwords, attachments), decrypted in memory only while the vault is unlocked
- the vault password and key file; with biometric unlock on, the password's hash, encrypted under an Android Keystore key that needs a Class 3 biometric for each use
- vault files, read and written only through the storage app you pick, and encrypted backup copies in app-private storage
- copied values, marked sensitive and cleared from the clipboard after 30 seconds

KashPass has no internet permission.

Out of scope, report to the project or vendor concerned:

- KeePass 2 and other KeePass apps
- storage apps and providers, and Android itself
- dependencies

## Supported versions

Security fixes go into the latest release only.

## Advice for users

- Keep KashPass up to date.
- Use a strong vault password, and a key file if you want a second factor.
- Keep a recent copy of your vault outside the storage app. KashPass's backups stay on the phone.
