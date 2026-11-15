# Contributing to KashPass

## Before you start

- Security issues: don't open a public issue. Report them privately, as described in
  [SECURITY.md](SECURITY.md).
- For a new feature, open an issue first, so we can agree it fits before you write code. Bug fixes
  can go straight to a pull request.
- KashPass has no internet access and declares two permissions, for biometric unlock and for
  hiding other apps' overlays. A pull request that adds a permission or a networking library is
  not merged.

## Pull requests

- One change per pull request.
- Run the tests first:
  ```bash
  ./gradlew :vault-core:test testDebugUnitTest
  ```
- If an AI tool wrote part of the change, say so in the pull request. Typo and formatting fixes
  don't need this.

## Contributor License Agreement

Before your first pull request is merged, you sign the [CLA](CLA.md) once: a bot comments on the
pull request with a sentence to reply with. The CLA lets onekash labs also offer KashPass under a
commercial license (see [LICENSING.md](LICENSING.md)). Everything you contribute stays available
under the GNU Affero General Public License v3.0 or (at your option) any later version.
