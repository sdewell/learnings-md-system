# Contributing

This repository is generated. Each release is built from a private
development repository by an export script, as one new commit on top of
the previous release. The commit message names the source commit, and
`PUBLIC-EXPORT-MANIFEST.json` lists every file with its SHA-256 digest.
Nothing here is edited by hand, so a pull request against this repository
cannot be merged as it is.

Issues are welcome: bug reports, questions, and descriptions of a mistake
the router failed to catch. A fix you propose in an issue or a pull request
is ported to the source by hand and arrives in the next release, credited
in its commit message.

Before you report a bug, please include:

- macOS version, `uv --version`, and `python3 --version`;
- the command you ran and its complete output;
- `learn state status --mode-only` (prints `neutral` or `legacy`).

The system is single-user and single-machine by design (README, "Status
and limits"). Requests outside that scope may be declined.
