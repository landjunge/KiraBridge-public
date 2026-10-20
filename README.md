# KiraBridge 0.8.0rc12

KiraBridge routes authenticated messages and work between explicitly configured desktop tools. It provides a Python runtime and a guarded installer. This release is a prerelease, not a stable 0.8.0 release.

## Receiver fixes

- A busy receiver does not block other receivers.
- Connection failures before handoff are recorded and retries are bounded.
- A full conversation cannot prevent an accepted task from sending its final reply.
- Retry timing, receiver isolation and explicit stop behavior are preserved.

## Install

Requirements: Python 3.11+, Git and uv. Download `KiraBridge-0.8.0rc12-runtime.tar.gz` from this repository's Releases and verify it with the included SHA256SUMS. Unpack it, enter the `KiraBridge-0.8.0rc12-runtime` folder and first prepare the installation:

```sh
python3 install.py prepare
```

Preparing does not replace a running service. When ready to install, run:

```sh
python3 install.py install
```

The installer pins its bundled source commit, checks file hashes, and preserves an existing configuration. New configurations require an explicit `--full-access` choice. Busy work prevents switching. The installer supports `status` and a guarded `rollback` command. Read the displayed plan before confirming a service change.

The archive includes the runtime wheel, source distribution, a single-commit source bundle, installer, license and checksums. It contains no account credentials, operator settings, session transcripts, machine paths or private repository history. No hosted CI, native macOS companion or fresh macOS installer run is claimed by this prerelease.

## Validation

The exact runtime source for this release passed 940 tests with 2 skipped and 0 failures on Linux with Python 3.12. Ruff lint and format checks passed. The release wheel was installed in an isolated environment and its authenticated local MCP health endpoint was checked. This is not a GitHub Actions badge or a macOS acceptance claim.

## License

This source is provided under the included [Netzwerkpunkt Personal Use License](LICENSE). It permits personal, non-commercial use. Commercial operation or redistribution requires separate written permission. This is a custom source-available license, not an OSI-approved open-source license.

---

# KiraBridge 0.8.0rc12 (English)

KiraBridge routes authenticated messages and work between explicitly configured desktop tools. This is a prerelease, not a stable 0.8.0 release.

## Receiver fixes

- A busy receiver does not block other receivers.
- Pre-handoff connection failures are visible and retries are bounded.
- A full conversation cannot prevent the final reply to an accepted task.
- Retry deadlines and explicit stop behavior are preserved.

## Install

Requirements: Python 3.11+, Git and uv. Download the runtime archive from Releases, verify it against `SHA256SUMS`, and unpack it. Run `python3 install.py prepare` first. Preparing never replaces a running service. When ready to install, run `python3 install.py install`. The installer pins its included source, checks its hashes, preserves existing configuration and refuses to switch while work is active. A new configuration requires an explicit `--full-access` choice. Use `python3 install.py status` and the guarded `python3 install.py rollback` as needed.

The archive includes the runtime wheel, source distribution, a single-commit source bundle, installer, license and checksums. It excludes account credentials, operator settings, session transcripts, machine paths and private repository history. The exact runtime source passed 940 tests, with 2 skipped and 0 failures, plus Ruff checks on Linux/Python3.12. This prerelease makes no hosted CI, macOS installer or native companion claim.

The included custom license allows personal non-commercial use. Commercial use or redistribution requires separate written permission; it is not an OSI-approved open-source license.
