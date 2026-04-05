# Project Guidelines

## Code Style
- Keep changes minimal and consistent with the existing single-file app structure in [privatecrossvpn.py](privatecrossvpn.py).
- Prefer standard library code unless the project already depends on a library. The runtime dependency list is intentionally small; see [requirements.txt](requirements.txt).
- Match the existing test style in [tests/test_core.py](tests/test_core.py): import the module fresh, isolate state with `monkeypatch`, and use temporary paths for filesystem-backed behavior.

## Architecture
- [privatecrossvpn.py](privatecrossvpn.py) is the application entrypoint and contains the UI, profile handling, tunnel orchestration, and platform-specific system integration.
- Profiles and settings are persisted under `~/.privatecrossvpn/`; keep HOME-sensitive behavior intact because tests rely on it.
- The app talks directly to system binaries such as `wg-quick`, `openvpn`, and `ssh`, and the kill-switch uses `iptables` on Linux or `netsh advfirewall` on Windows. See [README.md](README.md) and [BUILD.md](BUILD.md).
- For VPN server or domain setup guidance, link to the existing docs instead of repeating them: [docs/azure-setup.md](docs/azure-setup.md), [docs/digitalocean-setup.md](docs/digitalocean-setup.md), and [docs/namecheap-domain-setup.md](docs/namecheap-domain-setup.md).

## Build and Test
- Install runtime dependencies with `pip install -r requirements.txt`.
- Install development dependencies with `pip install -r requirements-dev.txt`.
- Run the app from source with `sudo -E python3 privatecrossvpn.py` on Linux or `python privatecrossvpn.py` on Windows.
- Run tests with `python -m pytest -q`.
- Run lint checks with `python -m ruff check .`; markdown changes should stay compatible with the repository’s markdown linting in CI.

## Commit Messages
- Use Conventional Commits for all AI-generated commit suggestions and final commits.
- Keep the subject line in the form `type: summary` or `type(scope): summary`.
- Allowed types are `feat`, `fix`, `refactor`, `chore`, `docs`, `build`, `ci`, `perf`, and `style`.
- Do not generate generic summaries like `Update files` or `Misc changes`.
- Prefer the smallest accurate type: documentation goes to `docs:`, and tooling or housekeeping goes to `chore:` unless a more specific type clearly fits.

## Conventions
- Use `sudo -E` on Linux so the user Python environment and packages remain available when elevation is required.
- Preserve the existing filename sanitization behavior for saved profiles; slashes in profile names are converted to safe filesystem names.
- Packaging, release, and binary build details belong in [BUILD.md](BUILD.md) rather than this file.
- Keep protocol and infrastructure setup details linked, not duplicated, so this file stays focused on agent-critical behavior.
