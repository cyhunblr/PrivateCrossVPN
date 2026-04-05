# PrivateCrossVPN — Build & Packaging Instructions

## Prerequisites

### Python

- Python **3.10+** is required.
- Install dependencies: `pip install -r requirements.txt`

### System Binaries (must be pre-installed by the user)

| Protocol   | Linux (Ubuntu 20.04)               | Windows 11                              |
|------------|------------------------------------|-----------------------------------------|
| WireGuard  | `sudo apt install wireguard`       | <https://www.wireguard.com/install/>      |
| OpenVPN    | `sudo apt install openvpn`         | <https://openvpn.net/community-downloads> |
| SSH SOCKS5 | `ssh` (pre-installed on Ubuntu)    | OpenSSH (built into Windows 11)         |

### Kill-Switch Dependencies

- **Linux**: `iptables` (pre-installed on Ubuntu)
- **Windows**: `netsh` (built-in)

---

## Running from Source

```bash
# Install dependencies
pip install -r requirements.txt

# Run (will prompt for elevation if not already root/admin)
python privatecrossvpn.py

# Or on Linux, run directly with sudo:
sudo python3 privatecrossvpn.py
```

---

## Packaging as Windows .exe (PyInstaller)

```powershell
# 1. Install PyInstaller
pip install pyinstaller

# 2. Build the executable
pyinstaller --noconfirm --onefile --windowed ^
    --name "PrivateCrossVPN" ^
    --add-data "path\to\customtkinter;customtkinter" ^
    --add-data "img;img" ^
    --icon "img\logo.ico" ^
    privatecrossvpn.py

# Find the customtkinter path with:
#   python -c "import customtkinter; print(customtkinter.__path__[0])"
#
# Example (adjust to your system):
# pyinstaller --noconfirm --onefile --windowed ^
#     --name "PrivateCrossVPN" ^
#     --add-data "C:\Python311\Lib\site-packages\customtkinter;customtkinter" ^
#     --add-data "img;img" ^
#     --icon "img\logo.ico" ^
#     privatecrossvpn.py
```

The resulting `.exe` will be in the `dist/` folder.

**Important**: The .exe must be run as **Administrator** (right-click → Run as administrator) for VPN and firewall operations to work.

---

## Packaging as Linux Binary (Nuitka)

```bash
# 1. Install Nuitka and dependencies
pip install nuitka ordered-set
sudo apt install patchelf ccache  # build helpers

# 2. Build the standalone binary
python3 -m nuitka \
    --onefile \
    --enable-plugin=tk-inter \
    --include-package=customtkinter \
    --include-data-dir=img=img \
    --linux-icon=img/logo_raw.png \
    --output-filename=PrivateCrossVPN \
    privatecrossvpn.py

# The binary will be created in the current directory.
```

**Alternative with PyInstaller on Linux:**

```bash
pip install pyinstaller
CUSTOMTKINTER_PATH=$(python3 -c "import customtkinter; print(customtkinter.__path__[0])")

pyinstaller --noconfirm --onefile --windowed \
    --name "PrivateCrossVPN" \
    --add-data "${CUSTOMTKINTER_PATH}:customtkinter" \
    --add-data "img:img" \
    privatecrossvpn.py
```

Run the resulting binary with `sudo`:

```bash
sudo ./dist/PrivateCrossVPN
```

---

## Usage Notes

1. **WireGuard**: Import a `.conf` file, select WireGuard protocol, and click Connect.
2. **OpenVPN**: Import a `.ovpn` file, select OpenVPN protocol, and click Connect.
3. **SSH SOCKS5**: Select SSH SOCKS5, fill in host/user/port, optionally import a `.pem` key, and click Connect. Configure your browser to use `SOCKS5 proxy at 127.0.0.1:<port>`.
4. **Kill-Switch**: Check the Kill-Switch box before connecting. It blocks all non-VPN traffic via OS firewall rules and is automatically disabled on disconnect.
5. **Auto-Reconnect**: Dropped tunnels are automatically restored (up to 5 retries with exponential back-off).

---

## CI/CD

- **CI**: `.github/workflows/ci.yml` runs markdown lint, `ruff check .`, and `pytest -q` on pull requests and pushes to all branches.
- **Release**: `.github/workflows/release.yml` runs only after the CI workflow succeeds on `main`, bumps the patch version automatically, builds a release matrix, creates a `v*` tag, and publishes one GitHub Release containing:
  - Linux self-hosted `ubuntu-20.04` artifact
  - Linux GitHub-hosted `ubuntu-22.04` artifact
  - Linux GitHub-hosted `ubuntu-24.04` artifact
  - Windows GitHub-hosted `windows-2022` artifact
  - Windows GitHub-hosted `windows-latest` artifact
  - Note: GitHub-hosted Windows runners are Windows Server images.
- **Markdown lint**: CI also runs `markdownlint-cli` against `README.md`, `BUILD.md`, and the docs under `docs/`.
- **Local dev checks**: `pip install -r requirements-dev.txt` then run `ruff check .` and `pytest -q`.

### Hybrid CI with Self-Hosted Runner

The CI workflow supports both GitHub-hosted and self-hosted Linux runners.

**How routing works:**

- `CI_RUNNER_MODE=self-hosted` (repository variable): push/PR jobs run on self-hosted.
- `CI_RUNNER_MODE=github` or unset: push/PR jobs run on GitHub-hosted Ubuntu.
- Manual runs (`workflow_dispatch`) can override routing with `runner_target` (`auto`, `github`, `self-hosted`).

**Set up a self-hosted Linux runner (one-time):**

1. Open GitHub repository settings: `Settings` → `Actions` → `Runners` → `New self-hosted runner`
2. Choose **Linux** and **x64** architecture.
3. Copy the generated setup commands from GitHub's page. They will include your unique token and repo URL. Run them on your runner machine:

```bash
# Create runner directory and download
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -o actions-runner-linux-x64.tar.gz -L https://github.com/actions/runner/releases/download/v2.325.0/actions-runner-linux-x64-2.325.0.tar.gz

# Optional: Validate the download (GitHub provides the hash on the setup page)
# echo "HASH_HERE  actions-runner-linux-x64.tar.gz" | shasum -a 256 -c

# Extract
tar xzf ./actions-runner-linux-x64.tar.gz

# Configure (replace <org>, <repo>, and <TOKEN> with values from GitHub)
./config.sh --url https://github.com/<org>/<repo> --token <TOKEN>

# Install and start as a background service
sudo ./svc.sh install
sudo ./svc.sh start
```

**Verify runner is connected:**

```bash
sudo ./svc.sh status
```

Runner logs are at `~/actions-runner/_diag/`.

**Enable self-hosted by default for this repo:**

1. `Settings` → `Secrets and variables` → `Actions` → `Variables`
2. Add a new repository variable with Name `CI_RUNNER_MODE` and Value `self-hosted`.
3. Next push will automatically use your self-hosted runner.

**Switch back to GitHub-hosted:**

- Set `CI_RUNNER_MODE=github` or delete the variable.

**Note on tokens:** The configuration token from GitHub's setup page is valid for a limited time. If setup takes longer or the token expires, regenerate it in `Settings` → `Actions` → `Runners` and run `./config.sh` again.
