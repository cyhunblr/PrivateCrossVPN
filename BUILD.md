# PrivateCrossVPN — Build & Packaging Instructions

## Prerequisites

### Python

- Python **3.10+** is required.
- Install dependencies: `pip install -r requirements.txt`

### System Binaries (must be pre-installed by the user)

| Protocol   | Linux (Ubuntu 20.04/22.04)         | Windows 11                              |
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

- **CI**: `.github/workflows/ci.yml` runs `ruff check .` and `pytest -q` on pull requests and pushes to `main`.
- **Release**: `.github/workflows/release.yml` runs only after the CI workflow succeeds on `main`, bumps the patch version automatically, builds Windows and Ubuntu 20.04 executables, creates a `v*` tag, and publishes the GitHub Release.
- **Markdown lint**: CI also runs `markdownlint-cli` against `README.md`, `BUILD.md`, and the docs under `docs/`.
- **Local dev checks**: `pip install -r requirements-dev.txt` then run `ruff check .` and `pytest -q`.
