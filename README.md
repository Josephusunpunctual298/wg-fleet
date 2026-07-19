# WG Fleet

A Windows desktop app for managing WireGuard peers across **multiple** VPS servers over SSH — add servers, add/remove/disable peers, watch live traffic and server health, and see what's actually happening on your VPN, all from one window.

![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

No agents to install on your servers beyond what the app sets up for you — just SSH access. WireGuard itself, traffic monitoring, and DNS logging can all be installed with one click from inside the app.

![Main window](docs/screenshot-main.png)

## Table of contents

- [How this is different](#how-this-is-different)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Getting started](#getting-started)
- [Responsible use](#responsible-use)
- [Security notes](#security-notes)
- [FAQ / Troubleshooting](#faq--troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## How this is different

Most WireGuard management tools ([wg-easy](https://github.com/wg-easy/wg-easy), wg-manager, wg-portal, WireGuard UI, and similar) are **web dashboards you deploy on the server itself** — great if you're managing one box, but you're logging into a different web UI, on a different port, for every server you run.

WG Fleet takes the opposite approach: it's a **native Windows desktop app that manages all your servers from one place**, connecting to each over plain SSH. There's no web service to expose, no extra port to secure, and no separate login per server — one app, all your VPSes, switchable from a dropdown.

| | WG Fleet | Typical web dashboards (wg-easy, etc.) |
|---|---|---|
| Interface | Native Windows desktop app | Self-hosted web UI (usually Docker) |
| Multiple servers | One app, switch via dropdown | One deployment per server |
| Exposed attack surface | None — SSH only, nothing new to expose | An extra web service + port per server |
| Credential storage | Encrypted locally with Windows DPAPI | Session/password stored on the server |
| Setup | Point it at a blank Ubuntu/Debian VPS; it installs WireGuard for you | Usually assumes Docker is already set up |

If you run one VPN server and want a polished self-service portal for end users, a web dashboard is still a great choice. If you administer a handful of VPS boxes yourself and want one native window instead of N browser tabs, that's what this is for.

## Features

- **Add servers from inside the app** — no config files to hand-edit.
  Saved passwords are encrypted at rest (Windows DPAPI, tied to your
  Windows login).
- **One-click WireGuard install** on a blank Ubuntu/Debian VPS — no
  manual server setup required.
- **Add / disable / enable / delete peers**, with duplicate-name checking
  and auto-detected subnet, port, and public IP.
- **Per-peer traffic totals and live Rx/Tx charts.**
- **QR code and encrypted `.conf` export** for any peer created through
  the app.
- **Live server health** — CPU, RAM, disk, network throughput, load,
  uptime — for every server.
- **Combined activity log** across all servers — every peer
  connect/disconnect event, merged into one sortable table.
- **Live connections** — see what each peer is currently talking to
  (destination IP/port/protocol), fetched in real time from the server's
  own connection table.
- **DNS query log** — see which domain names each peer has actually
  looked up, not just raw IPs.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Requirements

- **Client (your PC):** Windows 10/11, Python 3.10+
- **Servers:** Ubuntu or Debian VPS with SSH access (password or key).
  WireGuard itself can be installed automatically by the app if it isn't
  already there.

## Installation

### Option A: Download the prebuilt .exe (no Python needed)

Grab the latest `WG Fleet.exe` from the [Releases](../../releases) page
and run it. Nothing else to install.

### Option B: Run from source

```bash
git clone https://github.com/OTFRenji/wg-fleet.git
cd wg-fleet
pip install -r requirements.txt
python wg_fleet.py
```

### Option C: Build your own .exe

```bash
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --windowed --name "WG Fleet" wg_fleet.py
```

The built `.exe` will be in `dist/`. `servers_store.json` and a `configs/`
folder are created automatically next to wherever the app runs from, the
first time you use it.

## Getting started

1. Launch the app.
2. Click **Servers…** → **+ Add server**. Fill in a name, the server's
   host/IP, SSH port and user, and either a password or the path to your
   SSH private key. Leave the "Advanced" fields blank unless you need to
   override auto-detection.
3. If the server doesn't have WireGuard installed yet, you'll see a
   **"Setup WireGuard on this server"** button instead of an error —
   click it, pick a VPN subnet and port (sensible defaults are
   pre-filled), and let it run.
4. Type a name in the **Add peer** field and click **Add peer**. You'll
   get a QR code to scan with the WireGuard mobile app, plus a `.conf`
   file you can save or transfer to a desktop client.
5. Explore **Activity log**, **Live connections**, and **DNS log** in the
   top bar for visibility across all your servers at once.

Full feature details, including exactly how each monitoring feature works
and its limitations, are covered in [CHANGELOG.md](CHANGELOG.md) and the
inline help text throughout the app.

## Responsible use

This app includes traffic and DNS visibility features (**Live
connections**, **DNS log**) intended for administering infrastructure you
own and control. Some practical guidance:

- These features show **metadata only** — destination IPs, ports,
  protocols, and domain names looked up. They do not decrypt HTTPS
  traffic, log page content, or inspect payloads.
- If any peers on your VPN belong to other people (family, contractors,
  employees) rather than exclusively your own devices, let them know this
  visibility exists — the same courtesy you'd expect from any network you
  use.
- Check your local laws regarding monitoring network traffic of other
  people's devices before deploying this in a shared or organizational
  context. Requirements vary significantly by jurisdiction and
  relationship (e.g. employer/employee vs. household members).

## Security notes

- Saved SSH passwords are encrypted with Windows DPAPI, which ties
  decryption to your specific Windows user account on that specific
  machine. Moving `servers_store.json` to another PC or account makes it
  unreadable there — that's by design, not a bug. Prefer SSH keys over
  passwords where practical.
- The `configs/` folder contains WireGuard **private keys** for peers
  created through the app. Treat it like a folder of passwords.
- For peers created *before* you started using this app, QR/export isn't
  available — their private key only ever existed on the original
  device, which is WireGuard's own design (the server never has it),
  not a limitation of this tool.
- The app needs your SSH user to have (passwordless) sudo access on each
  server to manage WireGuard, install packages, and read logs.

## FAQ / Troubleshooting

**A button click does nothing.**
The app shows a dialog for any unexpected error, and also logs full
details to `wg_fleet_error.log` next to the app. Please attach that log
if you open an issue.

**DNS log / Live connections shows nothing after setup.**
Give the background monitor a minute to run (it checks in via cron every
60 seconds). Also confirm the peer's config actually points its `DNS =`
line at the server's VPN IP — setup only affects *new* peers created
afterward, not existing ones (see the in-app explanation when you click
**Set up**).

**My browser doesn't show up in the DNS log even though the connection
works.**
Many browsers default to Secure DNS (DoH), which bypasses whatever DNS
server your OS or VPN provides entirely. Test with `nslookup example.com`
from a terminal on the device instead of through a browser tab to rule
this out.

**Antivirus flags the built .exe.**
Common with `--onefile` PyInstaller builds in general, not specific to
this app. Build without `--onefile` (produces a folder instead of a
single file) or add an exclusion if you trust the source you built from.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
