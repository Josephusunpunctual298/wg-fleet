# Contributing

Issues and pull requests are welcome.

## Reporting a bug

Please include:
- What you clicked / did, and what you expected to happen
- The contents of `wg_fleet_error.log` (next to the app), if one was created
- Your OS and Python version (`python --version`)
- Whether you're running from source or a built `.exe`

## Development setup

```bash
git clone https://github.com/<your-username>/wg-fleet.git
cd wg-fleet
pip install -r requirements.txt
python wg_fleet.py
```

## Before submitting a pull request

- Test against a real VPS if your change touches any of the remote
  (SSH/bash) logic — most of this app's complexity lives in scripts that
  get pushed to and run on the server, which are easy to get subtly wrong
  in ways that only show up at runtime.
- Keep new remote-side scripts idempotent (safe to run repeatedly) since
  several already run automatically on every refresh.
- If you add a feature that reads more than connection metadata (i.e.
  anything approaching packet content), please open an issue to discuss
  first — this project intentionally stays at the metadata level (see
  "Responsible use" in the README).

## Project structure

Everything lives in the single `wg_fleet.py` file, organized roughly as:

1. Server storage (encrypted credentials, add/edit/remove)
2. SSH/remote helper functions
3. The background monitor script that gets installed on each VPS
   (usage tracking, connect/disconnect log, DNS query log) — this is a
   Python string template (`PEER_MONITOR_PY`) rendered and pushed via SSH,
   not a separate file in this repo
4. Peer management functions (add/remove/disable/enable)
5. WireGuard and DNS-logging auto-setup scripts (also string templates)
6. The GUI (customtkinter), one class per window
