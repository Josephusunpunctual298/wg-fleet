# Changelog

## 1.0.0

Initial release.

- Add, edit, and remove servers from inside the app, with saved passwords
  encrypted at rest (Windows DPAPI on Windows).
- One-click WireGuard install and configuration on a blank Ubuntu/Debian
  VPS.
- Add, disable/enable, and delete peers per server, with duplicate-name
  checking and auto-detected subnet, port, and public IP.
- Per-peer lifetime traffic totals and live Rx/Tx charts.
- QR code and encrypted `.conf` export for peers created through the app.
- Live server health (CPU, RAM, disk, network throughput, load, uptime)
  for every configured server.
- Combined activity log across all servers, merging every peer
  connect/disconnect event into one sortable table.
- Live connections view showing what each peer is currently talking to
  (destination IP/port/protocol), read directly from each server's
  connection table.
- DNS query log showing which domain names each peer has looked up.
- CSV export, peer search, and configurable auto-refresh.
