#!/usr/bin/env python3
"""
WG Fleet — Windows desktop app to manage WireGuard peers across
multiple VPS servers over SSH.

Features:
  - Add/edit/remove servers from inside the app (Servers... button).
    Saved passwords are encrypted at rest: Windows DPAPI when running on
    Windows (tied to the Windows login), with a local-key fallback on
    other OSes for development.
  - Add, disable/enable, and delete peers per server. Duplicate-name
    checking, auto-detected subnet/port/public IP.
  - If a VPS has no WireGuard installed (or no config), the app detects
    it and offers one-click install + configure (apt install, server
    keys, wg0.conf with NAT, IP forwarding, firewall rule, systemd
    service).
  - Live server health panel (CPU, RAM, disk, network throughput, load,
    uptime) plus a Restart WireGuard button.
  - Per-peer lifetime traffic totals and a live Rx/Tx chart, powered by a
    small monitor script the app installs on each server (checks in every
    minute via cron; also keeps itself updated across app versions).
  - Combined Activity log (connect/disconnect events), Live Connections
    (what each peer is currently talking to — destination IP/port/
    protocol, metadata only), and DNS log (which domains peers actually
    looked up) — all as sortable, filterable tables merged across every
    configured server at once.
  - QR code + encrypted export (password-protected) for any peer created
    through the app; local configs are saved so they can be re-shown or
    re-exported anytime.
  - CSV export of the peer list, peer search, optional auto-refresh.

Run directly:   python wg_fleet.py
Build an .exe:  pyinstaller --onefile --windowed --name "WG Fleet" wg_fleet.py

Requires: pip install customtkinter paramiko qrcode[pil]
"""

import csv
import json
import os
import re
import sys
import threading
import time
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
from tkinter import ttk

import customtkinter as ctk
import paramiko
import qrcode
from PIL import Image

# --------------------------------------------------------------------------
# Paths (work both as script and as PyInstaller exe)
# --------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SERVERS_STORE_FILE = os.path.join(BASE_DIR, "servers_store.json")
LEGACY_SERVERS_FILE = os.path.join(BASE_DIR, "servers.json")
CONFIGS_DIR = os.path.join(BASE_DIR, "configs")


# --------------------------------------------------------------------------
# Secret encryption: Windows DPAPI (tied to the Windows login) when available,
# else a local-key fallback so the app still runs during development on
# other OSes. Either way, passwords never sit in the JSON file as plain text.
# --------------------------------------------------------------------------
IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                   ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _to_blob(data):
        buf = ctypes.create_string_buffer(data, len(data))
        blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        return blob, buf  # keep buf alive for the call's duration

    def _dpapi_protect(data):
        blob_in, _buf = _to_blob(data)
        blob_out = _DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), "WG Fleet", None, None, None, 0, ctypes.byref(blob_out))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)

    def _dpapi_unprotect(data):
        blob_in, _buf = _to_blob(data)
        blob_out = _DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)

    def encrypt_secret(plaintext):
        import base64
        return base64.b64encode(_dpapi_protect(plaintext.encode("utf-8"))).decode("ascii")

    def decrypt_secret(token):
        import base64
        return _dpapi_unprotect(base64.b64decode(token)).decode("utf-8")

    SECRET_BACKEND = "Windows DPAPI (tied to this Windows login)"

else:
    # Non-Windows fallback (mainly for development/testing this file).
    # Key lives next to the store with restrictive permissions — not as
    # strong as DPAPI, but still far better than storing plain text.
    from cryptography.fernet import Fernet

    _FALLBACK_KEY_FILE = os.path.join(BASE_DIR, ".servers.key")

    def _fallback_key():
        if os.path.exists(_FALLBACK_KEY_FILE):
            with open(_FALLBACK_KEY_FILE, "rb") as f:
                return f.read()
        key = Fernet.generate_key()
        with open(_FALLBACK_KEY_FILE, "wb") as f:
            f.write(key)
        try:
            os.chmod(_FALLBACK_KEY_FILE, 0o600)
        except Exception:
            pass
        return key

    def encrypt_secret(plaintext):
        return Fernet(_fallback_key()).encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt_secret(token):
        return Fernet(_fallback_key()).decrypt(token.encode("ascii")).decode("utf-8")

    SECRET_BACKEND = "local key file (non-Windows fallback)"


# --------------------------------------------------------------------------
# Server store (add/edit/remove happens in-app; passwords stored encrypted)
# --------------------------------------------------------------------------
def _apply_server_defaults(s):
    s.setdefault("ssh_port", 22)
    s.setdefault("ssh_user", "root")
    s.setdefault("wg_interface", "wg0")
    s.setdefault("dns", "1.1.1.1")
    s.setdefault("allowed_ips", "0.0.0.0/0, ::/0")
    s.setdefault("keepalive", 25)
    s.setdefault("endpoint", "")          # blank = auto-detect
    s.setdefault("subnet", "")            # blank = auto-detect
    s.setdefault("ssh_key", "")
    s.setdefault("ssh_password", "")
    s["sudo"] = s["ssh_user"] != "root"
    return s


def save_servers(servers):
    """Write the server list to disk with passwords encrypted, never in plain text."""
    raw = []
    for s in servers:
        s2 = {k: v for k, v in s.items() if k not in ("ssh_password", "sudo")}
        pw = s.get("ssh_password", "")
        if pw:
            s2["ssh_password_enc"] = encrypt_secret(pw)
        raw.append(s2)
    tmp = SERVERS_STORE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2)
    os.replace(tmp, SERVERS_STORE_FILE)


def load_servers():
    """Returns (servers, migrated_from_legacy_bool)."""
    if os.path.exists(SERVERS_STORE_FILE):
        with open(SERVERS_STORE_FILE, encoding="utf-8-sig") as f:
            raw = json.load(f)
        servers = []
        for s in raw:
            s = dict(s)
            enc = s.pop("ssh_password_enc", None)
            if enc:
                try:
                    s["ssh_password"] = decrypt_secret(enc)
                except Exception:
                    s["ssh_password"] = ""  # undecryptable (moved to another machine/user)
            servers.append(_apply_server_defaults(s))
        return servers, False

    if os.path.exists(LEGACY_SERVERS_FILE):
        with open(LEGACY_SERVERS_FILE, encoding="utf-8-sig") as f:
            raw = json.load(f)
        servers = [_apply_server_defaults(dict(s)) for s in raw]
        save_servers(servers)
        try:
            os.replace(LEGACY_SERVERS_FILE, LEGACY_SERVERS_FILE + ".bak")
        except Exception:
            pass
        return servers, True

    return [], False


def safe_filename(name):
    return re.sub(r"[^A-Za-z0-9_-]", "_", name)


def local_conf_path(server, peer_name):
    d = os.path.join(CONFIGS_DIR, safe_filename(server["name"]))
    return os.path.join(d, f"{safe_filename(peer_name)}.conf")


def encrypt_conf(conf_text, password):
    """Password-encrypt a WireGuard config for safe storage/sharing.
    Returns a JSON string containing salt + ciphertext (not itself a valid .conf)."""
    import base64 as _b64
    import hashlib
    import secrets
    from cryptography.fernet import Fernet

    salt = secrets.token_bytes(16)
    iterations = 390000
    key = _b64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32))
    token = Fernet(key).encrypt(conf_text.encode())
    payload = {
        "wgmgr_encrypted": True,
        "salt": _b64.b64encode(salt).decode(),
        "iterations": iterations,
        "token": token.decode(),
    }
    return json.dumps(payload, indent=2)


def decrypt_conf(enc_text, password):
    """Reverse of encrypt_conf. Raises ValueError on wrong password / bad file."""
    import base64 as _b64
    import hashlib
    from cryptography.fernet import Fernet, InvalidToken

    try:
        payload = json.loads(enc_text)
        salt = _b64.b64decode(payload["salt"])
        iterations = payload.get("iterations", 390000)
        token = payload["token"].encode()
    except Exception:
        raise ValueError("This doesn't look like a WG Fleet encrypted config file.")

    key = _b64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32))
    try:
        return Fernet(key).decrypt(token).decode()
    except InvalidToken:
        raise ValueError("Wrong password (or corrupted file).")


def shell_quote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


def human_ago(ts):
    if not ts:
        return "never"
    d = int(time.time() - ts)
    if d < 60: return f"{d}s ago"
    if d < 3600: return f"{d // 60}m ago"
    if d < 86400: return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


def human_bytes(n, per_s=False):
    suffix = "/s" if per_s else ""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            v = f"{n:.0f}" if unit == "B" else f"{n:.1f}"
            return f"{v} {unit}{suffix}"
        n /= 1024
    return f"{n:.1f} PiB{suffix}"


def human_uptime(sec):
    d, r = divmod(int(sec), 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    if d: return f"{d}d {h}h"
    if h: return f"{h}h {m}m"
    return f"{m}m"


# --------------------------------------------------------------------------
# SSH / WireGuard backend
# --------------------------------------------------------------------------
def run_remote(server, command, timeout=30):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=server["host"], port=server["ssh_port"],
                  username=server["ssh_user"], timeout=10)
    if server.get("ssh_key"):
        kwargs["key_filename"] = os.path.expanduser(server["ssh_key"])
    elif server.get("ssh_password"):
        kwargs["password"] = server["ssh_password"]
    client.connect(**kwargs)
    try:
        prefix = "sudo -n bash -c " if server["sudo"] else "bash -c "
        stdin, stdout, stderr = client.exec_command(prefix + shell_quote(command),
                                                    timeout=timeout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    finally:
        client.close()


def read_remote_json(server, path, default):
    """Read a JSON file on the server safely (returns default if missing/invalid)."""
    rc, out, err = run_remote(server, f"cat {path} 2>/dev/null || echo '{{}}'")
    try:
        return json.loads(out.strip() or "{}")
    except Exception:
        return default


MONITOR_PATH = "/etc/wireguard/peer_monitor.py"
USAGE_STATE_FILE = "/etc/wireguard/usage_state.json"
TRAFFIC_HISTORY_FILE = "/etc/wireguard/traffic_history.json"
CONN_LOG_FILE = "/etc/wireguard/connection.log"

# Runs every minute via cron as root on the VPS. Pure stdlib. Tracks:
#  - cumulative lifetime bytes per peer (survives interface restarts)
#  - connect / disconnect events (logged with timestamp + peer name)
#  - a rolling window of rx/tx samples per peer for the traffic chart
PEER_MONITOR_PY = '''#!/usr/bin/env python3
"""Auto-generated by WG Fleet. Tracks usage, connect/disconnect events,
a short traffic history per peer, and (if enabled) DNS query logging.
Safe to run every minute via cron."""
import json, os, re, subprocess, time

IFACE = "%(iface)s"
CONF = "/etc/wireguard/%(iface)s.conf"
USAGE_FILE = "/etc/wireguard/usage_state.json"
STATUS_FILE = "/etc/wireguard/peer_status.json"
HISTORY_FILE = "/etc/wireguard/traffic_history.json"
CONN_LOG = "/etc/wireguard/connection.log"
HISTORY_MAX = 180          # ~3 hours of 1-minute samples
ONLINE_WINDOW = 150        # seconds since last handshake to count as "online"

DNSMASQ_LOG = "/var/log/wg-dns.log"
DNS_QUERY_LOG = "/etc/wireguard/dns_query.log"
DNS_CACHE_FILE = "/etc/wireguard/dns_cache.json"
DNS_OFFSET_FILE = "/etc/wireguard/dns_log_offset.txt"
DNS_CACHE_MAX = 3000
DNS_QUERY_LOG_MAX_LINES = 5000


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def log_event(msg):
    with open(CONN_LOG, "a") as f:
        f.write(time.strftime("%%Y-%%m-%%d %%H:%%M:%%S") + " " + msg + "\\n")


def peer_map():
    """Returns (names_by_pubkey, names_by_ip) parsed from the wg0.conf comments."""
    by_pubkey, by_ip = {}, {}
    try:
        with open(CONF) as f:
            conf_text = f.read()
    except Exception:
        return by_pubkey, by_ip
    for block in re.split(r"\\n\\s*\\n", conf_text):
        clean = block.replace("#OFF# ", "").replace("#OFF#", "")
        m_name = re.search(r"#\\s*(.+?)\\s*(?:\u2014|--|- added|$)", clean, re.M)
        m_pk = re.search(r"PublicKey\\s*=\\s*(\\S+)", clean)
        m_ip = re.search(r"AllowedIPs\\s*=\\s*([\\d.]+)", clean)
        if m_pk:
            name = m_name.group(1).strip() if m_name else m_pk.group(1)[:8]
            by_pubkey[m_pk.group(1)] = name
            if m_ip:
                by_ip[m_ip.group(1)] = name
    return by_pubkey, by_ip


def process_dns_log(names_by_ip):
    """Incrementally tails the dnsmasq query log (only if DNS logging has been
    set up on this server) and appends attributed queries to DNS_QUERY_LOG,
    plus keeps a system-wide {ip: domain} cache for connection enrichment."""
    if not os.path.exists(DNSMASQ_LOG):
        return

    try:
        offset = int(open(DNS_OFFSET_FILE).read().strip())
    except Exception:
        offset = 0

    try:
        size = os.path.getsize(DNSMASQ_LOG)
    except Exception:
        return
    if size < offset:
        offset = 0  # log rotated

    try:
        with open(DNSMASQ_LOG, "r", errors="replace") as f:
            f.seek(offset)
            new_data = f.read()
            new_offset = f.tell()
    except Exception:
        return

    with open(DNS_OFFSET_FILE, "w") as f:
        f.write(str(new_offset))

    if not new_data:
        return

    cache = load(DNS_CACHE_FILE, {})
    new_query_lines = []
    for line in new_data.splitlines():
        m = re.search(r"query\\[A+\\]\\s+(\\S+)\\s+from\\s+(\\S+)", line)
        if m:
            domain, client_ip = m.group(1), m.group(2)
            peer = names_by_ip.get(client_ip, client_ip)
            ts = time.strftime("%%Y-%%m-%%d %%H:%%M:%%S")
            new_query_lines.append(f"{ts} {peer} {domain}")
            continue
        m = re.search(r"reply\\s+(\\S+)\\s+is\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)", line)
        if m:
            domain, ip = m.group(1), m.group(2)
            cache[ip] = {"domain": domain, "ts": time.time()}

    if new_query_lines:
        with open(DNS_QUERY_LOG, "a") as f:
            f.write("\\n".join(new_query_lines) + "\\n")
        # keep the query log from growing forever
        try:
            with open(DNS_QUERY_LOG) as f:
                all_lines = f.readlines()
            if len(all_lines) > DNS_QUERY_LOG_MAX_LINES:
                with open(DNS_QUERY_LOG, "w") as f:
                    f.writelines(all_lines[-DNS_QUERY_LOG_MAX_LINES:])
        except Exception:
            pass

    if len(cache) > DNS_CACHE_MAX:
        newest = sorted(cache.items(), key=lambda kv: kv[1]["ts"], reverse=True)[:DNS_CACHE_MAX]
        cache = dict(newest)
    save(DNS_CACHE_FILE, cache)


def main():
    now = time.time()
    names, names_by_ip = peer_map()
    usage = load(USAGE_FILE, {})
    status = load(STATUS_FILE, {})
    history = load(HISTORY_FILE, {})

    try:
        dump = subprocess.run(["wg", "show", IFACE, "dump"],
                              capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return

    active = set()
    for line in dump.strip().splitlines()[1:]:
        parts = line.split("\\t")
        if len(parts) < 8:
            continue
        pub, psk, endpoint, allowed, handshake, rx, tx, ka = parts[:8]
        handshake = int(handshake)
        rx, tx = int(rx), int(tx)
        raw = rx + tx
        active.add(pub)
        name = names.get(pub, pub[:8])

        st = usage.get(pub, {"baseline": 0, "cumulative": 0})
        if raw < st["baseline"]:
            st["cumulative"] += raw
        else:
            st["cumulative"] += raw - st["baseline"]
        st["baseline"] = raw
        usage[pub] = st

        hist = history.get(pub, [])
        hist.append([int(now), rx, tx])
        history[pub] = hist[-HISTORY_MAX:]

        online = handshake > 0 and (now - handshake) < ONLINE_WINDOW
        prev = status.get(pub)
        if online and prev != "online":
            log_event(f"CONNECTED {name} ({pub[:12]}...)")
        elif not online and prev == "online":
            log_event(f"DISCONNECTED {name} ({pub[:12]}...)")
        status[pub] = "online" if online else "offline"

    for pub in list(status.keys()):
        if pub not in active and status.get(pub) == "online":
            name = names.get(pub, pub[:8])
            log_event(f"DISCONNECTED {name} ({pub[:12]}...) [peer removed or disabled]")
            status[pub] = "offline"

    save(USAGE_FILE, usage)
    save(STATUS_FILE, status)
    save(HISTORY_FILE, history)

    try:
        process_dns_log(names_by_ip)
    except Exception:
        pass  # DNS logging is optional; never let it break the rest of the monitor


if __name__ == "__main__":
    main()
'''


def _monitor_install_snippet(server):
    """Bash fragment that installs/updates the monitor + cron job.
    A version hash is embedded in the script so that upgrading the app
    also pushes the current monitor to any server that already has an
    older one installed, keeping every server's monitor in sync with
    whatever this build of the app expects."""
    import base64
    import hashlib

    base_content = PEER_MONITOR_PY % {"iface": server["wg_interface"]}
    version_hash = hashlib.sha256(base_content.encode()).hexdigest()[:12]
    shebang, rest = base_content.split("\n", 1)
    content = f"{shebang}\n# wgmgr-version:{version_hash}\n{rest}"
    payload = base64.b64encode(content.encode()).decode()
    cron_line = f"* * * * * /usr/bin/python3 {MONITOR_PATH}"
    return f'''
if command -v wg >/dev/null; then
  CURRENT_VERSION=$(sed -n '2p' {MONITOR_PATH} 2>/dev/null | grep -oP 'wgmgr-version:\\K[a-f0-9]+' || true)
  if [ "$CURRENT_VERSION" != "{version_hash}" ]; then
    echo {payload} | base64 -d > {MONITOR_PATH}
    chmod 700 {MONITOR_PATH}
  fi
  ( crontab -l 2>/dev/null | grep -v "{MONITOR_PATH}" ; echo "{cron_line}" ) | crontab - 2>/dev/null || true
fi
'''


def get_connection_log(server, lines=200):
    rc, out, err = run_remote(server, f"tail -n {lines} {CONN_LOG_FILE} 2>/dev/null || true")
    return out.strip().splitlines()


_LOG_LINE_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<event>CONNECTED|DISCONNECTED)\s+"
    r"(?P<name>.+?)\s+\((?P<pk>[^)]*)\.\.\.\)\s*(?P<note>.*)$"
)


def parse_log_line(line, server_name):
    """Turn one connection.log line into a structured row for the table.
    Returns None if the line doesn't match the expected format."""
    m = _LOG_LINE_RE.match(line.strip())
    if not m:
        return None
    return {
        "time": m.group("time"),
        "server": server_name,
        "event": m.group("event"),
        "peer": m.group("name"),
        "note": m.group("note").strip(),
    }


def get_all_connection_logs(servers, lines_per_server=200):
    """Fetches connection.log from every server in parallel.
    Returns (rows, errors) where rows is a flat list of parsed dicts
    (newest first) and errors maps server name -> error string."""
    import concurrent.futures

    rows = []
    errors = {}

    def fetch(s):
        try:
            return s["name"], get_connection_log(s, lines_per_server), None
        except Exception as e:
            return s["name"], [], str(e)

    if not servers:
        return rows, errors

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(servers))) as ex:
        for name, lines, err in ex.map(fetch, servers):
            if err:
                errors[name] = err
                continue
            for line in lines:
                row = parse_log_line(line, name)
                if row:
                    rows.append(row)

    rows.sort(key=lambda r: r["time"], reverse=True)
    return rows, errors


def get_traffic_history(server, pubkey):
    """Returns list of (timestamp, rx_bytes, tx_bytes) absolute cumulative samples."""
    history = read_remote_json(server, TRAFFIC_HISTORY_FILE, {})
    return history.get(pubkey, [])


# --------------------------------------------------------------------------
# Live connections: what each peer is currently talking to on the internet.
# Uses `conntrack -L` (the same NAT connection table the VPS already keeps
# for MASQUERADE to work) — metadata only (destination IP/port/protocol/
# state), never packet contents.
# --------------------------------------------------------------------------
_SERVICE_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

_TCP_STATES = ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT",
              "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "LISTEN")
_STATE_RE = re.compile(r"\b(" + "|".join(_TCP_STATES) + r")\b")
_KV_RE = {k: re.compile(rf"\b{k}=(\S+)") for k in ("src", "dst", "sport", "dport")}


def parse_conntrack_line(line):
    """Parse one `conntrack -L` line into {proto, src, dst, dport, state, service}.
    Only the ORIGINAL direction (peer -> destination) is kept — conntrack lines
    contain the reply-direction tuple too, but re.search finds the first
    (leftmost) match of each key, which is always the original tuple."""
    line = line.strip()
    if not line:
        return None
    parts = line.split()
    if len(parts) < 3:
        return None
    proto = parts[0]

    src_m = _KV_RE["src"].search(line)
    dst_m = _KV_RE["dst"].search(line)
    dport_m = _KV_RE["dport"].search(line)
    if not (src_m and dst_m):
        return None

    dport = None
    if dport_m:
        try:
            dport = int(dport_m.group(1))
        except ValueError:
            dport = None

    state_m = _STATE_RE.search(line)
    if state_m:
        state = state_m.group(1)
    elif "[ASSURED]" in line:
        state = "ASSURED"
    elif "[UNREPLIED]" in line:
        state = "UNREPLIED"
    else:
        state = proto.upper()

    return {
        "proto": proto,
        "src": src_m.group(1),
        "dst": dst_m.group(1),
        "dport": dport,
        "state": state,
        "service": _SERVICE_PORTS.get(dport, ""),
    }


def get_server_connections(server):
    """Returns (connections, reason). reason is None on success,
    'no_conntrack' if the conntrack-tools package isn't installed."""
    iface = server["wg_interface"]
    conf = f"/etc/wireguard/{iface}.conf"
    cmd = (f"cat {conf} 2>/dev/null; echo '===CONNTRACK==='; "
           f"if command -v conntrack >/dev/null; then conntrack -L 2>/dev/null; "
           f"else echo '===NO_CONNTRACK==='; fi; "
           f"echo '===DNSCACHE==='; cat {DNS_CACHE_FILE} 2>/dev/null || echo '{{}}'")
    rc, out, err = run_remote(server, cmd)

    conf_text, _, rest = out.partition("===CONNTRACK===")
    conntrack_text, _, dns_cache_text = rest.partition("===DNSCACHE===")
    if "===NO_CONNTRACK===" in conntrack_text:
        return None, "no_conntrack"

    try:
        dns_cache = json.loads(dns_cache_text.strip() or "{}")
    except Exception:
        dns_cache = {}

    # map VPN IP -> peer name, same parsing style used elsewhere in the app
    ip_to_name = {}
    for block in re.split(r"\n\s*\n", conf_text):
        clean = block.replace("#OFF# ", "").replace("#OFF#", "")
        nm = re.search(r"#\s*(.+?)\s*(?:—|--|- added|$)", clean, re.M)
        ip_m = re.search(r"AllowedIPs\s*=\s*([\d.]+)", clean)
        if ip_m:
            ip_to_name[ip_m.group(1)] = nm.group(1).strip() if nm else ip_m.group(1)

    connections = []
    for line in conntrack_text.strip().splitlines():
        row = parse_conntrack_line(line)
        if row and row["src"] in ip_to_name:
            row["peer"] = ip_to_name[row["src"]]
            row["domain"] = dns_cache.get(row["dst"], {}).get("domain", "")
            connections.append(row)
    return connections, None


def install_conntrack(server):
    rc, out, err = run_remote(
        server,
        "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && "
        "apt-get install -y -qq conntrack >/dev/null && echo OK",
        timeout=120)
    if rc != 0 or "OK" not in out:
        raise RuntimeError(err.strip() or "Install failed (Ubuntu/Debian only)")


def get_all_connections(servers):
    """Fetches live connections from every server in parallel.
    Returns (rows, errors); errors maps server name -> 'no_conntrack' or an error string."""
    import concurrent.futures

    rows = []
    errors = {}

    def fetch(s):
        try:
            conns, reason = get_server_connections(s)
            return s["name"], conns, reason
        except Exception as e:
            return s["name"], None, str(e)

    if not servers:
        return rows, errors

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(servers))) as ex:
        for name, conns, reason in ex.map(fetch, servers):
            if conns is None:
                errors[name] = reason or "unknown error"
                continue
            for c in conns:
                c["server"] = name
            rows.extend(conns)

    return rows, errors



HEALTH_SCRIPT = '''
S1=$(head -n1 /proc/stat)
NET_IF=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
if [ -n "$NET_IF" ]; then
  R1=$(cat /sys/class/net/$NET_IF/statistics/rx_bytes 2>/dev/null || echo 0)
  T1=$(cat /sys/class/net/$NET_IF/statistics/tx_bytes 2>/dev/null || echo 0)
else
  R1=0; T1=0
fi
sleep 0.6
S2=$(head -n1 /proc/stat)
if [ -n "$NET_IF" ]; then
  R2=$(cat /sys/class/net/$NET_IF/statistics/rx_bytes 2>/dev/null || echo 0)
  T2=$(cat /sys/class/net/$NET_IF/statistics/tx_bytes 2>/dev/null || echo 0)
else
  R2=0; T2=0
fi
echo "stat1 $S1"
echo "stat2 $S2"
echo "net $R1 $T1 $R2 $T2"
echo "mem $(free -b | awk '/^Mem:/ {print $2, $3}')"
echo "disk $(df -B1 / | awk 'NR==2 {print $2, $3}')"
echo "load $(awk '{print $1}' /proc/loadavg)"
echo "cores $(nproc)"
echo "uptime $(awk '{print int($1)}' /proc/uptime)"
echo "iface $NET_IF"
'''


def _parse_health(text):
    h = {"cpu": None, "mem_used": 0, "mem_total": 0, "disk_used": 0,
         "disk_total": 0, "load": 0.0, "cores": 1, "uptime": 0,
         "rx_rate": 0.0, "tx_rate": 0.0, "iface": ""}
    stat1 = stat2 = None
    for line in text.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        key, vals = parts[0], parts[1:]
        try:
            if key == "stat1":
                stat1 = [int(x) for x in vals[1:]]
            elif key == "stat2":
                stat2 = [int(x) for x in vals[1:]]
            elif key == "net" and len(vals) == 4:
                r1, t1, r2, t2 = map(int, vals)
                h["rx_rate"] = max(0, (r2 - r1) / 0.6)
                h["tx_rate"] = max(0, (t2 - t1) / 0.6)
            elif key == "mem" and len(vals) == 2:
                h["mem_total"], h["mem_used"] = int(vals[0]), int(vals[1])
            elif key == "disk" and len(vals) == 2:
                h["disk_total"], h["disk_used"] = int(vals[0]), int(vals[1])
            elif key == "load":
                h["load"] = float(vals[0])
            elif key == "cores":
                h["cores"] = int(vals[0])
            elif key == "uptime":
                h["uptime"] = int(vals[0])
            elif key == "iface" and vals:
                h["iface"] = vals[0]
        except (ValueError, IndexError):
            continue
    if stat1 and stat2 and len(stat1) >= 5 and len(stat2) >= 5:
        idle1 = stat1[3] + (stat1[4] if len(stat1) > 4 else 0)
        idle2 = stat2[3] + (stat2[4] if len(stat2) > 4 else 0)
        total1, total2 = sum(stat1[:8]), sum(stat2[:8])
        dt, di = total2 - total1, idle2 - idle1
        if dt > 0:
            h["cpu"] = max(0.0, min(100.0, 100.0 * (dt - di) / dt))
    return h


def get_server_state(server):
    """One SSH round-trip: conf + live dump + health metrics + setup detection + usage."""
    iface = server["wg_interface"]
    conf = f"/etc/wireguard/{iface}.conf"
    monitor_snippet = _monitor_install_snippet(server)
    cmd = (f"command -v wg >/dev/null || echo '===NO_WG==='; "
           f"[ -f {conf} ] || echo '===NO_CONF==='; "
           f"cat {conf} 2>/dev/null; echo '===DUMP==='; "
           f"wg show {iface} dump 2>/dev/null || true; "
           f"{monitor_snippet}\n"
           f"echo '===USAGE==='; cat {USAGE_STATE_FILE} 2>/dev/null || echo '{{}}'; "
           f"echo '===HEALTH==='\n{HEALTH_SCRIPT}")
    rc, out, err = run_remote(server, cmd)
    if "===DUMP===" not in out:
        raise RuntimeError(err.strip() or "Could not read server state")

    # ---- fresh-server detection ----
    needs_setup = None
    if "===NO_WG===" in out:
        needs_setup = "not_installed"
    elif "===NO_CONF===" in out:
        needs_setup = "no_config"
    if needs_setup:
        _, _, rest = out.partition("===DUMP===")
        _, _, rest = rest.partition("===HEALTH===")
        return {"peers": [], "subnet": "", "port": "", "iface_up": False,
                "needs_setup": needs_setup, "health": _parse_health(rest)}

    conf_text, _, rest = out.partition("===DUMP===")
    dump_text, _, rest = rest.partition("===USAGE===")
    usage_text, _, health_text = rest.partition("===HEALTH===")

    try:
        usage = json.loads(usage_text.strip() or "{}")
    except Exception:
        usage = {}

    # ---- auto-detect subnet + port ----
    m = re.search(r"Address\s*=\s*(\d+\.\d+\.\d+)\.\d+", conf_text)
    subnet = server["subnet"] or (m.group(1) if m else "10.10.0")
    m = re.search(r"ListenPort\s*=\s*(\d+)", conf_text)
    port = m.group(1) if m else "51820"

    # ---- parse peers block-wise (handles disabled #OFF# blocks) ----
    peers_conf = []
    for block in re.split(r"\n\s*\n", conf_text):
        stripped = block.strip()
        if not stripped:
            continue
        disabled = "#OFF#" in stripped.splitlines()[0] or "#OFF# [Peer]" in stripped
        clean = "\n".join(l.replace("#OFF# ", "").replace("#OFF#", "")
                          for l in stripped.splitlines())
        if "[Peer]" not in clean:
            continue
        nm = re.search(r"#\s*(.+?)\s*(?:—|--|- added|$)", clean, re.M)
        pk = re.search(r"PublicKey\s*=\s*(\S+)", clean)
        ip = re.search(r"AllowedIPs\s*=\s*([\d.]+)", clean)
        if pk:
            pubkey = pk.group(1)
            used_bytes = usage.get(pubkey, {}).get("cumulative", 0)
            peers_conf.append({
                "pubkey": pubkey,
                "name": (nm.group(1).strip() if nm else "(unnamed)"),
                "ip": ip.group(1) if ip else "",
                "disabled": disabled,
                "used_bytes": used_bytes,
            })

    live = {}
    for line in dump_text.strip().splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub, psk, endpoint, allowed, handshake, rx, tx, ka = parts[:8]
        handshake = int(handshake)
        live[pub] = {
            "handshake_ago": human_ago(handshake),
            "online": handshake > 0 and (time.time() - handshake) < 180,
            "rx": human_bytes(int(rx)),
            "tx": human_bytes(int(tx)),
        }

    peers = []
    for p in peers_conf:
        stats = live.get(p["pubkey"],
                         {"handshake_ago": "—" if p["disabled"] else "never",
                          "online": False, "rx": "0 B", "tx": "0 B"})
        peers.append({**p, **stats})

    return {"peers": peers, "subnet": subnet, "port": port,
            "iface_up": bool(dump_text.strip()), "needs_setup": None,
            "health": _parse_health(health_text)}


def add_peer(server, name, subnet):
    safe = re.sub(r"[^A-Za-z0-9_-]", "", name)
    if not safe:
        raise ValueError("Invalid peer name (letters, numbers, - and _ only)")
    iface = server["wg_interface"]
    script = f'''
set -e
IFACE="{iface}"
CONF="/etc/wireguard/$IFACE.conf"

SUBNET=$(grep -oP 'Address\\s*=\\s*\\K[0-9]+\\.[0-9]+\\.[0-9]+' "$CONF" | head -n1)
[ -z "$SUBNET" ] && SUBNET="{subnet}"

USED=$(grep -oP "AllowedIPs\\s*=\\s*\\K$SUBNET\\.[0-9]+" "$CONF" | awk -F. '{{print $4}}' | sort -n)
NEXT=2
for ip in $USED; do
  if [ "$ip" -ge "$NEXT" ]; then NEXT=$((ip+1)); fi
done
CLIENT_IP="$SUBNET.$NEXT"

PRIV=$(wg genkey)
PUB=$(echo "$PRIV" | wg pubkey)
PSK=$(wg genpsk)

if [ -f /etc/wireguard/privatekey ]; then
  SPUB=$(wg pubkey < /etc/wireguard/privatekey)
else
  SPUB=$(grep -oP 'PrivateKey\\s*=\\s*\\K.*' "$CONF" | head -n1 | wg pubkey)
fi

LISTEN=$(grep -oP 'ListenPort\\s*=\\s*\\K[0-9]+' "$CONF" | head -n1)
ENDPOINT="{server["endpoint"]}"
if [ -z "$ENDPOINT" ]; then
  PUBIP=$(curl -s -4 --max-time 5 ifconfig.me || hostname -I | awk '{{print $1}}')
  ENDPOINT="$PUBIP:${{LISTEN:-51820}}"
fi

printf '\\n# {safe} — added %s\\n[Peer]\\nPublicKey = %s\\nPresharedKey = %s\\nAllowedIPs = %s/32\\n' \\
  "$(date '+%Y-%m-%d %H:%M')" "$PUB" "$PSK" "$CLIENT_IP" >> "$CONF"

if wg show "$IFACE" >/dev/null 2>&1; then
  wg syncconf "$IFACE" <(wg-quick strip "$IFACE")
fi

echo "===CLIENT==="
printf '[Interface]\\nPrivateKey = %s\\nAddress = %s/32\\n' "$PRIV" "$CLIENT_IP"
[ -n "{server["dns"]}" ] && printf 'DNS = {server["dns"]}\\n'
printf '\\n[Peer]\\nPublicKey = %s\\nPresharedKey = %s\\nAllowedIPs = {server["allowed_ips"]}\\nEndpoint = %s\\nPersistentKeepalive = {server["keepalive"]}\\n' \\
  "$SPUB" "$PSK" "$ENDPOINT"
'''
    rc, out, err = run_remote(server, script)
    if rc != 0 or "===CLIENT===" not in out:
        raise RuntimeError(err.strip() or out.strip() or "Failed to add peer")
    conf = out.split("===CLIENT===", 1)[1].strip() + "\n"

    path = local_conf_path(server, safe)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(conf)
    return safe, conf


def remove_peer(server, pubkey):
    _check_pk(pubkey)
    iface = server["wg_interface"]
    script = f'''
set -e
IFACE="{iface}"
CONF="/etc/wireguard/$IFACE.conf"
PK="{pubkey}"
wg set "$IFACE" peer "$PK" remove 2>/dev/null || true
awk -v pk="$PK" 'BEGIN {{ RS=""; ORS="\\n\\n" }} index($0, pk) == 0 {{ print }}' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF"
chmod 600 "$CONF"
'''
    rc, out, err = run_remote(server, script)
    if rc != 0:
        raise RuntimeError(err.strip() or "Failed to remove peer")


def disable_peer(server, pubkey):
    _check_pk(pubkey)
    iface = server["wg_interface"]
    script = f'''
set -e
IFACE="{iface}"
CONF="/etc/wireguard/$IFACE.conf"
PK="{pubkey}"
wg set "$IFACE" peer "$PK" remove 2>/dev/null || true
awk -v pk="$PK" '
  BEGIN {{ RS=""; ORS="\\n\\n" }}
  index($0, pk) > 0 && index($0, "#OFF#") == 0 {{
    n = split($0, L, "\\n"); $0 = ""
    for (i = 1; i <= n; i++) $0 = $0 (i>1 ? "\\n" : "") "#OFF# " L[i]
  }}
  {{ print }}
' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF"
chmod 600 "$CONF"
'''
    rc, out, err = run_remote(server, script)
    if rc != 0:
        raise RuntimeError(err.strip() or "Failed to disable peer")


def enable_peer(server, pubkey):
    _check_pk(pubkey)
    iface = server["wg_interface"]
    script = f'''
set -e
IFACE="{iface}"
CONF="/etc/wireguard/$IFACE.conf"
PK="{pubkey}"
awk -v pk="$PK" '
  BEGIN {{ RS=""; ORS="\\n\\n" }}
  index($0, pk) > 0 {{ gsub(/#OFF# /, ""); gsub(/#OFF#/, "") }}
  {{ print }}
' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF"
chmod 600 "$CONF"
if wg show "$IFACE" >/dev/null 2>&1; then
  wg syncconf "$IFACE" <(wg-quick strip "$IFACE")
fi
'''
    rc, out, err = run_remote(server, script)
    if rc != 0:
        raise RuntimeError(err.strip() or "Failed to enable peer")


def restart_wireguard(server):
    iface = server["wg_interface"]
    rc, out, err = run_remote(server, f"systemctl restart wg-quick@{iface} && echo OK",
                              timeout=40)
    if rc != 0 or "OK" not in out:
        raise RuntimeError(err.strip() or "Restart failed")


def setup_wireguard(server, subnet, port):
    """Install WireGuard (if missing) and create a working wg0.conf with
    NAT + IP forwarding, then enable + start the service. Ubuntu/Debian."""
    if not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", subnet):
        raise ValueError("Subnet must look like 10.10.0")
    if not re.fullmatch(r"\d{2,5}", str(port)):
        raise ValueError("Port must be a number")
    iface = server["wg_interface"]
    script = f'''
set -e
export DEBIAN_FRONTEND=noninteractive
IFACE="{iface}"
CONF="/etc/wireguard/$IFACE.conf"

echo "[1/6] Checking packages..."
if ! command -v wg >/dev/null; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq wireguard wireguard-tools curl iptables >/dev/null
    echo "      installed wireguard + tools"
  else
    echo "ERROR: no apt-get found — this installer supports Ubuntu/Debian only."
    exit 1
  fi
else
  echo "      wireguard already installed"
fi

echo "[2/6] Server keys..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
if [ ! -f /etc/wireguard/privatekey ]; then
  wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
  chmod 600 /etc/wireguard/privatekey
  echo "      generated new keypair"
else
  echo "      existing keypair kept"
fi
PRIV=$(cat /etc/wireguard/privatekey)

echo "[3/6] Writing $CONF..."
if [ -f "$CONF" ]; then
  cp "$CONF" "$CONF.bak.$(date +%s)"
  echo "      existing config backed up"
fi
NET_IF=$(ip route | awk '/^default/ {{print $5; exit}}')
[ -z "$NET_IF" ] && NET_IF="eth0"
cat > "$CONF" << WGEOF
[Interface]
Address = {subnet}.1/24
ListenPort = {port}
PrivateKey = $PRIV
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $NET_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $NET_IF -j MASQUERADE
WGEOF
chmod 600 "$CONF"
echo "      subnet {subnet}.1/24, port {port}, NAT via $NET_IF"

echo "[4/6] Enabling IP forwarding..."
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
sysctl -q -p /etc/sysctl.d/99-wireguard.conf

echo "[5/6] Firewall..."
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow {port}/udp >/dev/null
  echo "      ufw: allowed {port}/udp"
else
  echo "      ufw not active — nothing to open"
fi

echo "[6/6] Starting service..."
systemctl enable wg-quick@$IFACE >/dev/null 2>&1
systemctl restart wg-quick@$IFACE
sleep 1
if wg show $IFACE >/dev/null 2>&1; then
  echo "===SETUP_OK==="
  echo "WireGuard is up on $IFACE — public key:"
  cat /etc/wireguard/publickey
else
  echo "ERROR: interface did not come up. Check: journalctl -u wg-quick@$IFACE"
  exit 1
fi
'''
    rc, out, err = run_remote(server, script, timeout=300)
    if rc != 0 or "===SETUP_OK===" not in out:
        raise RuntimeError((out + "\n" + err).strip() or "Setup failed")
    return out


# --------------------------------------------------------------------------
# DNS query logging: shows which domain names each peer actually looked up,
# not just which raw IPs it connected to. Requires dnsmasq running on the
# VPN interface, with peers pointed at the server's VPN IP for DNS.
# --------------------------------------------------------------------------
DNS_MARKER_FILE = "/etc/wireguard/.dns_logging_enabled"
DNS_QUERY_LOG_FILE = "/etc/wireguard/dns_query.log"
DNS_CACHE_FILE = "/etc/wireguard/dns_cache.json"


def setup_dns_logging(server):
    """Installs and configures dnsmasq to log DNS queries from VPN peers.
    Returns the server's VPN IP that should be used as the DNS setting for
    NEW peers going forward (existing peers keep whatever DNS they already
    have baked into their downloaded config)."""
    iface = server["wg_interface"]
    conf = f"/etc/wireguard/{iface}.conf"
    script = f'''
set -e
export DEBIAN_FRONTEND=noninteractive
IFACE="{iface}"
CONF="/etc/wireguard/$IFACE.conf"

VPN_IP=$(grep -oP 'Address\\s*=\\s*\\K[0-9.]+' "$CONF" | head -n1)
if [ -z "$VPN_IP" ]; then
  echo "ERROR: could not read this server's VPN address from $CONF"
  exit 1
fi

echo "[1/4] Installing dnsmasq..."
if ! command -v dnsmasq >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq dnsmasq >/dev/null
  echo "      installed"
else
  echo "      already installed"
fi

echo "[2/4] Configuring dnsmasq to log queries from the VPN only..."
mkdir -p /etc/dnsmasq.d
touch /var/log/wg-dns.log
chown syslog:adm /var/log/wg-dns.log 2>/dev/null || true
cat > /etc/dnsmasq.d/wg-fleet-logging.conf << DNSEOF
# Managed by WG Fleet -- logs DNS queries from WireGuard peers.
interface=$IFACE
bind-interfaces
listen-address=$VPN_IP
no-dhcp-interface=$IFACE
server=1.1.1.1
server=1.0.0.1
log-queries
log-facility=/var/log/wg-dns.log
DNSEOF

echo "[3/4] Restarting dnsmasq..."
systemctl enable dnsmasq >/dev/null 2>&1 || true
systemctl restart dnsmasq
sleep 1
if ! systemctl is-active --quiet dnsmasq; then
  echo "ERROR: dnsmasq failed to start. Check: journalctl -u dnsmasq -n 30"
  echo "(A common cause is systemd-resolved also using port 53 -- this setup"
  echo " only binds dnsmasq to the VPN interface, but conflicts can still occur.)"
  exit 1
fi

echo "[4/4] Done."
touch /etc/wireguard/.dns_logging_enabled
echo "===DNS_SETUP_OK==="
echo "$VPN_IP"
'''
    rc, out, err = run_remote(server, script, timeout=180)
    if rc != 0 or "===DNS_SETUP_OK===" not in out:
        raise RuntimeError((out + "\n" + err).strip() or "DNS logging setup failed")
    vpn_ip = out.split("===DNS_SETUP_OK===", 1)[1].strip().splitlines()[0].strip()
    return vpn_ip


def get_dns_logging_status(server):
    """Returns True/False/None (None = couldn't determine, e.g. unreachable)."""
    try:
        rc, out, err = run_remote(server, f"[ -f {DNS_MARKER_FILE} ] && echo YES || echo NO")
        return "YES" in out
    except Exception:
        return None


def get_dns_queries(server, lines=300):
    rc, out, err = run_remote(server, f"tail -n {lines} {DNS_QUERY_LOG_FILE} 2>/dev/null || true")
    return out.strip().splitlines()


_DNS_LINE_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<peer>\S+)\s+(?P<domain>\S+)$")


def parse_dns_line(line, server_name):
    m = _DNS_LINE_RE.match(line.strip())
    if not m:
        return None
    return {"time": m.group("time"), "server": server_name,
            "peer": m.group("peer"), "domain": m.group("domain")}


def get_all_dns_queries(servers, lines_per_server=300):
    """Fetches DNS query logs from every server in parallel.
    Returns (rows, not_enabled) where not_enabled lists servers without
    DNS logging set up yet."""
    import concurrent.futures

    rows = []
    not_enabled = []

    def fetch(s):
        try:
            enabled = get_dns_logging_status(s)
            if not enabled:
                return s["name"], [], True
            return s["name"], get_dns_queries(s, lines_per_server), False
        except Exception:
            return s["name"], [], False

    if not servers:
        return rows, not_enabled

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(servers))) as ex:
        for name, lines, needs_setup in ex.map(fetch, servers):
            if needs_setup:
                not_enabled.append(name)
                continue
            for line in lines:
                row = parse_dns_line(line, name)
                if row:
                    rows.append(row)

    rows.sort(key=lambda r: r["time"], reverse=True)
    return rows, not_enabled


def _check_pk(pubkey):
    if not re.fullmatch(r"[A-Za-z0-9+/=]{40,60}", pubkey):
        raise ValueError("Invalid public key")


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
ACCENT = "#C0313A"
OK = "#3FA47A"
WARN = "#C9873B"
MUTED = "#7C8FA3"
PANEL = "#1A222C"
LINE = "#2A3542"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


def usage_color(pct):
    if pct >= 90: return ACCENT
    if pct >= 70: return WARN
    return OK


class HealthCard(ctk.CTkFrame):
    """Small metric card: title, value, optional progress bar."""

    def __init__(self, master, title, with_bar=True):
        super().__init__(master, fg_color=PANEL, corner_radius=8)
        self.title_lbl = ctk.CTkLabel(self, text=title, text_color=MUTED,
                                      font=("Segoe UI", 11))
        self.title_lbl.pack(anchor="w", padx=10, pady=(7, 0))
        self.value_lbl = ctk.CTkLabel(self, text="—", font=("Consolas", 14, "bold"))
        self.value_lbl.pack(anchor="w", padx=10)
        self.bar = None
        if with_bar:
            self.bar = ctk.CTkProgressBar(self, height=6, fg_color=LINE,
                                          progress_color=OK)
            self.bar.set(0)
            self.bar.pack(fill="x", padx=10, pady=(3, 8))
        else:
            ctk.CTkLabel(self, text="", font=("Segoe UI", 2)).pack(pady=(0, 6))

    def update_metric(self, value_text, pct=None):
        self.value_lbl.configure(text=value_text)
        if self.bar is not None and pct is not None:
            self.bar.set(min(1.0, pct / 100))
            self.bar.configure(progress_color=usage_color(pct))


class WGManager(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WG Fleet")
        self.geometry("1000x700")
        self.minsize(860, 580)

        # Without this, any error raised inside a button click or other
        # Tkinter callback is only printed to stderr -- which is invisible
        # once the app is built with pyinstaller --windowed. This turns
        # every such error into a visible dialog instead of a silent no-op.
        self.report_callback_exception = self._show_callback_error

        self.servers, migrated = load_servers()
        self.current = self.servers[0] if self.servers else None
        self.state_data = None
        self.auto_refresh = ctk.BooleanVar(value=False)
        self._busy = False

        # ---- top bar ----
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 4))

        ctk.CTkLabel(top, text="Server", text_color=MUTED).pack(side="left", padx=(0, 8))
        names = [s["name"] for s in self.servers] or ["(no servers yet)"]
        self.server_menu = ctk.CTkOptionMenu(
            top, values=names, command=self.on_server_change,
            fg_color=PANEL, button_color=ACCENT, button_hover_color="#A02830", width=250)
        self.server_menu.pack(side="left")
        if not self.servers:
            self.server_menu.configure(state="disabled")

        ctk.CTkButton(top, text="Servers…", width=90, fg_color=ACCENT,
                      hover_color="#A02830", command=self.open_server_manager
                      ).pack(side="left", padx=8)

        ctk.CTkButton(top, text="Refresh", width=80, fg_color=LINE,
                      hover_color="#3A4756", command=self.refresh).pack(side="right")
        ctk.CTkCheckBox(top, text="Auto-refresh 30s", variable=self.auto_refresh,
                        text_color=MUTED, checkbox_width=18, checkbox_height=18,
                        fg_color=ACCENT, hover_color="#A02830",
                        command=self._schedule_auto).pack(side="right", padx=12)
        ctk.CTkButton(top, text="Export list (CSV)", width=120, fg_color=LINE,
                      hover_color="#3A4756", command=self.export_csv).pack(side="right", padx=(0, 4))
        ctk.CTkButton(top, text="Activity log", width=100, fg_color=LINE,
                      hover_color="#3A4756", command=self.open_activity_log).pack(side="right", padx=(0, 4))
        ctk.CTkButton(top, text="Live connections", width=130, fg_color=LINE,
                      hover_color="#3A4756", command=self.open_connections).pack(side="right", padx=(0, 4))
        ctk.CTkButton(top, text="DNS log", width=90, fg_color=LINE,
                      hover_color="#3A4756", command=self.open_dns_log).pack(side="right", padx=(0, 4))
        ctk.CTkButton(top, text="Decrypt config…", width=130, fg_color=LINE,
                      hover_color="#3A4756", command=self.open_decrypt).pack(side="right", padx=(0, 4))

        # ---- status line ----
        self.status_lbl = ctk.CTkLabel(self, text="", text_color=MUTED, anchor="w",
                                       font=("Consolas", 12))
        self.status_lbl.pack(fill="x", padx=18, pady=(0, 4))

        # ---- health panel ----
        health = ctk.CTkFrame(self, fg_color="transparent")
        health.pack(fill="x", padx=16, pady=(0, 4))
        for i in range(6):
            health.grid_columnconfigure(i, weight=1, uniform="h")

        self.card_cpu = HealthCard(health, "CPU")
        self.card_ram = HealthCard(health, "RAM")
        self.card_disk = HealthCard(health, "DISK /")
        self.card_net = HealthCard(health, "NETWORK ↓ / ↑", with_bar=False)
        self.card_up = HealthCard(health, "UPTIME · LOAD", with_bar=False)
        for i, c in enumerate([self.card_cpu, self.card_ram, self.card_disk,
                               self.card_net, self.card_up]):
            c.grid(row=0, column=i, sticky="nsew", padx=3)

        wgcard = ctk.CTkFrame(health, fg_color=PANEL, corner_radius=8)
        wgcard.grid(row=0, column=5, sticky="nsew", padx=3)
        ctk.CTkLabel(wgcard, text="WIREGUARD", text_color=MUTED,
                     font=("Segoe UI", 11)).pack(anchor="w", padx=10, pady=(7, 0))
        self.wg_lbl = ctk.CTkLabel(wgcard, text="—", font=("Consolas", 14, "bold"))
        self.wg_lbl.pack(anchor="w", padx=10)
        ctk.CTkButton(wgcard, text="Restart WG", height=20, width=90,
                      font=("Segoe UI", 11), fg_color="transparent", border_width=1,
                      border_color=LINE, text_color=MUTED, hover_color="#3A2226",
                      command=self.on_restart_wg).pack(anchor="w", padx=10, pady=(2, 7))

        # ---- add + search row ----
        addrow = ctk.CTkFrame(self, fg_color="transparent")
        addrow.pack(fill="x", padx=16, pady=4)

        self.name_entry = ctk.CTkEntry(addrow, placeholder_text="new-peer-name", width=260)
        self.name_entry.pack(side="left")
        self.name_entry.bind("<Return>", lambda e: self.on_add())
        self.add_btn = ctk.CTkButton(addrow, text="Add peer", width=100,
                                     fg_color=ACCENT, hover_color="#A02830",
                                     command=self.on_add)
        self.add_btn.pack(side="left", padx=8)

        self.search_entry = ctk.CTkEntry(addrow, placeholder_text="Search peers…", width=220)
        self.search_entry.pack(side="right")
        self.search_entry.bind("<KeyRelease>", lambda e: self._render_peers())

        # ---- peer list ----
        self.peer_frame = ctk.CTkScrollableFrame(self, fg_color="#141B24",
                                                 label_text="Peers", label_text_color=MUTED)
        self.peer_frame.pack(fill="both", expand=True, padx=16, pady=(6, 14))

        if self.current:
            self.refresh()
        else:
            self._render_empty_state()

        if migrated:
            self.after(300, lambda: messagebox.showinfo(
                "WG Fleet",
                f"Imported {len(self.servers)} server(s) from servers.json and "
                f"encrypted the saved passwords ({SECRET_BACKEND}).\n\n"
                "The original file was renamed to servers.json.bak — safe to "
                "delete once you've confirmed everything still works."))

    def _render_empty_state(self):
        self.status_lbl.configure(
            text="No servers yet — click “Servers…” to add your first VPS.",
            text_color=MUTED)
        for w in self.peer_frame.winfo_children():
            w.destroy()
        box = ctk.CTkFrame(self.peer_frame, fg_color=PANEL, corner_radius=10)
        box.pack(pady=40, padx=30, fill="x")
        ctk.CTkLabel(box, text="No servers configured", font=("Segoe UI", 15, "bold")
                     ).pack(pady=(18, 2))
        ctk.CTkLabel(box, text="Add a VPS to start managing WireGuard peers on it.",
                     text_color=MUTED).pack()
        ctk.CTkButton(box, text="+ Add your first server", fg_color=ACCENT,
                      hover_color="#A02830", width=220, height=36,
                      command=self.open_server_manager).pack(pady=16)

    def open_server_manager(self):
        ServerManagerWindow(self)

    def on_servers_changed(self):
        """Called after add/edit/delete in ServerManagerWindow. Persists + refreshes UI."""
        save_servers(self.servers)
        names = [s["name"] for s in self.servers] or ["(no servers yet)"]
        self.server_menu.configure(values=names)
        if self.servers:
            self.server_menu.configure(state="normal")
            self.add_btn.configure(state="normal")
            cur_name = self.current["name"] if self.current else None
            match = next((s for s in self.servers if s["name"] == cur_name), None)
            self.current = match or self.servers[0]
            self.server_menu.set(self.current["name"])
            self.state_data = None
            self.refresh()
        else:
            self.current = None
            self.server_menu.set("(no servers yet)")
            self.server_menu.configure(state="disabled")
            self.add_btn.configure(state="disabled")
            self.state_data = None
            self._render_empty_state()

    # ---------------- data ----------------
    def on_server_change(self, name):
        for s in self.servers:
            if s["name"] == name:
                self.current = s
                break
        self.state_data = None
        self.refresh()

    def refresh(self):
        if not self.current or self._busy:
            return
        self._busy = True
        self.status_lbl.configure(text="Connecting…", text_color=MUTED)
        self.add_btn.configure(state="disabled")
        threading.Thread(target=self._refresh_worker, daemon=True).start()

    def _refresh_worker(self):
        try:
            state = get_server_state(self.current)
            self.after(0, lambda: self._apply_state(state))
        except Exception as e:
            self.after(0, lambda: self._show_error(f"Connection failed: {e}"))

    def _apply_state(self, state):
        self._busy = False
        self.state_data = state
        self._render_health(state)

        if state["needs_setup"]:
            reason = ("WireGuard is not installed on this server."
                      if state["needs_setup"] == "not_installed"
                      else f"WireGuard is installed but {self.current['wg_interface']}.conf doesn't exist.")
            self.status_lbl.configure(
                text=f"{self.current['host']}  ·  {reason}", text_color=WARN)
            self.add_btn.configure(state="disabled")
            self._render_setup_banner(reason)
            return

        self.add_btn.configure(state="normal")
        peers = state["peers"]
        online = sum(1 for p in peers if p["online"])
        iface = "up" if state["iface_up"] else "DOWN"
        self.status_lbl.configure(
            text=(f"{self.current['host']}  ·  {self.current['wg_interface']} {iface}"
                  f"  ·  subnet {state['subnet']}.0/24 (auto)  ·  port {state['port']}"
                  f"  ·  {len(peers)} peers, {online} online"),
            text_color=OK if state["iface_up"] else WARN)
        self._render_peers()

    def _render_setup_banner(self, reason):
        for w in self.peer_frame.winfo_children():
            w.destroy()
        box = ctk.CTkFrame(self.peer_frame, fg_color=PANEL, corner_radius=10,
                           border_width=1, border_color=WARN)
        box.pack(pady=30, padx=30, fill="x")
        ctk.CTkLabel(box, text="This server needs WireGuard setup",
                     font=("Segoe UI", 15, "bold")).pack(pady=(16, 2))
        ctk.CTkLabel(box, text=reason + "\nThe app can install and configure everything automatically.",
                     text_color=MUTED, justify="center").pack()
        ctk.CTkButton(box, text="Setup WireGuard on this server", fg_color=ACCENT,
                      hover_color="#A02830", width=260, height=36,
                      command=self.open_setup).pack(pady=16)

    def open_setup(self):
        # suggest a subnet not used by the other servers (10.10.0 / 10.20.0 / ...)
        used = set()
        for s in self.servers:
            if s.get("subnet"):
                used.add(s["subnet"])
        suggestion = next((f"10.{n}.0" for n in range(10, 250, 10)
                           if f"10.{n}.0" not in used), "10.10.0")
        SetupWindow(self, self.current, suggestion)

    def _render_health(self, state):
        h = state["health"]
        if h["cpu"] is not None:
            self.card_cpu.update_metric(f"{h['cpu']:.0f}%", h["cpu"])
        else:
            self.card_cpu.update_metric("n/a", 0)
        if h["mem_total"]:
            pct = 100 * h["mem_used"] / h["mem_total"]
            self.card_ram.update_metric(
                f"{human_bytes(h['mem_used'])} / {human_bytes(h['mem_total'])}", pct)
        if h["disk_total"]:
            pct = 100 * h["disk_used"] / h["disk_total"]
            self.card_disk.update_metric(
                f"{human_bytes(h['disk_used'])} / {human_bytes(h['disk_total'])}", pct)
        self.card_net.update_metric(
            f"{human_bytes(h['rx_rate'], True)} / {human_bytes(h['tx_rate'], True)}")
        load_pct = 100 * h["load"] / max(1, h["cores"])
        self.card_up.update_metric(
            f"{human_uptime(h['uptime'])} · {h['load']:.2f}/{h['cores']}c")
        online = sum(1 for p in state["peers"] if p["online"])
        self.wg_lbl.configure(
            text=f"{'UP' if state['iface_up'] else 'DOWN'} · {online} online",
            text_color=OK if state["iface_up"] else ACCENT)

    def _show_error(self, msg):
        self._busy = False
        self.status_lbl.configure(text=msg, text_color=ACCENT)
        self.add_btn.configure(state="normal")

    def _schedule_auto(self):
        if self.auto_refresh.get():
            self._auto_tick()

    def _auto_tick(self):
        if self.auto_refresh.get():
            self.refresh()
            self.after(30000, self._auto_tick)

    # ---------------- render peers ----------------
    def _render_peers(self):
        for w in self.peer_frame.winfo_children():
            w.destroy()
        if not self.state_data:
            return
        query = self.search_entry.get().strip().lower()
        peers = [p for p in self.state_data["peers"]
                 if not query or query in p["name"].lower() or query in p["ip"]]

        if not peers:
            ctk.CTkLabel(self.peer_frame,
                         text="No peers match." if query else "No peers yet — add the first one above.",
                         text_color=MUTED).pack(pady=20)
            return

        for p in peers:
            row = ctk.CTkFrame(self.peer_frame, fg_color=PANEL, corner_radius=8)
            row.pack(fill="x", pady=3, padx=4)

            line1 = ctk.CTkFrame(row, fg_color="transparent")
            line1.pack(fill="x")

            color = OK if p["online"] else ("#3A4756" if not p["disabled"] else WARN)
            ctk.CTkLabel(line1, text="●", width=24, text_color=color).pack(side="left", padx=(8, 0))

            name_txt = p["name"] + ("  (disabled)" if p["disabled"] else "")
            ctk.CTkLabel(line1, text=name_txt, width=170, anchor="w",
                         font=("Segoe UI", 13, "bold"),
                         text_color=MUTED if p["disabled"] else "#DCE4EC").pack(side="left", padx=4)
            ctk.CTkLabel(line1, text=p["ip"], width=100, anchor="w",
                         text_color=MUTED, font=("Consolas", 12)).pack(side="left")
            ctk.CTkLabel(line1, text=p["handshake_ago"], width=80, anchor="w",
                         text_color=MUTED, font=("Consolas", 12)).pack(side="left")
            ctk.CTkLabel(line1, text=f"{p['rx']} ↓ / {p['tx']} ↑", width=140, anchor="w",
                         text_color=MUTED, font=("Consolas", 12)).pack(side="left")
            ctk.CTkLabel(line1, text=f"{human_bytes(p['used_bytes'])} total", width=100, anchor="w",
                         text_color=MUTED, font=("Consolas", 12)).pack(side="left")

            ctk.CTkButton(line1, text="Delete", width=60, height=26,
                          fg_color="transparent", border_width=1, border_color=LINE,
                          hover_color="#3A2226", text_color=MUTED,
                          command=lambda pk=p["pubkey"], nm=p["name"]: self.on_remove(pk, nm)
                          ).pack(side="right", padx=(4, 8), pady=6)

            if p["disabled"]:
                ctk.CTkButton(line1, text="Enable", width=64, height=26,
                              fg_color="transparent", border_width=1, border_color=OK,
                              text_color=OK, hover_color="#1E3A2E",
                              command=lambda pk=p["pubkey"]: self.on_toggle(pk, True)
                              ).pack(side="right", padx=4, pady=6)
            else:
                ctk.CTkButton(line1, text="Disable", width=64, height=26,
                              fg_color="transparent", border_width=1, border_color=LINE,
                              text_color=MUTED, hover_color="#3A3226",
                              command=lambda pk=p["pubkey"]: self.on_toggle(pk, False)
                              ).pack(side="right", padx=4, pady=6)

            ctk.CTkButton(line1, text="Chart", width=56, height=26,
                          fg_color="transparent", border_width=1, border_color=LINE,
                          hover_color=LINE, text_color=MUTED,
                          command=lambda pk=p["pubkey"], nm=p["name"]: self.open_chart(pk, nm)
                          ).pack(side="right", padx=4, pady=6)

            lp = local_conf_path(self.current, p["name"])
            if os.path.exists(lp):
                ctk.CTkButton(line1, text="Show QR", width=76, height=26,
                              fg_color="transparent", border_width=1, border_color=LINE,
                              text_color=MUTED, hover_color=LINE,
                              command=lambda path=lp, nm=p["name"]: self.show_saved(path, nm)
                              ).pack(side="right", padx=4, pady=6)

    def open_chart(self, pubkey, name):
        ChartWindow(self, self.current, pubkey, name)


    def on_add(self):
        name = self.name_entry.get().strip()
        if not name:
            messagebox.showwarning("WG Fleet", "Enter a peer name first.")
            return
        safe = re.sub(r"[^A-Za-z0-9_-]", "", name)
        if self.state_data:
            existing = {p["name"].lower() for p in self.state_data["peers"]}
            if safe.lower() in existing:
                messagebox.showwarning(
                    "WG Fleet",
                    f"A peer named “{safe}” already exists on {self.current['name']}.\n"
                    "Pick a different name.")
                return
        subnet = self.state_data["subnet"] if self.state_data else "10.10.0"
        self.add_btn.configure(state="disabled", text="Adding…")
        threading.Thread(target=self._add_worker, args=(name, subnet), daemon=True).start()

    def _add_worker(self, name, subnet):
        try:
            safe, conf = add_peer(self.current, name, subnet)
            self.after(0, lambda: self._peer_added(safe, conf))
        except Exception as e:
            self.after(0, lambda: (
                messagebox.showerror("WG Fleet", f"Could not add peer:\n{e}"),
                self.add_btn.configure(state="normal", text="Add peer")))

    def _peer_added(self, name, conf):
        self.add_btn.configure(state="normal", text="Add peer")
        self.name_entry.delete(0, "end")
        self.refresh()
        ResultWindow(self, name, conf)

    def on_toggle(self, pubkey, enable):
        fn = enable_peer if enable else disable_peer
        threading.Thread(target=self._toggle_worker, args=(fn, pubkey), daemon=True).start()

    def _toggle_worker(self, fn, pubkey):
        try:
            fn(self.current, pubkey)
            self.after(0, self.refresh)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("WG Fleet", f"Failed:\n{e}"))

    def on_remove(self, pubkey, name):
        if not messagebox.askyesno("WG Fleet",
                                   f"Delete peer “{name}” permanently?\n"
                                   "The device will lose access. This cannot be undone."):
            return
        threading.Thread(target=self._remove_worker, args=(pubkey, name), daemon=True).start()

    def _remove_worker(self, pubkey, name):
        try:
            remove_peer(self.current, pubkey)
            lp = local_conf_path(self.current, name)
            if os.path.exists(lp):
                os.remove(lp)
            self.after(0, self.refresh)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("WG Fleet", f"Could not delete peer:\n{e}"))

    def on_restart_wg(self):
        if not messagebox.askyesno(
                "WG Fleet",
                f"Restart WireGuard on {self.current['name']}?\n"
                "All peers will briefly reconnect (usually < 2 seconds)."):
            return
        self.wg_lbl.configure(text="restarting…", text_color=WARN)
        threading.Thread(target=self._restart_worker, daemon=True).start()

    def _restart_worker(self):
        try:
            restart_wireguard(self.current)
            self.after(0, self.refresh)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("WG Fleet", f"Restart failed:\n{e}"))

    def show_saved(self, path, name):
        with open(path, encoding="utf-8") as f:
            conf = f.read()
        ResultWindow(self, name, conf, created=False)

    def export_csv(self):
        if not self.state_data or not self.state_data["peers"]:
            messagebox.showinfo("WG Fleet", "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=f"{safe_filename(self.current['name'])}-peers.csv",
            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["name", "vpn_ip", "status", "last_handshake",
                        "download", "upload", "total_used", "public_key"])
            for p in self.state_data["peers"]:
                status = "disabled" if p["disabled"] else ("online" if p["online"] else "offline")
                w.writerow([p["name"], p["ip"], status, p["handshake_ago"],
                            p["rx"], p["tx"], human_bytes(p["used_bytes"]), p["pubkey"]])
        messagebox.showinfo("WG Fleet", f"Exported {len(self.state_data['peers'])} peers.")

    def _show_callback_error(self, exc, val, tb):
        import traceback
        text = "".join(traceback.format_exception(exc, val, tb))
        try:
            with open(os.path.join(BASE_DIR, "wg_fleet_error.log"), "a", encoding="utf-8") as f:
                f.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n{text}")
        except Exception:
            pass
        messagebox.showerror(
            "WG Fleet — error",
            f"Something went wrong:\n\n{val}\n\n"
            f"Full details were written to wg_fleet_error.log next to the app.")

    def open_activity_log(self):
        if not self.servers:
            return
        ActivityWindow(self, self.servers)

    def open_connections(self):
        if not self.servers:
            return
        ConnectionsWindow(self, self.servers)

    def open_dns_log(self):
        if not self.servers:
            return
        DNSLogWindow(self, self.servers)

    def open_decrypt(self):
        path = filedialog.askopenfilename(
            title="Select an encrypted WG Fleet config",
            filetypes=[("Encrypted config", "*.conf.enc *.enc"), ("All files", "*.*")])
        if not path:
            return
        dialog = ctk.CTkInputDialog(text="Password for this config:", title="Decrypt config")
        password = dialog.get_input()
        if not password:
            return
        try:
            with open(path, encoding="utf-8") as f:
                enc_text = f.read()
            conf = decrypt_conf(enc_text, password)
        except Exception as e:
            messagebox.showerror("Decrypt config", str(e))
            return
        name = os.path.splitext(os.path.splitext(os.path.basename(path))[0])[0]
        ResultWindow(self, name, conf, created=False)


class ResultWindow(ctk.CTkToplevel):
    """Shows a peer's config + QR."""

    def __init__(self, master, name, conf, created=True):
        super().__init__(master)
        self.title(("Peer created — " if created else "Peer config — ") + name)
        self.geometry("640x480")
        self.conf = conf
        self.name = name
        self.attributes("-topmost", True)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=16)

        qr_img = qrcode.make(conf).get_image().resize((240, 240), Image.NEAREST)
        self.qr_ctk = ctk.CTkImage(light_image=qr_img, dark_image=qr_img, size=(240, 240))
        ctk.CTkLabel(body, image=self.qr_ctk, text="").pack(side="left", padx=(0, 14), anchor="n")

        right = ctk.CTkFrame(body, fg_color="transparent")
        right.pack(side="left", fill="both", expand=True)

        title = f"Peer “{name}” created" if created else f"Config for “{name}”"
        ctk.CTkLabel(right, text=title, font=("Segoe UI", 15, "bold"),
                     anchor="w").pack(fill="x")
        ctk.CTkLabel(right, text="Scan the QR with the WireGuard app, or save the file.\n"
                                 "A copy is saved in the app's configs folder.",
                     text_color=MUTED, anchor="w", justify="left").pack(fill="x", pady=(2, 8))

        box = ctk.CTkTextbox(right, font=("Consolas", 11), fg_color="#141B24")
        box.insert("1.0", conf)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True)

        btns = ctk.CTkFrame(right, fg_color="transparent")
        btns.pack(fill="x", pady=(10, 0))
        ctk.CTkButton(btns, text="Save .conf", fg_color=OK, hover_color="#2F8560",
                      command=self.save).pack(side="left")
        ctk.CTkButton(btns, text="Copy to clipboard", fg_color=LINE,
                      hover_color="#3A4756", command=self.copy).pack(side="left", padx=8)
        ctk.CTkButton(btns, text="Encrypt & save…", fg_color=LINE,
                      hover_color="#3A4756", command=self.encrypt_and_save).pack(side="left", padx=8)

    def encrypt_and_save(self):
        dialog = ctk.CTkInputDialog(
            text="Choose a password to protect this config file:",
            title="Encrypt config")
        password = dialog.get_input()
        if not password:
            return
        enc = encrypt_conf(self.conf, password)
        path = filedialog.asksaveasfilename(
            defaultextension=".conf.enc", initialfile=f"{self.name}.conf.enc",
            filetypes=[("Encrypted config", "*.conf.enc")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(enc)
            messagebox.showinfo(
                "Encrypt config",
                "Saved. This file needs the password to be read — use "
                "\"Decrypt config…\" in the main window to open it later.")

    def save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".conf", initialfile=f"{self.name}.conf",
            filetypes=[("WireGuard config", "*.conf")])
        if path:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(self.conf)

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.conf)


class SetupWindow(ctk.CTkToplevel):
    """Collects subnet/port, runs the install script, streams the log."""

    def __init__(self, master, server, suggested_subnet):
        super().__init__(master)
        self.master_app = master
        self.server = server
        self.title(f"Setup WireGuard — {server['name']}")
        self.geometry("560x440")
        self.attributes("-topmost", True)
        self.resizable(True, True)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(body, text=f"Set up WireGuard on {server['name']}",
                     font=("Segoe UI", 15, "bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(body, text=f"{server['host']} · interface {server['wg_interface']}",
                     text_color=MUTED, anchor="w").pack(fill="x", pady=(0, 12))

        form = ctk.CTkFrame(body, fg_color="transparent")
        form.pack(fill="x")
        ctk.CTkLabel(form, text="VPN subnet", text_color=MUTED, width=90,
                     anchor="w").grid(row=0, column=0, sticky="w", pady=4)
        self.subnet_entry = ctk.CTkEntry(form, width=140)
        self.subnet_entry.insert(0, suggested_subnet)
        self.subnet_entry.grid(row=0, column=1, sticky="w", padx=(6, 0))
        ctk.CTkLabel(form, text=".0/24 — server takes .1", text_color=MUTED,
                     font=("Segoe UI", 11)).grid(row=0, column=2, sticky="w", padx=8)

        ctk.CTkLabel(form, text="Listen port", text_color=MUTED, width=90,
                     anchor="w").grid(row=1, column=0, sticky="w", pady=4)
        self.port_entry = ctk.CTkEntry(form, width=140)
        self.port_entry.insert(0, "51820")
        self.port_entry.grid(row=1, column=1, sticky="w", padx=(6, 0), pady=4)

        ctk.CTkLabel(body,
                     text=("This installs wireguard + wireguard-tools, generates server keys,\n"
                           "writes a wg0.conf with NAT/forwarding rules, opens the port in ufw\n"
                           "if active, and starts the service. Safe to run on a blank Ubuntu/Debian VPS."),
                     text_color=MUTED, justify="left", anchor="w").pack(fill="x", pady=(10, 10))

        self.log_box = ctk.CTkTextbox(body, font=("Consolas", 11), fg_color="#141B24")
        self.log_box.pack(fill="both", expand=True)
        self.log_box.configure(state="disabled")

        btns = ctk.CTkFrame(body, fg_color="transparent")
        btns.pack(fill="x", pady=(10, 0))
        self.run_btn = ctk.CTkButton(btns, text="Install & Configure", fg_color=ACCENT,
                                     hover_color="#A02830", command=self.on_run)
        self.run_btn.pack(side="left")
        ctk.CTkButton(btns, text="Cancel", fg_color=LINE, hover_color="#3A4756",
                      command=self.destroy).pack(side="left", padx=8)

    def _log(self, text):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def on_run(self):
        subnet = self.subnet_entry.get().strip()
        port = self.port_entry.get().strip()
        if not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", subnet):
            messagebox.showwarning("Setup", "Subnet should look like 10.10.0")
            return
        if not re.fullmatch(r"\d{2,5}", port):
            messagebox.showwarning("Setup", "Port should be a number, e.g. 51820")
            return
        self.run_btn.configure(state="disabled", text="Installing…")
        self._log(f"Connecting to {self.server['host']}…")
        threading.Thread(target=self._worker, args=(subnet, port), daemon=True).start()

    def _worker(self, subnet, port):
        try:
            out = setup_wireguard(self.server, subnet, port)
            self.after(0, lambda: self._done(out, subnet))
        except Exception as e:
            self.after(0, lambda: self._fail(str(e)))

    def _done(self, out, subnet):
        for line in out.strip().splitlines():
            self._log(line)
        self._log("\n✅ Setup complete.")
        self.run_btn.configure(text="Done", fg_color=OK)
        # remember the subnet so future add_peer calls default correctly
        self.server["subnet"] = subnet
        save_servers(self.master_app.servers)
        self.master_app.refresh()

    def _fail(self, msg):
        self._log(f"\n❌ Setup failed:\n{msg}")
        self.run_btn.configure(state="normal", text="Retry")


class ChartWindow(ctk.CTkToplevel):
    """Simple canvas-drawn Rx/Tx line chart for one peer, no extra dependencies."""

    def __init__(self, master, server, pubkey, name):
        super().__init__(master)
        self.server = server
        self.pubkey = pubkey
        self.name = name
        self.title(f"Traffic — {name}")
        self.geometry("640x420")
        self.attributes("-topmost", True)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(top, text=f"Rx / Tx — {name}", font=("Segoe UI", 15, "bold")).pack(side="left")
        ctk.CTkButton(top, text="Refresh", width=80, fg_color=LINE,
                      hover_color="#3A4756", command=self.load).pack(side="right")

        legend = ctk.CTkFrame(self, fg_color="transparent")
        legend.pack(fill="x", padx=16)
        ctk.CTkLabel(legend, text="●", text_color=OK, font=("Segoe UI", 14)).pack(side="left")
        ctk.CTkLabel(legend, text="Download (Rx)", text_color=MUTED).pack(side="left", padx=(2, 14))
        ctk.CTkLabel(legend, text="●", text_color="#5B8FD6", font=("Segoe UI", 14)).pack(side="left")
        ctk.CTkLabel(legend, text="Upload (Tx)", text_color=MUTED).pack(side="left", padx=(2, 0))

        self.status_lbl = ctk.CTkLabel(self, text="Loading…", text_color=MUTED)
        self.status_lbl.pack(fill="x", padx=16, pady=(2, 4))

        self.canvas = tk.Canvas(self, bg="#141B24", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True, padx=16, pady=(4, 16))
        self.canvas.bind("<Configure>", lambda e: self._redraw())
        self._points = []
        self.load()

    def load(self):
        self.status_lbl.configure(text="Loading…")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        try:
            raw = get_traffic_history(self.server, self.pubkey)
            self.after(0, lambda: self._apply(raw))
        except Exception as e:
            self.after(0, lambda: self.status_lbl.configure(
                text=f"Could not load history: {e}", text_color=ACCENT))

    def _apply(self, raw):
        # raw = [[ts, rx_abs, tx_abs], ...] absolute cumulative bytes at sample time.
        # Convert to per-interval rates (bytes/sec) for a meaningful chart.
        points = []
        for i in range(1, len(raw)):
            t0, rx0, tx0 = raw[i - 1]
            t1, rx1, tx1 = raw[i]
            dt = max(1, t1 - t0)
            rx_rate = max(0, rx1 - rx0) / dt
            tx_rate = max(0, tx1 - tx0) / dt
            points.append((t1, rx_rate, tx_rate))
        self._points = points
        if not points:
            self.status_lbl.configure(
                text="No samples yet — the server checks in every minute, come back shortly.",
                text_color=MUTED)
        else:
            span_min = (points[-1][0] - points[0][0]) / 60
            self.status_lbl.configure(
                text=f"{len(points)} samples over ~{span_min:.0f} minutes  ·  updates every minute",
                text_color=MUTED)
        self._redraw()

    def _redraw(self):
        c = self.canvas
        c.delete("all")
        w = c.winfo_width()
        h = c.winfo_height()
        if w < 20 or h < 20 or not self._points:
            return
        pad_l, pad_r, pad_t, pad_b = 55, 15, 15, 25
        plot_w = w - pad_l - pad_r
        plot_h = h - pad_t - pad_b
        if plot_w <= 0 or plot_h <= 0:
            return

        rx_vals = [p[1] for p in self._points]
        tx_vals = [p[2] for p in self._points]
        max_val = max(max(rx_vals), max(tx_vals), 1)

        # gridlines + y labels (4 bands)
        for i in range(5):
            y = pad_t + plot_h * i / 4
            c.create_line(pad_l, y, w - pad_r, y, fill=LINE)
            val = max_val * (1 - i / 4)
            c.create_text(pad_l - 8, y, text=human_bytes(val, True), fill=MUTED,
                          anchor="e", font=("Consolas", 9))

        n = len(self._points)

        def to_xy(i, val):
            x = pad_l + (plot_w * i / max(1, n - 1))
            y = pad_t + plot_h * (1 - val / max_val)
            return x, y

        def draw_line(vals, color):
            coords = []
            for i, v in enumerate(vals):
                x, y = to_xy(i, v)
                coords.extend([x, y])
            if len(coords) >= 4:
                c.create_line(*coords, fill=color, width=2, smooth=True)

        draw_line(rx_vals, OK)
        draw_line(tx_vals, "#5B8FD6")

        # x-axis time labels (first / middle / last)
        for i in (0, n // 2, n - 1):
            x, _ = to_xy(i, 0)
            t = time.strftime("%H:%M", time.localtime(self._points[i][0]))
            c.create_text(x, h - pad_b + 12, text=t, fill=MUTED, font=("Consolas", 9))


class ActivityWindow(ctk.CTkToplevel):
    """Connect/disconnect history across ALL servers at once, in a sortable table."""

    def __init__(self, master, servers):
        super().__init__(master)
        self.servers = servers
        self._rows = []          # full unfiltered dataset
        self._sort_col = "time"
        self._sort_reverse = True

        self.title("Activity log — all servers")
        self.geometry("820x520")
        self.attributes("-topmost", True)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(top, text="Connect / disconnect history — all servers",
                     font=("Segoe UI", 14, "bold")).pack(side="left")
        ctk.CTkButton(top, text="Refresh", width=80, fg_color=LINE,
                      hover_color="#3A4756", command=self.load).pack(side="right")

        filt = ctk.CTkFrame(self, fg_color="transparent")
        filt.pack(fill="x", padx=16, pady=(0, 6))
        ctk.CTkLabel(filt, text="Server", text_color=MUTED).pack(side="left", padx=(0, 6))
        server_names = ["All servers"] + [s["name"] for s in servers]
        self.server_filter = ctk.CTkOptionMenu(
            filt, values=server_names, command=lambda _v: self._render(),
            fg_color=PANEL, button_color=ACCENT, button_hover_color="#A02830", width=180)
        self.server_filter.pack(side="left")

        self.search_entry = ctk.CTkEntry(filt, placeholder_text="Search peer name…", width=200)
        self.search_entry.pack(side="left", padx=10)
        self.search_entry.bind("<KeyRelease>", lambda e: self._render())

        self.status_lbl = ctk.CTkLabel(filt, text="", text_color=MUTED)
        self.status_lbl.pack(side="right")

        # ---- table (ttk.Treeview, styled dark to match the rest of the app) ----
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("WG.Treeview", background="#141B24", fieldbackground="#141B24",
                        foreground="#DCE4EC", rowheight=26, borderwidth=0, font=("Consolas", 11))
        style.configure("WG.Treeview.Heading", background=PANEL, foreground=MUTED,
                        font=("Segoe UI", 11, "bold"), relief="flat")
        style.map("WG.Treeview", background=[("selected", "#2A3542")])
        style.map("WG.Treeview.Heading", background=[("active", LINE)])

        table_frame = ctk.CTkFrame(self, fg_color="#141B24")
        table_frame.pack(fill="both", expand=True, padx=16, pady=(4, 16))

        cols = ("time", "server", "event", "peer", "note")
        headers = {"time": "Time", "server": "Server", "event": "Event",
                  "peer": "Peer", "note": "Note"}
        widths = {"time": 150, "server": 130, "event": 110, "peer": 140, "note": 200}

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                 style="WG.Treeview", selectmode="none")
        for c in cols:
            self.tree.heading(c, text=headers[c], command=lambda c=c: self._sort_by(c))
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.tag_configure("connected", foreground=OK)
        self.tree.tag_configure("disconnected", foreground=MUTED)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.load()

    def load(self):
        self.status_lbl.configure(text="Loading…")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        rows, errors = get_all_connection_logs(self.servers, lines_per_server=300)
        self.after(0, lambda: self._apply(rows, errors))

    def _apply(self, rows, errors):
        self._rows = rows
        if errors:
            failed = ", ".join(errors.keys())
            self.status_lbl.configure(text=f"{len(rows)} events  ·  unreachable: {failed}",
                                      text_color=WARN)
        else:
            self.status_lbl.configure(text=f"{len(rows)} events", text_color=MUTED)
        self._render()

    def _sort_by(self, col):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = (col == "time")  # default newest-first for time
        self._render()

    def _render(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        server_choice = self.server_filter.get()
        query = self.search_entry.get().strip().lower()

        rows = self._rows
        if server_choice != "All servers":
            rows = [r for r in rows if r["server"] == server_choice]
        if query:
            rows = [r for r in rows if query in r["peer"].lower()]

        rows = sorted(rows, key=lambda r: r[self._sort_col], reverse=self._sort_reverse)

        if not rows:
            self.tree.insert("", "end", values=(
                "", "", "", "No matching events" if (server_choice != "All servers" or query)
                else "No connect/disconnect events recorded yet — check back after a peer connects.",
                ""))
            return

        for r in rows:
            tag = "connected" if r["event"] == "CONNECTED" else "disconnected"
            self.tree.insert("", "end", values=(
                r["time"], r["server"], r["event"], r["peer"], r["note"]), tags=(tag,))


class ConnectionsWindow(ctk.CTkToplevel):
    """Live connection table across all servers — what each peer is currently
    talking to on the internet (destination IP/port/protocol/state, metadata
    only — never packet contents)."""

    def __init__(self, master, servers):
        super().__init__(master)
        self.servers = servers
        self._rows = []
        self._errors = {}
        self._sort_col = "peer"
        self._sort_reverse = False
        self.auto_refresh = ctk.BooleanVar(value=False)

        self.title("Live connections — all servers")
        self.geometry("940x540")
        self.attributes("-topmost", True)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(top, text="What's connected right now — all servers",
                     font=("Segoe UI", 14, "bold")).pack(side="left")
        ctk.CTkButton(top, text="Refresh", width=80, fg_color=LINE,
                      hover_color="#3A4756", command=self.load).pack(side="right")
        ctk.CTkCheckBox(top, text="Auto-refresh 10s", variable=self.auto_refresh,
                        text_color=MUTED, checkbox_width=18, checkbox_height=18,
                        fg_color=ACCENT, hover_color="#A02830",
                        command=self._schedule_auto).pack(side="right", padx=12)

        ctk.CTkLabel(self, text="Destinations only (IP/port/protocol) — not page content or files.",
                     text_color=MUTED, font=("Segoe UI", 11), anchor="w"
                     ).pack(fill="x", padx=16)

        filt = ctk.CTkFrame(self, fg_color="transparent")
        filt.pack(fill="x", padx=16, pady=(6, 6))
        ctk.CTkLabel(filt, text="Server", text_color=MUTED).pack(side="left", padx=(0, 6))
        server_names = ["All servers"] + [s["name"] for s in servers]
        self.server_filter = ctk.CTkOptionMenu(
            filt, values=server_names, command=lambda _v: self._render(),
            fg_color=PANEL, button_color=ACCENT, button_hover_color="#A02830", width=180)
        self.server_filter.pack(side="left")
        self.search_entry = ctk.CTkEntry(filt, placeholder_text="Search peer or destination…", width=220)
        self.search_entry.pack(side="left", padx=10)
        self.search_entry.bind("<KeyRelease>", lambda e: self._render())
        self.status_lbl = ctk.CTkLabel(filt, text="", text_color=MUTED)
        self.status_lbl.pack(side="right")

        self.install_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.install_frame.pack(fill="x", padx=16)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("WG.Treeview", background="#141B24", fieldbackground="#141B24",
                        foreground="#DCE4EC", rowheight=26, borderwidth=0, font=("Consolas", 11))
        style.configure("WG.Treeview.Heading", background=PANEL, foreground=MUTED,
                        font=("Segoe UI", 11, "bold"), relief="flat")
        style.map("WG.Treeview", background=[("selected", "#2A3542")])
        style.map("WG.Treeview.Heading", background=[("active", LINE)])

        table_frame = ctk.CTkFrame(self, fg_color="#141B24")
        table_frame.pack(fill="both", expand=True, padx=16, pady=(6, 16))

        cols = ("server", "peer", "dest", "port", "proto", "state")
        headers = {"server": "Server", "peer": "Peer", "dest": "Destination",
                  "port": "Port / Service", "proto": "Protocol", "state": "State"}
        widths = {"server": 110, "peer": 120, "dest": 220, "port": 130,
                 "proto": 90, "state": 120}

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                 style="WG.Treeview", selectmode="none")
        for c in cols:
            self.tree.heading(c, text=headers[c], command=lambda c=c: self._sort_by(c))
            self.tree.column(c, width=widths[c], anchor="w")
        self.tree.tag_configure("established", foreground=OK)
        self.tree.tag_configure("other", foreground=MUTED)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.load()

    def load(self):
        self.status_lbl.configure(text="Loading…")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        rows, errors = get_all_connections(self.servers)
        self.after(0, lambda: self._apply(rows, errors))

    def _apply(self, rows, errors):
        self._rows = rows
        self._errors = errors
        parts = [f"{len(rows)} active connections"]
        unreachable = [n for n, r in errors.items() if r != "no_conntrack"]
        if unreachable:
            parts.append(f"unreachable: {', '.join(unreachable)}")
        self.status_lbl.configure(
            text="  ·  ".join(parts),
            text_color=WARN if errors else MUTED)
        self._render_install_prompts()
        self._render()

    def _render_install_prompts(self):
        for w in self.install_frame.winfo_children():
            w.destroy()
        needs_install = [n for n, r in self._errors.items() if r == "no_conntrack"]
        for name in needs_install:
            row = ctk.CTkFrame(self.install_frame, fg_color=PANEL, corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{name}: conntrack-tools isn't installed — "
                                   "needed to see live connections.",
                        text_color=WARN, font=("Segoe UI", 11)).pack(side="left", padx=10, pady=6)
            ctk.CTkButton(row, text="Install", width=70, height=26, fg_color=ACCENT,
                         hover_color="#A02830",
                         command=lambda n=name: self._install(n)).pack(side="right", padx=8, pady=5)

    def _install(self, server_name):
        server = next((s for s in self.servers if s["name"] == server_name), None)
        if not server:
            return
        threading.Thread(target=self._install_worker, args=(server,), daemon=True).start()

    def _install_worker(self, server):
        try:
            install_conntrack(server)
            self.after(0, self.load)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror(
                "Live connections", f"Could not install conntrack-tools on {server['name']}:\n{e}"))

    def _schedule_auto(self):
        if self.auto_refresh.get():
            self._auto_tick()

    def _auto_tick(self):
        if self.auto_refresh.get() and self.winfo_exists():
            self.load()
            self.after(10000, self._auto_tick)

    def _sort_by(self, col):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False
        self._render()

    def _render(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        server_choice = self.server_filter.get()
        query = self.search_entry.get().strip().lower()

        rows = self._rows
        if server_choice != "All servers":
            rows = [r for r in rows if r["server"] == server_choice]
        if query:
            rows = [r for r in rows
                   if query in r["peer"].lower() or query in r["dst"].lower()]

        def sort_key(r):
            if self._sort_col == "port":
                return r["dport"] or 0
            return str(r.get(self._display_key(self._sort_col), "")).lower()

        rows = sorted(rows, key=sort_key, reverse=self._sort_reverse)

        if not rows:
            msg = ("No matching connections" if (server_choice != "All servers" or query)
                  else "No active connections right now.")
            self.tree.insert("", "end", values=("", "", "", "", "", msg))
            return

        for r in rows:
            port_txt = f"{r['dport']} ({r['service']})" if r["service"] else str(r["dport"] or "")
            dest_txt = f"{r['domain']} ({r['dst']})" if r.get("domain") else r["dst"]
            tag = "established" if r["state"] == "ESTABLISHED" else "other"
            self.tree.insert("", "end", values=(
                r["server"], r["peer"], dest_txt, port_txt, r["proto"].upper(), r["state"]
            ), tags=(tag,))

    @staticmethod
    def _display_key(col):
        return {"dest": "dst", "proto": "proto"}.get(col, col)


class DNSLogWindow(ctk.CTkToplevel):
    """Which domain names each peer has actually looked up, across all servers.
    More readable than raw destination IPs since it's the hostname the
    device asked for, not just where the connection happened to land."""

    def __init__(self, master, servers):
        super().__init__(master)
        self.master_app = master
        self.servers = servers
        self._rows = []
        self._sort_col = "time"
        self._sort_reverse = True

        self.title("DNS log — all servers")
        self.geometry("820x520")
        self.attributes("-topmost", True)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(top, text="Domains looked up — all servers",
                     font=("Segoe UI", 14, "bold")).pack(side="left")
        ctk.CTkButton(top, text="Refresh", width=80, fg_color=LINE,
                      hover_color="#3A4756", command=self.load).pack(side="right")

        filt = ctk.CTkFrame(self, fg_color="transparent")
        filt.pack(fill="x", padx=16, pady=(2, 6))
        ctk.CTkLabel(filt, text="Server", text_color=MUTED).pack(side="left", padx=(0, 6))
        server_names = ["All servers"] + [s["name"] for s in servers]
        self.server_filter = ctk.CTkOptionMenu(
            filt, values=server_names, command=lambda _v: self._render(),
            fg_color=PANEL, button_color=ACCENT, button_hover_color="#A02830", width=180)
        self.server_filter.pack(side="left")
        self.search_entry = ctk.CTkEntry(filt, placeholder_text="Search peer or domain…", width=220)
        self.search_entry.pack(side="left", padx=10)
        self.search_entry.bind("<KeyRelease>", lambda e: self._render())
        self.status_lbl = ctk.CTkLabel(filt, text="", text_color=MUTED)
        self.status_lbl.pack(side="right")

        self.setup_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.setup_frame.pack(fill="x", padx=16)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("WG.Treeview", background="#141B24", fieldbackground="#141B24",
                        foreground="#DCE4EC", rowheight=26, borderwidth=0, font=("Consolas", 11))
        style.configure("WG.Treeview.Heading", background=PANEL, foreground=MUTED,
                        font=("Segoe UI", 11, "bold"), relief="flat")
        style.map("WG.Treeview", background=[("selected", "#2A3542")])

        table_frame = ctk.CTkFrame(self, fg_color="#141B24")
        table_frame.pack(fill="both", expand=True, padx=16, pady=(6, 16))

        cols = ("time", "server", "peer", "domain")
        headers = {"time": "Time", "server": "Server", "peer": "Peer", "domain": "Domain"}
        widths = {"time": 150, "server": 130, "peer": 130, "domain": 260}

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                 style="WG.Treeview", selectmode="none")
        for c in cols:
            self.tree.heading(c, text=headers[c], command=lambda c=c: self._sort_by(c))
            self.tree.column(c, width=widths[c], anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.load()

    def load(self):
        self.status_lbl.configure(text="Loading…")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        rows, not_enabled = get_all_dns_queries(self.servers)
        self.after(0, lambda: self._apply(rows, not_enabled))

    def _apply(self, rows, not_enabled):
        self._rows = rows
        self._not_enabled = not_enabled
        self.status_lbl.configure(text=f"{len(rows)} queries", text_color=MUTED)
        self._render_setup_prompts()
        self._render()

    def _render_setup_prompts(self):
        for w in self.setup_frame.winfo_children():
            w.destroy()
        for name in self._not_enabled:
            row = ctk.CTkFrame(self.setup_frame, fg_color=PANEL, corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{name}: DNS logging isn't set up yet.",
                        text_color=WARN, font=("Segoe UI", 11)).pack(side="left", padx=10, pady=6)
            ctk.CTkButton(row, text="Set up", width=70, height=26, fg_color=ACCENT,
                         hover_color="#A02830",
                         command=lambda n=name: self._start_dns_setup(n)).pack(side="right", padx=8, pady=5)

    def _start_dns_setup(self, server_name):
        server = next((s for s in self.servers if s["name"] == server_name), None)
        if not server:
            return
        DNSSetupWindow(self, self.master_app, server, on_done=self.load)

    def _sort_by(self, col):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = (col == "time")
        self._render()

    def _render(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        server_choice = self.server_filter.get()
        query = self.search_entry.get().strip().lower()

        rows = self._rows
        if server_choice != "All servers":
            rows = [r for r in rows if r["server"] == server_choice]
        if query:
            rows = [r for r in rows
                   if query in r["peer"].lower() or query in r["domain"].lower()]

        rows = sorted(rows, key=lambda r: r[self._sort_col], reverse=self._sort_reverse)

        if not rows:
            if self._not_enabled and not self._rows:
                msg = "No servers have DNS logging set up yet — see above."
            elif server_choice != "All servers" or query:
                msg = "No matching queries."
            else:
                msg = "No DNS queries recorded yet."
            self.tree.insert("", "end", values=("", "", "", msg))
            return

        for r in rows:
            self.tree.insert("", "end", values=(r["time"], r["server"], r["peer"], r["domain"]))


class DNSSetupWindow(ctk.CTkToplevel):
    """Runs setup_dns_logging on one server and explains the one manual
    step needed for peers that already exist."""

    def __init__(self, master, master_app, server, on_done=None):
        super().__init__(master)
        self.master_app = master_app
        self.server = server
        self.on_done = on_done
        self.title(f"Set up DNS logging — {server['name']}")
        self.geometry("520x420")
        self.attributes("-topmost", True)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=18, pady=18)

        ctk.CTkLabel(body, text=f"DNS logging — {server['name']}",
                     font=("Segoe UI", 15, "bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(body,
                     text=("Installs dnsmasq and points it at this server's WireGuard\n"
                           "interface, logging every domain name peers look up.\n\n"
                           "NEW peers created after this will automatically use it.\n"
                           "EXISTING peers keep whatever DNS is in their saved config —\n"
                           "you'd need to edit each device's WireGuard config and change\n"
                           "its DNS line to this server's VPN address to include it."),
                     text_color=MUTED, justify="left", anchor="w").pack(fill="x", pady=(8, 12))

        self.log_box = ctk.CTkTextbox(body, font=("Consolas", 11), fg_color="#141B24")
        self.log_box.pack(fill="both", expand=True)
        self.log_box.configure(state="disabled")

        btns = ctk.CTkFrame(body, fg_color="transparent")
        btns.pack(fill="x", pady=(10, 0))
        self.run_btn = ctk.CTkButton(btns, text="Install & configure", fg_color=ACCENT,
                                     hover_color="#A02830", command=self.on_run)
        self.run_btn.pack(side="left")
        ctk.CTkButton(btns, text="Cancel", fg_color=LINE, hover_color="#3A4756",
                      command=self.destroy).pack(side="left", padx=8)

    def _log(self, text):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def on_run(self):
        self.run_btn.configure(state="disabled", text="Working…")
        self._log(f"Connecting to {self.server['host']}…")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        try:
            vpn_ip = setup_dns_logging(self.server)
            self.after(0, lambda: self._done(vpn_ip))
        except Exception as e:
            self.after(0, lambda: self._fail(str(e)))

    def _done(self, vpn_ip):
        self._log(f"\n✅ Done. New peers on this server will use DNS = {vpn_ip}")
        self.server["dns"] = vpn_ip
        save_servers(self.master_app.servers)
        self.run_btn.configure(text="Done", fg_color=OK)
        if self.on_done:
            self.on_done()

    def _fail(self, msg):
        self._log(f"\n❌ Failed:\n{msg}")
        self.run_btn.configure(state="normal", text="Retry")


class ServerManagerWindow(ctk.CTkToplevel):
    """List, add, edit, and remove servers. Changes save immediately
    (encrypted) via the parent app's on_servers_changed()."""

    def __init__(self, master):
        super().__init__(master)
        self.master_app = master
        self.title("Manage servers")
        self.geometry("620x480")
        self.attributes("-topmost", True)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(top, text="Servers", font=("Segoe UI", 15, "bold")).pack(side="left")
        ctk.CTkLabel(top, text=f"passwords encrypted via {SECRET_BACKEND}",
                     text_color=MUTED, font=("Segoe UI", 11)).pack(side="left", padx=10)
        ctk.CTkButton(top, text="+ Add server", fg_color=ACCENT, hover_color="#A02830",
                      command=self.on_add).pack(side="right")

        self.list_frame = ctk.CTkScrollableFrame(self, fg_color="#141B24")
        self.list_frame.pack(fill="both", expand=True, padx=16, pady=(6, 16))
        self.render()

    def render(self):
        for w in self.list_frame.winfo_children():
            w.destroy()
        if not self.master_app.servers:
            ctk.CTkLabel(self.list_frame, text="No servers yet — click “+ Add server” above.",
                         text_color=MUTED).pack(pady=24)
            return
        for idx, s in enumerate(self.master_app.servers):
            row = ctk.CTkFrame(self.list_frame, fg_color=PANEL, corner_radius=8)
            row.pack(fill="x", pady=3, padx=4)
            auth = "SSH key" if s.get("ssh_key") else ("password" if s.get("ssh_password") else "not set")
            ctk.CTkLabel(row, text=s["name"], width=170, anchor="w",
                         font=("Segoe UI", 13, "bold")).pack(side="left", padx=(10, 4), pady=9)
            ctk.CTkLabel(row, text=f"{s['ssh_user']}@{s['host']}:{s.get('ssh_port', 22)}",
                         width=210, anchor="w", text_color=MUTED,
                         font=("Consolas", 11)).pack(side="left")
            ctk.CTkLabel(row, text=auth, width=80, anchor="w", text_color=MUTED,
                         font=("Consolas", 11)).pack(side="left")

            ctk.CTkButton(row, text="Delete", width=64, height=26,
                          fg_color="transparent", border_width=1, border_color=LINE,
                          hover_color="#3A2226", text_color=MUTED,
                          command=lambda i=idx: self.on_delete(i)
                          ).pack(side="right", padx=(4, 10), pady=6)
            ctk.CTkButton(row, text="Edit", width=64, height=26,
                          fg_color="transparent", border_width=1, border_color=LINE,
                          hover_color=LINE, text_color=MUTED,
                          command=lambda i=idx: self.on_edit(i)
                          ).pack(side="right", padx=4, pady=6)

    def on_add(self):
        ServerEditDialog(self, self.master_app, None)

    def on_edit(self, idx):
        ServerEditDialog(self, self.master_app, idx)

    def on_delete(self, idx):
        s = self.master_app.servers[idx]
        if not messagebox.askyesno(
                "Manage servers",
                f"Remove “{s['name']}” from WG Fleet?\n"
                "This only removes it from the app's list — nothing changes on the VPS itself."):
            return
        del self.master_app.servers[idx]
        self.master_app.on_servers_changed()
        self.render()


class ServerEditDialog(ctk.CTkToplevel):
    """Add or edit a single server entry."""

    def __init__(self, manager_window, app, index):
        super().__init__(manager_window)
        self.manager_window = manager_window
        self.app = app
        self.index = index  # None = adding a new server
        existing = app.servers[index] if index is not None else {}

        self.title("Edit server" if index is not None else "Add server")
        self.geometry("460x620")
        self.attributes("-topmost", True)

        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=18, pady=18)

        def field(label, key, default=""):
            ctk.CTkLabel(body, text=label, text_color=MUTED, anchor="w").pack(fill="x", pady=(8, 2))
            e = ctk.CTkEntry(body)
            e.insert(0, str(existing.get(key, default)))
            e.pack(fill="x")
            return e

        ctk.CTkLabel(body, text=("Edit server" if index is not None else "Add a new server"),
                     font=("Segoe UI", 15, "bold"), anchor="w").pack(fill="x")

        self.name_e = field("Server name", "name", "My VPS")
        self.host_e = field("Host / IP", "host")
        self.port_e = field("SSH port", "ssh_port", 22)
        self.user_e = field("SSH user", "ssh_user", "root")

        ctk.CTkLabel(body, text="Authentication", text_color=MUTED, anchor="w").pack(fill="x", pady=(14, 4))
        self.auth_var = ctk.StringVar(value="key" if existing.get("ssh_key") else "password")
        auth_row = ctk.CTkFrame(body, fg_color="transparent")
        auth_row.pack(fill="x")
        ctk.CTkRadioButton(auth_row, text="Password", variable=self.auth_var, value="password",
                          fg_color=ACCENT, hover_color="#A02830",
                          command=self._toggle_auth).pack(side="left")
        ctk.CTkRadioButton(auth_row, text="SSH key", variable=self.auth_var, value="key",
                          fg_color=ACCENT, hover_color="#A02830",
                          command=self._toggle_auth).pack(side="left", padx=20)

        self.password_frame = ctk.CTkFrame(body, fg_color="transparent")
        ctk.CTkLabel(self.password_frame, text="Password", text_color=MUTED,
                     anchor="w").pack(fill="x", pady=(8, 2))
        self.password_e = ctk.CTkEntry(self.password_frame, show="•")
        self.password_e.insert(0, existing.get("ssh_password", ""))
        self.password_e.pack(fill="x")
        ctk.CTkLabel(self.password_frame,
                     text=f"Stored encrypted on this PC ({SECRET_BACKEND}), never in plain text.",
                     text_color=MUTED, font=("Segoe UI", 10), anchor="w",
                     wraplength=400, justify="left").pack(fill="x", pady=(4, 0))

        self.key_frame = ctk.CTkFrame(body, fg_color="transparent")
        ctk.CTkLabel(self.key_frame, text="Private key path", text_color=MUTED,
                     anchor="w").pack(fill="x", pady=(8, 2))
        key_row = ctk.CTkFrame(self.key_frame, fg_color="transparent")
        key_row.pack(fill="x")
        self.key_e = ctk.CTkEntry(key_row)
        self.key_e.insert(0, existing.get("ssh_key", ""))
        self.key_e.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(key_row, text="Browse…", width=80, fg_color=LINE,
                      hover_color="#3A4756", command=self._browse_key).pack(side="left", padx=(6, 0))

        self._toggle_auth()

        ctk.CTkLabel(body, text="Advanced (optional — blank = auto-detect)",
                     text_color=MUTED, anchor="w").pack(fill="x", pady=(16, 2))
        self.iface_e = field("WireGuard interface", "wg_interface", "wg0")
        self.subnet_e = field("VPN subnet override", "subnet", "")
        self.dns_e = field("Client DNS", "dns", "1.1.1.1")
        self.allowed_e = field("Client AllowedIPs", "allowed_ips", "0.0.0.0/0, ::/0")
        self.keepalive_e = field("PersistentKeepalive", "keepalive", 25)
        self.endpoint_e = field("Endpoint override (host:port)", "endpoint", "")

        self.msg_lbl = ctk.CTkLabel(body, text="", text_color=ACCENT, anchor="w",
                                    wraplength=400, justify="left")
        self.msg_lbl.pack(fill="x", pady=(10, 0))

        btns = ctk.CTkFrame(body, fg_color="transparent")
        btns.pack(fill="x", pady=(10, 4))
        ctk.CTkButton(btns, text="Save", fg_color=ACCENT, hover_color="#A02830",
                      command=self.on_save).pack(side="left")
        ctk.CTkButton(btns, text="Cancel", fg_color=LINE, hover_color="#3A4756",
                      command=self.destroy).pack(side="left", padx=8)

    def _toggle_auth(self):
        self.password_frame.pack_forget()
        self.key_frame.pack_forget()
        if self.auth_var.get() == "password":
            self.password_frame.pack(fill="x")
        else:
            self.key_frame.pack(fill="x")

    def _browse_key(self):
        path = filedialog.askopenfilename(title="Select SSH private key")
        if path:
            self.key_e.delete(0, "end")
            self.key_e.insert(0, path)

    def on_save(self):
        name = self.name_e.get().strip()
        host = self.host_e.get().strip()
        user = self.user_e.get().strip() or "root"
        try:
            port = int(self.port_e.get().strip() or 22)
        except ValueError:
            self.msg_lbl.configure(text="SSH port must be a number.")
            return
        if not name or not host:
            self.msg_lbl.configure(text="Server name and host are required.")
            return
        for i, s in enumerate(self.app.servers):
            if i != self.index and s["name"].lower() == name.lower():
                self.msg_lbl.configure(text=f"A server named “{name}” already exists.")
                return

        server = {
            "name": name, "host": host, "ssh_port": port, "ssh_user": user,
            "wg_interface": self.iface_e.get().strip() or "wg0",
            "subnet": self.subnet_e.get().strip(),
            "dns": self.dns_e.get().strip() or "1.1.1.1",
            "allowed_ips": self.allowed_e.get().strip() or "0.0.0.0/0, ::/0",
            "endpoint": self.endpoint_e.get().strip(),
        }
        try:
            server["keepalive"] = int(self.keepalive_e.get().strip() or 25)
        except ValueError:
            server["keepalive"] = 25

        if self.auth_var.get() == "password":
            pw = self.password_e.get()
            if not pw:
                self.msg_lbl.configure(text="Enter a password, or switch to SSH key.")
                return
            server["ssh_password"] = pw
            server["ssh_key"] = ""
        else:
            key = self.key_e.get().strip()
            if not key:
                self.msg_lbl.configure(text="Choose a private key file, or switch to Password.")
                return
            server["ssh_key"] = key
            server["ssh_password"] = ""

        server = _apply_server_defaults(server)

        if self.index is not None:
            self.app.servers[self.index] = server
        else:
            self.app.servers.append(server)

        self.app.on_servers_changed()
        self.manager_window.render()
        self.destroy()


if __name__ == "__main__":
    app = WGManager()
    app.mainloop()
