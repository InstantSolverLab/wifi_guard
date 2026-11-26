#!/usr/bin/env python3
"""
wifi_guard.py - safety audit and live monitor for public Wi-Fi.

  python3 wifi_guard.py            one-off audit of this laptop and the network
  python3 wifi_guard.py --watch    keep watching for attacks while you work

Standard library only. Works on Windows, macOS and Linux.
READ-ONLY: it inspects settings and reports; it never changes anything.
Some checks are heuristics - treat results as strong hints, not proof.
"""
import argparse
import ipaddress
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

OS = platform.system()  # "Windows", "Darwin" (macOS) or "Linux"

OK, INFO, WARN, FAIL, SKIP = "OK", "INFO", "WARN", "FAIL", "SKIP"
COLORS = {OK: "32", INFO: "36", WARN: "33", FAIL: "31", SKIP: "90"}
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
if USE_COLOR and OS == "Windows":
    os.system("")  # switches on ANSI colour support in Windows terminals

# Ports that should not be reachable by strangers on a shared network.
RISKY_PORTS = {
    21: "FTP", 22: "SSH / Remote Login", 23: "Telnet", 135: "Windows RPC",
    139: "NetBIOS file sharing", 445: "SMB file sharing", 548: "AFP file sharing",
    631: "Printer sharing", 3389: "Remote Desktop", 5900: "VNC / Screen Sharing",
    5000: "AirPlay Receiver / dev server", 7000: "AirPlay Receiver",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}
VPN_HINT = re.compile(
    r"tun|tap|wg|ppp|ipsec|vpn|wireguard|nord|proton|mullvad|tailscale|warp|"
    r"zerotier|anyconnect|globalprotect|forti|zscaler|openvpn", re.I)
TLS_TEST_HOSTS = ["www.cloudflare.com", "www.google.com", "www.microsoft.com"]


# ----------------------------------------------------------------- helpers

def run(cmd, timeout=20):
    """Run a command and return its stdout ('' if it fails or is missing)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def powershell(script):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])


def as_ip(token):
    token = token.strip("[](),;").split("%")[0].split("#")[0]
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def norm_mac(mac):
    return ":".join(part.zfill(2) for part in re.split("[:-]", mac.lower()))


def paint(level, text):
    return f"\033[{COLORS[level]}m{text}\033[0m" if USE_COLOR else text


class Report:
    def __init__(self):
        self.items = []

    def add(self, level, title, detail="", fix=""):
        self.items.append((level, title, detail, fix))

    def show(self):
        for level, title, detail, fix in self.items:
            print(f"{paint(level, f'[{level:^4}]')} {title}")
            for line in detail.splitlines():
                print(f"         {line}")
            if fix:
                print(f"         {paint(level, 'Fix:')} {fix}")
        fails = sum(1 for i in self.items if i[0] == FAIL)
        warns = sum(1 for i in self.items if i[0] == WARN)
        print()
        if fails:
            print(paint(FAIL, f"VERDICT: {fails} serious problem(s), {warns} warning(s). "
                              "Fix these before doing anything sensitive."))
        elif warns:
            print(paint(WARN, f"VERDICT: {warns} warning(s). Usable with care; "
                              "see the fixes above."))
        else:
            print(paint(OK, "VERDICT: no problems detected. Stay alert anyway."))
        return 2 if fails else 1 if warns else 0


# ------------------------------------------------------- facts about the PC

def wifi_info():
    """Return (ssid, security) of the current Wi-Fi link, or (None, None)."""
    if OS == "Linux":
        for line in run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"]).splitlines():
            if line.startswith("yes:"):
                ssid, _, sec = line[4:].rpartition(":")
                return ssid.replace("\\:", ":"), sec
    elif OS == "Windows":
        out = run(["netsh", "wlan", "show", "interfaces"])
        ssid = re.search(r"^\s*SSID\s*:\s*(.*)$", out, re.M)
        auth = re.search(r"^\s*Authentication\s*:\s*(.*)$", out, re.M)
        if ssid and auth:
            return ssid.group(1).strip(), auth.group(1).strip()
    elif OS == "Darwin":
        out = run(["system_profiler", "SPAirPortDataType"], timeout=40)
        _, found, rest = out.partition("Current Network Information:")
        if found:
            lines = [l.strip() for l in rest.splitlines() if l.strip()]
            sec = re.search(r"^\s*Security:\s*(.*)$", rest, re.M)
            if lines and sec:
                return lines[0].rstrip(":"), sec.group(1).strip()
    return None, None


def firewall_state():
    """Return True (on), False (off) or None (unknown), plus a description."""
    if OS == "Windows":
        states = re.findall(r"\b(ON|OFF)\b", run(["netsh", "advfirewall", "show", "allprofiles", "state"]))
        if not states:
            return None, "could not read Windows Firewall state"
        return "OFF" not in states, f"profiles: {', '.join(states)}"
    if OS == "Darwin":
        tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        out = run([tool, "--getglobalstate"]).lower()
        if not out:
            return None, "could not read macOS firewall state"
        stealth = run([tool, "--getstealthmode"]).lower()
        stealth_on = "enabled" in stealth or " on" in stealth
        return "enabled" in out, f"stealth mode {'on' if stealth_on else 'off'}"
    # Linux
    try:
        with open("/etc/ufw/ufw.conf") as fh:
            if re.search(r"^ENABLED=yes", fh.read(), re.M | re.I):
                return True, "ufw enabled"
    except OSError:
        pass
    if "running" in run(["firewall-cmd", "--state"]):
        return True, "firewalld running"
    if os.geteuid() == 0 and shutil.which("nft"):
        if "hook input" in run(["nft", "list", "ruleset"]):
            return True, "nftables input rules present"
        return False, "no ufw, firewalld or nftables input rules"
    return None, "no active ufw/firewalld found (run with sudo to inspect nftables)"


def route_info():
    """Return (gateway_ip, label_of_interface_carrying_internet_traffic)."""
    gw, iface = None, ""
    if OS == "Linux":
        m = re.search(r"default via (\S+)", run(["ip", "route", "show", "default"]))
        gw = m.group(1) if m else None
        m = re.search(r"dev (\S+)", run(["ip", "route", "get", "1.1.1.1"]))
        iface = m.group(1) if m else ""
    elif OS == "Darwin":
        for line in run(["netstat", "-rn", "-f", "inet"]).splitlines():
            parts = line.split()
            if len(parts) > 1 and parts[0] == "default" and as_ip(parts[1]):
                gw = parts[1]
                break
        m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get", "1.1.1.1"]))
        iface = m.group(1) if m else ""
    elif OS == "Windows":
        out = powershell(
            "$g=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
            " Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric |"
            " Select-Object -First 1).NextHop;"
            "$r=Find-NetRoute -RemoteIPAddress 1.1.1.1 | Select-Object -First 1;"
            "$a=Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue;"
            "Write-Output \"GW=$g\"; Write-Output \"IF=$($r.InterfaceAlias) $($a.InterfaceDescription)\"")
        m = re.search(r"^GW=(\S+)", out, re.M)
        gw = m.group(1) if m else None
        m = re.search(r"^IF=(.*)$", out, re.M)
        iface = m.group(1).strip() if m else ""
    return gw, iface


def arp_table():
    """Return {ip: mac} for unicast neighbours on the local network."""
    out = run(["ip", "neigh"]) if OS == "Linux" else run(["arp", "-a"] if OS == "Windows" else ["arp", "-an"])
    table = {}
    for line in out.splitlines():
        ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac = re.search(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b", line)
        if not (ip and mac):
            continue
        addr, hw = as_ip(ip.group(1)), norm_mac(mac.group(1))
        if addr is None or addr.is_multicast or int(hw[:2], 16) & 1:  # skip broadcast/multicast
            continue
        table[str(addr)] = hw
    return table


def ping_once(ip):
    """Nudge the OS into learning the gateway's hardware address."""
    cmd = {"Windows": ["ping", "-n", "1", "-w", "1000", ip],
           "Darwin": ["ping", "-c", "1", "-t", "1", ip]}.get(OS, ["ping", "-c", "1", "-W", "1", ip])
    run(cmd, timeout=5)


def dns_servers():
    if OS == "Windows":
        out = powershell("Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses")
    elif OS == "Darwin":
        out = "\n".join(l.split(":", 1)[1] for l in run(["scutil", "--dns"]).splitlines()
                        if "nameserver[" in l and ":" in l)
    else:
        out = run(["resolvectl", "dns"])
        out = "\n".join(l.split(":", 1)[1] for l in out.splitlines() if ":" in l)
        if not out.strip():
            try:
                with open("/etc/resolv.conf") as fh:
                    out = "\n".join(l.split(None, 1)[1] for l in fh
                                    if l.startswith("nameserver") and len(l.split()) > 1)
            except OSError:
                out = ""
    found = []
    for token in out.split():
        ip = as_ip(token)
        if ip and not ip.is_link_local and str(ip) not in found:
            found.append(str(ip))
    return found


def exposed_listeners():
    """Return a sorted list of (port, process) reachable from the network, or None."""
    rows = []
    if OS == "Linux":
        if not shutil.which("ss"):
            return None
        for line in run(["ss", "-H", "-tlnp"]).splitlines():
            parts = line.split()
            if len(parts) >= 4:
                proc = re.search(r'\("([^"]+)"', line)
                rows.append((parts[3], proc.group(1) if proc else ""))
    elif OS == "Darwin":
        out = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        if not out:
            return None
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                rows.append((parts[-2], parts[0]))
    else:
        out = run(["netstat", "-ano"])
        if not out:
            return None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "TCP" and parts[3] == "LISTENING":
                rows.append((parts[1], f"pid {parts[-1]}"))
    exposed = set()
    for local, proc in rows:
        host, _, port = local.rpartition(":")
        ip = as_ip(host)
        if not port.isdigit() or (ip and ip.is_loopback) or host == "localhost":
            continue
        exposed.add((int(port), proc))
    return sorted(exposed)


# ------------------------------------------------------------------ checks

def check_wifi(rep):
    ssid, sec = wifi_info()
    if ssid is None:
        rep.add(SKIP, "Wi-Fi encryption: could not be determined",
                "Not on Wi-Fi, or the OS withheld the details (location permission).")
        return
    s = (sec or "").lower()
    name = f'Network "{ssid}"'
    if "owe" in s or "enhanced open" in s:
        rep.add(OK, f"{name}: Enhanced Open (encrypted without a password)")
    elif s in ("", "--", "none") or "open" in s:
        rep.add(FAIL, f"{name}: OPEN, no Wi-Fi encryption",
                "Anyone nearby can capture whatever you send that is not already encrypted.",
                "Use a VPN for the whole session, or use your phone's hotspot instead.")
    elif "wep" in s or ("wpa" in s and not re.search(r"wpa[23]|sae|rsn", s)):
        rep.add(WARN, f"{name}: outdated encryption ({sec})",
                "WEP and original WPA can be cracked in minutes.", "Treat it as open: use a VPN.")
    else:
        rep.add(OK, f"{name}: encrypted ({sec})",
                "Note: everyone who has the cafe password is still 'inside' with you,\n"
                "so the rest of these checks still matter.")


def check_firewall(rep):
    state, desc = firewall_state()
    if state is True:
        rep.add(OK, f"Firewall is on ({desc})")
    elif state is False:
        rep.add(FAIL, f"Firewall is OFF ({desc})",
                "Other people on this network can reach services on your laptop.",
                {"Windows": "Settings > Privacy & security > Windows Security > Firewall: turn on all profiles.",
                 "Darwin": "System Settings > Network > Firewall: turn on (and enable stealth mode in Options)."
                 }.get(OS, "sudo ufw enable   (or start firewalld)"))
    else:
        rep.add(WARN, "Firewall status unknown", desc, "Confirm manually that a firewall is active.")


def check_vpn(rep, iface):
    if iface and VPN_HINT.search(iface):
        rep.add(OK, f"VPN appears active (internet traffic leaves via '{iface}')",
                "Enable your VPN's kill switch so traffic stops if the VPN drops.")
        return True
    rep.add(WARN, "No VPN detected" + (f" (traffic leaves via '{iface}')" if iface else ""),
            "The hotspot operator and possibly other guests can see which sites you visit\n"
            "and can tamper with anything not protected by HTTPS.",
            "Connect a trusted VPN before doing anything else. (Detection is a heuristic;\n"
            "         a split-tunnel or unusual VPN may not be recognised.)")
    return False


def check_listeners(rep):
    exposed = exposed_listeners()
    if exposed is None:
        rep.add(SKIP, "Exposed services: could not list listening ports")
        return
    risky = [(p, proc) for p, proc in exposed if p in RISKY_PORTS]
    other = [(p, proc) for p, proc in exposed if p not in RISKY_PORTS]
    fmt = lambda rows: "\n".join(
        f"port {p:<6}{RISKY_PORTS.get(p, 'unidentified service')}{f'  [{proc}]' if proc else ''}"
        for p, proc in rows)
    if risky:
        rep.add(WARN, f"{len(risky)} sharing/remote-access service(s) listening on the network",
                fmt(risky + other),
                "Turn off file sharing, remote login, screen sharing and AirPlay Receiver\n"
                "         while on public Wi-Fi (a firewall may already be blocking these).")
    elif other:
        rep.add(INFO, f"{len(other)} other service(s) listening on the network", fmt(other))
    else:
        rep.add(OK, "No services exposed to the network")


def check_arp(rep, gw):
    if not gw:
        rep.add(SKIP, "Router check: no default gateway found (not connected?)")
        return
    table = arp_table()
    if gw not in table:
        ping_once(gw)
        table = arp_table()
    mac = table.get(gw)
    if not mac:
        rep.add(SKIP, f"Router check: no hardware address known yet for {gw}")
        return
    twins = [ip for ip, m in table.items() if m == mac and ip != gw]
    if twins:
        rep.add(FAIL, "Possible ARP spoofing (man-in-the-middle)",
                f"Router {gw} and {', '.join(twins)} claim the same hardware address {mac}.\n"
                "That is how an attacker on the network inserts themselves between you and the router.",
                "Disconnect. If you must stay, use a VPN and never click through certificate warnings.")
    else:
        rep.add(OK, f"Router {gw} has a unique hardware address ({mac})",
                "Run with --watch to be alerted if it changes mid-session.")


def check_dns(rep, gw, vpn):
    servers = dns_servers()
    if not servers:
        rep.add(SKIP, "DNS: could not determine resolvers")
    else:
        local = [s for s in servers if ipaddress.ip_address(s).is_private
                 and not ipaddress.ip_address(s).is_loopback]
        listing = ", ".join(servers)
        if vpn:
            rep.add(OK, f"DNS servers: {listing}", "Lookups should be travelling through the VPN.")
        elif local or gw in servers:
            rep.add(INFO, f"DNS is controlled by this hotspot ({listing})",
                    "The operator can log every site name you look up and could redirect you.",
                    "Turn on encrypted DNS (DNS-over-HTTPS) in your browser or OS, or use a VPN.")
        else:
            rep.add(INFO, f"DNS servers: {listing}",
                    "Unless encrypted DNS is enabled, lookups are still readable on this network.")
    bogus = f"wifiguard-{secrets.token_hex(6)}.invalid"
    try:
        answer = socket.getaddrinfo(bogus, 80)[0][4][0]
        rep.add(WARN, "DNS returns answers for names that cannot exist",
                f"'{bogus}' resolved to {answer}.\n"
                "Either you have not completed the hotspot login page yet, or DNS is being hijacked.",
                "Finish the login page and re-run. If it persists, do not trust this network.")
    except OSError:
        rep.add(OK, "DNS correctly rejects non-existent names (no blanket hijacking)")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def check_captive(rep):
    url = "http://connectivitycheck.gstatic.com/generate_204"
    try:
        code = urllib.request.build_opener(_NoRedirect).open(url, timeout=8).status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except (OSError, ValueError):
        rep.add(SKIP, "Captive portal check: no internet connectivity")
        return
    if code == 204:
        rep.add(OK, "No captive portal or web-traffic rewriting detected")
    else:
        rep.add(WARN, f"Web traffic is being intercepted or redirected (HTTP {code})",
                "Usually a login page you have not completed; occasionally content injection.",
                "Complete the login (give no real passwords), then re-run this audit.")


def check_tls(rep):
    ctx = ssl.create_default_context()
    good, bad, unreachable = [], [], 0
    for host in TLS_TEST_HOSTS:
        try:
            with socket.create_connection((host, 443), timeout=6) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    issuer = dict(x[0] for x in tls.getpeercert().get("issuer", ()))
                    good.append(f"{host}  (issued by {issuer.get('organizationName', '?')})")
        except ssl.SSLCertVerificationError as exc:
            bad.append(f"{host}: {exc.verify_message}")
        except (OSError, ssl.SSLError):
            unreachable += 1
    if bad:
        rep.add(FAIL, "HTTPS certificate validation FAILED: likely interception",
                "\n".join(bad) + "\nSomething between you and these sites presented an untrusted certificate.\n"
                "(If this also fails on your home network, your Python lacks root certificates.)",
                "Finish any hotspot login first. If it still fails, leave this network.\n"
                "         Never click 'proceed anyway' on a browser certificate warning here.")
    elif good:
        rep.add(OK, "HTTPS connections verify correctly (no TLS interception seen)", "\n".join(good))
    else:
        rep.add(SKIP, "HTTPS check: could not reach test sites")


def audit():
    print(f"wifi_guard: public Wi-Fi audit on {OS if OS != 'Darwin' else 'macOS'}, "
          f"{time.strftime('%Y-%m-%d %H:%M')}\n")
    rep = Report()
    gw, iface = route_info()
    check_wifi(rep)
    check_firewall(rep)
    vpn = check_vpn(rep, iface)
    check_listeners(rep)
    check_arp(rep, gw)
    check_dns(rep, gw, vpn)
    check_captive(rep)
    check_tls(rep)
    return rep.show()


# ------------------------------------------------------------------- watch

def snapshot():
    gw, iface = route_info()
    table = arp_table()
    mac = table.get(gw) if gw else None
    return {
        "ssid": wifi_info()[0],
        "gw": gw,
        "gw_mac": mac,
        "twins": sorted(ip for ip, m in table.items() if mac and m == mac and ip != gw),
        "vpn": bool(iface and VPN_HINT.search(iface)),
        "dns": sorted(dns_servers()),
    }


def watch(interval):
    def say(level, msg):
        bell = "\a" if level in (FAIL, WARN) else ""
        print(f"{time.strftime('%H:%M:%S')} {paint(level, f'[{level:^4}]')} {msg}{bell}", flush=True)

    base = snapshot()
    if base["gw"] and not base["gw_mac"]:
        ping_once(base["gw"])
        base = snapshot()
    say(INFO, f"Watching network '{base['ssid'] or '?'}': router {base['gw']} at {base['gw_mac']}, "
              f"VPN {'on' if base['vpn'] else 'OFF'}, DNS {', '.join(base['dns']) or '?'}")
    say(INFO, f"Checking every {interval}s. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(interval)
            now = snapshot()
            if now["ssid"] != base["ssid"] or now["gw"] != base["gw"]:
                say(WARN, f"Network changed: '{base['ssid']}' -> '{now['ssid']}' (router {now['gw']}). "
                          "If you did not switch networks yourself, you may have been moved to a look-alike hotspot.")
                base = now
                continue
            if now["gw_mac"] and base["gw_mac"] and now["gw_mac"] != base["gw_mac"]:
                say(FAIL, f"ROUTER HARDWARE ADDRESS CHANGED {base['gw_mac']} -> {now['gw_mac']}. "
                          "Classic sign of ARP spoofing / man-in-the-middle. Disconnect now.")
            if now["twins"] and now["twins"] != base["twins"]:
                say(FAIL, f"Device(s) {', '.join(now['twins'])} now share the router's hardware address. "
                          "Possible man-in-the-middle. Disconnect.")
            if base["vpn"] and not now["vpn"]:
                say(FAIL, "VPN DROPPED: your traffic is now exposed to this network. Reconnect it.")
            if now["vpn"] and not base["vpn"]:
                say(OK, "VPN is now active.")
            if now["dns"] != base["dns"]:
                say(WARN, f"DNS servers changed: {', '.join(base['dns']) or '?'} -> {', '.join(now['dns']) or '?'}")
            if not now["gw_mac"]:
                now["gw_mac"] = base["gw_mac"]  # entry merely expired from the OS cache
            base = now
    except KeyboardInterrupt:
        print("\nStopped.")


def main():
    ap = argparse.ArgumentParser(description="Public Wi-Fi safety audit and monitor (read-only).")
    ap.add_argument("--watch", action="store_true", help="monitor continuously for attacks")
    ap.add_argument("--interval", type=int, default=10, help="seconds between checks in --watch mode")
    args = ap.parse_args()
    if args.watch:
        watch(max(2, args.interval))
        return 0
    return audit()


if __name__ == "__main__":
    sys.exit(main())
