import atexit
import fnmatch
import json
import os
import signal
import socket
import subprocess
import sys
import threading
from dnslib import DNSRecord, DNSHeader, RR, A, AAAA, QTYPE

CONFIG_FILE = "config.json"
ACTIVE_ADAPTER = None
ORIGINAL_IPV4_DNS = []
ORIGINAL_IPV6_DNS = []

def load_config():
    if os.path.exists(CONFIG_FILE):
        path = CONFIG_FILE
    else:
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        fallback_path = os.path.join(base_dir, CONFIG_FILE)
        path = fallback_path if os.path.exists(fallback_path) else CONFIG_FILE

    with open(path, "r") as f:
        return json.load(f)

# --- Windows Network Adapter Management ---

def get_primary_adapter():
    cmd = (
        'powershell -Command "Get-NetRoute -DestinationPrefix 0.0.0.0/0 '
        '| Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceAlias -First 1"'
    )
    try:
        output = subprocess.check_output(cmd, shell=True).decode().strip()
        return output if output else None
    except Exception:
        return None

def backup_adapter_dns(adapter_name):
    global ORIGINAL_IPV4_DNS, ORIGINAL_IPV6_DNS
    # Backup IPv4
    cmd_v4 = f'powershell -Command "(Get-DnsClientServerAddress -InterfaceAlias \'{adapter_name}\' -AddressFamily IPv4).ServerAddresses"'
    try:
        out_v4 = subprocess.check_output(cmd_v4, shell=True).decode().strip()
        ORIGINAL_IPV4_DNS = [a.strip() for a in out_v4.splitlines() if a.strip()]
    except Exception:
        ORIGINAL_IPV4_DNS = []

    # Backup IPv6
    cmd_v6 = f'powershell -Command "(Get-DnsClientServerAddress -InterfaceAlias \'{adapter_name}\' -AddressFamily IPv6).ServerAddresses"'
    try:
        out_v6 = subprocess.check_output(cmd_v6, shell=True).decode().strip()
        ORIGINAL_IPV6_DNS = [a.strip() for a in out_v6.splitlines() if a.strip()]
    except Exception:
        ORIGINAL_IPV6_DNS = []

def configure_adapter_dns(adapter_name, local_ipv4="127.0.0.1"):
    # Route IPv4 to local redirector
    cmd_v4 = f'powershell -Command "Set-DnsClientServerAddress -InterfaceAlias \'{adapter_name}\' -ServerAddresses (\\"{local_ipv4}\\")"'
    subprocess.run(cmd_v4, shell=True, check=True)
    
    # Route IPv6 to loopback so ISP IPv6 resolvers don't bypass our tool
    cmd_v6 = f'powershell -Command "Set-DnsClientServerAddress -InterfaceAlias \'{adapter_name}\' -AddressFamily IPv6 -ServerAddresses (\\\"::1\\\")"'
    subprocess.run(cmd_v6, shell=True, capture_output=True)

    subprocess.run("ipconfig /flushdns", shell=True, capture_output=True)

def restore_adapter_dns():
    global ACTIVE_ADAPTER, ORIGINAL_IPV4_DNS, ORIGINAL_IPV6_DNS
    if not ACTIVE_ADAPTER:
        return

    print(f"\n[*] Restoring DNS configuration on [{ACTIVE_ADAPTER}]...")
    try:
        # Build instant netsh commands (native Windows C binaries, ~15ms execution)
        cmds = []

        # 1. Restore IPv4
        if ORIGINAL_IPV4_DNS:
            # Set primary
            cmds.append(f'netsh interface ipv4 set dnsservers name="{ACTIVE_ADAPTER}" static {ORIGINAL_IPV4_DNS[0]} primary')
            # Add remaining secondary servers
            for sec in ORIGINAL_IPV4_DNS[1:]:
                cmds.append(f'netsh interface ipv4 add dnsservers name="{ACTIVE_ADAPTER}" {sec} index=2')
        else:
            cmds.append(f'netsh interface ipv4 set dnsservers name="{ACTIVE_ADAPTER}" source=dhcp')

        # 2. Restore IPv6
        if ORIGINAL_IPV6_DNS:
            cmds.append(f'netsh interface ipv6 set dnsservers name="{ACTIVE_ADAPTER}" static {ORIGINAL_IPV6_DNS[0]} primary')
            for sec in ORIGINAL_IPV6_DNS[1:]:
                cmds.append(f'netsh interface ipv6 add dnsservers name="{ACTIVE_ADAPTER}" {sec} index=2')
        else:
            cmds.append(f'netsh interface ipv6 set dnsservers name="{ACTIVE_ADAPTER}" source=dhcp')

        # 3. Flush DNS
        cmds.append("ipconfig /flushdns")

        # Execute all commands in a single cmd.exe pipeline
        batch_cmd = " && ".join(cmds)
        subprocess.run(batch_cmd, shell=True, capture_output=True)

        print("[+] Adapter DNS restored instantly.")
    except Exception as e:
        print(f"[!] Cleanup error: {e}")

# --- DNS Processing Logic ---

def match_domain(domain_name, rules):
    clean_domain = domain_name.rstrip(".").lower()
    for pattern, target_ip in rules.items():
        if fnmatch.fnmatch(clean_domain, pattern.rstrip(".").lower()):
            return target_ip
    return None

def process_dns_query(data, client_addr, server_sock, config):
    try:
        request = DNSRecord.parse(data)
    except Exception:
        return

    qname = str(request.q.qname)
    qtype = QTYPE[request.q.qtype]
    rules = config.get("rules", {})
    redirect_ip = match_domain(qname, rules)

    # 1. Custom rule match
    if redirect_ip:
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        if qtype == "A":
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(redirect_ip), ttl=30))
            server_sock.sendto(reply.pack(), client_addr)
            print(f"[REDIRECT] {qname.rstrip('.')} (A) -> {redirect_ip}")
            return
        elif qtype == "AAAA":
            # Return empty response for IPv6 queries on redirected domains
            server_sock.sendto(reply.pack(), client_addr)
            print(f"[REDIRECT] {qname.rstrip('.')} (AAAA) -> SINKHOLE")
            return

    # 2. Forward unmatched queries to Control D
    upstream_ip = config.get("upstream_dns", "76.76.2.2")
    upstream_port = config.get("upstream_port", 53)
    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.settimeout(2.5)

    try:
        upstream_sock.sendto(data, (upstream_ip, upstream_port))
        upstream_response, _ = upstream_sock.recvfrom(4096)
        server_sock.sendto(upstream_response, client_addr)
    except socket.timeout:
        pass
    except Exception as e:
        print(f"[!] Forwarding error for {qname.rstrip('.')}: {e}")
    finally:
        upstream_sock.close()

def main():
    global ACTIVE_ADAPTER
    config = load_config()

    atexit.register(restore_adapter_dns)

    bind_ip = config.get("bind_ip", "127.0.0.1")
    bind_port = config.get("bind_port", 53)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((bind_ip, bind_port))
    # Allows the loop to check for Ctrl+C twice per second without blocking
    server_sock.settimeout(0.5)

    print(f"[*] DNS Server listening on {bind_ip}:{bind_port}")

    if config.get("auto_configure_adapter", True):
        adapter = get_primary_adapter()
        if adapter:
            ACTIVE_ADAPTER = adapter
            backup_adapter_dns(adapter)
            configure_adapter_dns(adapter, bind_ip)
            print(f"[*] Adapter [{adapter}] configured.")

    print("[*] Ready. Press Ctrl+C to stop.\n")

    running = True
    while running:
        try:
            data, client_addr = server_sock.recvfrom(4096)
            threading.Thread(
                target=process_dns_query,
                args=(data, client_addr, server_sock, config),
                daemon=True
            ).start()
        except socket.timeout:
            continue
        except (KeyboardInterrupt, SystemExit):
            running = False
            break
        except Exception as e:
            print(f"[!] Socket loop error: {e}")

    server_sock.close()
    sys.exit(0)

if __name__ == "__main__":
    main()