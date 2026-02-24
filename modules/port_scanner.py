#!/usr/bin/env python3
"""
Port Scanner Module
TCP/UDP port scanning with configurable aggressiveness levels.
Wraps nmap when available, falls back to socket-based scanning.
"""

import re
import socket
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.base_scanner import BaseScanner

logger = logging.getLogger('cpt-recon.portscan')

# Port profiles by aggressiveness
PORT_PROFILES = {
    1: list(range(1, 100)) + [102, 443, 445, 502, 3389, 8080],  # Ultra-light: top 100 + OT
    2: [],  # Top 200 + OT — populated from nmap-services or hardcoded
    3: [],  # Top 1000
    4: [],  # Top 5000
    5: list(range(1, 65536)),  # Full 65535
}

# Top 200 common ports
TOP_200 = [
    7,20,21,22,23,25,26,37,43,49,53,67,68,69,79,80,81,88,102,110,111,113,119,
    135,137,139,143,161,162,179,194,199,389,443,445,465,502,512,513,514,515,
    520,523,548,554,587,593,623,626,631,636,646,666,771,789,873,902,993,995,
    1023,1025,1026,1027,1028,1029,1080,1099,1194,1214,1241,1311,1433,1434,
    1521,1723,1741,1812,1883,1900,1911,2000,2049,2082,2083,2086,2087,2095,
    2096,2100,2181,2222,2375,2376,2404,2455,2480,2628,3000,3128,3260,3268,
    3306,3389,3478,3690,3780,4000,4200,4443,4444,4445,4786,4840,4848,4899,
    5000,5001,5003,5060,5061,5432,5555,5601,5672,5800,5900,5901,5984,5985,
    5986,6000,6379,6443,6588,6666,7000,7001,7002,7070,7443,7474,7547,7777,
    8000,8001,8008,8009,8010,8020,8042,8080,8081,8082,8083,8088,8090,8161,
    8443,8445,8500,8787,8888,8899,9000,9001,9042,9090,9092,9100,9200,9300,
    9418,9443,9600,9999,10000,10250,10443,11211,11443,12345,15672,18245,
    20000,20547,25565,27017,28017,30718,32400,33333,44818,47808,49152,50000,
    50070,61616
]

# OT-critical ports always included
OT_PORTS = [102, 502, 789, 1911, 2222, 2404, 4840, 9600, 18245, 20000, 44818, 47808]

PORT_PROFILES[2] = sorted(set(TOP_200 + OT_PORTS))
PORT_PROFILES[3] = sorted(set(TOP_200 + OT_PORTS + list(range(1, 1024))))
PORT_PROFILES[4] = sorted(set(TOP_200 + OT_PORTS + list(range(1, 5001))))


class PortScanner(BaseScanner):
    """TCP/UDP port scanning with tiered aggressiveness."""

    def __init__(self, engine, scan_id, mission_id, target, config, stop_flag, aggressiveness=3):
        super().__init__(engine, scan_id, mission_id, target, config, stop_flag)
        self.aggressiveness = min(5, max(1, aggressiveness))
        self.scan_udp = config.get('scan_udp', False)
        self.threads = config.get('threads', 100)
        self.timeout = config.get('timeout', 1.5)

    def run(self):
        targets = self.parse_targets()
        if not targets:
            return {'error': 'No valid targets specified'}

        ports = PORT_PROFILES.get(self.aggressiveness, PORT_PROFILES[3])
        total_work = len(targets) * len(ports)

        self.progress(0, f"Port scanning {len(targets)} hosts, {len(ports)} ports (level {self.aggressiveness})")
        logger.info(f"Scan {self.scan_id}: {len(targets)} hosts × {len(ports)} ports = {total_work} checks")

        aggr_desc = {1:'Ultra-safe (top ~100 + OT)', 2:'Conservative (top ~200 + OT)',
                     3:'Normal (top 1024 + OT)', 4:'Aggressive (top 5000 + OT)', 5:'Full (1-65535)'}
        use_nmap = self.tool_available('nmap') and self.aggressiveness >= 2
        self.log(f"Port scan initiated: {len(targets)} hosts × {len(ports)} ports = {total_work} total probes. "
                 f"Aggressiveness: L{self.aggressiveness} — {aggr_desc.get(self.aggressiveness,'')}. "
                 f"Tool: {'nmap SYN scan (-sS -sV -O)' if use_nmap else 'TCP connect scan (socket)'}. "
                 f"UDP scan: {'YES' if self.scan_udp else 'NO'}. "
                 f"Actions: TCP SYN packets to each port on each target. "
                 f"Nmap will also attempt service version detection (-sV) and OS fingerprinting (-O).",
                 severity='ACTION', category='config',
                 raw_detail=f"Targets: {self.target} | OT ports always included: {','.join(str(p) for p in OT_PORTS)}")

        # Use nmap if available and aggressiveness > 1
        if use_nmap:
            results = self._nmap_scan(targets, ports)
        else:
            results = self._socket_scan(targets, ports)

        # Scan UDP if requested
        if self.scan_udp and not self.is_stopped():
            self.progress(85, "UDP scanning common ports...")
            udp_results = self._udp_scan(targets)
            for ip, udp_ports in udp_results.items():
                if ip not in results:
                    results[ip] = []
                results[ip].extend(udp_ports)

        total_services = sum(len(v) for v in results.values())
        self.progress(100, f"Scan complete: {total_services} open services on {len(results)} hosts")

        self.results_summary = {
            'hosts_with_services': len(results),
            'total_services': total_services,
            'aggressiveness': self.aggressiveness,
            'ports_scanned': len(ports),
            'hosts': list(results.keys())
        }
        return self.results_summary

    def _nmap_scan(self, targets, ports):
        """Use nmap for port scanning."""
        results = {}
        chunk_size = 32  # Hosts per nmap invocation
        chunks = [targets[i:i+chunk_size] for i in range(0, len(targets), chunk_size)]

        # Build port string - use ranges where possible for efficiency
        if self.aggressiveness == 5:
            port_str = "1-65535"
        elif self.aggressiveness >= 3:
            port_str = f"1-1024,{','.join(str(p) for p in OT_PORTS if p > 1024)}"
        else:
            port_str = ','.join(str(p) for p in ports[:500])  # nmap has command line limits

        # Timing template based on aggressiveness
        timing = min(4, self.aggressiveness)  # T1-T4

        for ci, chunk in enumerate(chunks):
            if self.is_stopped():
                break

            pct = int((ci / len(chunks)) * 80)
            self.progress(pct, f"Nmap scanning chunk {ci+1}/{len(chunks)}")

            target_str = ' '.join(chunk)
            cmd = (
                f"nmap -sS -sV --version-intensity {min(5, self.aggressiveness)} "
                f"-T{timing} -p {port_str} "
                f"--min-rate={100 * self.aggressiveness} "
                f"-O --osscan-guess "
                f"-oX - {target_str} 2>/dev/null"
            )
            # Scale timeout by aggressiveness and host count: L5 full-port scans need much longer
            nmap_timeout = {1: 300, 2: 300, 3: 600, 4: 900, 5: 1800}.get(self.aggressiveness, 600)
            # Add extra time for large target sets (30s per host at L5)
            if self.aggressiveness >= 4:
                nmap_timeout += len(chunk) * 30
            rc, stdout, stderr = self.run_command(cmd, timeout=nmap_timeout)

            if rc == 0 and stdout:
                chunk_results = self._parse_nmap_output(stdout)
                results.update(chunk_results)

        return results

    def _parse_nmap_output(self, xml_output):
        """Parse nmap XML output for open ports, services, and OS detection."""
        results = {}
        host_blocks = re.findall(r'<host\b.*?</host>', xml_output, re.DOTALL)

        for block in host_blocks:
            if 'state="up"' not in block:
                continue

            ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"', block)
            vendor_match = re.search(r'addrtype="mac"[^/]*vendor="([^"]*)"', block)
            mac = mac_match.group(1) if mac_match else None
            vendor = vendor_match.group(1) if vendor_match else None

            # OS detection
            os_match = re.search(r'<osmatch name="([^"]+)".*?accuracy="(\d+)"', block)
            os_name = None
            if os_match and int(os_match.group(2)) > 80:
                os_name = os_match.group(1)

            # Hostname
            hostname_match = re.search(r'<hostname name="([^"]+)"', block)
            hostname = hostname_match.group(1) if hostname_match else None

            # Submit host
            host_kwargs = {'discovered_via': 'nmap_scan'}
            if mac:
                host_kwargs['mac_address'] = mac
            if vendor:
                host_kwargs['device_vendor'] = vendor
            if os_name:
                host_kwargs['os_name'] = os_name
                host_kwargs['os_fingerprint_method'] = 'nmap'
            if hostname:
                host_kwargs['hostname'] = hostname

            # Parse ports
            host_ports = []
            port_blocks = re.findall(r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>', block, re.DOTALL)

            for proto, portid, port_content in port_blocks:
                state_match = re.search(r'<state state="(\w+)"', port_content)
                state = state_match.group(1) if state_match else 'unknown'

                if state != 'open':
                    continue

                port = int(portid)
                service_match = re.search(
                    r'<service name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?'
                    r'(?:\s+extrainfo="([^"]*)")?',
                    port_content
                )

                svc_name = service_match.group(1) if service_match else None
                svc_product = service_match.group(2) if service_match else None
                svc_version = service_match.group(3) if service_match else None
                svc_extra = service_match.group(4) if service_match else None

                # Build version string
                version_str = ''
                if svc_product:
                    version_str = svc_product
                    if svc_version:
                        version_str += f' {svc_version}'

                # Check for OT protocol
                ot_info = self.get_ot_info(port)
                is_ot = 1 if ot_info else 0
                ot_name = ot_info[0] if ot_info else None

                # Banner from extra info
                banner = svc_extra

                self.submit_service(
                    ip, port, proto,
                    state='open',
                    service_name=svc_name or (ot_info[1] if ot_info else None),
                    service_version=version_str or None,
                    banner=banner,
                    is_ot_protocol=is_ot,
                    ot_protocol_name=ot_name
                )

                host_ports.append(port)

            # Infer device type and criticality
            if host_ports:
                device_type = self.infer_device_type(host_ports, os_name, hostname)
                criticality = self.infer_criticality(device_type, host_ports)
                host_kwargs['device_type'] = device_type
                host_kwargs['criticality'] = criticality

            self.submit_host(ip, **host_kwargs)
            results[ip] = host_ports

        return results

    def _socket_scan(self, targets, ports):
        """Fallback socket-based TCP connect scan."""
        results = {}
        total = len(targets)

        for ti, ip in enumerate(targets):
            if self.is_stopped():
                break

            pct = int((ti / total) * 80)
            if ti % 5 == 0:
                self.progress(pct, f"Socket scanning {ip} ({ti+1}/{total})")

            open_ports = self._scan_host_ports(ip, ports)

            if open_ports:
                device_type = self.infer_device_type(open_ports)
                criticality = self.infer_criticality(device_type, open_ports)

                self.submit_host(
                    ip,
                    device_type=device_type,
                    criticality=criticality,
                    discovered_via='tcp_connect'
                )

                for port in open_ports:
                    ot_info = self.get_ot_info(port)
                    self.submit_service(
                        ip, port, 'tcp',
                        state='open',
                        service_name=ot_info[1] if ot_info else None,
                        is_ot_protocol=1 if ot_info else 0,
                        ot_protocol_name=ot_info[0] if ot_info else None
                    )

                results[ip] = open_ports

        return results

    def _scan_host_ports(self, ip, ports):
        """Scan a single host's ports using thread pool."""
        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                if self.is_stopped():
                    break
                result = future.result()
                if result is not None:
                    open_ports.append(result)

        return sorted(open_ports)

    def _udp_scan(self, targets):
        """Scan common UDP ports. Uses nmap if available."""
        results = {}
        udp_ports = "53,67,68,69,123,137,161,162,500,514,520,523,1434,1604,1900,4500,5353,5683,47808"

        if self.tool_available('nmap'):
            target_str = ' '.join(targets)
            cmd = f"nmap -sU -p {udp_ports} -T3 --max-retries 1 -oX - {target_str} 2>/dev/null"
            rc, stdout, _ = self.run_command(cmd, timeout=300)

            if rc == 0 and stdout:
                for block in re.findall(r'<host\b.*?</host>', stdout, re.DOTALL):
                    ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
                    if not ip_match:
                        continue
                    ip = ip_match.group(1)

                    for proto, portid, content in re.findall(
                        r'<port protocol="udp" portid="(\d+)">(.*?)</port>', block, re.DOTALL
                    ):
                        if 'state="open"' in content:
                            port = int(portid)
                            svc_match = re.search(r'<service name="([^"]*)"', content)
                            svc_name = svc_match.group(1) if svc_match else None

                            self.submit_service(ip, port, 'udp', state='open', service_name=svc_name)

                            if ip not in results:
                                results[ip] = []
                            results[ip].append(port)

        return results
