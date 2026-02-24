#!/usr/bin/env python3
"""
Network Discovery Module
ARP sweep, ICMP ping sweep, and subnet auto-detection.
"""

import re
import logging
import ipaddress
import socket
import struct
import time
from modules.base_scanner import BaseScanner, IS_WINDOWS

logger = logging.getLogger('blue-reccoon.discovery')


class ARPScanner(BaseScanner):
    """ARP-based host discovery — most reliable for local subnets."""

    def run(self):
        targets = self.parse_targets()
        if not targets:
            return {'error': 'No valid targets specified'}

        found_hosts = []
        total = len(targets)
        method = self.config.get('method', 'auto')

        self.progress(0, f"Starting network discovery on {total} targets")
        self.log(f"Host discovery initiated: {total} target IPs, method={method}. "
                 f"Actions: ARP requests (local subnet), ICMP Echo Request (ping), "
                 f"or nmap -sn -PR -PE (ARP+ICMP ping scan). No port scanning performed.",
                 severity='ACTION', category='config',
                 raw_detail=f"Target specification: {self.target}")

        # Try methods in order of reliability
        if method == 'auto' or method == 'nmap':
            if self.tool_available('nmap'):
                self.log("Using nmap for host discovery (ARP ping + ICMP echo)", severity='INFO', category='config', tool='nmap')
                found_hosts = self._nmap_discovery(targets)
            elif method == 'nmap':
                return {'error': 'nmap not installed'}

        if not found_hosts and (method == 'auto' or method == 'arping'):
            if self.tool_available('arping'):
                found_hosts = self._arping_discovery(targets)

        if not found_hosts and (method == 'auto' or method == 'ping'):
            found_hosts = self._ping_discovery(targets)

        # Infer subnets from discovered hosts
        if found_hosts:
            self.infer_subnets([h['ip'] for h in found_hosts])

        self.progress(100, f"Discovery complete: {len(found_hosts)} hosts found")

        self.results_summary = {
            'hosts_found': len(found_hosts),
            'targets_scanned': total,
            'method': method,
            'hosts': [h['ip'] for h in found_hosts]
        }
        return self.results_summary

    def _nmap_discovery(self, targets):
        """Use nmap for host discovery. Most comprehensive."""
        found = []
        # Process in chunks for large target lists
        chunk_size = 256
        chunks = [targets[i:i+chunk_size] for i in range(0, len(targets), chunk_size)]

        for ci, chunk in enumerate(chunks):
            if self.is_stopped():
                break

            target_str = ' '.join(chunk)
            pct = int((ci / len(chunks)) * 80)
            self.progress(pct, f"Nmap discovery: chunk {ci+1}/{len(chunks)}")

            # -sn: ping scan only, -PR: ARP ping, -PE: ICMP echo, --min-rate for speed
            cmd = f"nmap -sn -PR -PE --min-rate=300 -oX - {target_str} 2>/dev/null"
            rc, stdout, stderr = self.run_command(cmd, timeout=120)

            if rc == 0 and stdout:
                found.extend(self._parse_nmap_discovery(stdout))

        return found

    def _parse_nmap_discovery(self, xml_output):
        """Parse nmap -sn XML output for discovered hosts."""
        hosts = []
        # Simple XML parsing without lxml dependency
        host_blocks = re.findall(r'<host\b.*?</host>', xml_output, re.DOTALL)

        for block in host_blocks:
            # Check if host is up
            if 'state="up"' not in block:
                continue

            ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
            mac_match = re.search(r'<address addr="([^"]+)" addrtype="mac"', block)
            vendor_match = re.search(r'addrtype="mac"[^/]*vendor="([^"]*)"', block)
            hostname_match = re.search(r'<hostname name="([^"]+)"', block)

            if ip_match:
                ip = ip_match.group(1)
                mac = mac_match.group(1) if mac_match else None
                vendor = vendor_match.group(1) if vendor_match else None
                hostname = hostname_match.group(1) if hostname_match else None

                self.submit_host(
                    ip,
                    mac_address=mac,
                    hostname=hostname,
                    device_vendor=vendor,
                    discovered_via='nmap_discovery'
                )

                hosts.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor})

        return hosts

    def _arping_discovery(self, targets):
        """Use arping for ARP-based discovery on local subnets."""
        found = []
        total = len(targets)

        for i, ip in enumerate(targets):
            if self.is_stopped():
                break

            if i % 10 == 0:
                pct = int((i / total) * 80)
                self.progress(pct, f"ARP scanning: {i}/{total}")

            cmd = f"arping -c 1 -w 1 {ip} 2>/dev/null"
            rc, stdout, stderr = self.run_command(cmd, timeout=5)

            if rc == 0 and 'bytes from' in stdout:
                mac_match = re.search(r'\[([0-9A-Fa-f:]+)\]', stdout)
                mac = mac_match.group(1) if mac_match else None

                self.submit_host(ip, mac_address=mac, discovered_via='arping')
                found.append({'ip': ip, 'mac': mac})

        return found

    def _ping_discovery(self, targets):
        """Fallback ICMP ping sweep."""
        found = []
        total = len(targets)

        for i, ip in enumerate(targets):
            if self.is_stopped():
                break

            if i % 10 == 0:
                pct = int((i / total) * 80)
                self.progress(pct, f"Ping sweep: {i}/{total}")

            cmd = self.ping_cmd(ip, count=1, timeout_sec=1)
            rc, stdout, stderr = self.run_command(cmd, timeout=5)

            if rc == 0:
                # Try to extract TTL for passive OS fingerprinting
                ttl_match = re.search(r'ttl[=:](\d+)', stdout, re.IGNORECASE)
                ttl = int(ttl_match.group(1)) if ttl_match else None

                os_guess = None
                if ttl:
                    if ttl <= 64:
                        os_guess = 'Linux/Unix'
                    elif ttl <= 128:
                        os_guess = 'Windows'
                    elif ttl <= 255:
                        os_guess = 'Network Device'

                self.submit_host(
                    ip,
                    os_name=os_guess,
                    os_fingerprint_method='passive_ttl' if os_guess else None,
                    discovered_via='icmp_ping'
                )
                found.append({'ip': ip, 'ttl': ttl, 'os_guess': os_guess})

        return found


class SubnetDetector(BaseScanner):
    """Detect active subnets by analyzing routing tables and ARP caches."""

    def run(self):
        subnets = []

        self.progress(10, "Checking local interfaces")
        subnets.extend(self._from_interfaces())

        self.progress(40, "Reading ARP cache")
        subnets.extend(self._from_arp_cache())

        self.progress(70, "Checking routing table")
        subnets.extend(self._from_routes())

        # Deduplicate
        seen = set()
        unique = []
        for s in subnets:
            if s['cidr'] not in seen:
                seen.add(s['cidr'])
                unique.append(s)
                self.submit_subnet(s['cidr'], gateway=s.get('gateway'),
                                   discovered_via='local_detection',
                                   name=s.get('name'))

        self.progress(100, f"Detected {len(unique)} subnets")
        return {'subnets_detected': len(unique), 'subnets': [s['cidr'] for s in unique]}

    def _from_interfaces(self):
        """Detect subnets from local network interfaces."""
        subnets = []
        if IS_WINDOWS:
            rc, stdout, _ = self.run_command("ipconfig")
        else:
            rc, stdout, _ = self.run_command("ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null")
        if rc == 0:
            if IS_WINDOWS:
                # Parse ipconfig: "IPv4 Address. . . . : 10.0.0.5" + "Subnet Mask . . . : 255.255.255.0"
                blocks = re.split(r'\r?\n\r?\n', stdout)
                for block in blocks:
                    ip_match = re.search(r'IPv4 Address[\.\s]*:\s*(\d+\.\d+\.\d+\.\d+)', block)
                    mask_match = re.search(r'Subnet Mask[\.\s]*:\s*(\d+\.\d+\.\d+\.\d+)', block)
                    if ip_match and mask_match:
                        ip_str, mask_str = ip_match.group(1), mask_match.group(1)
                        try:
                            net = ipaddress.ip_network(f"{ip_str}/{mask_str}", strict=False)
                            subnets.append({'cidr': str(net), 'name': f'Local ({ip_str})'})
                        except Exception:
                            pass
            else:
                for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', stdout):
                    ip, prefix = match.group(1), match.group(2)
                    try:
                        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                        subnets.append({'cidr': str(net), 'name': f'Local ({ip})'})
                    except Exception:
                        pass
        return subnets

    def _from_arp_cache(self):
        """Infer subnets from ARP cache entries."""
        subnets = set()
        if IS_WINDOWS:
            rc, stdout, _ = self.run_command("arp -a")
        else:
            rc, stdout, _ = self.run_command("arp -a 2>/dev/null || ip neigh show 2>/dev/null")
        if rc == 0:
            for match in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', stdout):
                ip = match.group(1)
                try:
                    net = ipaddress.ip_network(f"{ip}/24", strict=False)
                    subnets.add(str(net))
                except Exception:
                    pass
        return [{'cidr': s} for s in subnets]

    def _from_routes(self):
        """Detect subnets from routing table."""
        subnets = []
        if IS_WINDOWS:
            rc, stdout, _ = self.run_command("route print")
            if rc == 0:
                # Parse Windows route table: "Network Destination  Netmask  Gateway"
                for match in re.finditer(
                    r'(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)',
                    stdout
                ):
                    dest, mask, gw = match.group(1), match.group(2), match.group(3)
                    if dest == '0.0.0.0' or dest == '255.255.255.255' or dest == '127.0.0.0':
                        continue
                    try:
                        net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
                        if net.prefixlen < 32:
                            subnets.append({'cidr': str(net), 'gateway': gw})
                    except Exception:
                        pass
        else:
            rc, stdout, _ = self.run_command("ip route show 2>/dev/null || netstat -rn 2>/dev/null")
            if rc == 0:
                for match in re.finditer(r'(\d+\.\d+\.\d+\.\d+/\d+).*?via\s+(\d+\.\d+\.\d+\.\d+)', stdout):
                    cidr, gw = match.group(1), match.group(2)
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        subnets.append({'cidr': str(net), 'gateway': gw})
                    except Exception:
                        pass
        return subnets
