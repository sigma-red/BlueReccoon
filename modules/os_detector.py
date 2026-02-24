#!/usr/bin/env python3
"""
OS Detection Module
Active and passive OS fingerprinting.
"""

import re
import logging
from modules.base_scanner import BaseScanner

logger = logging.getLogger('blue-reccoon.os')


class OSDetector(BaseScanner):
    """OS detection using nmap and passive analysis."""

    def run(self):
        targets = self.parse_targets()
        if not targets:
            return {'error': 'No valid targets specified'}

        detected = 0
        total = len(targets)

        self.progress(0, f"OS detection on {total} hosts")

        if self.tool_available('nmap'):
            detected = self._nmap_os_detect(targets)
        else:
            detected = self._passive_os_detect(targets)

        self.progress(100, f"OS detection complete: {detected}/{total} identified")
        return {'detected': detected, 'total': total}

    def _nmap_os_detect(self, targets):
        """Use nmap for OS detection."""
        detected = 0
        chunk_size = 16
        chunks = [targets[i:i+chunk_size] for i in range(0, len(targets), chunk_size)]

        for ci, chunk in enumerate(chunks):
            if self.is_stopped():
                break

            pct = int((ci / len(chunks)) * 90)
            self.progress(pct, f"Nmap OS scan: chunk {ci+1}/{len(chunks)}")

            target_str = ' '.join(chunk)
            cmd = f"nmap -O --osscan-guess -T3 -oX - {target_str} 2>/dev/null"
            rc, stdout, _ = self.run_command(cmd, timeout=300)

            if rc == 0 and stdout:
                for block in re.findall(r'<host\b.*?</host>', stdout, re.DOTALL):
                    ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
                    if not ip_match:
                        continue
                    ip = ip_match.group(1)

                    os_match = re.search(r'<osmatch name="([^"]+)".*?accuracy="(\d+)"', block)
                    if os_match and int(os_match.group(2)) > 70:
                        os_full = os_match.group(1)
                        os_name, os_version = self._parse_os_string(os_full)

                        self.submit({
                            'type': 'os_info',
                            'ip_address': ip,
                            'os_name': os_name,
                            'os_version': os_version,
                            'method': 'nmap'
                        })
                        detected += 1

        return detected

    def _passive_os_detect(self, targets):
        """Passive OS detection using TTL and TCP characteristics."""
        detected = 0

        for ip in targets:
            if self.is_stopped():
                break

            cmd = self.ping_cmd(ip, count=1, timeout_sec=1)
            rc, stdout, _ = self.run_command(cmd, timeout=5)
            if rc == 0:
                # Windows: "TTL=128", Linux: "ttl=64"
                ttl_match = re.search(r'ttl[=:](\d+)', stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    os_name = None

                    if 0 < ttl <= 64:
                        os_name = 'Linux/Unix'
                    elif 64 < ttl <= 128:
                        os_name = 'Windows'
                    elif 128 < ttl <= 255:
                        os_name = 'Network Device'

                    if os_name:
                        self.submit({
                            'type': 'os_info',
                            'ip_address': ip,
                            'os_name': os_name,
                            'method': 'passive_ttl'
                        })
                        detected += 1

        return detected

    @staticmethod
    def _parse_os_string(os_full):
        """Parse nmap OS string into name and version."""
        # "Microsoft Windows 10 1903" -> ("Windows 10", "1903")
        # "Linux 4.15 - 5.6" -> ("Linux", "4.15 - 5.6")
        os_full = os_full.replace('Microsoft ', '')

        patterns = [
            (r'(Windows Server \d{4})\s*(.*)', None),
            (r'(Windows \d+)\s*(.*)', None),
            (r'(Windows [A-Za-z]+)\s*(.*)', None),
            (r'(Linux)\s*(.*)', None),
            (r'(FreeBSD)\s*(.*)', None),
            (r'(Ubuntu)\s*(.*)', None),
            (r'(CentOS)\s*(.*)', None),
            (r'(Cisco IOS)\s*(.*)', None),
        ]

        for pattern, _ in patterns:
            match = re.match(pattern, os_full)
            if match:
                return match.group(1).strip(), match.group(2).strip() or None

        return os_full, None
