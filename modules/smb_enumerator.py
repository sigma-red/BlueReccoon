#!/usr/bin/env python3
"""
SMB Enumerator Module
Enumerates SMB shares, users, domain info, and sessions.
Uses smbclient/rpcclient/enum4linux when available, falls back to native probes.
"""

import re
import logging
from modules.base_scanner import BaseScanner

logger = logging.getLogger('blue-reccoon.smb')


class SMBEnumerator(BaseScanner):
    """SMB/NetBIOS enumeration for Windows hosts."""

    def run(self):
        targets = self.parse_targets()
        if not targets:
            return {'error': 'No valid targets specified'}

        creds = self.config.get('credentials', {})
        username = creds.get('username', '')
        password = creds.get('password', '')
        domain = creds.get('domain', '')

        total_shares = 0
        total_users = 0
        enumerated_hosts = 0

        self.progress(0, f"SMB enumeration on {len(targets)} hosts")

        for ti, ip in enumerate(targets):
            if self.is_stopped():
                break

            pct = int((ti / len(targets)) * 90)
            self.progress(pct, f"Enumerating {ip}")

            host_results = {}

            # Try enum4linux-ng first (most comprehensive)
            if self.tool_available('enum4linux-ng'):
                host_results = self._enum4linux_ng(ip, username, password, domain)
            elif self.tool_available('enum4linux'):
                host_results = self._enum4linux(ip, username, password)
            else:
                # Manual enumeration
                host_results = self._manual_enum(ip, username, password, domain)

            if host_results:
                enumerated_hosts += 1
                shares = host_results.get('shares', [])
                users = host_results.get('users', [])
                total_shares += len(shares)
                total_users += len(users)

                # Update host info
                if host_results.get('hostname') or host_results.get('domain'):
                    self.submit({
                        'type': 'host_update',
                        'ip_address': ip,
                        'hostname': host_results.get('hostname'),
                        'domain': host_results.get('domain'),
                        'os_name': host_results.get('os'),
                        'os_fingerprint_method': 'smb'
                    })

                # Submit domain info
                if host_results.get('domain_info'):
                    self.submit({
                        'type': 'domain_info',
                        **host_results['domain_info']
                    })

                # Submit SMB shares
                for share in shares:
                    self.submit({
                        'type': 'smb_share',
                        'ip_address': ip,
                        'share_name': share['name'],
                        'share_type': share.get('type', ''),
                        'comment': share.get('comment', '')
                    })

                # Submit enumerated users as accounts
                for user in users:
                    self.submit({
                        'type': 'privileged_account',
                        'account_name': user['name'],
                        'account_type': 'user',
                        'domain': host_results.get('domain', ''),
                        'groups': [],
                        'is_admin': 0,
                        'notes': f"Enumerated via SMB on {ip}"
                    })

        self.progress(100, f"SMB enum complete: {enumerated_hosts} hosts, {total_shares} shares, {total_users} users")

        return {
            'hosts_enumerated': enumerated_hosts,
            'total_shares': total_shares,
            'total_users': total_users
        }

    def _enum4linux_ng(self, ip, username, password, domain):
        """Use enum4linux-ng for comprehensive enumeration."""
        results = {}
        auth = f"-u '{username}' -p '{password}'" if username else ''
        cmd = f"enum4linux-ng {auth} -A {ip} 2>/dev/null"
        rc, stdout, _ = self.run_command(cmd, timeout=120)

        if rc == 0 and stdout:
            results = self._parse_enum4linux_output(stdout)
        return results

    def _enum4linux(self, ip, username, password):
        """Use classic enum4linux."""
        results = {}
        auth = f"-u '{username}' -p '{password}'" if username else ''
        cmd = f"enum4linux {auth} -a {ip} 2>/dev/null"
        rc, stdout, _ = self.run_command(cmd, timeout=120)

        if rc == 0 and stdout:
            results = self._parse_enum4linux_output(stdout)
        return results

    def _manual_enum(self, ip, username, password, domain):
        """Manual SMB enumeration using smbclient and rpcclient."""
        results = {}

        # NetBIOS name
        if self.tool_available('nmblookup'):
            rc, stdout, _ = self.run_command(f"nmblookup -A {ip} 2>/dev/null", timeout=10)
            if rc == 0:
                name_match = re.search(r'^\s+(\S+)\s+<00>\s+-\s+', stdout, re.MULTILINE)
                if name_match:
                    results['hostname'] = name_match.group(1)

                domain_match = re.search(r'^\s+(\S+)\s+<1c>\s+-\s+<GROUP>', stdout, re.MULTILINE)
                if domain_match:
                    results['domain'] = domain_match.group(1)

        # Share enumeration
        if self.tool_available('smbclient'):
            auth_str = f"-U '{domain}\\{username}%{password}'" if username else "-N"
            cmd = f"smbclient -L //{ip} {auth_str} 2>/dev/null"
            rc, stdout, _ = self.run_command(cmd, timeout=15)

            if rc == 0 and stdout:
                shares = []
                for match in re.finditer(r'^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*?)$', stdout, re.MULTILINE):
                    shares.append({
                        'name': match.group(1),
                        'type': match.group(2),
                        'comment': match.group(3).strip()
                    })
                results['shares'] = shares

        # RPC user enumeration
        if self.tool_available('rpcclient'):
            auth_str = f"-U '{domain}\\{username}%{password}'" if username else "-N"
            cmd = f"rpcclient -c 'enumdomusers' {auth_str} {ip} 2>/dev/null"
            rc, stdout, _ = self.run_command(cmd, timeout=15)

            if rc == 0 and stdout:
                users = []
                for match in re.finditer(r'user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]', stdout):
                    users.append({'name': match.group(1), 'rid': match.group(2)})
                results['users'] = users

        return results

    def _parse_enum4linux_output(self, output):
        """Parse enum4linux output for relevant info."""
        results = {'shares': [], 'users': []}

        # Hostname
        name_match = re.search(r'NetBIOS computer name:\s*(\S+)', output)
        if name_match:
            results['hostname'] = name_match.group(1)

        # Domain
        domain_match = re.search(r'Domain Name:\s*(\S+)', output) or re.search(r'Workgroup/Domain:\s*(\S+)', output)
        if domain_match:
            results['domain'] = domain_match.group(1)

        # OS
        os_match = re.search(r'OS:\s*(.+?)(?:\n|$)', output)
        if os_match:
            results['os'] = os_match.group(1).strip()

        # Shares
        for match in re.finditer(r'^\s+(\S+)\s+(Disk|IPC|Printer)\s+(.*?)$', output, re.MULTILINE):
            results['shares'].append({
                'name': match.group(1),
                'type': match.group(2),
                'comment': match.group(3).strip()
            })

        # Users
        for match in re.finditer(r'user:\[([^\]]+)\]', output):
            results['users'].append({'name': match.group(1)})

        return results
