#!/usr/bin/env python3
"""Host Profiler - deep profiling via WMI/WinRM/SSH for individual hosts."""
import re, json, logging
from modules.base_scanner import BaseScanner
logger = logging.getLogger('cpt-recon.profiler')

class HostProfiler(BaseScanner):
    def run(self):
        targets = self.parse_targets()
        if not targets: return {'error':'No targets'}
        creds = self.config.get('credentials', {})
        profiled = 0
        for ti, ip in enumerate(targets):
            if self.is_stopped(): break
            self.progress(int((ti/len(targets))*90), f"Profiling {ip}")
            # Try WinRM first, then SSH
            result = self._profile_winrm(ip, creds) or self._profile_ssh(ip, creds)
            if result:
                profiled += 1
                self.submit({'type':'host_update','ip_address':ip, **result})
        self.progress(100, f"Profiled {profiled}/{len(targets)} hosts")
        return {'profiled': profiled}

    def _profile_winrm(self, ip, creds):
        if not creds.get('username'): return None
        # Use crackmapexec or evil-winrm if available
        if not self.tool_available('crackmapexec'): return None
        u, p, d = creds.get('username',''), creds.get('password',''), creds.get('domain','')
        cmd = f"crackmapexec winrm {ip} -u '{u}' -p '{p}' {'-d '+d if d else ''} --no-bruteforce 2>/dev/null"
        rc, out, _ = self.run_command(cmd, timeout=30)
        if rc == 0 and ('Pwn3d' in out or '+' in out):
            info = {}
            # Get hostname
            rc2, out2, _ = self.run_command(
                f"crackmapexec smb {ip} -u '{u}' -p '{p}' {'-d '+d if d else ''} 2>/dev/null", timeout=15)
            if rc2 == 0:
                m = re.search(r'name:(\S+)', out2)
                if m: info['hostname'] = m.group(1)
                m = re.search(r'domain:(\S+)', out2)
                if m: info['domain'] = m.group(1)
            return info if info else None
        return None

    def _profile_ssh(self, ip, creds):
        if not creds.get('username') or not self.tool_available('sshpass'): return None
        u, p = creds.get('username',''), creds.get('password','')
        info = {}
        rc, out, _ = self.run_command(
            f"sshpass -p '{p}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {u}@{ip} 'hostname; uname -a; cat /etc/os-release 2>/dev/null' 2>/dev/null",
            timeout=15)
        if rc == 0 and out:
            lines = out.strip().split('\n')
            if lines: info['hostname'] = lines[0].strip()
            if len(lines) > 1: info['os_name'] = 'Linux'
            for line in lines:
                if line.startswith('PRETTY_NAME='):
                    info['os_name'] = line.split('=',1)[1].strip('"')
            return info
        return None
