#!/usr/bin/env python3
"""
Host Profiler — deep host-level profiling via WinRM/WMI (Windows) and SSH (Linux).

Collects per-host baseline data:
  - Hostname, domain, OS (existing)
  - Installed software inventory
  - Running processes and services
  - Scheduled tasks
  - Local group memberships

Requires credentials to be provided in scan config.
"""
import re
import json
import logging
from modules.base_scanner import BaseScanner

logger = logging.getLogger('cpt-recon.profiler')

# Privileged group names for flagging
PRIVILEGED_GROUPS = {
    'administrators', 'domain admins', 'enterprise admins', 'schema admins',
    'account operators', 'backup operators', 'server operators', 'dnsadmins',
    'remote desktop users', 'hyper-v administrators', 'print operators',
}


class HostProfiler(BaseScanner):
    """Deep host profiling scanner — collects software, processes, tasks, groups."""

    def run(self):
        targets = self.parse_targets()
        if not targets:
            return {'error': 'No targets'}

        creds = self.config.get('credentials', {})
        # Which subsections to collect (all by default)
        sections = self.config.get('sections', [
            'identity', 'software', 'processes', 'tasks', 'groups'
        ])

        profiled = 0
        total = len(targets)

        for ti, ip in enumerate(targets):
            if self.is_stopped():
                break
            pct = int((ti / total) * 90)
            self.progress(pct, f"Profiling {ip} ({ti+1}/{total})")

            # Determine OS family and collect accordingly
            result = self._profile_windows(ip, creds, sections)
            if not result:
                result = self._profile_linux(ip, creds, sections)

            if result:
                profiled += 1

        self.progress(100, f"Profiled {profiled}/{total} hosts")
        return {'profiled': profiled, 'total': total}

    # ════════════════════════════════════════════════════════════════════
    # Windows profiling via crackmapexec/WinRM + PowerShell
    # ════════════════════════════════════════════════════════════════════

    def _profile_windows(self, ip, creds, sections):
        """Profile a Windows host using crackmapexec WinRM + PowerShell commands."""
        if not creds.get('username'):
            return None
        if not self.tool_available('crackmapexec'):
            return None

        u = creds.get('username', '')
        p = creds.get('password', '')
        d = creds.get('domain', '')
        domain_flag = f"-d '{d}'" if d else ''

        # Check WinRM access first
        check_cmd = f"crackmapexec winrm {ip} -u '{u}' -p '{p}' {domain_flag} --no-bruteforce 2>/dev/null"
        rc, out, _ = self.run_command(check_cmd, timeout=30)
        if rc != 0 or ('Pwn3d' not in out and '+' not in out):
            return None

        self.log_discovery(f"WinRM access confirmed on {ip}, starting deep profile", target_ip=ip)
        collected = False

        # ── Identity (hostname, domain, OS) ──
        if 'identity' in sections:
            self._win_collect_identity(ip, u, p, domain_flag)
            collected = True

        # ── Installed Software ──
        if 'software' in sections:
            if self._win_collect_software(ip, u, p, domain_flag):
                collected = True

        # ── Running Processes & Services ──
        if 'processes' in sections:
            if self._win_collect_processes(ip, u, p, domain_flag):
                collected = True

        # ── Scheduled Tasks ──
        if 'tasks' in sections:
            if self._win_collect_tasks(ip, u, p, domain_flag):
                collected = True

        # ── Local Groups ──
        if 'groups' in sections:
            if self._win_collect_groups(ip, u, p, domain_flag):
                collected = True

        return {'os_family': 'windows'} if collected else None

    def _cme_exec(self, ip, u, p, domain_flag, ps_command, timeout=45):
        """Execute a PowerShell command via crackmapexec WinRM and return output."""
        # Escape single quotes in PS command for shell
        escaped = ps_command.replace("'", "'\\''")
        cmd = f"crackmapexec winrm {ip} -u '{u}' -p '{p}' {domain_flag} -x '{escaped}' --no-bruteforce 2>/dev/null"
        rc, out, _ = self.run_command(cmd, timeout=timeout)
        if rc != 0:
            return None
        # crackmapexec prefixes output with hostname; strip control lines
        lines = []
        for line in out.split('\n'):
            # Skip CME status/banner lines
            if line.strip().startswith(('SMB', 'WINRM', '[*]', '[+]', '[-]')):
                continue
            lines.append(line)
        return '\n'.join(lines).strip()

    def _win_collect_identity(self, ip, u, p, domain_flag):
        """Collect hostname, domain, and OS info from Windows host."""
        smb_cmd = f"crackmapexec smb {ip} -u '{u}' -p '{p}' {domain_flag} 2>/dev/null"
        rc, out, _ = self.run_command(smb_cmd, timeout=15)
        if rc == 0:
            info = {}
            m = re.search(r'name:(\S+)', out)
            if m:
                info['hostname'] = m.group(1)
            m = re.search(r'domain:(\S+)', out)
            if m:
                info['domain'] = m.group(1)
            m = re.search(r'os:([^\)]+)', out) or re.search(r'Windows\s+\S+', out)
            if m:
                info['os_name'] = m.group(0) if not m.lastindex else m.group(1)
            if info:
                self.submit({'type': 'host_update', 'ip_address': ip, **info})

    def _win_collect_software(self, ip, u, p, domain_flag):
        """Collect installed software from Windows registry via PowerShell."""
        ps = (
            "Get-ItemProperty "
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
            "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "2>$null | Where-Object {$_.DisplayName} | "
            "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallSource | "
            "ConvertTo-Json -Compress"
        )
        out = self._cme_exec(ip, u, p, domain_flag, ps, timeout=60)
        if not out:
            return False

        try:
            items = json.loads(out)
            if isinstance(items, dict):
                items = [items]
        except (json.JSONDecodeError, TypeError):
            logger.debug(f"Failed to parse software JSON from {ip}")
            return False

        count = 0
        for item in items:
            name = item.get('DisplayName', '').strip()
            if not name:
                continue
            self.submit({
                'type': 'software',
                'ip_address': ip,
                'name': name,
                'version': (item.get('DisplayVersion') or '').strip(),
                'publisher': (item.get('Publisher') or '').strip(),
                'install_date': (item.get('InstallDate') or '').strip(),
                'install_source': 'registry',
                'architecture': 'x64',
            })
            count += 1

        if count:
            self.log_discovery(f"Collected {count} installed software entries from {ip}", target_ip=ip)
        return count > 0

    def _win_collect_processes(self, ip, u, p, domain_flag):
        """Collect running processes and Windows services."""
        collected = False

        # ── Processes ──
        ps_proc = (
            "Get-CimInstance Win32_Process 2>$null | "
            "Select-Object ProcessId,Name,ExecutablePath,CommandLine,"
            "ParentProcessId,@{N='User';E={(Invoke-CimMethod -InputObject $_ "
            "-MethodName GetOwner -ErrorAction SilentlyContinue).User}},"
            "@{N='WS';E={$_.WorkingSetSize}} | ConvertTo-Json -Compress"
        )
        out = self._cme_exec(ip, u, p, domain_flag, ps_proc, timeout=60)
        if out:
            try:
                procs = json.loads(out)
                if isinstance(procs, dict):
                    procs = [procs]
                for proc in procs:
                    name = proc.get('Name', '').strip()
                    if not name:
                        continue
                    self.submit({
                        'type': 'process',
                        'ip_address': ip,
                        'pid': proc.get('ProcessId'),
                        'name': name,
                        'exe_path': (proc.get('ExecutablePath') or '').strip(),
                        'command_line': (proc.get('CommandLine') or '').strip(),
                        'username': (proc.get('User') or '').strip(),
                        'parent_pid': proc.get('ParentProcessId'),
                        'is_service': 0,
                        'memory_bytes': proc.get('WS'),
                    })
                self.log_discovery(f"Collected {len(procs)} processes from {ip}", target_ip=ip)
                collected = True
            except (json.JSONDecodeError, TypeError):
                logger.debug(f"Failed to parse process JSON from {ip}")

        # ── Windows Services ──
        ps_svc = (
            "Get-CimInstance Win32_Service 2>$null | "
            "Select-Object ProcessId,Name,DisplayName,State,StartMode,"
            "PathName,StartName | ConvertTo-Json -Compress"
        )
        out = self._cme_exec(ip, u, p, domain_flag, ps_svc, timeout=60)
        if out:
            try:
                svcs = json.loads(out)
                if isinstance(svcs, dict):
                    svcs = [svcs]
                for svc in svcs:
                    name = svc.get('Name', '').strip()
                    if not name:
                        continue
                    self.submit({
                        'type': 'process',
                        'ip_address': ip,
                        'pid': svc.get('ProcessId'),
                        'name': name,
                        'exe_path': (svc.get('PathName') or '').strip(),
                        'username': (svc.get('StartName') or '').strip(),
                        'is_service': 1,
                        'service_name': name,
                        'service_display_name': (svc.get('DisplayName') or '').strip(),
                        'service_state': (svc.get('State') or '').strip().lower(),
                        'start_type': (svc.get('StartMode') or '').strip().lower(),
                    })
                self.log_discovery(f"Collected {len(svcs)} services from {ip}", target_ip=ip)
                collected = True
            except (json.JSONDecodeError, TypeError):
                logger.debug(f"Failed to parse services JSON from {ip}")

        return collected

    def _win_collect_tasks(self, ip, u, p, domain_flag):
        """Collect scheduled tasks from Windows."""
        ps = (
            "Get-ScheduledTask 2>$null | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | "
            "ForEach-Object { $info = Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue; "
            "[pscustomobject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath; "
            "State=$_.State.ToString(); Author=$_.Author; "
            "RunAs=$_.Principal.UserId; "
            "Command=($_.Actions | Select-Object -First 1).Execute; "
            "LastRun=if($info){$info.LastRunTime.ToString('o')}else{''}; "
            "NextRun=if($info){$info.NextRunTime.ToString('o')}else{''}; "
            "LastResult=if($info){$info.LastTaskResult}else{''} } } | "
            "ConvertTo-Json -Compress"
        )
        out = self._cme_exec(ip, u, p, domain_flag, ps, timeout=60)
        if not out:
            return False

        try:
            tasks = json.loads(out)
            if isinstance(tasks, dict):
                tasks = [tasks]
        except (json.JSONDecodeError, TypeError):
            logger.debug(f"Failed to parse scheduled tasks JSON from {ip}")
            return False

        count = 0
        for task in tasks:
            name = task.get('TaskName', '').strip()
            if not name:
                continue
            self.submit({
                'type': 'scheduled_task',
                'ip_address': ip,
                'task_name': name,
                'task_path': (task.get('TaskPath') or '').strip(),
                'status': (task.get('State') or '').strip(),
                'last_run': (task.get('LastRun') or '').strip(),
                'next_run': (task.get('NextRun') or '').strip(),
                'last_result': str(task.get('LastResult', '')).strip(),
                'author': (task.get('Author') or '').strip(),
                'run_as_user': (task.get('RunAs') or '').strip(),
                'command': (task.get('Command') or '').strip(),
                'source': 'schtasks',
            })
            count += 1

        if count:
            self.log_discovery(f"Collected {count} scheduled tasks from {ip}", target_ip=ip)
        return count > 0

    def _win_collect_groups(self, ip, u, p, domain_flag):
        """Collect local group memberships from Windows."""
        ps = (
            "Get-LocalGroup 2>$null | ForEach-Object { "
            "$members = (Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Name) -join '|'; "
            "[pscustomobject]@{ Name=$_.Name; Description=$_.Description; "
            "Members=$members } } | ConvertTo-Json -Compress"
        )
        out = self._cme_exec(ip, u, p, domain_flag, ps, timeout=45)
        if not out:
            return False

        try:
            groups = json.loads(out)
            if isinstance(groups, dict):
                groups = [groups]
        except (json.JSONDecodeError, TypeError):
            logger.debug(f"Failed to parse local groups JSON from {ip}")
            return False

        count = 0
        for grp in groups:
            name = grp.get('Name', '').strip()
            if not name:
                continue
            members_str = grp.get('Members', '')
            members = [m.strip() for m in members_str.split('|') if m.strip()] if members_str else []
            self.submit({
                'type': 'local_group',
                'ip_address': ip,
                'group_name': name,
                'group_type': 'local',
                'members': members,
                'description': (grp.get('Description') or '').strip(),
                'is_privileged': 1 if name.lower() in PRIVILEGED_GROUPS else 0,
            })
            count += 1

        if count:
            self.log_discovery(f"Collected {count} local groups from {ip}", target_ip=ip)
        return count > 0

    # ════════════════════════════════════════════════════════════════════
    # Linux profiling via SSH
    # ════════════════════════════════════════════════════════════════════

    def _profile_linux(self, ip, creds, sections):
        """Profile a Linux host using SSH commands."""
        if not creds.get('username') or not self.tool_available('sshpass'):
            return None

        u = creds.get('username', '')
        p = creds.get('password', '')

        # Test SSH access
        test_out = self._ssh_exec(ip, u, p, 'echo OK', timeout=10)
        if test_out is None or 'OK' not in test_out:
            return None

        self.log_discovery(f"SSH access confirmed on {ip}, starting deep profile", target_ip=ip)
        collected = False

        if 'identity' in sections:
            self._linux_collect_identity(ip, u, p)
            collected = True

        if 'software' in sections:
            if self._linux_collect_software(ip, u, p):
                collected = True

        if 'processes' in sections:
            if self._linux_collect_processes(ip, u, p):
                collected = True

        if 'tasks' in sections:
            if self._linux_collect_tasks(ip, u, p):
                collected = True

        if 'groups' in sections:
            if self._linux_collect_groups(ip, u, p):
                collected = True

        return {'os_family': 'linux'} if collected else None

    def _ssh_exec(self, ip, u, p, command, timeout=30):
        """Execute a command via SSH and return stdout."""
        escaped = command.replace("'", "'\\''")
        cmd = (
            f"sshpass -p '{p}' ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=5 -o BatchMode=no {u}@{ip} '{escaped}' 2>/dev/null"
        )
        rc, out, _ = self.run_command(cmd, timeout=timeout)
        if rc != 0:
            return None
        return out.strip()

    def _linux_collect_identity(self, ip, u, p):
        """Collect hostname and OS from Linux host."""
        out = self._ssh_exec(ip, u, p, 'hostname; uname -a; cat /etc/os-release 2>/dev/null')
        if not out:
            return
        info = {}
        lines = out.split('\n')
        if lines:
            info['hostname'] = lines[0].strip()
        if len(lines) > 1:
            info['os_name'] = 'Linux'
        for line in lines:
            if line.startswith('PRETTY_NAME='):
                info['os_name'] = line.split('=', 1)[1].strip('"')
            elif line.startswith('VERSION_ID='):
                info['os_version'] = line.split('=', 1)[1].strip('"')
        if info:
            self.submit({'type': 'host_update', 'ip_address': ip, **info})

    def _linux_collect_software(self, ip, u, p):
        """Collect installed packages from Linux (dpkg or rpm)."""
        # Try dpkg first (Debian/Ubuntu), then rpm (RHEL/CentOS)
        out = self._ssh_exec(
            ip, u, p,
            "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n' 2>/dev/null || "
            "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n' 2>/dev/null",
            timeout=30
        )
        if not out:
            return False

        count = 0
        source = 'dpkg' if '\t' in out.split('\n')[0] else 'rpm'
        for line in out.split('\n'):
            parts = line.strip().split('\t')
            if len(parts) < 2 or not parts[0]:
                continue
            self.submit({
                'type': 'software',
                'ip_address': ip,
                'name': parts[0],
                'version': parts[1] if len(parts) > 1 else '',
                'publisher': '',
                'install_date': '',
                'install_source': source,
                'architecture': parts[2] if len(parts) > 2 else '',
            })
            count += 1

        if count:
            self.log_discovery(f"Collected {count} packages from {ip} ({source})", target_ip=ip)
        return count > 0

    def _linux_collect_processes(self, ip, u, p):
        """Collect running processes and systemd services from Linux."""
        collected = False

        # ── Processes via ps ──
        out = self._ssh_exec(
            ip, u, p,
            "ps axo pid,ppid,user,rss,comm,args --no-headers 2>/dev/null",
            timeout=20
        )
        if out:
            count = 0
            for line in out.split('\n'):
                parts = line.split(None, 5)
                if len(parts) < 5:
                    continue
                pid_str, ppid_str, user, rss_str, name = parts[0], parts[1], parts[2], parts[3], parts[4]
                cmdline = parts[5] if len(parts) > 5 else name
                try:
                    pid = int(pid_str)
                    ppid = int(ppid_str)
                    rss = int(rss_str) * 1024  # KB to bytes
                except ValueError:
                    continue
                self.submit({
                    'type': 'process',
                    'ip_address': ip,
                    'pid': pid,
                    'name': name.strip(),
                    'exe_path': '',
                    'command_line': cmdline.strip(),
                    'username': user.strip(),
                    'parent_pid': ppid,
                    'is_service': 0,
                    'memory_bytes': rss,
                })
                count += 1
            if count:
                self.log_discovery(f"Collected {count} processes from {ip}", target_ip=ip)
                collected = True

        # ── Systemd services ──
        out = self._ssh_exec(
            ip, u, p,
            "systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null",
            timeout=20
        )
        if out:
            count = 0
            for line in out.split('\n'):
                parts = line.split(None, 4)
                if len(parts) < 4:
                    continue
                unit = parts[0].strip()
                # load, active, sub states
                state = parts[2].strip() if len(parts) > 2 else ''
                sub = parts[3].strip() if len(parts) > 3 else ''
                desc = parts[4].strip() if len(parts) > 4 else ''
                svc_name = unit.replace('.service', '')
                self.submit({
                    'type': 'process',
                    'ip_address': ip,
                    'name': svc_name,
                    'is_service': 1,
                    'service_name': unit,
                    'service_display_name': desc,
                    'service_state': sub,  # running, exited, dead, etc.
                    'start_type': state,   # active, inactive
                })
                count += 1
            if count:
                self.log_discovery(f"Collected {count} systemd services from {ip}", target_ip=ip)
                collected = True

        return collected

    def _linux_collect_tasks(self, ip, u, p):
        """Collect cron jobs and systemd timers from Linux."""
        collected = False

        # ── User crontab ──
        out = self._ssh_exec(ip, u, p, "crontab -l 2>/dev/null", timeout=10)
        if out:
            count = 0
            for line in out.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Parse cron: min hour dom mon dow command
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                schedule = ' '.join(parts[:5])
                command = parts[5]
                self.submit({
                    'type': 'scheduled_task',
                    'ip_address': ip,
                    'task_name': command.split()[0].split('/')[-1],
                    'task_path': '',
                    'status': 'active',
                    'run_as_user': u,
                    'command': command,
                    'trigger_info': schedule,
                    'source': 'cron',
                })
                count += 1
            if count:
                self.log_discovery(f"Collected {count} cron jobs from {ip}", target_ip=ip)
                collected = True

        # ── System cron ──
        out = self._ssh_exec(
            ip, u, p,
            "cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/*; do echo \"## $f\"; cat $f 2>/dev/null; done",
            timeout=15
        )
        if out:
            count = 0
            current_file = '/etc/crontab'
            for line in out.split('\n'):
                line = line.strip()
                if line.startswith('## '):
                    current_file = line[3:]
                    continue
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 6)
                if len(parts) < 7:
                    continue
                schedule = ' '.join(parts[:5])
                run_user = parts[5]
                command = parts[6]
                self.submit({
                    'type': 'scheduled_task',
                    'ip_address': ip,
                    'task_name': command.split()[0].split('/')[-1],
                    'task_path': current_file,
                    'status': 'active',
                    'run_as_user': run_user,
                    'command': command,
                    'trigger_info': schedule,
                    'source': 'cron',
                })
                count += 1
            if count:
                self.log_discovery(f"Collected {count} system cron entries from {ip}", target_ip=ip)
                collected = True

        # ── Systemd timers ──
        out = self._ssh_exec(
            ip, u, p,
            "systemctl list-timers --all --no-pager --no-legend 2>/dev/null",
            timeout=15
        )
        if out:
            count = 0
            for line in out.split('\n'):
                parts = line.split(None, 5)
                if len(parts) < 2:
                    continue
                # Last column is the unit name
                unit = parts[-1].strip() if parts else ''
                if not unit.endswith('.timer'):
                    continue
                self.submit({
                    'type': 'scheduled_task',
                    'ip_address': ip,
                    'task_name': unit.replace('.timer', ''),
                    'task_path': '',
                    'status': 'active',
                    'command': unit,
                    'source': 'systemd-timer',
                })
                count += 1
            if count:
                self.log_discovery(f"Collected {count} systemd timers from {ip}", target_ip=ip)
                collected = True

        return collected

    def _linux_collect_groups(self, ip, u, p):
        """Collect local groups from Linux /etc/group."""
        out = self._ssh_exec(ip, u, p, "cat /etc/group 2>/dev/null", timeout=10)
        if not out:
            return False

        linux_priv_groups = {
            'root', 'sudo', 'wheel', 'adm', 'shadow', 'docker', 'lxd',
        }

        count = 0
        for line in out.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 4:
                continue
            group_name = parts[0]
            members = [m.strip() for m in parts[3].split(',') if m.strip()]
            self.submit({
                'type': 'local_group',
                'ip_address': ip,
                'group_name': group_name,
                'group_type': 'local',
                'members': members,
                'description': '',
                'is_privileged': 1 if group_name.lower() in linux_priv_groups else 0,
            })
            count += 1

        if count:
            self.log_discovery(f"Collected {count} local groups from {ip}", target_ip=ip)
        return count > 0
