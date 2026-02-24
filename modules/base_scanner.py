#!/usr/bin/env python3
"""
Base scanner class — all enumeration modules inherit from this.
Provides common utilities for result submission, progress reporting, and target parsing.
"""

import ipaddress
import logging
import platform
import subprocess
import shutil

logger = logging.getLogger('cpt-recon.scanner')

IS_WINDOWS = platform.system().lower() == 'windows'


class BaseScanner:
    """Base class for all scanner modules."""

    def __init__(self, engine, scan_id, mission_id, target, config, stop_flag):
        self.engine = engine
        self.scan_id = scan_id
        self.mission_id = mission_id
        self.target = target
        self.config = config
        self.stop_flag = stop_flag
        self.results_summary = {}

    def run(self):
        """Override in subclass. Must return results summary dict."""
        raise NotImplementedError

    def is_stopped(self):
        """Check if scan has been cancelled."""
        return self.stop_flag.is_set()

    def progress(self, pct, message=''):
        """Report progress to UI."""
        self.engine.report_progress(self.scan_id, self.mission_id, pct, message)

    # ─── Activity logging (ROE compliance) ───

    def log(self, message, severity='INFO', category='general', **kwargs):
        """Log a scan action for operator accountability.
        All keyword args forwarded to engine.log_action()."""
        self.engine.log_action(
            self.scan_id, self.mission_id, message,
            severity=severity, category=category, **kwargs
        )

    def log_send(self, target_ip, target_port, protocol, message, tool=None, command=None, **kwargs):
        """Log an outbound network action (packet/probe sent to target)."""
        self.log(message, severity='SEND', category='network_send',
                 target_ip=target_ip, target_port=target_port,
                 protocol=protocol, tool=tool, command=command, **kwargs)

    def log_recv(self, target_ip, message, target_port=None, protocol=None, **kwargs):
        """Log a response received from a target."""
        self.log(message, severity='RECV', category='network_recv',
                 target_ip=target_ip, target_port=target_port,
                 protocol=protocol, **kwargs)

    def log_discovery(self, message, target_ip=None, **kwargs):
        """Log a discovery event (host found, service identified, etc.)."""
        self.log(message, severity='INFO', category='discovery',
                 target_ip=target_ip, **kwargs)

    def log_tool(self, tool, command, message, **kwargs):
        """Log an external tool execution."""
        self.log(message, severity='ACTION', category='tool_exec',
                 tool=tool, command=command, **kwargs)

    def submit(self, result):
        """Submit a discovery result for DB ingestion."""
        result['mission_id'] = self.mission_id
        self.engine.submit_result(result)

    def submit_host(self, ip, **kwargs):
        """Convenience method to submit a discovered host."""
        self.submit({
            'type': 'host',
            'ip_address': ip,
            **kwargs
        })
        via = kwargs.get('discovered_via', 'scan')
        self.log_discovery(f"Host discovered: {ip}" +
                          (f" (MAC: {kwargs['mac_address']})" if kwargs.get('mac_address') else '') +
                          (f" — {kwargs['hostname']}" if kwargs.get('hostname') else '') +
                          (f" [{kwargs['os_name']}]" if kwargs.get('os_name') else '') +
                          (f" via {via}" if via else ''),
                          target_ip=ip)

    def submit_service(self, ip, port, protocol='tcp', **kwargs):
        """Convenience method to submit a discovered service."""
        self.submit({
            'type': 'service',
            'ip_address': ip,
            'port': port,
            'protocol': protocol,
            **kwargs
        })
        svc = kwargs.get('service_name', 'unknown')
        ver = kwargs.get('service_version', '')
        ot_label = f" [OT: {kwargs['ot_protocol_name']}]" if kwargs.get('ot_protocol_name') else ''
        self.log_discovery(
            f"Service found: {ip}:{port}/{protocol} — {svc} {ver}{ot_label}".strip(),
            target_ip=ip, target_port=port, protocol=protocol
        )

    def submit_subnet(self, cidr, **kwargs):
        """Convenience method to submit a discovered subnet."""
        self.submit({
            'type': 'subnet',
            'cidr': cidr,
            **kwargs
        })

    def submit_connection(self, src_ip, dst_ip, dst_port, protocol='tcp', **kwargs):
        """Convenience method to submit a discovered connection."""
        self.submit({
            'type': 'connection',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': protocol,
            **kwargs
        })

    # ─── Target parsing ───

    def parse_targets(self):
        """Parse target string into list of IP addresses.
        Supports: single IP, CIDR, range (10.0.0.1-254), comma-separated.
        """
        targets = []
        if not self.target:
            return targets

        for part in self.target.split(','):
            part = part.strip()
            if not part:
                continue
            try:
                if '/' in part:
                    # CIDR notation
                    network = ipaddress.ip_network(part, strict=False)
                    targets.extend([str(ip) for ip in network.hosts()])
                elif '-' in part and '.' in part:
                    # Range: 10.0.0.1-254 or 10.0.0.1-10.0.0.254
                    self._parse_range(part, targets)
                else:
                    # Single IP
                    ipaddress.ip_address(part)
                    targets.append(part)
            except ValueError as e:
                logger.warning(f"Invalid target '{part}': {e}")

        return targets

    def _parse_range(self, range_str, targets):
        """Parse IP range like 10.0.0.1-254 or 10.0.0.1-10.0.0.254"""
        parts = range_str.split('-')
        if len(parts) != 2:
            return

        start_str = parts[0].strip()
        end_str = parts[1].strip()

        if '.' in end_str:
            # Full IP range
            start = int(ipaddress.ip_address(start_str))
            end = int(ipaddress.ip_address(end_str))
        else:
            # Short range: 10.0.0.1-254
            start = int(ipaddress.ip_address(start_str))
            prefix = start_str.rsplit('.', 1)[0]
            end = int(ipaddress.ip_address(f"{prefix}.{end_str}"))

        for ip_int in range(start, end + 1):
            targets.append(str(ipaddress.ip_address(ip_int)))

    def infer_subnets(self, ip_list):
        """Infer /24 subnets from a list of IPs and auto-submit them."""
        seen = set()
        for ip in ip_list:
            try:
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
                cidr = str(network)
                if cidr not in seen:
                    seen.add(cidr)
                    self.submit_subnet(cidr, discovered_via='inferred')
            except Exception:
                pass

    # ─── Tool availability ───

    @staticmethod
    def tool_available(name):
        """Check if an external tool is available on PATH."""
        return shutil.which(name) is not None

    def run_command(self, cmd, timeout=300, log_output=False):
        """Run a shell command and return (returncode, stdout, stderr).
        Automatically logs the execution for ROE compliance.
        Cross-platform: strips Linux shell redirects on Windows."""
        # Platform fixups
        if IS_WINDOWS:
            cmd = cmd.replace(' 2>/dev/null', '').replace(' 2>&1', '')

        # Extract tool name from command
        tool_name = cmd.split()[0] if cmd else 'unknown'
        # Extract target IPs from command for logging context
        import re
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', cmd)
        target_ip = ip_match.group(1) if ip_match else None

        self.log_tool(tool_name, cmd,
                      f"Executing: {tool_name}" +
                      (f" against {target_ip}" if target_ip else ''),
                      target_ip=target_ip)

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0 and result.stderr:
                self.log(f"Tool returned error (rc={result.returncode}): {result.stderr[:200]}",
                        severity='WARN', category='tool_exec', tool=tool_name)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.log(f"Tool timed out after {timeout}s: {tool_name}",
                    severity='WARN', category='tool_exec', tool=tool_name)
            return -1, '', 'Command timed out'
        except Exception as e:
            self.log(f"Tool execution failed: {e}",
                    severity='ERROR', category='tool_exec', tool=tool_name)
            return -1, '', str(e)

    @staticmethod
    def run_command_static(cmd, timeout=300):
        """Static version of run_command for use outside scanner context."""
        if IS_WINDOWS:
            cmd = cmd.replace(' 2>/dev/null', '').replace(' 2>&1', '')
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, '', 'Command timed out'
        except Exception as e:
            return -1, '', str(e)

    @staticmethod
    def ping_cmd(ip, count=1, timeout_sec=1):
        """Return platform-appropriate ping command."""
        if IS_WINDOWS:
            return f'ping -n {count} -w {timeout_sec * 1000} {ip}'
        else:
            return f'ping -c {count} -W {timeout_sec} {ip} 2>/dev/null'

    # ─── OT Protocol helpers ───

    OT_PORT_MAP = {
        102: ('s7comm', 'Siemens S7'),
        502: ('modbus', 'Modbus/TCP'),
        20000: ('dnp3', 'DNP3'),
        44818: ('ethernetip', 'EtherNet/IP'),
        2222: ('ethernetip', 'EtherNet/IP (implicit)'),
        4840: ('opcua', 'OPC UA'),
        47808: ('bacnet', 'BACnet'),
        1911: ('fox', 'Niagara Fox'),
        9600: ('omron', 'OMRON FINS'),
        18245: ('gryphon', 'GE SRTP'),
        789: ('crimson', 'Red Lion Crimson'),
    }

    @classmethod
    def is_ot_port(cls, port):
        """Check if a port is associated with an OT/ICS protocol."""
        return port in cls.OT_PORT_MAP

    @classmethod
    def get_ot_info(cls, port):
        """Get OT protocol info for a port. Returns (protocol_name, display_name) or None."""
        return cls.OT_PORT_MAP.get(port)

    # ─── Device type inference ───

    @staticmethod
    def infer_device_type(services=None, os_name=None, hostname=None):
        """Attempt to infer device type from available data."""
        hostname = (hostname or '').lower()
        os_name = (os_name or '').lower()
        ports = set(services or [])

        # OT device inference
        if ports & {102, 502, 20000, 44818}:
            if 80 in ports or 443 in ports:
                return 'hmi'
            return 'plc'
        if ports & {4840, 47808}:
            return 'hmi'

        # Network infrastructure
        if any(kw in hostname for kw in ['fw', 'firewall', 'palo', 'asa', 'fortigate']):
            return 'firewall'
        if any(kw in hostname for kw in ['rtr', 'router', 'gw-']):
            return 'router'
        if any(kw in hostname for kw in ['sw-', 'switch']):
            return 'switch'

        # Domain controllers
        if 88 in ports and 389 in ports and 636 in ports:
            return 'dc'
        if any(kw in hostname for kw in ['dc0', 'dc-', 'dc1', 'dc2']):
            return 'dc'

        # Servers
        if 'server' in os_name:
            return 'server'

        # Printers
        if 9100 in ports or 'print' in hostname:
            return 'printer'

        # Workstations
        if 'windows' in os_name and 'server' not in os_name:
            return 'workstation'

        if ports:
            return 'server'

        return 'unknown'

    @staticmethod
    def infer_criticality(device_type, services=None):
        """Infer criticality based on device type and services."""
        critical_types = {'dc', 'firewall', 'plc', 'rtu', 'scada'}
        high_types = {'server', 'hmi', 'router'}

        if device_type in critical_types:
            return 'critical'
        if device_type in high_types:
            return 'high'

        # Check for critical services
        critical_ports = {88, 389, 636, 53, 102, 502, 20000, 44818}
        if services and set(services) & critical_ports:
            return 'high'

        return 'medium'
