#!/usr/bin/env python3
"""
Service Scanner Module
Service version detection using nmap -sV as the primary method.
Falls back to socket-based banner grabbing when nmap is unavailable.
"""

import re
import socket
import ssl
import logging
from modules.base_scanner import BaseScanner

logger = logging.getLogger('blue-reccoon.service')

# Protocol probes — bytes to send to elicit a response (used in socket fallback)
PROBES = {
    'http': b'GET / HTTP/1.0\r\nHost: target\r\n\r\n',
    'https': b'GET / HTTP/1.0\r\nHost: target\r\n\r\n',
    'ssh': b'',  # SSH sends banner first
    'ftp': b'',  # FTP sends banner first
    'smtp': b'',  # SMTP sends banner first
    'pop3': b'',  # POP3 sends banner first
    'imap': b'',  # IMAP sends banner first
    'rdp': b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00',
    'mysql': b'',
    'mssql': b'',
    'smb': b'\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40',
    'telnet': b'',
    'modbus': b'\x00\x01\x00\x00\x00\x05\x01\x03\x00\x00\x00\x01',  # Read holding register
    'dnp3': b'\x05\x64\x05\xc0\x01\x00\x00\x04\xe9\x21',  # DNP3 link layer
    's7comm': b'\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02',
    'bacnet': b'\x81\x04\x00\x19\x01\x00\x30\x01\x0c\x0c\x02\x3f\xff\xff\x19\x4b',
}

# Port to protocol hints
PORT_HINTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 88: 'kerberos', 102: 's7comm', 110: 'pop3', 111: 'rpc',
    135: 'msrpc', 139: 'netbios', 143: 'imap', 161: 'snmp', 389: 'ldap',
    443: 'https', 445: 'smb', 465: 'smtps', 502: 'modbus', 587: 'smtp',
    636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
    2222: 'ethernetip', 3306: 'mysql', 3389: 'rdp', 4840: 'opcua',
    5432: 'postgres', 5900: 'vnc', 5985: 'winrm', 5986: 'winrm',
    6379: 'redis', 8080: 'http', 8443: 'https', 9200: 'elasticsearch',
    9600: 'omron', 20000: 'dnp3', 27017: 'mongodb', 44818: 'ethernetip',
    47808: 'bacnet',
}


class ServiceScanner(BaseScanner):
    """Service version detection using nmap -sV with socket-based fallback."""

    def run(self):
        targets = self.parse_targets()
        if not targets:
            return {'error': 'No valid targets specified'}

        use_nmap = self.tool_available('nmap')
        method_desc = ("nmap -sV (service version probing)" if use_nmap
                       else "TCP connect banner grabbing (socket)")

        self.log(f"Service detection scan initiated on {len(targets)} hosts. "
                 f"Method: {method_desc}. "
                 f"Probes open ports discovered by Port Scan to identify running services. "
                 f"Updates service name, version, and banner fields for each port. "
                 f"All operations are read-only.",
                 severity='ACTION', category='config',
                 raw_detail=f"Targets: {self.target}")

        if use_nmap:
            return self._nmap_service_scan(targets)
        else:
            return self._socket_service_scan(targets)

    # ─── Primary method: nmap -sV ───

    def _nmap_service_scan(self, targets):
        """Use nmap -sV for service version detection."""
        db = self.engine._get_db()

        # Collect per-host port lists from the database
        host_ports = {}
        for ip in targets:
            host = db.execute(
                "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
                (self.mission_id, ip)
            ).fetchone()

            if host:
                services = db.execute(
                    "SELECT port FROM services WHERE host_id = ? "
                    "AND state = 'open' AND protocol = 'tcp'",
                    (host['id'],)
                ).fetchall()
                if services:
                    host_ports[ip] = [s['port'] for s in services]
                else:
                    host_ports[ip] = [22, 80, 443, 445, 3389]
            else:
                host_ports[ip] = [22, 80, 443, 445, 3389]

        db.close()

        total_services = 0
        total_detected = 0

        # Process targets in chunks
        chunk_size = 16
        ip_list = list(host_ports.keys())
        chunks = [ip_list[i:i + chunk_size] for i in range(0, len(ip_list), chunk_size)]

        for ci, chunk in enumerate(chunks):
            if self.is_stopped():
                break

            pct = int((ci / len(chunks)) * 90)
            self.progress(pct, f"Nmap service scan: chunk {ci + 1}/{len(chunks)}")

            # Collect all unique ports across this chunk
            all_ports = set()
            for ip in chunk:
                all_ports.update(host_ports[ip])
            port_str = ','.join(str(p) for p in sorted(all_ports))
            target_str = ' '.join(chunk)

            self.log_send(
                chunk[0], None, 'tcp',
                f"nmap -sV service probe: {len(chunk)} hosts, "
                f"{len(all_ports)} ports ({port_str})",
                tool='nmap',
                command=f"nmap -sV -T3 -p {port_str} {target_str}"
            )

            cmd = (
                f"nmap -sV -T3 "
                f"-p {port_str} "
                f"--version-intensity 5 "
                f"-oX - {target_str} 2>/dev/null"
            )
            nmap_timeout = max(180, len(chunk) * 30 + len(all_ports) * 2)
            rc, stdout, stderr = self.run_command(cmd, timeout=nmap_timeout)

            if rc == 0 and stdout:
                chunk_services, chunk_detected = self._parse_nmap_sv_output(stdout)
                total_services += chunk_services
                total_detected += chunk_detected

        self.progress(100, f"Service detection complete: {total_detected} services identified")
        return {
            'services_probed': total_services,
            'banners_grabbed': total_detected
        }

    def _parse_nmap_sv_output(self, xml_output):
        """Parse nmap -sV XML output for service version info."""
        total_services = 0
        total_detected = 0

        host_blocks = re.findall(r'<host\b.*?</host>', xml_output, re.DOTALL)

        for block in host_blocks:
            if 'state="up"' not in block:
                continue

            ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            port_blocks = re.findall(
                r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>',
                block, re.DOTALL
            )

            for proto, portid, port_content in port_blocks:
                state_match = re.search(r'<state state="(\w+)"', port_content)
                state = state_match.group(1) if state_match else 'unknown'

                if state != 'open':
                    continue

                port = int(portid)
                total_services += 1

                result = {'state': 'open'}

                # Extract service attributes from nmap XML
                svc_match = re.search(r'<service\s+([^>]*?)/?>', port_content)
                if svc_match:
                    svc_attrs = svc_match.group(1)
                    name = re.search(r'name="([^"]*)"', svc_attrs)
                    product = re.search(r'product="([^"]*)"', svc_attrs)
                    version = re.search(r'version="([^"]*)"', svc_attrs)
                    extrainfo = re.search(r'extrainfo="([^"]*)"', svc_attrs)
                    tunnel = re.search(r'tunnel="([^"]*)"', svc_attrs)

                    svc_name = name.group(1) if name else None
                    svc_product = product.group(1) if product else None
                    svc_version = version.group(1) if version else None
                    svc_extra = extrainfo.group(1) if extrainfo else None
                    svc_tunnel = tunnel.group(1) if tunnel else None

                    # Build version string: "product version (extrainfo)"
                    version_parts = []
                    if svc_product:
                        version_parts.append(svc_product)
                    if svc_version:
                        version_parts.append(svc_version)
                    if svc_extra:
                        version_parts.append(f"({svc_extra})")
                    version_str = ' '.join(version_parts) if version_parts else None

                    # Use tunnel-aware service name (e.g. "ssl/http" → "https")
                    if svc_tunnel == 'ssl' and svc_name == 'http':
                        result['service_name'] = 'https'
                    else:
                        result['service_name'] = svc_name

                    result['service_version'] = version_str

                    # Build banner from available info
                    banner_parts = [p for p in [svc_product, svc_version, svc_extra] if p]
                    result['banner'] = ' '.join(banner_parts) if banner_parts else svc_name

                    if svc_name or version_str:
                        total_detected += 1

                # Check for OT protocol
                ot_info = self.get_ot_info(port)
                if ot_info:
                    result['is_ot_protocol'] = 1
                    result['ot_protocol_name'] = ot_info[0]
                    if not result.get('service_name'):
                        result['service_name'] = ot_info[1]

                self.submit_service(ip, port, proto, **result)

        return total_services, total_detected

    # ─── Fallback: socket-based banner grabbing ───

    def _socket_service_scan(self, targets):
        """Fallback method: socket-based banner grabbing when nmap is unavailable."""
        db = self.engine._get_db()
        total_services = 0
        total_banners = 0

        for ti, ip in enumerate(targets):
            if self.is_stopped():
                break

            pct = int((ti / len(targets)) * 90)
            self.progress(pct, f"Probing services on {ip}")

            host = db.execute(
                "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
                (self.mission_id, ip)
            ).fetchone()

            if not host:
                continue

            services = db.execute(
                "SELECT port, protocol FROM services WHERE host_id = ? AND state = 'open'",
                (host['id'],)
            ).fetchall()

            if not services:
                # If no services known yet, try common ports
                services = [{'port': p, 'protocol': 'tcp'} for p in [22, 80, 443, 445, 3389]]

            for svc in services:
                if self.is_stopped():
                    break

                port = svc['port']
                proto = svc['protocol']

                if proto == 'udp':
                    continue  # Skip UDP for banner grabbing

                result = self._grab_banner(ip, port)
                if result:
                    total_banners += 1
                    self.submit_service(
                        ip, port, proto,
                        **result
                    )

                total_services += 1

        db.close()

        self.progress(100, f"Service detection complete: {total_banners} banners grabbed")
        return {
            'services_probed': total_services,
            'banners_grabbed': total_banners
        }

    def _grab_banner(self, ip, port, timeout=3):
        """Grab banner from a service. Returns dict with service info or None."""
        protocol_hint = PORT_HINTS.get(port, 'unknown')
        use_ssl = port in (443, 636, 993, 995, 8443, 5986) or protocol_hint in ('https', 'ldaps', 'imaps', 'pop3s')

        probe_desc = 'wait for server banner'
        if protocol_hint in ('http', 'https'):
            probe_desc = 'HTTP GET / request'
        elif protocol_hint == 'rdp':
            probe_desc = 'RDP X.224 Connection Request'
        elif protocol_hint == 'smb':
            probe_desc = 'SMB Negotiate Protocol'
        elif protocol_hint in ('modbus', 's7comm', 'dnp3', 'ethernetip', 'bacnet'):
            probe_desc = f'{protocol_hint} identification probe (read-only)'

        self.log_send(ip, port, 'tcp',
                     f"Banner grab: {ip}:{port} — "
                     f"{'TLS handshake + ' if use_ssl else ''}{probe_desc}",
                     tool='socket')

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)

                # Extract cert info
                cert = sock.getpeercert(binary_form=False)
                cert_info = self._parse_cert(cert) if cert else {}

            # Send probe if we have one
            probe = PROBES.get(protocol_hint, b'')
            if probe:
                sock.sendall(probe)

            # Receive response
            banner_raw = b''
            try:
                banner_raw = sock.recv(4096)
            except socket.timeout:
                pass

            sock.close()

            if not banner_raw and not use_ssl:
                return None

            banner = banner_raw.decode('utf-8', errors='replace').strip()
            result = self._identify_service(port, protocol_hint, banner, banner_raw)

            if use_ssl and 'cert_info' in dir():
                result['banner'] = (result.get('banner', '') + f" | TLS cert: {cert_info.get('subject', '')}").strip()

            return result

        except ConnectionRefusedError:
            return {'state': 'closed'}
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"Banner grab failed {ip}:{port}: {e}")
            return None

    def _identify_service(self, port, hint, banner, raw_bytes):
        """Identify service from banner response."""
        result = {
            'state': 'open',
            'banner': banner[:500] if banner else None,
        }

        # SSH
        if banner.startswith('SSH-'):
            match = re.match(r'SSH-[\d.]+-(.+)', banner)
            result['service_name'] = 'ssh'
            result['service_version'] = match.group(1) if match else None
            return result

        # HTTP
        if banner.startswith('HTTP/') or 'HTTP/' in banner[:100]:
            server_match = re.search(r'Server:\s*(.+?)[\r\n]', banner, re.IGNORECASE)
            result['service_name'] = 'https' if port == 443 else 'http'
            result['service_version'] = server_match.group(1).strip() if server_match else None
            return result

        # FTP
        if re.match(r'2[12]\d\s', banner):
            result['service_name'] = 'ftp'
            result['service_version'] = banner.split('\n')[0][:100]
            return result

        # SMTP
        if banner.startswith('220 '):
            result['service_name'] = 'smtp'
            result['service_version'] = banner.split('\n')[0][4:].strip()[:100]
            return result

        # MySQL
        if raw_bytes and len(raw_bytes) > 4 and raw_bytes[4] == 10:  # Protocol v10
            version_end = raw_bytes.find(b'\x00', 5)
            if version_end > 5:
                result['service_name'] = 'mysql'
                result['service_version'] = raw_bytes[5:version_end].decode('utf-8', errors='replace')
                return result

        # RDP
        if raw_bytes and raw_bytes[:2] == b'\x03\x00':
            result['service_name'] = 'rdp'
            result['service_version'] = 'Microsoft RDP'
            return result

        # SMB
        if raw_bytes and b'\xff\x53\x4d\x42' in raw_bytes[:50]:
            result['service_name'] = 'smb'
            result['service_version'] = 'Microsoft SMB'
            return result
        if raw_bytes and b'\xfe\x53\x4d\x42' in raw_bytes[:50]:
            result['service_name'] = 'smb'
            result['service_version'] = 'Microsoft SMB 2/3'
            return result

        # S7comm (Siemens)
        if raw_bytes and len(raw_bytes) > 6 and raw_bytes[0] == 0x03:
            ot_info = self.get_ot_info(port)
            if ot_info:
                result['service_name'] = ot_info[1]
                result['is_ot_protocol'] = 1
                result['ot_protocol_name'] = ot_info[0]
                return result

        # Modbus
        if port == 502 and raw_bytes:
            result['service_name'] = 'Modbus/TCP'
            result['is_ot_protocol'] = 1
            result['ot_protocol_name'] = 'modbus'
            return result

        # DNP3
        if port == 20000 and raw_bytes and len(raw_bytes) > 2:
            if raw_bytes[0] == 0x05 and raw_bytes[1] == 0x64:
                result['service_name'] = 'DNP3'
                result['is_ot_protocol'] = 1
                result['ot_protocol_name'] = 'dnp3'
                return result

        # EtherNet/IP
        if port in (44818, 2222):
            result['service_name'] = 'EtherNet/IP'
            result['is_ot_protocol'] = 1
            result['ot_protocol_name'] = 'ethernetip'
            return result

        # Generic OT port check
        ot_info = self.get_ot_info(port)
        if ot_info:
            result['service_name'] = ot_info[1]
            result['is_ot_protocol'] = 1
            result['ot_protocol_name'] = ot_info[0]
            return result

        # Fallback — use port hint
        if hint != 'unknown':
            result['service_name'] = hint

        return result

    def _parse_cert(self, cert):
        """Extract useful info from a TLS certificate."""
        if not cert:
            return {}
        info = {}
        subject = cert.get('subject', ())
        for field in subject:
            for key, value in field:
                if key == 'commonName':
                    info['subject'] = value
                elif key == 'organizationName':
                    info['org'] = value
        san = cert.get('subjectAltName', ())
        info['alt_names'] = [v for _, v in san]
        return info
