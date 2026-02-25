#!/usr/bin/env python3
"""
Service Scanner Module
Service version detection using nmap -sV as the primary method,
with socket-based banner grabbing as fallback.
Identifies running services, versions, and protocols on open ports.
"""

import re
import socket
import ssl
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.base_scanner import BaseScanner

logger = logging.getLogger('blue-reccoon.service')

# Protocol probes — bytes to send to elicit a response (used in fallback mode)
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
        method_desc = ("nmap -sV service version detection (primary), "
                       "socket-based banner grabbing (fallback)" if use_nmap
                       else "socket-based banner grabbing")

        self.log(f"Service detection scan initiated on {len(targets)} hosts. "
                 f"Method: {method_desc}. "
                 f"Actions: {'nmap -sV probes for service fingerprinting; ' if use_nmap else ''}"
                 f"TCP connect to open ports, protocol-specific probes "
                 f"(HTTP GET, SSH banner wait, SMB negotiate, RDP handshake, Modbus Device ID, etc.), "
                 f"banner fingerprinting. TLS certificate extraction on SSL ports. "
                 f"Updates service name, version, and banner fields for each port. "
                 f"All operations are read-only.",
                 severity='ACTION', category='config',
                 raw_detail=f"Targets: {self.target}")

        db = self.engine._get_db()
        total_services = 0
        total_banners = 0

        # Collect all host:port pairs to scan
        host_ports = {}
        for ip in targets:
            if self.is_stopped():
                break

            host = db.execute(
                "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
                (self.mission_id, ip)
            ).fetchone()

            if not host:
                logger.debug(f"No host record for {ip}, skipping")
                continue

            services = db.execute(
                "SELECT port, protocol FROM services WHERE host_id = ? AND state = 'open'",
                (host['id'],)
            ).fetchall()

            if not services:
                # If no services known yet, try common ports
                services = [{'port': p, 'protocol': 'tcp'} for p in [22, 80, 443, 445, 3389]]
                logger.info(f"No open services in DB for {ip}, trying common ports")

            host_ports[ip] = [(s['port'], s['protocol']) for s in services]

        if not host_ports:
            db.close()
            logger.warning("No hosts with open services found — run Port Scan first")
            self.progress(100, "No hosts with open services found — run Port Scan first")
            return {
                'services_probed': 0,
                'banners_grabbed': 0,
                'warning': 'No hosts with open services found. Run Port Scan first.'
            }

        logger.info(f"Service scan: {len(host_ports)} hosts, "
                     f"{sum(len(v) for v in host_ports.values())} total ports to probe")

        if use_nmap:
            # ── Primary method: nmap -sV ──
            nmap_results = self._nmap_service_scan(host_ports)

            # Submit nmap results
            for ip, port_results in nmap_results.items():
                for port, result in port_results.items():
                    total_services += 1
                    if result.get('service_name') or result.get('service_version') or result.get('banner'):
                        total_banners += 1
                    # Resolve original protocol from host_ports
                    proto = 'tcp'
                    if ip in host_ports:
                        for p, pr in host_ports[ip]:
                            if p == port:
                                proto = pr
                                break
                    self.submit_service(ip, port, proto, **result)

            # Fallback: socket-based banner grabbing for ports nmap missed
            self.progress(85, "Fallback banner grabbing for remaining services")
            for ip, ports_list in host_ports.items():
                if self.is_stopped():
                    break
                for port, proto in ports_list:
                    if proto == 'udp':
                        continue
                    if ip in nmap_results and port in nmap_results[ip]:
                        continue
                    result = self._grab_banner(ip, port)
                    if result:
                        total_banners += 1
                        self.submit_service(ip, port, proto, **result)
                    total_services += 1
        else:
            # ── Fallback only: socket-based banner grabbing ──
            host_list = list(host_ports.keys())
            for ti, ip in enumerate(host_list):
                if self.is_stopped():
                    break

                pct = int((ti / max(len(host_list), 1)) * 90)
                self.progress(pct, f"Probing services on {ip}")

                for port, proto in host_ports[ip]:
                    if self.is_stopped():
                        break
                    if proto == 'udp':
                        continue

                    result = self._grab_banner(ip, port)
                    if result:
                        total_banners += 1
                        self.submit_service(ip, port, proto, **result)
                    total_services += 1

        db.close()

        self.progress(100, f"Service detection complete: {total_banners} banners grabbed")
        return {
            'services_probed': total_services,
            'banners_grabbed': total_banners
        }

    # ── nmap -sV primary method ──

    def _nmap_service_scan(self, host_ports):
        """Use nmap -sV for service version detection. Primary scanning method.

        Args:
            host_ports: dict mapping IP -> list of (port, protocol) tuples

        Returns:
            dict mapping IP -> {port: result_dict}
        """
        results = {}

        # Collect all unique TCP ports and target IPs
        all_ports = set()
        all_ips = []
        for ip, ports_list in host_ports.items():
            all_ips.append(ip)
            for port, proto in ports_list:
                if proto != 'udp':
                    all_ports.add(port)

        if not all_ports or not all_ips:
            return results

        port_str = ','.join(str(p) for p in sorted(all_ports))

        # Process hosts in chunks
        chunk_size = 16
        chunks = [all_ips[i:i + chunk_size] for i in range(0, len(all_ips), chunk_size)]

        for ci, chunk in enumerate(chunks):
            if self.is_stopped():
                break

            pct = int((ci / max(len(chunks), 1)) * 80)
            self.progress(pct, f"nmap -sV scanning chunk {ci + 1}/{len(chunks)}")

            target_str = ' '.join(chunk)
            cmd = (
                f"nmap -sV -Pn --version-intensity 5 "
                f"-p {port_str} -oX - {target_str}"
            )

            self.log_send(
                chunk[0], None, 'tcp',
                f"nmap -sV service detection: {len(chunk)} hosts, "
                f"{len(all_ports)} ports — version-intensity 5",
                tool='nmap', command=cmd
            )

            # Scale timeout by number of hosts and ports
            timeout = max(300, len(chunk) * len(all_ports) // 10)
            rc, stdout, stderr = self.run_command(cmd, timeout=timeout)

            if rc == 0 and stdout:
                chunk_results = self._parse_nmap_service_output(stdout)
                results.update(chunk_results)
                logger.info(f"nmap -sV chunk {ci + 1}: identified services on "
                            f"{len(chunk_results)} hosts")
            else:
                logger.warning(f"nmap -sV failed for chunk {ci + 1}: rc={rc}, "
                               f"stderr={stderr[:200] if stderr else 'none'}")
                self.log(f"nmap -sV failed (rc={rc}), falling back to socket probes",
                         severity='WARN', category='tool_exec', tool='nmap')

        return results

    def _parse_nmap_service_output(self, xml_output):
        """Parse nmap -sV XML output for service versions.

        Returns:
            dict mapping IP -> {port: result_dict}
        """
        results = {}
        host_blocks = re.findall(r'<host\b.*?</host>', xml_output, re.DOTALL)

        for block in host_blocks:
            if 'state="up"' not in block:
                continue

            ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            results[ip] = {}

            port_blocks = re.findall(
                r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>',
                block, re.DOTALL
            )

            for proto, portid, port_content in port_blocks:
                state_match = re.search(r'<state state="(\w+)"', port_content)
                state = state_match.group(1) if state_match else 'unknown'

                port = int(portid)
                result = {'state': state}

                # Parse service info from nmap -sV output
                svc_match = re.search(r'<service\s+([^>]+)', port_content)
                if svc_match:
                    svc_attrs = svc_match.group(1)

                    name_m = re.search(r'name="([^"]*)"', svc_attrs)
                    product_m = re.search(r'product="([^"]*)"', svc_attrs)
                    version_m = re.search(r'version="([^"]*)"', svc_attrs)
                    extrainfo_m = re.search(r'extrainfo="([^"]*)"', svc_attrs)

                    if name_m:
                        result['service_name'] = name_m.group(1)

                    # Build version string from product + version + extrainfo
                    version_parts = []
                    if product_m and product_m.group(1):
                        version_parts.append(product_m.group(1))
                    if version_m and version_m.group(1):
                        version_parts.append(version_m.group(1))
                    if extrainfo_m and extrainfo_m.group(1):
                        version_parts.append(extrainfo_m.group(1))
                    if version_parts:
                        result['service_version'] = ' '.join(version_parts)

                    # Use nmap version string as banner
                    if version_parts:
                        result['banner'] = ' '.join(version_parts)

                # Check for OT protocol by port
                ot_info = self.get_ot_info(port)
                if ot_info:
                    result['is_ot_protocol'] = 1
                    result['ot_protocol_name'] = ot_info[0]
                    if not result.get('service_name'):
                        result['service_name'] = ot_info[1]

                results[ip][port] = result

        return results

    # ── Socket-based fallback methods ──

    def _grab_banner(self, ip, port, timeout=3):
        """Grab banner from a service via socket. Fallback when nmap is unavailable.
        Returns dict with service info or None."""
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
                     f"Banner grab (fallback): {ip}:{port} — "
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
