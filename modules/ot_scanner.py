#!/usr/bin/env python3
"""
OT/ICS Scanner Module
Protocol-aware scanning for industrial control systems.
Includes safety controls to prevent disruption of OT devices.

SAFETY FIRST: This scanner has built-in rate limiting and read-only operations
to minimize impact on sensitive OT environments.
"""

import re
import socket
import struct
import logging
import time
from modules.base_scanner import BaseScanner

logger = logging.getLogger('cpt-recon.ot')

# Aggressiveness rate limits (seconds between probes per host)
OT_RATE_LIMITS = {
    1: 5.0,   # Ultra-safe: 5s between probes
    2: 2.0,   # Conservative: 2s between probes
    3: 1.0,   # Normal: 1s
    4: 0.5,   # Aggressive: 500ms
    5: 0.2,   # Full speed: 200ms
}


class OTScanner(BaseScanner):
    """ICS/SCADA-aware scanner with safety controls."""

    def __init__(self, engine, scan_id, mission_id, target, config, stop_flag, aggressiveness=2):
        super().__init__(engine, scan_id, mission_id, target, config, stop_flag)
        self.aggressiveness = min(5, max(1, aggressiveness))
        self.rate_limit = OT_RATE_LIMITS.get(self.aggressiveness, 1.0)
        self.timeout = config.get('timeout', 3)

    def run(self):
        targets = self.parse_targets()
        if not targets:
            return {'error': 'No valid targets specified'}

        self.progress(0, f"OT scan starting ({len(targets)} targets, aggression level {self.aggressiveness})")
        self.log(f"OT/ICS scan initiated: {len(targets)} targets, aggressiveness={self.aggressiveness}, "
                 f"rate_limit={self.rate_limit}s between probes per host. READ-ONLY probes only.",
                 severity='ACTION', category='config')
        self.log(f"OT protocols to probe: Modbus/TCP (502), S7comm (102), DNP3 (20000), "
                 f"EtherNet/IP (44818), BACnet/IP (47808/udp), OPC UA (4840)",
                 severity='INFO', category='config')
        logger.info(f"OT Scan {self.scan_id}: {len(targets)} targets, rate limit {self.rate_limit}s")

        total_ot_devices = 0
        results_by_protocol = {}

        for ti, ip in enumerate(targets):
            if self.is_stopped():
                break

            pct = int((ti / len(targets)) * 90)
            self.progress(pct, f"Probing {ip} for OT protocols")

            # Probe each OT protocol
            protocols_found = []

            # Modbus/TCP (port 502)
            modbus_result = self._probe_modbus(ip)
            if modbus_result:
                protocols_found.append('modbus')
                results_by_protocol.setdefault('modbus', []).append(ip)
            time.sleep(self.rate_limit)

            if self.is_stopped():
                break

            # Siemens S7comm (port 102)
            s7_result = self._probe_s7comm(ip)
            if s7_result:
                protocols_found.append('s7comm')
                results_by_protocol.setdefault('s7comm', []).append(ip)
            time.sleep(self.rate_limit)

            if self.is_stopped():
                break

            # DNP3 (port 20000)
            dnp3_result = self._probe_dnp3(ip)
            if dnp3_result:
                protocols_found.append('dnp3')
                results_by_protocol.setdefault('dnp3', []).append(ip)
            time.sleep(self.rate_limit)

            if self.is_stopped():
                break

            # EtherNet/IP (port 44818)
            enip_result = self._probe_ethernetip(ip)
            if enip_result:
                protocols_found.append('ethernetip')
                results_by_protocol.setdefault('ethernetip', []).append(ip)
            time.sleep(self.rate_limit)

            if self.is_stopped():
                break

            # BACnet (port 47808)
            bacnet_result = self._probe_bacnet(ip)
            if bacnet_result:
                protocols_found.append('bacnet')
                results_by_protocol.setdefault('bacnet', []).append(ip)
            time.sleep(self.rate_limit)

            if self.is_stopped():
                break

            # OPC UA (port 4840)
            opcua_result = self._probe_opcua(ip)
            if opcua_result:
                protocols_found.append('opcua')
                results_by_protocol.setdefault('opcua', []).append(ip)
            time.sleep(self.rate_limit)

            if protocols_found:
                total_ot_devices += 1

                # Determine device type
                device_class = self._classify_ot_device(protocols_found, ip)

                # Submit host as OT device
                self.submit_host(
                    ip,
                    device_type=device_class.lower(),
                    criticality='critical',
                    discovered_via='ot_scan'
                )

                # Submit OT device details
                all_results = {
                    'modbus': modbus_result, 's7comm': s7_result,
                    'dnp3': dnp3_result, 'ethernetip': enip_result,
                    'bacnet': bacnet_result, 'opcua': opcua_result
                }
                device_info = self._merge_device_info(all_results)

                self.submit({
                    'type': 'ot_device',
                    'ip_address': ip,
                    'device_class': device_class,
                    'vendor': device_info.get('vendor'),
                    'model': device_info.get('model'),
                    'firmware': device_info.get('firmware'),
                    'serial_number': device_info.get('serial'),
                    'protocol': ','.join(protocols_found),
                    'master_slave_role': device_info.get('role'),
                    'notes': f"Protocols: {', '.join(protocols_found)}"
                })

        self.progress(100, f"OT scan complete: {total_ot_devices} OT devices found")

        return {
            'ot_devices_found': total_ot_devices,
            'protocols': results_by_protocol,
            'aggressiveness': self.aggressiveness,
            'hosts': [ip for proto_ips in results_by_protocol.values() for ip in proto_ips]
        }

    # ─── Protocol probes ───

    def _probe_modbus(self, ip, port=502):
        """Probe for Modbus/TCP. Read Device ID (Function 43/14) — read-only."""
        try:
            self.log_send(ip, port, 'tcp',
                         'Modbus/TCP probe: TCP connect + Read Device Identification (FC 43, MEI 14). '
                         'This is a READ-ONLY query that requests vendor name, product code, and revision. '
                         'No registers are written. No configuration is changed.',
                         tool='socket',
                         raw_detail='Modbus ADU: TxID=0001 ProtoID=0000 UnitID=01 FC=0x2B MEI=0x0E ReadCode=01 ObjID=00')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Modbus Read Device Identification (FC 43, MEI 14)
            # Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + FC (1) + MEI (1) + Read Device ID (1) + Object ID (1)
            request = struct.pack('>HHHBBBBB',
                0x0001,  # Transaction ID
                0x0000,  # Protocol ID (Modbus)
                0x0005,  # Length
                0x01,    # Unit ID
                0x2B,    # Function Code 43 (Read Device ID)
                0x0E,    # MEI Type 14
                0x01,    # Read Device ID code: Basic
                0x00     # Object ID: Vendor Name
            )
            sock.sendall(request)
            response = sock.recv(1024)
            sock.close()

            if len(response) > 7:
                self.submit_service(ip, port, 'tcp',
                    service_name='Modbus/TCP', is_ot_protocol=1, ot_protocol_name='modbus')

                result = {'protocol': 'modbus'}
                # Parse Device ID response
                if len(response) > 15:
                    try:
                        result.update(self._parse_modbus_device_id(response))
                    except Exception:
                        pass
                return result

        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        except Exception as e:
            logger.debug(f"Modbus probe failed for {ip}: {e}")
        return None

    def _parse_modbus_device_id(self, response):
        """Parse Modbus Read Device ID response for vendor/model info."""
        info = {}
        try:
            # Skip MBAP header (7 bytes) + FC (1) + MEI (1) + Read Device ID (1) + Conformity (1) + More (1) + Next (1) + Num Objects (1)
            offset = 14
            while offset < len(response) - 2:
                obj_id = response[offset]
                obj_len = response[offset + 1]
                obj_val = response[offset + 2:offset + 2 + obj_len].decode('utf-8', errors='replace')

                if obj_id == 0:
                    info['vendor'] = obj_val
                elif obj_id == 1:
                    info['model'] = obj_val  # Product Code
                elif obj_id == 2:
                    info['firmware'] = obj_val  # Major Minor Revision

                offset += 2 + obj_len
        except Exception:
            pass
        return info

    def _probe_s7comm(self, ip, port=102):
        """Probe for Siemens S7 protocol. COTP connection + SZL read — read-only."""
        try:
            self.log_send(ip, port, 'tcp',
                         'S7comm probe: COTP Connection Request + S7 Setup Communication. '
                         'This establishes an ISO-on-TCP session and negotiates S7 PDU size. '
                         'No PLC program is read or written. No outputs are toggled.',
                         tool='socket',
                         raw_detail='COTP CR (0xE0) → expect CC (0xD0), then S7 Setup Communication PDU')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # COTP Connection Request
            cotp_cr = bytes.fromhex(
                '0300001611e00000000100c0010ac1020100c2020102'
            )
            sock.sendall(cotp_cr)
            response = sock.recv(1024)

            if len(response) < 6 or response[5] != 0xD0:  # COTP CC
                sock.close()
                return None

            # S7 Setup Communication
            s7_setup = bytes.fromhex(
                '0300001902f08032010000000000080000f0000001000101e0'
            )
            sock.sendall(s7_setup)
            response = sock.recv(1024)
            sock.close()

            if len(response) > 10:
                self.submit_service(ip, port, 'tcp',
                    service_name='Siemens S7', is_ot_protocol=1, ot_protocol_name='s7comm')

                result = {'protocol': 's7comm', 'vendor': 'Siemens'}

                # Try to identify module type from response
                if len(response) > 27:
                    # Basic module info might be in the response
                    result['model'] = 'S7 PLC'

                return result

        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        except Exception as e:
            logger.debug(f"S7comm probe failed for {ip}: {e}")
        return None

    def _probe_dnp3(self, ip, port=20000):
        """Probe for DNP3 protocol. Data Link layer confirm — read-only."""
        try:
            self.log_send(ip, port, 'tcp',
                         'DNP3 probe: Data Link Layer request. '
                         'Sends a minimal DNP3 frame (Start=0x0564) to check for protocol presence. '
                         'No application-layer commands issued. No points read or written.',
                         tool='socket',
                         raw_detail='DNP3 DLL: Start=0564 Len=05 Ctrl=C0 Dst=0001 Src=0400')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # DNP3 Data Link Layer request (Read Class 0)
            # Start: 0564, Length: 05, Control: C0, Dest: 0001, Src: 0400
            dnp3_request = bytes.fromhex('056405c001000004e921')
            sock.sendall(dnp3_request)
            response = sock.recv(1024)
            sock.close()

            if len(response) > 2 and response[0] == 0x05 and response[1] == 0x64:
                self.submit_service(ip, port, 'tcp',
                    service_name='DNP3', is_ot_protocol=1, ot_protocol_name='dnp3')
                return {'protocol': 'dnp3'}

        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        except Exception as e:
            logger.debug(f"DNP3 probe failed for {ip}: {e}")
        return None

    def _probe_ethernetip(self, ip, port=44818):
        """Probe for EtherNet/IP (CIP). List Identity — read-only and standard."""
        try:
            self.log_send(ip, port, 'tcp',
                         'EtherNet/IP probe: List Identity command (0x0063). '
                         'This is a standard CIP discovery command that returns device vendor, '
                         'product type, product name, and serial number. '
                         'No CIP services are invoked. No I/O connections opened.',
                         tool='socket',
                         raw_detail='ENIP encapsulation: Cmd=0x0063 (ListIdentity) Len=0 Session=0')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # EtherNet/IP: List Identity command (0x0063)
            enip_list_identity = struct.pack('<HHIHIIQ',
                0x0063,  # Command: List Identity
                0x0000,  # Length
                0x00000000,  # Session Handle
                0x00000000,  # Status
                0,  # Sender Context (low)
                0,  # Sender Context (high)
                0   # Options
            )
            # Trim to correct 24 bytes
            enip_list_identity = enip_list_identity[:24]
            sock.sendall(enip_list_identity)
            response = sock.recv(1024)
            sock.close()

            if len(response) > 24:
                self.submit_service(ip, port, 'tcp',
                    service_name='EtherNet/IP', is_ot_protocol=1, ot_protocol_name='ethernetip')

                result = {'protocol': 'ethernetip'}
                if len(response) > 50:
                    try:
                        result.update(self._parse_enip_identity(response))
                    except Exception:
                        pass
                return result

        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        except Exception as e:
            logger.debug(f"EtherNet/IP probe failed for {ip}: {e}")
        return None

    def _parse_enip_identity(self, response):
        """Parse EtherNet/IP List Identity response."""
        info = {}
        try:
            # Skip encapsulation header (24 bytes) + item count (2) + type/length
            offset = 34
            if offset + 2 <= len(response):
                vendor_id = struct.unpack_from('<H', response, offset)[0]
                info['vendor_id'] = vendor_id

                # Known vendor IDs
                vendor_map = {
                    1: 'Rockwell Automation', 20: 'ABB', 283: 'Siemens',
                    345: 'Schneider Electric', 90: 'Omron'
                }
                info['vendor'] = vendor_map.get(vendor_id, f'Vendor {vendor_id}')

            if offset + 4 <= len(response):
                device_type = struct.unpack_from('<H', response, offset + 2)[0]
                device_types = {
                    0: 'Generic', 2: 'AC Drive', 7: 'PLC', 12: 'Communication Adapter',
                    14: 'Programmable Controller', 33: 'HMI', 43: 'Safety'
                }
                info['device_class'] = device_types.get(device_type, f'Type {device_type}')

            if offset + 6 <= len(response):
                product_code = struct.unpack_from('<H', response, offset + 4)[0]
                info['model'] = f'Product {product_code}'

            # Product name is further in as a counted string
            try:
                name_offset = offset + 14
                if name_offset < len(response):
                    name_len = response[name_offset]
                    if name_offset + 1 + name_len <= len(response):
                        info['model'] = response[name_offset+1:name_offset+1+name_len].decode('utf-8', errors='replace')
            except Exception:
                pass

        except Exception:
            pass
        return info

    def _probe_bacnet(self, ip, port=47808):
        """Probe for BACnet/IP. Who-Is broadcast — read-only."""
        try:
            self.log_send(ip, port, 'udp',
                         'BACnet/IP probe: Who-Is service request (UDP). '
                         'Standard BACnet device discovery. '
                         'No objects read or written. No schedules or programs affected.',
                         tool='socket',
                         raw_detail='BACnet BVLC: Type=0x81 Func=0x04 (Original-Unicast) + Who-Is APDU')
            # BACnet uses UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # BACnet Who-Is request
            bacnet_whois = bytes.fromhex('810400001001080009011c02')
            sock.sendto(bacnet_whois, (ip, port))
            response, _ = sock.recvfrom(1024)
            sock.close()

            if len(response) > 4 and response[0] == 0x81:
                self.submit_service(ip, port, 'udp',
                    service_name='BACnet', is_ot_protocol=1, ot_protocol_name='bacnet')
                return {'protocol': 'bacnet'}

        except (socket.timeout, OSError):
            pass
        except Exception as e:
            logger.debug(f"BACnet probe failed for {ip}: {e}")
        return None

    def _probe_opcua(self, ip, port=4840):
        """Probe for OPC UA. Get Endpoints — read-only discovery."""
        try:
            self.log_send(ip, port, 'tcp',
                         'OPC UA probe: Hello message (HEL). '
                         'Initiates OPC UA connection negotiation. '
                         'Expects ACK response indicating OPC UA server. '
                         'No sessions opened. No nodes browsed or read.',
                         tool='socket',
                         raw_detail=f'OPC UA HEL: ProtocolVersion=0 EndpointUrl=opc.tcp://{ip}:{port}')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # OPC UA Hello message
            endpoint_url = f'opc.tcp://{ip}:{port}'.encode('utf-8')
            url_len = len(endpoint_url)
            msg_len = 32 + url_len

            hello = b'HEL' + b'F'  # Message Type + Chunk Type
            hello += struct.pack('<I', msg_len)  # Message Size
            hello += struct.pack('<I', 0)  # Protocol Version
            hello += struct.pack('<I', 65536)  # Receive Buffer Size
            hello += struct.pack('<I', 65536)  # Send Buffer Size
            hello += struct.pack('<I', 0)  # Max Message Size (0 = no limit)
            hello += struct.pack('<I', 0)  # Max Chunk Count (0 = no limit)
            hello += struct.pack('<I', url_len)  # Endpoint URL length
            hello += endpoint_url

            sock.sendall(hello)
            response = sock.recv(1024)
            sock.close()

            if len(response) > 8 and response[:3] == b'ACK':
                self.submit_service(ip, port, 'tcp',
                    service_name='OPC UA', is_ot_protocol=1, ot_protocol_name='opcua')
                return {'protocol': 'opcua'}

        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        except Exception as e:
            logger.debug(f"OPC UA probe failed for {ip}: {e}")
        return None

    # ─── Device classification ───

    def _classify_ot_device(self, protocols, ip):
        """Classify OT device type based on protocols and behavior."""
        if 's7comm' in protocols and 'ethernetip' not in protocols:
            return 'PLC'
        if 'ethernetip' in protocols:
            return 'PLC'
        if 'modbus' in protocols and 'dnp3' in protocols:
            return 'RTU'
        if 'dnp3' in protocols and 'modbus' not in protocols:
            return 'RTU'
        if 'bacnet' in protocols:
            return 'HMI'
        if 'opcua' in protocols:
            return 'HMI'
        if 'modbus' in protocols:
            return 'PLC'
        return 'PLC'

    def _merge_device_info(self, all_results):
        """Merge device info from all protocol probes."""
        info = {}
        for proto, result in all_results.items():
            if result and isinstance(result, dict):
                for key in ['vendor', 'model', 'firmware', 'serial', 'role', 'device_class']:
                    if key in result and result[key] and key not in info:
                        info[key] = result[key]
        return info
