#!/usr/bin/env python3
"""
BLUE RECCOON - Scan Engine
Orchestrates active and passive enumeration modules.
Manages scan jobs, threading, progress reporting, and result ingestion.
"""

import json
import threading
import logging
import sqlite3
import time
import ipaddress
from datetime import datetime, timezone
from queue import Queue

logger = logging.getLogger('blue-reccoon.engine')


class ScanEngine:
    """Central scan orchestrator. Manages scan lifecycle, threading, and results."""

    def __init__(self, db_path, socketio=None):
        self.db_path = db_path
        self.socketio = socketio
        self.active_scans = {}  # scan_id -> thread
        self.result_queue = Queue()
        self._stop_flags = {}  # scan_id -> threading.Event
        self._lock = threading.Lock()

        # Start result ingestion thread
        self._ingest_thread = threading.Thread(target=self._ingest_results, daemon=True)
        self._ingest_thread.start()

    def _get_db(self):
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _emit(self, event, data, mission_id=None):
        """Emit real-time event to connected clients."""
        if self.socketio:
            room = f'mission_{mission_id}' if mission_id else None
            self.socketio.emit(event, data, room=room)

    # ─── Scan lifecycle ───

    def start_scan(self, scan_id, mission_id):
        """Launch a scan job in a background thread."""
        db = self._get_db()
        job = db.execute("SELECT * FROM scan_jobs WHERE id = ?", (scan_id,)).fetchone()
        db.close()

        if not job:
            logger.error(f"Scan job {scan_id} not found")
            return False

        job = dict(job)
        job_type = job['job_type']
        config = json.loads(job.get('config') or '{}')
        target = job.get('target', '')
        mode = job.get('mode', 'active')
        aggressiveness = job.get('aggressiveness', 3)

        stop_flag = threading.Event()
        self._stop_flags[scan_id] = stop_flag

        def run_scan():
            try:
                self._update_scan_status(scan_id, 'running')
                self._emit('scan_status', {
                    'scan_id': scan_id, 'status': 'running',
                    'job_type': job_type, 'target': target
                }, mission_id)

                # Route to appropriate scanner
                if job_type == 'arp_sweep':
                    from modules.network_discovery import ARPScanner
                    scanner = ARPScanner(self, scan_id, mission_id, target, config, stop_flag)
                elif job_type == 'port_scan':
                    from modules.port_scanner import PortScanner
                    scanner = PortScanner(self, scan_id, mission_id, target, config, stop_flag, aggressiveness)
                elif job_type == 'service_scan':
                    from modules.service_scanner import ServiceScanner
                    scanner = ServiceScanner(self, scan_id, mission_id, target, config, stop_flag)
                elif job_type == 'os_detect':
                    from modules.os_detector import OSDetector
                    scanner = OSDetector(self, scan_id, mission_id, target, config, stop_flag)
                elif job_type == 'ad_enum':
                    from modules.ad_enumerator import ADEnumerator
                    scanner = ADEnumerator(self, scan_id, mission_id, target, config, stop_flag)
                elif job_type == 'smb_enum':
                    from modules.smb_enumerator import SMBEnumerator
                    scanner = SMBEnumerator(self, scan_id, mission_id, target, config, stop_flag)
                elif job_type == 'snmp_enum':
                    from modules.snmp_enumerator import SNMPEnumerator
                    scanner = SNMPEnumerator(self, scan_id, mission_id, target, config, stop_flag)
                elif job_type == 'ot_scan':
                    from modules.ot_scanner import OTScanner
                    scanner = OTScanner(self, scan_id, mission_id, target, config, stop_flag, aggressiveness)
                elif job_type == 'passive_capture':
                    from modules.passive_capture import PassiveCapture
                    scanner = PassiveCapture(self, scan_id, mission_id, target, config, stop_flag)
                elif job_type == 'pcap_import':
                    from modules.pcap_importer import PCAPImporter
                    scanner = PCAPImporter(self, scan_id, mission_id, target, config, stop_flag)
                elif job_type == 'full_active':
                    from modules.full_scan import FullActiveScan
                    scanner = FullActiveScan(self, scan_id, mission_id, target, config, stop_flag, aggressiveness)
                elif job_type == 'host_profile':
                    from modules.host_profiler import HostProfiler
                    scanner = HostProfiler(self, scan_id, mission_id, target, config, stop_flag)
                else:
                    raise ValueError(f"Unknown scan type: {job_type}")

                results = scanner.run()

                if stop_flag.is_set():
                    self._update_scan_status(scan_id, 'cancelled', results)
                    self._emit('scan_status', {
                        'scan_id': scan_id, 'status': 'cancelled', 'job_type': job_type
                    }, mission_id)
                else:
                    self._update_scan_status(scan_id, 'completed', results)
                    self._emit('scan_status', {
                        'scan_id': scan_id, 'status': 'completed',
                        'job_type': job_type, 'summary': results
                    }, mission_id)

            except Exception as e:
                logger.exception(f"Scan {scan_id} failed: {e}")
                self._update_scan_status(scan_id, 'failed', {'error': str(e)})
                self._emit('scan_status', {
                    'scan_id': scan_id, 'status': 'failed',
                    'job_type': job_type, 'error': str(e)
                }, mission_id)
            finally:
                with self._lock:
                    self.active_scans.pop(scan_id, None)
                    self._stop_flags.pop(scan_id, None)

        thread = threading.Thread(target=run_scan, daemon=True, name=f'scan-{scan_id}')
        with self._lock:
            self.active_scans[scan_id] = thread
        thread.start()
        return True

    def stop_scan(self, scan_id):
        """Signal a running scan to stop."""
        flag = self._stop_flags.get(scan_id)
        if flag:
            flag.set()
            logger.info(f"Stop signal sent to scan {scan_id}")
            return True
        return False

    def get_active_scans(self):
        """Return list of currently running scan IDs."""
        with self._lock:
            return list(self.active_scans.keys())

    # ─── Result ingestion ───

    def submit_result(self, result):
        """Queue a discovery result for DB ingestion. Thread-safe."""
        self.result_queue.put(result)

    def _ingest_results(self):
        """Background thread that processes queued results into the database."""
        while True:
            try:
                result = self.result_queue.get(timeout=1)
                self._process_result(result)
            except Exception:
                continue

    def _process_result(self, result):
        """Ingest a single result into the database."""
        db = self._get_db()
        try:
            rtype = result.get('type')
            mission_id = result.get('mission_id')

            if rtype == 'host':
                self._ingest_host(db, result)
            elif rtype == 'service':
                self._ingest_service(db, result)
            elif rtype == 'subnet':
                self._ingest_subnet(db, result)
            elif rtype == 'connection':
                self._ingest_connection(db, result)
            elif rtype == 'os_info':
                self._ingest_os_info(db, result)
            elif rtype == 'domain_info':
                self._ingest_domain_info(db, result)
            elif rtype == 'privileged_account':
                self._ingest_privileged_account(db, result)
            elif rtype == 'ot_device':
                self._ingest_ot_device(db, result)
            elif rtype == 'software':
                self._ingest_software(db, result)
            elif rtype == 'process':
                self._ingest_process(db, result)
            elif rtype == 'scheduled_task':
                self._ingest_scheduled_task(db, result)
            elif rtype == 'local_group':
                self._ingest_local_group(db, result)
            elif rtype == 'host_update':
                self._update_host_fields(db, result)

            db.commit()

            # Emit real-time update
            self._emit('discovery', {
                'type': rtype,
                'data': {k: v for k, v in result.items() if k != 'type'}
            }, mission_id)

        except Exception as e:
            logger.error(f"Failed to ingest result: {e}")
        finally:
            db.close()

    def _ingest_host(self, db, result):
        """Insert or update a discovered host."""
        mission_id = result['mission_id']
        ip = result['ip_address']

        existing = db.execute(
            "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
            (mission_id, ip)
        ).fetchone()

        if existing:
            # Update existing host
            fields = []
            values = []
            for key in ['mac_address', 'hostname', 'domain', 'os_name', 'os_version',
                        'device_type', 'device_vendor', 'device_model', 'firmware_version',
                        'criticality', 'discovered_via', 'os_fingerprint_method']:
                if key in result and result[key]:
                    fields.append(f"{key} = ?")
                    values.append(result[key])

            if fields:
                fields.append("last_seen = datetime('now')")
                fields.append("is_alive = 1")
                values.append(existing['id'])
                db.execute(f"UPDATE hosts SET {', '.join(fields)} WHERE id = ?", values)

            return existing['id']
        else:
            # Auto-assign subnet
            subnet_id = self._find_subnet(db, mission_id, ip)

            cursor = db.execute("""
                INSERT INTO hosts (mission_id, ip_address, mac_address, hostname, domain,
                    os_name, os_version, os_fingerprint_method, device_type, device_vendor,
                    device_model, firmware_version, criticality, discovered_via, subnet_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mission_id, ip,
                result.get('mac_address'), result.get('hostname'), result.get('domain'),
                result.get('os_name'), result.get('os_version'), result.get('os_fingerprint_method'),
                result.get('device_type', 'unknown'), result.get('device_vendor'),
                result.get('device_model'), result.get('firmware_version'),
                result.get('criticality', 'medium'), result.get('discovered_via', 'active'),
                subnet_id
            ))
            return cursor.lastrowid

    def _ingest_service(self, db, result):
        """Insert or update a discovered service."""
        host_id = result.get('host_id')
        if not host_id:
            # Look up host by IP
            row = db.execute(
                "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
                (result['mission_id'], result['ip_address'])
            ).fetchone()
            if not row:
                return
            host_id = row['id']

        port = result['port']
        protocol = result.get('protocol', 'tcp')

        existing = db.execute(
            "SELECT id FROM services WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, port, protocol)
        ).fetchone()

        if existing:
            updates = []
            values = []
            for key in ['service_name', 'service_version', 'banner', 'state',
                        'is_ot_protocol', 'ot_protocol_name']:
                if key in result and result[key] is not None:
                    updates.append(f"{key} = ?")
                    values.append(result[key])
            if updates:
                values.append(existing['id'])
                db.execute(f"UPDATE services SET {', '.join(updates)} WHERE id = ?", values)
        else:
            db.execute("""
                INSERT INTO services (host_id, port, protocol, state, service_name,
                    service_version, banner, is_ot_protocol, ot_protocol_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                host_id, port, protocol, result.get('state', 'open'),
                result.get('service_name'), result.get('service_version'),
                result.get('banner'), result.get('is_ot_protocol', 0),
                result.get('ot_protocol_name')
            ))

    def _ingest_subnet(self, db, result):
        """Insert or update a discovered subnet."""
        mission_id = result['mission_id']
        cidr = result['cidr']

        existing = db.execute(
            "SELECT id FROM subnets WHERE mission_id = ? AND cidr = ?",
            (mission_id, cidr)
        ).fetchone()

        if not existing:
            db.execute("""
                INSERT INTO subnets (mission_id, cidr, vlan_id, name, description,
                    network_type, gateway, discovered_via)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mission_id, cidr, result.get('vlan_id'), result.get('name'),
                result.get('description'), result.get('network_type', 'IT'),
                result.get('gateway'), result.get('discovered_via', 'active')
            ))

    def _ingest_connection(self, db, result):
        """Insert or update a network connection."""
        mission_id = result['mission_id']
        src_ip = result.get('src_ip')
        dst_ip = result.get('dst_ip')

        # Resolve host IDs
        src_host = db.execute(
            "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
            (mission_id, src_ip)
        ).fetchone() if src_ip else None

        dst_host = db.execute(
            "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
            (mission_id, dst_ip)
        ).fetchone() if dst_ip else None

        src_id = src_host['id'] if src_host else None
        dst_id = dst_host['id'] if dst_host else None

        # Check for existing connection
        if src_id and dst_id:
            existing = db.execute("""
                SELECT id, packet_count, bytes_sent, bytes_recv FROM connections
                WHERE mission_id = ? AND src_host_id = ? AND dst_host_id = ? AND dst_port = ?
            """, (mission_id, src_id, dst_id, result.get('dst_port'))).fetchone()

            if existing:
                db.execute("""
                    UPDATE connections SET
                        packet_count = packet_count + ?,
                        bytes_sent = bytes_sent + ?,
                        bytes_recv = bytes_recv + ?,
                        last_seen = datetime('now')
                    WHERE id = ?
                """, (
                    result.get('packet_count', 0),
                    result.get('bytes_sent', 0),
                    result.get('bytes_recv', 0),
                    existing['id']
                ))
                return

        db.execute("""
            INSERT INTO connections (mission_id, src_host_id, dst_host_id, src_ip, dst_ip,
                src_port, dst_port, protocol, bytes_sent, bytes_recv, packet_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            mission_id, src_id, dst_id, src_ip, dst_ip,
            result.get('src_port'), result.get('dst_port'),
            result.get('protocol'), result.get('bytes_sent', 0),
            result.get('bytes_recv', 0), result.get('packet_count', 0)
        ))

    def _ingest_os_info(self, db, result):
        """Update host with OS detection results."""
        db.execute("""
            UPDATE hosts SET os_name = ?, os_version = ?, os_fingerprint_method = ?,
                last_seen = datetime('now')
            WHERE mission_id = ? AND ip_address = ?
        """, (
            result.get('os_name'), result.get('os_version'),
            result.get('method', 'nmap'),
            result['mission_id'], result['ip_address']
        ))

    def _ingest_domain_info(self, db, result):
        """Insert AD domain information."""
        mission_id = result['mission_id']
        domain = result['domain_name']

        existing = db.execute(
            "SELECT id FROM domain_info WHERE mission_id = ? AND domain_name = ?",
            (mission_id, domain)
        ).fetchone()

        if existing:
            db.execute("""
                UPDATE domain_info SET forest_name = ?, domain_controllers = ?,
                    functional_level = ?, trusts = ?, ous = ?, gpos = ?
                WHERE id = ?
            """, (
                result.get('forest_name'), json.dumps(result.get('domain_controllers', [])),
                result.get('functional_level'), json.dumps(result.get('trusts', [])),
                json.dumps(result.get('ous', [])), json.dumps(result.get('gpos', [])),
                existing['id']
            ))
        else:
            db.execute("""
                INSERT INTO domain_info (mission_id, domain_name, forest_name,
                    domain_controllers, functional_level, trusts, ous, gpos)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mission_id, domain, result.get('forest_name'),
                json.dumps(result.get('domain_controllers', [])),
                result.get('functional_level'),
                json.dumps(result.get('trusts', [])),
                json.dumps(result.get('ous', [])),
                json.dumps(result.get('gpos', []))
            ))

    def _ingest_privileged_account(self, db, result):
        """Insert a discovered privileged account."""
        mission_id = result['mission_id']
        name = result['account_name']
        domain = result.get('domain', '')

        existing = db.execute(
            "SELECT id FROM privileged_accounts WHERE mission_id = ? AND account_name = ? AND domain = ?",
            (mission_id, name, domain)
        ).fetchone()

        if not existing:
            db.execute("""
                INSERT INTO privileged_accounts (mission_id, account_name, account_type,
                    domain, groups, is_admin, last_logon, logon_count, password_last_set, spn, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mission_id, name, result.get('account_type', 'user'),
                domain, json.dumps(result.get('groups', [])),
                result.get('is_admin', 0), result.get('last_logon'),
                result.get('logon_count'), result.get('password_last_set'),
                result.get('spn'), result.get('notes')
            ))

    def _ingest_ot_device(self, db, result):
        """Insert or update OT device details."""
        host_id = result.get('host_id')
        if not host_id:
            row = db.execute(
                "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
                (result['mission_id'], result['ip_address'])
            ).fetchone()
            if not row:
                return
            host_id = row['id']

        existing = db.execute("SELECT id FROM ot_devices WHERE host_id = ?", (host_id,)).fetchone()

        if existing:
            db.execute("""
                UPDATE ot_devices SET device_class = ?, vendor = ?, model = ?,
                    firmware = ?, serial_number = ?, protocol = ?,
                    master_slave_role = ?, notes = ?
                WHERE id = ?
            """, (
                result.get('device_class'), result.get('vendor'), result.get('model'),
                result.get('firmware'), result.get('serial_number'), result.get('protocol'),
                result.get('master_slave_role'), result.get('notes'), existing['id']
            ))
        else:
            db.execute("""
                INSERT INTO ot_devices (host_id, device_class, vendor, model, firmware,
                    serial_number, protocol, master_slave_role, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                host_id, result.get('device_class'), result.get('vendor'),
                result.get('model'), result.get('firmware'), result.get('serial_number'),
                result.get('protocol'), result.get('master_slave_role'), result.get('notes')
            ))

    def _resolve_host_id(self, db, result):
        """Resolve host_id from result, looking up by IP if needed."""
        host_id = result.get('host_id')
        if host_id:
            return host_id
        row = db.execute(
            "SELECT id FROM hosts WHERE mission_id = ? AND ip_address = ?",
            (result['mission_id'], result['ip_address'])
        ).fetchone()
        return row['id'] if row else None

    def _ingest_software(self, db, result):
        """Insert an installed software entry."""
        host_id = self._resolve_host_id(db, result)
        if not host_id:
            return
        # Avoid duplicates by name+version
        existing = db.execute(
            "SELECT id FROM software_inventory WHERE host_id = ? AND name = ? AND version = ?",
            (host_id, result['name'], result.get('version', ''))
        ).fetchone()
        if not existing:
            db.execute("""
                INSERT INTO software_inventory (host_id, name, version, publisher,
                    install_date, install_source, architecture)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                host_id, result['name'], result.get('version', ''),
                result.get('publisher', ''), result.get('install_date', ''),
                result.get('install_source', ''), result.get('architecture', '')
            ))

    def _ingest_process(self, db, result):
        """Insert a running process or service entry."""
        host_id = self._resolve_host_id(db, result)
        if not host_id:
            return
        is_service = result.get('is_service', 0)
        name = result.get('name', '')
        # For services, avoid duplicates by service_name
        if is_service:
            svc_name = result.get('service_name', name)
            existing = db.execute(
                "SELECT id FROM running_processes WHERE host_id = ? AND is_service = 1 AND service_name = ?",
                (host_id, svc_name)
            ).fetchone()
            if existing:
                db.execute("""
                    UPDATE running_processes SET service_state = ?, start_type = ?,
                        service_display_name = ?, collected_at = datetime('now')
                    WHERE id = ?
                """, (
                    result.get('service_state', ''), result.get('start_type', ''),
                    result.get('service_display_name', ''), existing['id']
                ))
                return
        else:
            # For processes, avoid duplicates by pid (per collection run)
            pid = result.get('pid')
            if pid is not None:
                existing = db.execute(
                    "SELECT id FROM running_processes WHERE host_id = ? AND pid = ? AND is_service = 0",
                    (host_id, pid)
                ).fetchone()
                if existing:
                    return

        db.execute("""
            INSERT INTO running_processes (host_id, pid, name, exe_path, command_line,
                username, parent_pid, is_service, service_name, service_display_name,
                service_state, start_type, memory_bytes, cpu_percent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            host_id, result.get('pid'), name,
            result.get('exe_path', ''), result.get('command_line', ''),
            result.get('username', ''), result.get('parent_pid'),
            is_service, result.get('service_name', ''),
            result.get('service_display_name', ''),
            result.get('service_state', ''), result.get('start_type', ''),
            result.get('memory_bytes'), result.get('cpu_percent')
        ))

    def _ingest_scheduled_task(self, db, result):
        """Insert a scheduled task entry."""
        host_id = self._resolve_host_id(db, result)
        if not host_id:
            return
        task_name = result['task_name']
        source = result.get('source', '')
        # Avoid duplicates by task_name + source
        existing = db.execute(
            "SELECT id FROM scheduled_tasks WHERE host_id = ? AND task_name = ? AND source = ?",
            (host_id, task_name, source)
        ).fetchone()
        if existing:
            db.execute("""
                UPDATE scheduled_tasks SET status = ?, next_run = ?, last_run = ?,
                    last_result = ?, collected_at = datetime('now')
                WHERE id = ?
            """, (
                result.get('status', ''), result.get('next_run', ''),
                result.get('last_run', ''), result.get('last_result', ''),
                existing['id']
            ))
            return

        db.execute("""
            INSERT INTO scheduled_tasks (host_id, task_name, task_path, status,
                next_run, last_run, last_result, author, run_as_user,
                command, trigger_info, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            host_id, task_name, result.get('task_path', ''),
            result.get('status', ''), result.get('next_run', ''),
            result.get('last_run', ''), result.get('last_result', ''),
            result.get('author', ''), result.get('run_as_user', ''),
            result.get('command', ''), result.get('trigger_info', ''),
            source
        ))

    def _ingest_local_group(self, db, result):
        """Insert a local group entry."""
        host_id = self._resolve_host_id(db, result)
        if not host_id:
            return
        group_name = result['group_name']
        group_type = result.get('group_type', 'local')
        # Avoid duplicates
        existing = db.execute(
            "SELECT id FROM local_groups WHERE host_id = ? AND group_name = ? AND group_type = ?",
            (host_id, group_name, group_type)
        ).fetchone()
        members_json = json.dumps(result.get('members', []))
        if existing:
            db.execute("""
                UPDATE local_groups SET members = ?, description = ?,
                    is_privileged = ?, collected_at = datetime('now')
                WHERE id = ?
            """, (members_json, result.get('description', ''),
                  result.get('is_privileged', 0), existing['id']))
        else:
            db.execute("""
                INSERT INTO local_groups (host_id, group_name, group_type, members,
                    description, is_privileged)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                host_id, group_name, group_type, members_json,
                result.get('description', ''), result.get('is_privileged', 0)
            ))

    def _update_host_fields(self, db, result):
        """Generic host field update."""
        mission_id = result['mission_id']
        ip = result['ip_address']
        fields = []
        values = []
        for key in ['hostname', 'domain', 'os_name', 'os_version', 'device_type',
                     'device_vendor', 'device_model', 'firmware_version', 'criticality',
                     'mac_address', 'notes']:
            if key in result and result[key]:
                fields.append(f"{key} = ?")
                values.append(result[key])
        if fields:
            fields.append("last_seen = datetime('now')")
            values.extend([mission_id, ip])
            db.execute(
                f"UPDATE hosts SET {', '.join(fields)} WHERE mission_id = ? AND ip_address = ?",
                values
            )

    # ─── Helpers ───

    def _find_subnet(self, db, mission_id, ip_str):
        """Find which subnet an IP belongs to."""
        try:
            ip = ipaddress.ip_address(ip_str)
            subnets = db.execute(
                "SELECT id, cidr FROM subnets WHERE mission_id = ?", (mission_id,)
            ).fetchall()
            for s in subnets:
                if ip in ipaddress.ip_network(s['cidr'], strict=False):
                    return s['id']
        except Exception:
            pass
        return None

    def _update_scan_status(self, scan_id, status, results_summary=None):
        """Update scan job status in DB."""
        db = self._get_db()
        ts_field = 'completed_at' if status in ('completed', 'failed', 'cancelled') else 'started_at'
        db.execute(
            f"UPDATE scan_jobs SET status = ?, results_summary = ?, {ts_field} = datetime('now') WHERE id = ?",
            (status, json.dumps(results_summary) if results_summary else None, scan_id)
        )
        db.commit()
        db.close()

    def report_progress(self, scan_id, mission_id, progress, message=''):
        """Report scan progress to connected clients."""
        self._emit('scan_progress', {
            'scan_id': scan_id,
            'progress': progress,
            'message': message
        }, mission_id)

    def log_action(self, scan_id, mission_id, message, severity='INFO',
                   category='general', source_ip=None, target_ip=None,
                   target_port=None, protocol=None, tool=None,
                   command=None, raw_detail=None):
        """
        Log a scan action for ROE compliance and operator accountability.
        Every network-touching operation MUST be logged through this method.

        Severities: INFO, ACTION, SEND, RECV, WARN, ERROR
        Categories: general, network_send, network_recv, tool_exec, discovery, config
        """
        # Sanitize credentials from commands before logging
        if command:
            command = self._sanitize_command(command)

        db = self._get_db()
        try:
            db.execute("""
                INSERT INTO scan_activity_log
                    (scan_id, mission_id, severity, category, source_ip, target_ip,
                     target_port, protocol, tool, command, message, raw_detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (scan_id, mission_id, severity, category, source_ip, target_ip,
                  target_port, protocol, tool, command, message, raw_detail))
            db.commit()
            row_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        except Exception as e:
            logger.error(f"Failed to write activity log: {e}")
            row_id = None
        finally:
            db.close()

        # Emit real-time to UI
        self._emit('scan_log', {
            'id': row_id,
            'scan_id': scan_id,
            'severity': severity,
            'category': category,
            'source_ip': source_ip,
            'target_ip': target_ip,
            'target_port': target_port,
            'protocol': protocol,
            'tool': tool,
            'command': command,
            'message': message,
            'raw_detail': raw_detail,
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        }, mission_id)

    @staticmethod
    def _sanitize_command(cmd):
        """Strip credentials from commands before logging."""
        import re
        # Replace -w 'password' or -p 'password' patterns
        cmd = re.sub(r"(-[wWpP])\s+'[^']*'", r"\1 '***REDACTED***'", cmd)
        cmd = re.sub(r"(-[wWpP])\s+\S+", r"\1 ***REDACTED***", cmd)
        # Replace inline passwords in URIs
        cmd = re.sub(r"://([^:]+):[^@]+@", r"://\1:***@", cmd)
        return cmd
