#!/usr/bin/env python3
"""
CPT Recon - Cyber Protection Team Reconnaissance & Baseline Tool
A mission-prep platform for threat hunters operating on unfamiliar networks.
Supports standalone (single operator) and team server (multi-analyst) modes.
"""

import os
import json
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, g, send_file
)
from flask_socketio import SocketIO, emit, join_room

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DATABASE'] = os.environ.get('DB_PATH', 'cpt_recon.db')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('cpt-recon')

# Scan engine (initialized after DB)
scan_engine = None

def get_scan_engine():
    """Lazy-initialize the scan engine."""
    global scan_engine
    if scan_engine is None:
        from modules.scan_engine import ScanEngine
        scan_engine = ScanEngine(app.config['DATABASE'], socketio)
    return scan_engine

# Scan engine (initialized after app start)
scan_engine = None

# Scan engine (initialized after app setup)
scan_engine = None

def get_scan_engine():
    global scan_engine
    if scan_engine is None:
        scan_engine = app.config.get('SCAN_ENGINE')
    return scan_engine

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")

    db.executescript("""
    -- Missions (each engagement/assessment)
    CREATE TABLE IF NOT EXISTS missions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        network_type TEXT DEFAULT 'IT',  -- IT, OT, Hybrid
        classification TEXT DEFAULT 'UNCLASSIFIED',
        status TEXT DEFAULT 'active',  -- active, completed, archived
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    );

    -- Discovered subnets
    CREATE TABLE IF NOT EXISTS subnets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER NOT NULL,
        cidr TEXT NOT NULL,
        vlan_id INTEGER,
        name TEXT,
        description TEXT,
        network_type TEXT DEFAULT 'IT',  -- IT, OT, DMZ, Management
        gateway TEXT,
        discovered_via TEXT,  -- passive, active
        discovered_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (mission_id) REFERENCES missions(id)
    );

    -- Discovered hosts
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER NOT NULL,
        ip_address TEXT NOT NULL,
        mac_address TEXT,
        hostname TEXT,
        domain TEXT,
        os_name TEXT,
        os_version TEXT,
        os_fingerprint_method TEXT,  -- passive_ttl, nmap, banner, wmi
        device_type TEXT,  -- workstation, server, dc, router, switch, plc, hmi, rtu, scada, firewall, printer, iot
        device_vendor TEXT,
        device_model TEXT,
        firmware_version TEXT,
        criticality TEXT DEFAULT 'medium',  -- critical, high, medium, low
        notes TEXT,
        discovered_via TEXT DEFAULT 'active',
        first_seen TEXT DEFAULT (datetime('now')),
        last_seen TEXT DEFAULT (datetime('now')),
        subnet_id INTEGER,
        is_alive INTEGER DEFAULT 1,
        FOREIGN KEY (mission_id) REFERENCES missions(id),
        FOREIGN KEY (subnet_id) REFERENCES subnets(id)
    );

    -- Host ports/services
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT DEFAULT 'tcp',
        state TEXT DEFAULT 'open',
        service_name TEXT,
        service_version TEXT,
        banner TEXT,
        is_ot_protocol INTEGER DEFAULT 0,
        ot_protocol_name TEXT,  -- modbus, dnp3, bacnet, ethernetip, s7comm, opcua
        notes TEXT,
        discovered_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );

    -- Network connections observed (traffic flows)
    CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER NOT NULL,
        src_host_id INTEGER,
        dst_host_id INTEGER,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        bytes_sent INTEGER DEFAULT 0,
        bytes_recv INTEGER DEFAULT 0,
        packet_count INTEGER DEFAULT 0,
        first_seen TEXT DEFAULT (datetime('now')),
        last_seen TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (mission_id) REFERENCES missions(id),
        FOREIGN KEY (src_host_id) REFERENCES hosts(id),
        FOREIGN KEY (dst_host_id) REFERENCES hosts(id)
    );

    -- AD/Domain information
    CREATE TABLE IF NOT EXISTS domain_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER NOT NULL,
        domain_name TEXT NOT NULL,
        forest_name TEXT,
        domain_controllers TEXT,  -- JSON array
        functional_level TEXT,
        trusts TEXT,  -- JSON array of trust relationships
        ous TEXT,  -- JSON array
        gpos TEXT,  -- JSON array
        discovered_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (mission_id) REFERENCES missions(id)
    );

    -- Privileged accounts and groups
    CREATE TABLE IF NOT EXISTS privileged_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER NOT NULL,
        account_name TEXT NOT NULL,
        account_type TEXT,  -- user, service, computer
        domain TEXT,
        groups TEXT,  -- JSON array
        is_admin INTEGER DEFAULT 0,
        last_logon TEXT,
        logon_count INTEGER,
        password_last_set TEXT,
        spn TEXT,  -- Service Principal Names (kerberoastable)
        notes TEXT,
        FOREIGN KEY (mission_id) REFERENCES missions(id)
    );

    -- OT-specific device details
    CREATE TABLE IF NOT EXISTS ot_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        device_class TEXT,  -- PLC, HMI, RTU, DCS, Engineering Workstation, Historian
        vendor TEXT,
        model TEXT,
        firmware TEXT,
        serial_number TEXT,
        protocol TEXT,
        master_slave_role TEXT,  -- master, slave, both
        connected_devices TEXT,  -- JSON array of host_ids
        io_config TEXT,  -- JSON - input/output configuration
        last_program_change TEXT,
        notes TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );

    -- Installed software inventory (per host)
    CREATE TABLE IF NOT EXISTS software_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        version TEXT,
        publisher TEXT,
        install_date TEXT,
        install_source TEXT,  -- wmi, registry, dpkg, rpm, snap
        architecture TEXT,    -- x64, x86, arm64
        collected_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );

    -- Running processes and services baseline (per host)
    CREATE TABLE IF NOT EXISTS running_processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        pid INTEGER,
        name TEXT NOT NULL,
        exe_path TEXT,
        command_line TEXT,
        username TEXT,
        parent_pid INTEGER,
        is_service INTEGER DEFAULT 0,
        service_name TEXT,        -- Windows service name or systemd unit
        service_display_name TEXT,
        service_state TEXT,       -- running, stopped, auto, manual
        start_type TEXT,          -- auto, manual, disabled, demand
        memory_bytes INTEGER,
        cpu_percent REAL,
        collected_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );

    -- Scheduled tasks (per host)
    CREATE TABLE IF NOT EXISTS scheduled_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        task_name TEXT NOT NULL,
        task_path TEXT,
        status TEXT,              -- Ready, Running, Disabled
        next_run TEXT,
        last_run TEXT,
        last_result TEXT,
        author TEXT,
        run_as_user TEXT,
        command TEXT,             -- action/command to execute
        trigger_info TEXT,        -- schedule description
        source TEXT,              -- schtasks, cron, systemd-timer
        collected_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );

    -- Local and domain group memberships (per host)
    CREATE TABLE IF NOT EXISTS local_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        group_name TEXT NOT NULL,
        group_type TEXT,          -- local, domain
        members TEXT,             -- JSON array of member names
        description TEXT,
        is_privileged INTEGER DEFAULT 0,
        collected_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );

    -- Scan/discovery jobs
    CREATE TABLE IF NOT EXISTS scan_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER NOT NULL,
        job_type TEXT NOT NULL,  -- passive_capture, arp_sweep, port_scan, service_scan, os_detect, ad_enum, ot_scan, full_active
        target TEXT,
        status TEXT DEFAULT 'pending',  -- pending, running, completed, failed, cancelled
        mode TEXT DEFAULT 'active',  -- passive, active
        aggressiveness INTEGER DEFAULT 3,  -- 1-5 scale
        config TEXT,  -- JSON config
        results_summary TEXT,  -- JSON summary
        started_at TEXT,
        completed_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        created_by TEXT,
        FOREIGN KEY (mission_id) REFERENCES missions(id)
    );

    -- Audit log
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        user_name TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );

    -- Scan activity log — granular per-action audit trail for ROE compliance
    CREATE TABLE IF NOT EXISTS scan_activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        mission_id INTEGER NOT NULL,
        timestamp TEXT DEFAULT (datetime('now')),
        severity TEXT DEFAULT 'INFO',    -- INFO, ACTION, SEND, RECV, WARN, ERROR
        category TEXT DEFAULT 'general', -- general, network_send, network_recv, tool_exec, discovery, config
        source_ip TEXT,                  -- our IP (if applicable)
        target_ip TEXT,                  -- target IP (if applicable)
        target_port INTEGER,             -- target port (if applicable)
        protocol TEXT,                   -- tcp, udp, icmp, arp, etc.
        tool TEXT,                       -- nmap, arping, ldapsearch, socket, etc.
        command TEXT,                    -- exact command executed (sanitized of creds)
        message TEXT NOT NULL,
        raw_detail TEXT,                 -- additional technical detail
        FOREIGN KEY (scan_id) REFERENCES scan_jobs(id),
        FOREIGN KEY (mission_id) REFERENCES missions(id)
    );

    -- Hunt hypotheses generated from intel + baseline
    CREATE TABLE IF NOT EXISTS hunt_hypotheses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        mitre_technique TEXT,
        target_hosts TEXT,  -- JSON array of host_ids
        priority TEXT DEFAULT 'medium',
        status TEXT DEFAULT 'pending',  -- pending, investigating, confirmed, false_positive
        evidence TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (mission_id) REFERENCES missions(id)
    );

    -- Threat intel (imported for the mission)
    CREATE TABLE IF NOT EXISTS threat_intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mission_id INTEGER NOT NULL,
        threat_actor TEXT,
        description TEXT,
        ttps TEXT,  -- JSON array of MITRE ATT&CK IDs
        iocs TEXT,  -- JSON array of IOCs
        target_sectors TEXT,
        source TEXT,
        imported_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (mission_id) REFERENCES missions(id)
    );
    """)
    db.commit()
    db.close()
    logger.info("Database initialized")

# ---------------------------------------------------------------------------
# Auth helpers (lightweight for field use)
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Routes - Auth
# ---------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simple passphrase-based auth for field deployment
        passphrase = request.form.get('passphrase', '')
        operator = request.form.get('operator', 'Operator')
        stored_hash = os.environ.get('AUTH_HASH', hashlib.sha256(b'cpt-recon-2024').hexdigest())
        if hashlib.sha256(passphrase.encode()).hexdigest() == stored_hash:
            session['authenticated'] = True
            session['operator'] = operator
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid passphrase')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------------------------------------------------------------------------
# Routes - Dashboard & Core Pages
# ---------------------------------------------------------------------------
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/mission/<int:mission_id>')
@login_required
def mission_view(mission_id):
    return render_template('mission.html', mission_id=mission_id)

@app.route('/mission/<int:mission_id>/topology')
@login_required
def topology_view(mission_id):
    return render_template('topology.html', mission_id=mission_id)

@app.route('/mission/<int:mission_id>/scans')
@login_required
def scan_control_view(mission_id):
    return render_template('scan_control.html', mission_id=mission_id)

# ---------------------------------------------------------------------------
# API - Missions
# ---------------------------------------------------------------------------
@app.route('/api/missions', methods=['GET'])
@login_required
def get_missions():
    db = get_db()
    missions = db.execute("""
        SELECT m.*,
            (SELECT COUNT(*) FROM hosts WHERE mission_id = m.id) as host_count,
            (SELECT COUNT(*) FROM subnets WHERE mission_id = m.id) as subnet_count,
            (SELECT COUNT(*) FROM scan_jobs WHERE mission_id = m.id) as scan_count
        FROM missions m ORDER BY m.updated_at DESC
    """).fetchall()
    return jsonify([dict(m) for m in missions])

@app.route('/api/missions', methods=['POST'])
@login_required
def create_mission():
    data = request.get_json()
    db = get_db()
    cursor = db.execute(
        "INSERT INTO missions (name, description, network_type, classification) VALUES (?, ?, ?, ?)",
        (data['name'], data.get('description', ''), data.get('network_type', 'IT'), data.get('classification', 'UNCLASSIFIED'))
    )
    db.commit()
    mission_id = cursor.lastrowid
    log_audit(db, mission_id, 'mission_created', f"Mission '{data['name']}' created")
    return jsonify({'id': mission_id, 'status': 'created'}), 201

@app.route('/api/missions/<int:mission_id>', methods=['GET'])
@login_required
def get_mission(mission_id):
    db = get_db()
    mission = db.execute("SELECT * FROM missions WHERE id = ?", (mission_id,)).fetchone()
    if not mission:
        return jsonify({'error': 'Mission not found'}), 404
    return jsonify(dict(mission))

@app.route('/api/missions/<int:mission_id>', methods=['PUT'])
@login_required
def update_mission(mission_id):
    data = request.get_json()
    db = get_db()
    db.execute(
        "UPDATE missions SET name=?, description=?, network_type=?, classification=?, status=?, updated_at=datetime('now') WHERE id=?",
        (data['name'], data.get('description',''), data.get('network_type','IT'), data.get('classification','UNCLASSIFIED'), data.get('status','active'), mission_id)
    )
    db.commit()
    return jsonify({'status': 'updated'})

# ---------------------------------------------------------------------------
# API - Hosts
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/hosts', methods=['GET'])
@login_required
def get_hosts(mission_id):
    db = get_db()
    hosts = db.execute("""
        SELECT h.*, s.cidr as subnet_cidr,
            (SELECT COUNT(*) FROM services WHERE host_id = h.id) as service_count,
            (SELECT GROUP_CONCAT(port || '/' || protocol || ':' || COALESCE(service_name,'')) FROM services WHERE host_id = h.id AND state='open') as open_ports_summary
        FROM hosts h
        LEFT JOIN subnets s ON h.subnet_id = s.id
        WHERE h.mission_id = ?
        ORDER BY h.ip_address
    """, (mission_id,)).fetchall()
    return jsonify([dict(h) for h in hosts])

@app.route('/api/missions/<int:mission_id>/hosts', methods=['POST'])
@login_required
def add_host(mission_id):
    data = request.get_json()
    db = get_db()
    cursor = db.execute("""
        INSERT INTO hosts (mission_id, ip_address, mac_address, hostname, domain, os_name, os_version,
            device_type, device_vendor, device_model, criticality, notes, discovered_via)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (mission_id, data['ip_address'], data.get('mac_address'), data.get('hostname'),
          data.get('domain'), data.get('os_name'), data.get('os_version'),
          data.get('device_type', 'unknown'), data.get('device_vendor'), data.get('device_model'),
          data.get('criticality', 'medium'), data.get('notes'), data.get('discovered_via', 'manual')))
    db.commit()
    host_id = cursor.lastrowid
    socketio.emit('host_discovered', {'mission_id': mission_id, 'host_id': host_id, 'ip': data['ip_address']}, room=f'mission_{mission_id}')
    return jsonify({'id': host_id, 'status': 'created'}), 201

@app.route('/api/hosts/<int:host_id>', methods=['GET'])
@login_required
def get_host_detail(host_id):
    db = get_db()
    host = db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if not host:
        return jsonify({'error': 'Host not found'}), 404
    services = db.execute("SELECT * FROM services WHERE host_id = ? ORDER BY port", (host_id,)).fetchall()
    connections = db.execute("""
        SELECT * FROM connections WHERE src_host_id = ? OR dst_host_id = ? ORDER BY last_seen DESC LIMIT 100
    """, (host_id, host_id)).fetchall()
    ot_device = db.execute("SELECT * FROM ot_devices WHERE host_id = ?", (host_id,)).fetchone()
    software = db.execute("SELECT * FROM software_inventory WHERE host_id = ? ORDER BY name", (host_id,)).fetchall()
    processes = db.execute("SELECT * FROM running_processes WHERE host_id = ? AND is_service = 0 ORDER BY name", (host_id,)).fetchall()
    host_services = db.execute("SELECT * FROM running_processes WHERE host_id = ? AND is_service = 1 ORDER BY service_name", (host_id,)).fetchall()
    tasks = db.execute("SELECT * FROM scheduled_tasks WHERE host_id = ? ORDER BY task_name", (host_id,)).fetchall()
    groups = db.execute("SELECT * FROM local_groups WHERE host_id = ? ORDER BY is_privileged DESC, group_name", (host_id,)).fetchall()
    return jsonify({
        'host': dict(host),
        'services': [dict(s) for s in services],
        'connections': [dict(c) for c in connections],
        'ot_device': dict(ot_device) if ot_device else None,
        'software': [dict(s) for s in software],
        'processes': [dict(p) for p in processes],
        'host_services': [dict(s) for s in host_services],
        'scheduled_tasks': [dict(t) for t in tasks],
        'local_groups': [dict(g) for g in groups],
    })

@app.route('/api/hosts/<int:host_id>', methods=['PUT'])
@login_required
def update_host(host_id):
    data = request.get_json()
    db = get_db()
    fields = []
    values = []
    allowed = ['hostname', 'domain', 'os_name', 'os_version', 'device_type', 'device_vendor',
               'device_model', 'firmware_version', 'criticality', 'notes', 'mac_address']
    for field in allowed:
        if field in data:
            fields.append(f"{field} = ?")
            values.append(data[field])
    if fields:
        values.append(host_id)
        db.execute(f"UPDATE hosts SET {', '.join(fields)}, last_seen = datetime('now') WHERE id = ?", values)
        db.commit()
    return jsonify({'status': 'updated'})

# ---------------------------------------------------------------------------
# API - Services
# ---------------------------------------------------------------------------
@app.route('/api/hosts/<int:host_id>/services', methods=['GET'])
@login_required
def get_services(host_id):
    db = get_db()
    services = db.execute("SELECT * FROM services WHERE host_id = ? ORDER BY port", (host_id,)).fetchall()
    return jsonify([dict(s) for s in services])

@app.route('/api/hosts/<int:host_id>/services', methods=['POST'])
@login_required
def add_service(host_id):
    data = request.get_json()
    db = get_db()
    cursor = db.execute("""
        INSERT INTO services (host_id, port, protocol, state, service_name, service_version, banner, is_ot_protocol, ot_protocol_name, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (host_id, data['port'], data.get('protocol', 'tcp'), data.get('state', 'open'),
          data.get('service_name'), data.get('service_version'), data.get('banner'),
          data.get('is_ot_protocol', 0), data.get('ot_protocol_name'), data.get('notes')))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'status': 'created'}), 201

# ---------------------------------------------------------------------------
# API - Host Profile Data (software, processes, tasks, groups)
# ---------------------------------------------------------------------------
@app.route('/api/hosts/<int:host_id>/software', methods=['GET'])
@login_required
def get_host_software(host_id):
    db = get_db()
    rows = db.execute("SELECT * FROM software_inventory WHERE host_id = ? ORDER BY name", (host_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/hosts/<int:host_id>/processes', methods=['GET'])
@login_required
def get_host_processes(host_id):
    db = get_db()
    rows = db.execute("SELECT * FROM running_processes WHERE host_id = ? AND is_service = 0 ORDER BY name", (host_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/hosts/<int:host_id>/host_services', methods=['GET'])
@login_required
def get_host_services(host_id):
    db = get_db()
    rows = db.execute("SELECT * FROM running_processes WHERE host_id = ? AND is_service = 1 ORDER BY service_name", (host_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/hosts/<int:host_id>/tasks', methods=['GET'])
@login_required
def get_host_tasks(host_id):
    db = get_db()
    rows = db.execute("SELECT * FROM scheduled_tasks WHERE host_id = ? ORDER BY task_name", (host_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/hosts/<int:host_id>/groups', methods=['GET'])
@login_required
def get_host_groups(host_id):
    db = get_db()
    rows = db.execute("SELECT * FROM local_groups WHERE host_id = ? ORDER BY is_privileged DESC, group_name", (host_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

# ---------------------------------------------------------------------------
# API - Subnets
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/subnets', methods=['GET'])
@login_required
def get_subnets(mission_id):
    db = get_db()
    subnets = db.execute("""
        SELECT s.*,
            (SELECT COUNT(*) FROM hosts WHERE subnet_id = s.id) as host_count
        FROM subnets s WHERE s.mission_id = ?
    """, (mission_id,)).fetchall()
    return jsonify([dict(s) for s in subnets])

@app.route('/api/missions/<int:mission_id>/subnets', methods=['POST'])
@login_required
def add_subnet(mission_id):
    data = request.get_json()
    db = get_db()
    cursor = db.execute(
        "INSERT INTO subnets (mission_id, cidr, vlan_id, name, description, network_type, gateway, discovered_via) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (mission_id, data['cidr'], data.get('vlan_id'), data.get('name'), data.get('description'),
         data.get('network_type', 'IT'), data.get('gateway'), data.get('discovered_via', 'manual'))
    )
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'status': 'created'}), 201

# ---------------------------------------------------------------------------
# API - Connections
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/connections', methods=['GET'])
@login_required
def get_connections(mission_id):
    db = get_db()
    connections = db.execute("""
        SELECT c.*,
            sh.ip_address as src_ip_resolved, sh.hostname as src_hostname, sh.device_type as src_device_type,
            dh.ip_address as dst_ip_resolved, dh.hostname as dst_hostname, dh.device_type as dst_device_type
        FROM connections c
        LEFT JOIN hosts sh ON c.src_host_id = sh.id
        LEFT JOIN hosts dh ON c.dst_host_id = dh.id
        WHERE c.mission_id = ?
        ORDER BY c.packet_count DESC
    """, (mission_id,)).fetchall()
    return jsonify([dict(c) for c in connections])

# ---------------------------------------------------------------------------
# API - Topology Data (for visualization)
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/topology', methods=['GET'])
@login_required
def get_topology(mission_id):
    db = get_db()

    # Get all hosts with their services
    hosts = db.execute("""
        SELECT h.*,
            s.cidr as subnet_cidr, s.network_type as subnet_type, s.name as subnet_name,
            (SELECT COUNT(*) FROM services WHERE host_id = h.id AND state = 'open') as open_port_count,
            (SELECT GROUP_CONCAT(DISTINCT service_name) FROM services WHERE host_id = h.id AND state = 'open' AND service_name IS NOT NULL) as service_list
        FROM hosts h
        LEFT JOIN subnets s ON h.subnet_id = s.id
        WHERE h.mission_id = ?
    """, (mission_id,)).fetchall()

    # Get all connections
    connections = db.execute("""
        SELECT c.*, 
            sh.ip_address as src_ip_addr, dh.ip_address as dst_ip_addr
        FROM connections c
        LEFT JOIN hosts sh ON c.src_host_id = sh.id
        LEFT JOIN hosts dh ON c.dst_host_id = dh.id
        WHERE c.mission_id = ?
    """, (mission_id,)).fetchall()

    # Get subnets
    subnets = db.execute("SELECT * FROM subnets WHERE mission_id = ?", (mission_id,)).fetchall()

    # Get OT devices
    ot_devices = db.execute("""
        SELECT o.*, h.ip_address, h.hostname
        FROM ot_devices o
        JOIN hosts h ON o.host_id = h.id
        WHERE h.mission_id = ?
    """, (mission_id,)).fetchall()

    # Build topology graph data
    nodes = []
    for h in hosts:
        hd = dict(h)
        node = {
            'id': hd['id'],
            'ip': hd['ip_address'],
            'hostname': hd['hostname'] or hd['ip_address'],
            'mac': hd['mac_address'],
            'os': hd['os_name'],
            'device_type': hd['device_type'] or 'unknown',
            'criticality': hd['criticality'],
            'subnet_cidr': hd['subnet_cidr'],
            'subnet_type': hd['subnet_type'],
            'subnet_name': hd['subnet_name'],
            'open_ports': hd['open_port_count'],
            'services': hd['service_list'],
            'domain': hd['domain'],
            'vendor': hd['device_vendor'],
            'model': hd['device_model'],
            'firmware': hd['firmware_version'],
            'is_alive': hd['is_alive']
        }
        nodes.append(node)

    edges = []
    for c in connections:
        cd = dict(c)
        edges.append({
            'source': cd['src_host_id'],
            'target': cd['dst_host_id'],
            'src_ip': cd['src_ip_addr'],
            'dst_ip': cd['dst_ip_addr'],
            'protocol': cd['protocol'],
            'dst_port': cd['dst_port'],
            'packet_count': cd['packet_count'],
            'bytes_total': (cd['bytes_sent'] or 0) + (cd['bytes_recv'] or 0)
        })

    subnet_groups = []
    for s in subnets:
        sd = dict(s)
        subnet_groups.append({
            'id': sd['id'],
            'cidr': sd['cidr'],
            'name': sd['name'] or sd['cidr'],
            'type': sd['network_type'],
            'vlan': sd['vlan_id'],
            'gateway': sd['gateway']
        })

    return jsonify({
        'nodes': nodes,
        'edges': edges,
        'subnets': subnet_groups,
        'ot_devices': [dict(o) for o in ot_devices],
        'stats': {
            'total_hosts': len(nodes),
            'total_connections': len(edges),
            'total_subnets': len(subnet_groups),
            'by_device_type': {},
            'by_os': {},
            'by_criticality': {}
        }
    })

# ---------------------------------------------------------------------------
# API - Scan Jobs
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/scans', methods=['GET'])
@login_required
def get_scans(mission_id):
    db = get_db()
    scans = db.execute("SELECT * FROM scan_jobs WHERE mission_id = ? ORDER BY created_at DESC", (mission_id,)).fetchall()
    return jsonify([dict(s) for s in scans])

@app.route('/api/missions/<int:mission_id>/scans', methods=['POST'])
@login_required
def create_scan(mission_id):
    data = request.get_json()
    db = get_db()
    cursor = db.execute("""
        INSERT INTO scan_jobs (mission_id, job_type, target, mode, aggressiveness, config, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (mission_id, data['job_type'], data.get('target', ''),
          data.get('mode', 'active'), data.get('aggressiveness', 3),
          json.dumps(data.get('config', {})), session.get('operator', 'unknown')))
    db.commit()
    scan_id = cursor.lastrowid
    log_audit(db, mission_id, 'scan_created', f"Scan job {data['job_type']} created targeting {data.get('target', 'N/A')}")
    socketio.emit('scan_created', {'mission_id': mission_id, 'scan_id': scan_id, 'type': data['job_type']}, room=f'mission_{mission_id}')

    # Auto-start scan if requested
    if data.get('auto_start', True):
        engine = get_scan_engine()
        if engine:
            engine.start_scan(scan_id, mission_id)

    return jsonify({'id': scan_id, 'status': 'created'}), 201

@app.route('/api/scans/<int:scan_id>/start', methods=['POST'])
@login_required
def start_scan(scan_id):
    db = get_db()
    job = db.execute("SELECT mission_id FROM scan_jobs WHERE id = ?", (scan_id,)).fetchone()
    if not job:
        return jsonify({'error': 'Scan not found'}), 404
    if get_scan_engine():
        get_scan_engine().start_scan(scan_id, job['mission_id'])
        return jsonify({'status': 'started'})
    return jsonify({'error': 'Scan engine not initialized'}), 500

@app.route('/api/scans/<int:scan_id>/stop', methods=['POST'])
@login_required
def stop_scan(scan_id):
    if get_scan_engine():
        get_scan_engine().stop_scan(scan_id)
        return jsonify({'status': 'stopping'})
    return jsonify({'error': 'Scan engine not initialized'}), 500

@app.route('/api/scans/<int:scan_id>/cancel', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    """Cancel a scan — works for pending scans or as a stop for running ones."""
    db = get_db()
    job = db.execute("SELECT status, mission_id FROM scan_jobs WHERE id = ?", (scan_id,)).fetchone()
    if not job:
        return jsonify({'error': 'Scan not found'}), 404

    if job['status'] == 'running':
        # Signal running scan to stop
        engine = get_scan_engine()
        if engine:
            engine.stop_scan(scan_id)
        db.execute("UPDATE scan_jobs SET status = 'cancelled', completed_at = datetime('now') WHERE id = ?", (scan_id,))
        db.commit()
        log_audit(db, job['mission_id'], 'scan_cancelled', f"Scan #{scan_id} cancelled by operator")
        socketio.emit('scan_status', {'scan_id': scan_id, 'status': 'cancelled'}, room=f'mission_{job["mission_id"]}')
        return jsonify({'status': 'cancelled'})
    elif job['status'] == 'pending':
        db.execute("UPDATE scan_jobs SET status = 'cancelled', completed_at = datetime('now') WHERE id = ?", (scan_id,))
        db.commit()
        log_audit(db, job['mission_id'], 'scan_cancelled', f"Scan #{scan_id} cancelled before start")
        socketio.emit('scan_status', {'scan_id': scan_id, 'status': 'cancelled'}, room=f'mission_{job["mission_id"]}')
        return jsonify({'status': 'cancelled'})
    else:
        return jsonify({'error': f'Cannot cancel scan in state: {job["status"]}'}), 400

@app.route('/api/scans/active', methods=['GET'])
@login_required
def get_active_scans():
    if get_scan_engine():
        return jsonify({'active': get_scan_engine().get_active_scans()})
    return jsonify({'active': []})

# ---------------------------------------------------------------------------
# API - Scan Activity Log (ROE Compliance)
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/activity_log', methods=['GET'])
@login_required
def get_mission_activity_log(mission_id):
    """Get all scan activity for a mission, ordered chronologically."""
    db = get_db()
    limit = request.args.get('limit', 500, type=int)
    after_id = request.args.get('after_id', 0, type=int)
    scan_id_filter = request.args.get('scan_id', None, type=int)

    query = "SELECT * FROM scan_activity_log WHERE mission_id = ? AND id > ?"
    params = [mission_id, after_id]

    if scan_id_filter:
        query += " AND scan_id = ?"
        params.append(scan_id_filter)

    query += " ORDER BY id ASC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/scans/<int:scan_id>/activity_log', methods=['GET'])
@login_required
def get_scan_activity_log(scan_id):
    """Get all activity for a specific scan."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM scan_activity_log WHERE scan_id = ? ORDER BY id ASC",
        (scan_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/missions/<int:mission_id>/activity_log/export', methods=['GET'])
@login_required
def export_activity_log(mission_id):
    """Export full activity log as formatted text for operator notes."""
    db = get_db()
    mission = db.execute("SELECT * FROM missions WHERE id = ?", (mission_id,)).fetchone()
    rows = db.execute(
        "SELECT * FROM scan_activity_log WHERE mission_id = ? ORDER BY id ASC",
        (mission_id,)
    ).fetchall()

    lines = []
    lines.append("=" * 80)
    lines.append(f"CPT RECON — ACTIONS ON NETWORK LOG")
    lines.append(f"Mission: {mission['name'] if mission else 'Unknown'}")
    lines.append(f"Exported: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"Total Entries: {len(rows)}")
    lines.append("=" * 80)
    lines.append("")

    for r in rows:
        r = dict(r)
        ts = r['timestamp']
        sev = r['severity'].ljust(6)
        cat = r['category']
        msg = r['message']
        line = f"[{ts}] [{sev}] [{cat}] {msg}"

        if r.get('target_ip'):
            target_str = r['target_ip']
            if r.get('target_port'):
                target_str += f":{r['target_port']}"
            if r.get('protocol'):
                target_str += f" ({r['protocol']})"
            line += f"  →  {target_str}"

        if r.get('tool'):
            line += f"  [tool: {r['tool']}]"

        lines.append(line)

        if r.get('command'):
            lines.append(f"    CMD: {r['command']}")
        if r.get('raw_detail'):
            lines.append(f"    DETAIL: {r['raw_detail']}")

    lines.append("")
    lines.append("=" * 80)
    lines.append("END OF LOG")
    lines.append("=" * 80)

    return '\n'.join(lines), 200, {
        'Content-Type': 'text/plain',
        'Content-Disposition': f'attachment; filename=actions_on_net_mission_{mission_id}.txt'
    }

# ---------------------------------------------------------------------------
# API - Threat Intel
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/threat_intel', methods=['GET'])
@login_required
def get_threat_intel(mission_id):
    db = get_db()
    intel = db.execute("SELECT * FROM threat_intel WHERE mission_id = ? ORDER BY imported_at DESC", (mission_id,)).fetchall()
    return jsonify([dict(i) for i in intel])

@app.route('/api/missions/<int:mission_id>/threat_intel', methods=['POST'])
@login_required
def add_threat_intel(mission_id):
    data = request.get_json()
    db = get_db()
    cursor = db.execute("""
        INSERT INTO threat_intel (mission_id, threat_actor, description, ttps, iocs, target_sectors, source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (mission_id, data.get('threat_actor'), data.get('description'),
          json.dumps(data.get('ttps', [])), json.dumps(data.get('iocs', [])),
          data.get('target_sectors'), data.get('source')))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'status': 'created'}), 201

# ---------------------------------------------------------------------------
# API - Hunt Hypotheses
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/hypotheses', methods=['GET'])
@login_required
def get_hypotheses(mission_id):
    db = get_db()
    hyps = db.execute("SELECT * FROM hunt_hypotheses WHERE mission_id = ? ORDER BY created_at DESC", (mission_id,)).fetchall()
    return jsonify([dict(h) for h in hyps])

@app.route('/api/missions/<int:mission_id>/hypotheses', methods=['POST'])
@login_required
def add_hypothesis(mission_id):
    data = request.get_json()
    db = get_db()
    cursor = db.execute("""
        INSERT INTO hunt_hypotheses (mission_id, title, description, mitre_technique, target_hosts, priority)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (mission_id, data['title'], data.get('description'), data.get('mitre_technique'),
          json.dumps(data.get('target_hosts', [])), data.get('priority', 'medium')))
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'status': 'created'}), 201

# ---------------------------------------------------------------------------
# API - Domain Info
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/domain_info', methods=['GET'])
@login_required
def get_domain_info(mission_id):
    db = get_db()
    domains = db.execute("SELECT * FROM domain_info WHERE mission_id = ?", (mission_id,)).fetchall()
    return jsonify([dict(d) for d in domains])

# ---------------------------------------------------------------------------
# API - Privileged Accounts
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/privileged_accounts', methods=['GET'])
@login_required
def get_privileged_accounts(mission_id):
    db = get_db()
    accounts = db.execute("SELECT * FROM privileged_accounts WHERE mission_id = ? ORDER BY is_admin DESC", (mission_id,)).fetchall()
    return jsonify([dict(a) for a in accounts])

# ---------------------------------------------------------------------------
# API - Stats/Metrics
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/stats', methods=['GET'])
@login_required
def get_mission_stats(mission_id):
    db = get_db()
    stats = {
        'hosts': {
            'total': db.execute("SELECT COUNT(*) FROM hosts WHERE mission_id = ?", (mission_id,)).fetchone()[0],
            'alive': db.execute("SELECT COUNT(*) FROM hosts WHERE mission_id = ? AND is_alive = 1", (mission_id,)).fetchone()[0],
            'by_type': {},
            'by_os': {},
            'by_criticality': {}
        },
        'services': {
            'total': db.execute("SELECT COUNT(*) FROM services s JOIN hosts h ON s.host_id = h.id WHERE h.mission_id = ?", (mission_id,)).fetchone()[0],
            'ot_protocols': db.execute("SELECT COUNT(*) FROM services s JOIN hosts h ON s.host_id = h.id WHERE h.mission_id = ? AND s.is_ot_protocol = 1", (mission_id,)).fetchone()[0],
        },
        'subnets': db.execute("SELECT COUNT(*) FROM subnets WHERE mission_id = ?", (mission_id,)).fetchone()[0],
        'connections': db.execute("SELECT COUNT(*) FROM connections WHERE mission_id = ?", (mission_id,)).fetchone()[0],
        'scans': {
            'total': db.execute("SELECT COUNT(*) FROM scan_jobs WHERE mission_id = ?", (mission_id,)).fetchone()[0],
            'running': db.execute("SELECT COUNT(*) FROM scan_jobs WHERE mission_id = ? AND status = 'running'", (mission_id,)).fetchone()[0],
        },
        'profile': {
            'software': db.execute("SELECT COUNT(*) FROM software_inventory si JOIN hosts h ON si.host_id = h.id WHERE h.mission_id = ?", (mission_id,)).fetchone()[0],
            'processes': db.execute("SELECT COUNT(*) FROM running_processes rp JOIN hosts h ON rp.host_id = h.id WHERE h.mission_id = ? AND rp.is_service = 0", (mission_id,)).fetchone()[0],
            'services_baselined': db.execute("SELECT COUNT(*) FROM running_processes rp JOIN hosts h ON rp.host_id = h.id WHERE h.mission_id = ? AND rp.is_service = 1", (mission_id,)).fetchone()[0],
            'tasks': db.execute("SELECT COUNT(*) FROM scheduled_tasks st JOIN hosts h ON st.host_id = h.id WHERE h.mission_id = ?", (mission_id,)).fetchone()[0],
            'groups': db.execute("SELECT COUNT(*) FROM local_groups lg JOIN hosts h ON lg.host_id = h.id WHERE h.mission_id = ?", (mission_id,)).fetchone()[0],
            'hosts_profiled': db.execute("SELECT COUNT(DISTINCT si.host_id) FROM software_inventory si JOIN hosts h ON si.host_id = h.id WHERE h.mission_id = ?", (mission_id,)).fetchone()[0],
        }
    }

    # By device type
    for row in db.execute("SELECT device_type, COUNT(*) as cnt FROM hosts WHERE mission_id = ? GROUP BY device_type", (mission_id,)):
        stats['hosts']['by_type'][row['device_type'] or 'unknown'] = row['cnt']

    # By OS
    for row in db.execute("SELECT os_name, COUNT(*) as cnt FROM hosts WHERE mission_id = ? AND os_name IS NOT NULL GROUP BY os_name", (mission_id,)):
        stats['hosts']['by_os'][row['os_name']] = row['cnt']

    # By criticality
    for row in db.execute("SELECT criticality, COUNT(*) as cnt FROM hosts WHERE mission_id = ? GROUP BY criticality", (mission_id,)):
        stats['hosts']['by_criticality'][row['criticality']] = row['cnt']

    return jsonify(stats)

# ---------------------------------------------------------------------------
# API - Import/Export
# ---------------------------------------------------------------------------
@app.route('/api/missions/<int:mission_id>/export', methods=['GET'])
@login_required
def export_mission(mission_id):
    db = get_db()
    mission = dict(db.execute("SELECT * FROM missions WHERE id = ?", (mission_id,)).fetchone())
    export_data = {
        'mission': mission,
        'hosts': [dict(h) for h in db.execute("SELECT * FROM hosts WHERE mission_id = ?", (mission_id,)).fetchall()],
        'subnets': [dict(s) for s in db.execute("SELECT * FROM subnets WHERE mission_id = ?", (mission_id,)).fetchall()],
        'services': [dict(s) for s in db.execute("""
            SELECT s.* FROM services s JOIN hosts h ON s.host_id = h.id WHERE h.mission_id = ?
        """, (mission_id,)).fetchall()],
        'connections': [dict(c) for c in db.execute("SELECT * FROM connections WHERE mission_id = ?", (mission_id,)).fetchall()],
        'domain_info': [dict(d) for d in db.execute("SELECT * FROM domain_info WHERE mission_id = ?", (mission_id,)).fetchall()],
        'threat_intel': [dict(t) for t in db.execute("SELECT * FROM threat_intel WHERE mission_id = ?", (mission_id,)).fetchall()],
        'hypotheses': [dict(h) for h in db.execute("SELECT * FROM hunt_hypotheses WHERE mission_id = ?", (mission_id,)).fetchall()],
        'software_inventory': [dict(s) for s in db.execute("""
            SELECT si.* FROM software_inventory si JOIN hosts h ON si.host_id = h.id WHERE h.mission_id = ?
        """, (mission_id,)).fetchall()],
        'running_processes': [dict(p) for p in db.execute("""
            SELECT rp.* FROM running_processes rp JOIN hosts h ON rp.host_id = h.id WHERE h.mission_id = ?
        """, (mission_id,)).fetchall()],
        'scheduled_tasks': [dict(t) for t in db.execute("""
            SELECT st.* FROM scheduled_tasks st JOIN hosts h ON st.host_id = h.id WHERE h.mission_id = ?
        """, (mission_id,)).fetchall()],
        'local_groups': [dict(g) for g in db.execute("""
            SELECT lg.* FROM local_groups lg JOIN hosts h ON lg.host_id = h.id WHERE h.mission_id = ?
        """, (mission_id,)).fetchall()],
        'exported_at': datetime.now(timezone.utc).isoformat()
    }
    return jsonify(export_data)

# ---------------------------------------------------------------------------
# API - Demo/Seed Data
# ---------------------------------------------------------------------------
@app.route('/api/demo/seed', methods=['POST'])
@login_required
def seed_demo_data():
    """Seed realistic demo data for demonstration purposes"""
    db = get_db()

    # Create a demo mission
    cursor = db.execute(
        "INSERT INTO missions (name, description, network_type, classification) VALUES (?, ?, ?, ?)",
        ("Operation IRON SENTINEL", "CPT assessment of critical infrastructure SCADA network with hybrid IT/OT environment. Threat intel indicates APT targeting energy sector ICS.", "Hybrid", "UNCLASSIFIED//FOUO")
    )
    mid = cursor.lastrowid

    # Create subnets
    subnets_data = [
        (mid, "10.10.1.0/24", 10, "Corporate IT", "Standard corporate workstations and servers", "IT", "10.10.1.1", "active"),
        (mid, "10.10.2.0/24", 20, "Server Farm", "Data center servers and domain controllers", "IT", "10.10.2.1", "active"),
        (mid, "10.10.3.0/24", 30, "DMZ", "Internet-facing services", "DMZ", "10.10.3.1", "active"),
        (mid, "172.16.50.0/24", 100, "OT Control Network", "SCADA/ICS control systems", "OT", "172.16.50.1", "active"),
        (mid, "172.16.51.0/24", 101, "OT Field Devices", "PLCs, RTUs, and field instruments", "OT", "172.16.51.1", "active"),
        (mid, "192.168.100.0/24", 200, "Management", "Network management and monitoring", "Management", "192.168.100.1", "active"),
    ]
    subnet_ids = {}
    for s in subnets_data:
        c = db.execute("INSERT INTO subnets (mission_id, cidr, vlan_id, name, description, network_type, gateway, discovered_via) VALUES (?,?,?,?,?,?,?,?)", s)
        subnet_ids[s[1]] = c.lastrowid

    # Create hosts
    hosts_data = [
        # Corporate IT
        (mid, "10.10.1.10", "AA:BB:CC:01:01:0A", "WS-ADMIN01", "energy.local", "Windows 11", "23H2", "workstation", "Dell", "OptiPlex 7090", "high", subnet_ids["10.10.1.0/24"]),
        (mid, "10.10.1.11", "AA:BB:CC:01:01:0B", "WS-ENG01", "energy.local", "Windows 10", "21H2", "workstation", "HP", "EliteDesk 800", "medium", subnet_ids["10.10.1.0/24"]),
        (mid, "10.10.1.12", "AA:BB:CC:01:01:0C", "WS-ENG02", "energy.local", "Windows 10", "21H2", "workstation", "HP", "EliteDesk 800", "medium", subnet_ids["10.10.1.0/24"]),
        (mid, "10.10.1.50", "AA:BB:CC:01:01:32", "PRINTER-FL1", None, None, None, "printer", "HP", "LaserJet Pro", "low", subnet_ids["10.10.1.0/24"]),

        # Server Farm
        (mid, "10.10.2.10", "AA:BB:CC:02:02:0A", "DC01", "energy.local", "Windows Server 2019", "1809", "dc", "Dell", "PowerEdge R740", "critical", subnet_ids["10.10.2.0/24"]),
        (mid, "10.10.2.11", "AA:BB:CC:02:02:0B", "DC02", "energy.local", "Windows Server 2019", "1809", "dc", "Dell", "PowerEdge R740", "critical", subnet_ids["10.10.2.0/24"]),
        (mid, "10.10.2.20", "AA:BB:CC:02:02:14", "FILE-SRV01", "energy.local", "Windows Server 2016", "1607", "server", "Dell", "PowerEdge R640", "high", subnet_ids["10.10.2.0/24"]),
        (mid, "10.10.2.30", "AA:BB:CC:02:02:1E", "EXCHANGE01", "energy.local", "Windows Server 2016", "1607", "server", "Dell", "PowerEdge R640", "high", subnet_ids["10.10.2.0/24"]),
        (mid, "10.10.2.40", "AA:BB:CC:02:02:28", "SCCM01", "energy.local", "Windows Server 2019", "1809", "server", "Dell", "PowerEdge R740", "high", subnet_ids["10.10.2.0/24"]),
        (mid, "10.10.2.50", "AA:BB:CC:02:02:32", "WSUS01", "energy.local", "Windows Server 2016", "1607", "server", "HP", "ProLiant DL380", "medium", subnet_ids["10.10.2.0/24"]),

        # DMZ
        (mid, "10.10.3.10", "AA:BB:CC:03:03:0A", "WEB-EXT01", None, "Ubuntu", "22.04", "server", "Dell", "PowerEdge R340", "high", subnet_ids["10.10.3.0/24"]),
        (mid, "10.10.3.20", "AA:BB:CC:03:03:14", "VPN-GW01", None, "Palo Alto PAN-OS", "11.0", "firewall", "Palo Alto", "PA-3260", "critical", subnet_ids["10.10.3.0/24"]),

        # OT Control Network
        (mid, "172.16.50.10", "AA:BB:CC:32:32:0A", "SCADA-SRV01", None, "Windows Server 2012 R2", "6.3", "server", "Dell", "PowerEdge T440", "critical", subnet_ids["172.16.50.0/24"]),
        (mid, "172.16.50.11", "AA:BB:CC:32:32:0B", "HIST-SRV01", None, "Windows Server 2016", "1607", "server", "HP", "ProLiant DL360", "critical", subnet_ids["172.16.50.0/24"]),
        (mid, "172.16.50.20", "AA:BB:CC:32:32:14", "HMI-01", None, "Windows 7", "SP1", "workstation", "Siemens", "IPC477E", "critical", subnet_ids["172.16.50.0/24"]),
        (mid, "172.16.50.21", "AA:BB:CC:32:32:15", "HMI-02", None, "Windows 7", "SP1", "workstation", "Siemens", "IPC477E", "critical", subnet_ids["172.16.50.0/24"]),
        (mid, "172.16.50.30", "AA:BB:CC:32:32:1E", "ENG-WS01", None, "Windows 10", "LTSC 2021", "workstation", "Dell", "Precision 3640", "critical", subnet_ids["172.16.50.0/24"]),

        # OT Field Devices
        (mid, "172.16.51.10", "AA:BB:CC:33:33:0A", "PLC-TURB01", None, None, None, "plc", "Siemens", "S7-1500", "critical", subnet_ids["172.16.51.0/24"]),
        (mid, "172.16.51.11", "AA:BB:CC:33:33:0B", "PLC-TURB02", None, None, None, "plc", "Siemens", "S7-1500", "critical", subnet_ids["172.16.51.0/24"]),
        (mid, "172.16.51.20", "AA:BB:CC:33:33:14", "PLC-PUMP01", None, None, None, "plc", "Allen-Bradley", "ControlLogix 5580", "critical", subnet_ids["172.16.51.0/24"]),
        (mid, "172.16.51.30", "AA:BB:CC:33:33:1E", "RTU-SUB01", None, None, None, "rtu", "SEL", "SEL-3530", "critical", subnet_ids["172.16.51.0/24"]),
        (mid, "172.16.51.40", "AA:BB:CC:33:33:28", "RTU-SUB02", None, None, None, "rtu", "GE", "D25", "critical", subnet_ids["172.16.51.0/24"]),

        # Management
        (mid, "192.168.100.10", "AA:BB:CC:C8:C8:0A", "SIEM01", None, "CentOS", "7.9", "server", "Dell", "PowerEdge R740", "high", subnet_ids["192.168.100.0/24"]),
        (mid, "192.168.100.20", "AA:BB:CC:C8:C8:14", "NMS01", None, "Ubuntu", "20.04", "server", "HP", "ProLiant DL380", "high", subnet_ids["192.168.100.0/24"]),
        (mid, "192.168.100.30", "AA:BB:CC:C8:C8:1E", "JUMP-SRV01", "energy.local", "Windows Server 2019", "1809", "server", "Dell", "PowerEdge R640", "critical", subnet_ids["192.168.100.0/24"]),
    ]

    host_ids = {}
    for h in hosts_data:
        c = db.execute("""
            INSERT INTO hosts (mission_id, ip_address, mac_address, hostname, domain, os_name, os_version,
                device_type, device_vendor, device_model, criticality, subnet_id, discovered_via)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
        """, h)
        host_ids[h[1]] = c.lastrowid

    # Add services to hosts
    services_data = [
        # DC01
        (host_ids["10.10.2.10"], 53, "tcp", "open", "dns", "Microsoft DNS", None, 0, None),
        (host_ids["10.10.2.10"], 88, "tcp", "open", "kerberos", "Microsoft Kerberos", None, 0, None),
        (host_ids["10.10.2.10"], 135, "tcp", "open", "msrpc", "Microsoft RPC", None, 0, None),
        (host_ids["10.10.2.10"], 389, "tcp", "open", "ldap", "Microsoft LDAP", None, 0, None),
        (host_ids["10.10.2.10"], 445, "tcp", "open", "smb", "Microsoft SMB 3.0", None, 0, None),
        (host_ids["10.10.2.10"], 636, "tcp", "open", "ldaps", "Microsoft LDAPS", None, 0, None),
        (host_ids["10.10.2.10"], 3389, "tcp", "open", "rdp", "Microsoft RDP", None, 0, None),

        # DC02
        (host_ids["10.10.2.11"], 53, "tcp", "open", "dns", "Microsoft DNS", None, 0, None),
        (host_ids["10.10.2.11"], 88, "tcp", "open", "kerberos", "Microsoft Kerberos", None, 0, None),
        (host_ids["10.10.2.11"], 389, "tcp", "open", "ldap", "Microsoft LDAP", None, 0, None),
        (host_ids["10.10.2.11"], 445, "tcp", "open", "smb", "Microsoft SMB 3.0", None, 0, None),

        # Web server
        (host_ids["10.10.3.10"], 80, "tcp", "open", "http", "Apache 2.4.54", None, 0, None),
        (host_ids["10.10.3.10"], 443, "tcp", "open", "https", "Apache 2.4.54", None, 0, None),
        (host_ids["10.10.3.10"], 22, "tcp", "open", "ssh", "OpenSSH 8.9", None, 0, None),

        # VPN Gateway
        (host_ids["10.10.3.20"], 443, "tcp", "open", "ssl-vpn", "GlobalProtect", None, 0, None),
        (host_ids["10.10.3.20"], 4443, "tcp", "open", "management", "PAN-OS WebUI", None, 0, None),

        # SCADA Server
        (host_ids["172.16.50.10"], 502, "tcp", "open", "modbus", "Modbus/TCP", None, 1, "modbus"),
        (host_ids["172.16.50.10"], 20000, "tcp", "open", "dnp3", "DNP3", None, 1, "dnp3"),
        (host_ids["172.16.50.10"], 3389, "tcp", "open", "rdp", "Microsoft RDP", None, 0, None),
        (host_ids["172.16.50.10"], 102, "tcp", "open", "s7comm", "Siemens S7", None, 1, "s7comm"),

        # Historian
        (host_ids["172.16.50.11"], 1433, "tcp", "open", "mssql", "SQL Server 2016", None, 0, None),
        (host_ids["172.16.50.11"], 3389, "tcp", "open", "rdp", "Microsoft RDP", None, 0, None),

        # PLCs
        (host_ids["172.16.51.10"], 102, "tcp", "open", "s7comm", "Siemens S7-1500", "S7 Protocol v3.0", 1, "s7comm"),
        (host_ids["172.16.51.11"], 102, "tcp", "open", "s7comm", "Siemens S7-1500", "S7 Protocol v3.0", 1, "s7comm"),
        (host_ids["172.16.51.20"], 44818, "tcp", "open", "ethernetip", "EtherNet/IP", "CIP v1.0", 1, "ethernetip"),
        (host_ids["172.16.51.20"], 2222, "tcp", "open", "ethernetip", "EtherNet/IP (implicit)", None, 1, "ethernetip"),

        # RTUs
        (host_ids["172.16.51.30"], 20000, "tcp", "open", "dnp3", "DNP3", None, 1, "dnp3"),
        (host_ids["172.16.51.40"], 20000, "tcp", "open", "dnp3", "DNP3", None, 1, "dnp3"),
        (host_ids["172.16.51.40"], 502, "tcp", "open", "modbus", "Modbus/TCP", None, 1, "modbus"),

        # Exchange
        (host_ids["10.10.2.30"], 25, "tcp", "open", "smtp", "Microsoft Exchange 2016", None, 0, None),
        (host_ids["10.10.2.30"], 443, "tcp", "open", "https", "Microsoft Exchange OWA", None, 0, None),
        (host_ids["10.10.2.30"], 445, "tcp", "open", "smb", "Microsoft SMB", None, 0, None),

        # Jump Server
        (host_ids["192.168.100.30"], 3389, "tcp", "open", "rdp", "Microsoft RDP", None, 0, None),
        (host_ids["192.168.100.30"], 22, "tcp", "open", "ssh", "OpenSSH 8.1", None, 0, None),
        (host_ids["192.168.100.30"], 445, "tcp", "open", "smb", "Microsoft SMB 3.0", None, 0, None),

        # SIEM
        (host_ids["192.168.100.10"], 514, "udp", "open", "syslog", "rsyslog", None, 0, None),
        (host_ids["192.168.100.10"], 9200, "tcp", "open", "elasticsearch", "Elasticsearch 7.17", None, 0, None),
        (host_ids["192.168.100.10"], 5601, "tcp", "open", "kibana", "Kibana 7.17", None, 0, None),

        # File Server
        (host_ids["10.10.2.20"], 445, "tcp", "open", "smb", "Microsoft SMB 3.0", None, 0, None),
        (host_ids["10.10.2.20"], 3389, "tcp", "open", "rdp", "Microsoft RDP", None, 0, None),

        # HMIs
        (host_ids["172.16.50.20"], 80, "tcp", "open", "http", "Siemens WinCC", None, 1, "opcua"),
        (host_ids["172.16.50.20"], 102, "tcp", "open", "s7comm", "Siemens S7", None, 1, "s7comm"),
        (host_ids["172.16.50.21"], 80, "tcp", "open", "http", "Siemens WinCC", None, 1, "opcua"),
        (host_ids["172.16.50.21"], 4840, "tcp", "open", "opcua", "OPC UA Server", None, 1, "opcua"),
    ]
    for s in services_data:
        db.execute("INSERT INTO services (host_id, port, protocol, state, service_name, service_version, banner, is_ot_protocol, ot_protocol_name) VALUES (?,?,?,?,?,?,?,?,?)", s)

    # Add connections (communication flows)
    conn_data = [
        # IT normal traffic
        (mid, host_ids["10.10.1.10"], host_ids["10.10.2.10"], 445, "tcp", 15000, 8000, 250),
        (mid, host_ids["10.10.1.11"], host_ids["10.10.2.10"], 389, "tcp", 5000, 3000, 120),
        (mid, host_ids["10.10.1.10"], host_ids["10.10.2.20"], 445, "tcp", 80000, 120000, 500),
        (mid, host_ids["10.10.1.10"], host_ids["10.10.2.30"], 443, "tcp", 25000, 40000, 300),

        # SCADA to PLCs
        (mid, host_ids["172.16.50.10"], host_ids["172.16.51.10"], 102, "tcp", 50000, 45000, 2000),
        (mid, host_ids["172.16.50.10"], host_ids["172.16.51.11"], 102, "tcp", 48000, 43000, 1900),
        (mid, host_ids["172.16.50.10"], host_ids["172.16.51.20"], 44818, "tcp", 35000, 30000, 1500),
        (mid, host_ids["172.16.50.10"], host_ids["172.16.51.30"], 20000, "tcp", 20000, 18000, 800),
        (mid, host_ids["172.16.50.10"], host_ids["172.16.51.40"], 20000, "tcp", 22000, 19000, 850),

        # HMIs to PLCs
        (mid, host_ids["172.16.50.20"], host_ids["172.16.51.10"], 102, "tcp", 15000, 12000, 600),
        (mid, host_ids["172.16.50.21"], host_ids["172.16.51.11"], 102, "tcp", 14000, 11000, 580),

        # Historian collecting data
        (mid, host_ids["172.16.50.11"], host_ids["172.16.50.10"], 502, "tcp", 30000, 35000, 1200),

        # ENG workstation to PLCs (programming)
        (mid, host_ids["172.16.50.30"], host_ids["172.16.51.10"], 102, "tcp", 5000, 3000, 100),
        (mid, host_ids["172.16.50.30"], host_ids["172.16.51.20"], 44818, "tcp", 4000, 2500, 80),

        # Jump server to OT
        (mid, host_ids["192.168.100.30"], host_ids["172.16.50.10"], 3389, "tcp", 60000, 100000, 800),
        (mid, host_ids["192.168.100.30"], host_ids["10.10.2.10"], 445, "tcp", 10000, 8000, 200),

        # Cross-zone (suspicious - IT to OT without jump)
        (mid, host_ids["10.10.1.12"], host_ids["172.16.50.10"], 3389, "tcp", 8000, 15000, 50),

        # SIEM collecting logs
        (mid, host_ids["10.10.2.10"], host_ids["192.168.100.10"], 514, "udp", 50000, 0, 10000),
        (mid, host_ids["172.16.50.10"], host_ids["192.168.100.10"], 514, "udp", 30000, 0, 5000),
    ]
    for c in conn_data:
        db.execute("""
            INSERT INTO connections (mission_id, src_host_id, dst_host_id, dst_port, protocol, bytes_sent, bytes_recv, packet_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, c)

    # Add OT device details
    ot_data = [
        (host_ids["172.16.51.10"], "PLC", "Siemens", "S7-1500 CPU 1516-3 PN/DP", "V2.9.4", "SN-2024-TRB-001", "s7comm", "slave", None, None),
        (host_ids["172.16.51.11"], "PLC", "Siemens", "S7-1500 CPU 1516-3 PN/DP", "V2.9.4", "SN-2024-TRB-002", "s7comm", "slave", None, None),
        (host_ids["172.16.51.20"], "PLC", "Allen-Bradley", "ControlLogix 5580", "V33.011", "SN-2023-PMP-001", "ethernetip", "slave", None, None),
        (host_ids["172.16.51.30"], "RTU", "SEL", "SEL-3530 RTAC", "R148-V0", "SN-2022-SUB-001", "dnp3", "both", None, None),
        (host_ids["172.16.51.40"], "RTU", "GE", "D25 Multilin", "8.00", "SN-2021-SUB-002", "dnp3", "both", None, None),
        (host_ids["172.16.50.20"], "HMI", "Siemens", "IPC477E WinCC", "V7.5 SP2", "SN-2023-HMI-001", "s7comm", "master", None, None),
        (host_ids["172.16.50.21"], "HMI", "Siemens", "IPC477E WinCC", "V7.5 SP2", "SN-2023-HMI-002", "s7comm", "master", None, None),
    ]
    for o in ot_data:
        db.execute("""
            INSERT INTO ot_devices (host_id, device_class, vendor, model, firmware, serial_number, protocol, master_slave_role, connected_devices, io_config)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, o)

    # Add threat intel
    db.execute("""
        INSERT INTO threat_intel (mission_id, threat_actor, description, ttps, iocs, target_sectors, source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (mid, "VOLTZITE",
          "Nation-state actor targeting energy sector ICS/SCADA systems. Known for living-off-the-land techniques, lateral movement via RDP, and targeting of engineering workstations to modify PLC logic.",
          json.dumps(["T1078", "T1021.001", "T1059.001", "T1053.005", "T1087.002", "T1018", "T1082", "T1570", "T1021.002", "T0843", "T0834"]),
          json.dumps(["185.220.101.0/24", "evil-update.energy-sector.com", "d4a97b3c8e1f2a5b6c7d8e9f0a1b2c3d", "svchost_updater.exe"]),
          "Energy, Utilities, Critical Infrastructure",
          "CISA Advisory AA23-XXX"))

    # Add some hunt hypotheses
    hypotheses = [
        (mid, "Unauthorized IT-to-OT Access", "WS-ENG02 (10.10.1.12) has direct RDP connections to SCADA-SRV01 bypassing the jump server. Investigate for unauthorized lateral movement.", "T1021.001", json.dumps([host_ids["10.10.1.12"], host_ids["172.16.50.10"]]), "high"),
        (mid, "Kerberoastable Service Accounts", "Enumerate service accounts with SPNs set that could be targeted for offline cracking.", "T1558.003", json.dumps([host_ids["10.10.2.10"]]), "medium"),
        (mid, "PLC Logic Modification", "Check for recent program changes on S7-1500 PLCs. Engineering workstation ENG-WS01 has programming access.", "T0843", json.dumps([host_ids["172.16.51.10"], host_ids["172.16.51.11"], host_ids["172.16.50.30"]]), "critical"),
        (mid, "Outdated OT Systems", "Multiple HMIs running Windows 7 SP1 - check for exploitation of known vulnerabilities and any unauthorized patches.", "T1190", json.dumps([host_ids["172.16.50.20"], host_ids["172.16.50.21"]]), "high"),
    ]
    for h in hypotheses:
        db.execute("INSERT INTO hunt_hypotheses (mission_id, title, description, mitre_technique, target_hosts, priority) VALUES (?,?,?,?,?,?)", h)

    db.commit()
    return jsonify({'status': 'seeded', 'mission_id': mid})

# ---------------------------------------------------------------------------
# Socket.IO events
# ---------------------------------------------------------------------------
@socketio.on('join_mission')
def on_join_mission(data):
    room = f"mission_{data['mission_id']}"
    join_room(room)
    emit('operator_joined', {'operator': session.get('operator', 'Unknown'), 'mission_id': data['mission_id']}, room=room)

@socketio.on('scan_update')
def on_scan_update(data):
    room = f"mission_{data['mission_id']}"
    emit('scan_progress', data, room=room)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def log_audit(db, mission_id, action, details):
    db.execute(
        "INSERT INTO audit_log (mission_id, action, details, user_name) VALUES (?, ?, ?, ?)",
        (mission_id, action, details, session.get('operator', 'system'))
    )
    db.commit()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='CPT Recon - Cyber Protection Team Reconnaissance Tool')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (0.0.0.0 for team server, 127.0.0.1 for standalone)')
    parser.add_argument('--port', type=int, default=5000, help='Port number')
    parser.add_argument('--standalone', action='store_true', help='Run in standalone mode (localhost only)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()

    # Initialize scan engine
    from modules.scan_engine import ScanEngine
    scan_engine_instance = ScanEngine(app.config['DATABASE'], socketio)
    # Store on app for access
    app.config['SCAN_ENGINE'] = scan_engine_instance
    logger.info("Scan engine initialized")

    bind_host = '127.0.0.1' if args.standalone else args.host
    logger.info(f"CPT Recon starting in {'standalone' if args.standalone else 'team server'} mode on {bind_host}:{args.port}")
    socketio.run(app, host=bind_host, port=args.port, debug=args.debug, allow_unsafe_werkzeug=True)
