#!/usr/bin/env python3
"""Full Active Scan - orchestrates all active enumeration modules sequentially."""
import logging
from modules.base_scanner import BaseScanner
logger = logging.getLogger('blue-reccoon.fullscan')

class FullActiveScan(BaseScanner):
    def __init__(self, engine, scan_id, mission_id, target, config, stop_flag, aggressiveness=3):
        super().__init__(engine, scan_id, mission_id, target, config, stop_flag)
        self.aggressiveness = aggressiveness

    def run(self):
        self.progress(0, "Starting full active enumeration")
        results = {}

        # Phase 1: Host Discovery
        self.progress(5, "Phase 1: Host Discovery")
        from modules.network_discovery import ARPScanner
        disc = ARPScanner(self.engine, self.scan_id, self.mission_id, self.target, self.config, self.stop_flag)
        disc_results = disc.run()
        results['discovery'] = disc_results
        if self.is_stopped(): return results

        # Phase 2: Port Scanning
        self.progress(25, "Phase 2: Port Scanning")
        from modules.port_scanner import PortScanner
        ps = PortScanner(self.engine, self.scan_id, self.mission_id, self.target,
                        self.config, self.stop_flag, self.aggressiveness)
        port_results = ps.run()
        results['ports'] = port_results
        if self.is_stopped(): return results

        # Phase 3: Service Detection
        self.progress(50, "Phase 3: Service Version Detection")
        from modules.service_scanner import ServiceScanner
        ss = ServiceScanner(self.engine, self.scan_id, self.mission_id, self.target, self.config, self.stop_flag)
        svc_results = ss.run()
        results['services'] = svc_results
        if self.is_stopped(): return results

        # Phase 4: OT Protocol Scanning
        self.progress(65, "Phase 4: OT Protocol Detection")
        from modules.ot_scanner import OTScanner
        ot = OTScanner(self.engine, self.scan_id, self.mission_id, self.target,
                      self.config, self.stop_flag, max(1, self.aggressiveness - 1))
        ot_results = ot.run()
        results['ot'] = ot_results
        if self.is_stopped(): return results

        # Phase 5: SNMP Enumeration
        self.progress(80, "Phase 5: SNMP Enumeration")
        from modules.snmp_enumerator import SNMPEnumerator
        snmp = SNMPEnumerator(self.engine, self.scan_id, self.mission_id, self.target, self.config, self.stop_flag)
        snmp_results = snmp.run()
        results['snmp'] = snmp_results

        self.progress(100, "Full active scan complete")
        return results
