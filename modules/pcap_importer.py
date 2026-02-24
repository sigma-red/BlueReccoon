#!/usr/bin/env python3
"""PCAP Importer - import and analyze existing PCAP files."""
import os, re, logging
from modules.base_scanner import BaseScanner, IS_WINDOWS
logger = logging.getLogger('cpt-recon.pcap')

class PCAPImporter(BaseScanner):
    def run(self):
        pcap_file = self.config.get('pcap_file', self.target)
        if not pcap_file:
            return {'error': 'No PCAP file specified'}
        if not self.tool_available('tshark'):
            return {'error': 'tshark required for PCAP analysis'}
        if not os.path.exists(pcap_file):
            return {'error': f'PCAP file not found: {pcap_file}'}

        self.progress(0, f"Importing PCAP: {pcap_file}")

        self.progress(10, "Extracting hosts from PCAP")
        hosts = self._extract_hosts(pcap_file)

        self.progress(40, "Extracting connections")
        conns = self._extract_connections(pcap_file)

        self.progress(60, "Passive OS fingerprinting")
        os_results = self._passive_os_fingerprint(pcap_file)

        self.progress(80, "Protocol analysis")
        protocols = self._analyze_protocols(pcap_file)

        self.progress(100, f"PCAP import complete: {len(hosts)} hosts, {len(conns)} connections")
        return {'hosts': len(hosts), 'connections': len(conns), 'protocols': protocols}

    def _extract_hosts(self, pcap):
        hosts = set()
        rc, out, _ = self.run_command(
            f'tshark -r "{pcap}" -T fields -e ip.src -e eth.src', timeout=120)
        if rc == 0 and out:
            for line in out.strip().split('\n'):
                parts = line.split('\t')
                if parts[0].strip():
                    ip = parts[0].strip()
                    mac = parts[1].strip() if len(parts) > 1 else None
                    if ip and not ip.startswith('255.') and ip != '0.0.0.0' and ip not in hosts:
                        hosts.add(ip)
                        self.submit_host(ip, mac_address=mac, discovered_via='pcap_import')
        return hosts

    def _extract_connections(self, pcap):
        conns = []
        rc, out, _ = self.run_command(
            f'tshark -r "{pcap}" -T fields -e ip.src -e ip.dst -e tcp.dstport -e frame.protocols',
            timeout=120)
        if rc == 0 and out:
            # Count connections manually (cross-platform, no sort/uniq pipes)
            conn_counts = {}
            for line in out.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 3:
                    src, dst = parts[0].strip(), parts[1].strip()
                    port = parts[2].strip()
                    if src and dst and port and port.isdigit():
                        key = (src, dst, int(port))
                        conn_counts[key] = conn_counts.get(key, 0) + 1

            for (src, dst, port), count in sorted(conn_counts.items(), key=lambda x: -x[1])[:2000]:
                self.submit_connection(src, dst, port, packet_count=count)
                conns.append((src, dst, port))
        return conns

    def _passive_os_fingerprint(self, pcap):
        rc, out, _ = self.run_command(
            f'tshark -r "{pcap}" -T fields -e ip.src -e ip.ttl', timeout=60)
        results = {}
        if rc == 0 and out:
            for line in out.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2 and parts[0].strip() and parts[1].strip():
                    ip = parts[0].strip()
                    try:
                        ttl = int(parts[1].strip())
                        if ip not in results:
                            os_guess = 'Linux/Unix' if ttl <= 64 else 'Windows' if ttl <= 128 else 'Network Device'
                            results[ip] = os_guess
                            self.submit({'type':'os_info','ip_address':ip,'os_name':os_guess,'method':'passive_ttl'})
                    except ValueError:
                        pass
        return results

    def _analyze_protocols(self, pcap):
        protocols = {}
        rc, out, _ = self.run_command(
            f'tshark -r "{pcap}" -T fields -e frame.protocols', timeout=60)
        if rc == 0 and out:
            for line in out.strip().split('\n'):
                proto = line.strip()
                if proto:
                    protocols[proto] = protocols.get(proto, 0) + 1
        return dict(sorted(protocols.items(), key=lambda x: -x[1])[:50])
