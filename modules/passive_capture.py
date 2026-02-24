#!/usr/bin/env python3
"""Passive Capture - live traffic capture and analysis without sending packets."""
import os, re, logging, time, subprocess, tempfile
from modules.base_scanner import BaseScanner, IS_WINDOWS
logger = logging.getLogger('cpt-recon.passive')

class PassiveCapture(BaseScanner):
    def run(self):
        interface = self.config.get('interface', 'any')
        duration = self.config.get('duration', 60)
        pcap_file = self.config.get('pcap_file',
            os.path.join(tempfile.gettempdir(), f'cpt_capture_{self.scan_id}.pcap'))

        if not self.tool_available('tcpdump') and not self.tool_available('tshark'):
            return {'error': 'tcpdump or tshark required for passive capture'}

        self.progress(0, f"Passive capture on {interface} for {duration}s")

        # Launch capture in background subprocess
        if self.tool_available('tshark'):
            cmd_parts = ['tshark', '-i', interface, '-a', f'duration:{duration}', '-w', pcap_file]
        else:
            cmd_parts = ['tcpdump', '-i', interface, '-w', pcap_file, '-G', str(duration), '-W', '1']

        try:
            proc = subprocess.Popen(cmd_parts, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            return {'error': f'Failed to start capture: {e}'}

        # Monitor progress
        elapsed = 0
        while elapsed < duration and not self.is_stopped():
            time.sleep(5)
            elapsed += 5
            self.progress(int((elapsed / duration) * 80), f"Capturing... {elapsed}/{duration}s")
            if proc.poll() is not None:
                break

        # Kill if still running (e.g. on cancel)
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)

        # Analyze captured traffic
        self.progress(85, "Analyzing captured traffic")
        results = self._analyze_pcap(pcap_file)

        self.progress(100, f"Capture complete: {results.get('hosts_found', 0)} hosts observed")
        return results

    def _analyze_pcap(self, pcap_file):
        results = {'hosts_found': 0, 'connections': 0, 'protocols': []}

        if not os.path.exists(pcap_file) or not self.tool_available('tshark'):
            return results

        # Extract IPs and ports — tshark works the same on all platforms
        rc, out, _ = self.run_command(
            f'tshark -r "{pcap_file}" -T fields -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport',
            timeout=120)
        if rc == 0 and out:
            seen_ips = set()
            for line in out.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    for ip in parts[:2]:
                        ip = ip.strip()
                        if ip and not ip.startswith('255.') and ip != '0.0.0.0' and ip not in seen_ips:
                            seen_ips.add(ip)
                            self.submit_host(ip, discovered_via='passive_capture')

                    if len(parts) >= 3 and parts[0].strip() and parts[1].strip():
                        port = parts[2].strip() or (parts[3].strip() if len(parts) > 3 else '')
                        if port:
                            try:
                                self.submit_connection(parts[0].strip(), parts[1].strip(),
                                    int(port), packet_count=1)
                                results['connections'] += 1
                            except (ValueError, IndexError):
                                pass

            results['hosts_found'] = len(seen_ips)

        return results
