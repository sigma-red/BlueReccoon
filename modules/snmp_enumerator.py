#!/usr/bin/env python3
"""SNMP Enumerator - community string testing and device info."""
import re, logging
from modules.base_scanner import BaseScanner
logger = logging.getLogger('blue-reccoon.snmp')
DEFAULT_COMMUNITIES = ['public','private','community','snmp','monitor','admin','default']

class SNMPEnumerator(BaseScanner):
    def run(self):
        targets = self.parse_targets()
        if not targets: return {'error':'No targets'}
        communities = self.config.get('communities', DEFAULT_COMMUNITIES)
        found = 0
        for ti, ip in enumerate(targets):
            if self.is_stopped(): break
            self.progress(int((ti/len(targets))*90), f"SNMP probing {ip}")
            for comm in communities:
                if self.is_stopped(): break
                result = self._snmp_get(ip, comm)
                if result:
                    found += 1
                    self.submit_service(ip, 161, 'udp', service_name='snmp',
                        service_version=f'community: {comm}', banner=result.get('sysDescr',''))
                    if result.get('sysDescr'):
                        os_n, vendor, model = self._parse_sysdescr(result['sysDescr'])
                        self.submit({'type':'host_update','ip_address':ip,'os_name':os_n,
                            'device_vendor':vendor,'device_model':model,'hostname':result.get('sysName')})
                    break
        self.progress(100, f"SNMP complete: {found} responded")
        return {'devices_found':found}

    def _snmp_get(self, ip, comm, timeout=3):
        info = {}
        if self.tool_available('snmpget'):
            for name, oid in [('sysDescr','1.3.6.1.2.1.1.1.0'),('sysName','1.3.6.1.2.1.1.5.0')]:
                rc, out, _ = self.run_command(f"snmpget -v2c -c '{comm}' -t {timeout} -r 1 {ip} {oid} 2>/dev/null", timeout=timeout+2)
                if rc == 0 and 'STRING:' in out:
                    info[name] = out.split('STRING:',1)[1].strip().strip('"')
                elif rc != 0: return None
        else: return None
        return info if info else None

    def _parse_sysdescr(self, d):
        dl = d.lower()
        if 'cisco' in dl: return 'Cisco IOS','Cisco',None
        if 'windows' in dl: return 'Windows',None,None
        if 'linux' in dl: return 'Linux',None,None
        if 'siemens' in dl: return None,'Siemens',None
        return None,None,None
