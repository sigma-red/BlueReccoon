#!/usr/bin/env python3
"""Active Directory Enumerator - DCs, trusts, OUs, GPOs, privileged accounts, SPNs."""

import re, json, logging
from modules.base_scanner import BaseScanner
logger = logging.getLogger('blue-reccoon.ad')

class ADEnumerator(BaseScanner):
    def run(self):
        target = self.target
        if not target:
            return {'error': 'No target DC specified'}
        creds = self.config.get('credentials', {})
        username, password = creds.get('username', ''), creds.get('password', '')
        domain = creds.get('domain', '')
        self.progress(0, f"AD enumeration against {target}")
        results = {'domain_name': None, 'forest_name': None, 'domain_controllers': [],
                   'functional_level': None, 'trusts': [], 'ous': [], 'gpos': [],
                   'privileged_groups': {}, 'spn_accounts': [], 'total_users': 0, 'total_computers': 0}

        self.progress(10, "Querying LDAP root DSE")
        results.update(self._query_root_dse(target))

        if username and password:
            domain = domain or results.get('domain_name', '')
            base_dn = self._to_dn(domain)
            self.progress(25, "Enumerating DCs"); results['domain_controllers'] = self._enum_dcs(target, username, password, domain, base_dn)
            self.progress(40, "Enumerating trusts"); results['trusts'] = self._enum_trusts(target, username, password, domain, base_dn)
            self.progress(50, "Enumerating OUs"); results['ous'] = self._enum_ous(target, username, password, domain, base_dn)
            self.progress(60, "Enumerating privileged groups"); results['privileged_groups'] = self._enum_priv_groups(target, username, password, domain, base_dn)
            self.progress(75, "Enumerating SPNs (Kerberoastable)"); results['spn_accounts'] = self._enum_spns(target, username, password, domain, base_dn)
            self.progress(85, "Counting objects"); results.update(self._count_objects(target, username, password, domain, base_dn))

        if results['domain_name']:
            self.submit({'type': 'domain_info', 'domain_name': results['domain_name'],
                        'forest_name': results.get('forest_name'), 'domain_controllers': results.get('domain_controllers', []),
                        'functional_level': results.get('functional_level'), 'trusts': results.get('trusts', []),
                        'ous': results.get('ous', []), 'gpos': results.get('gpos', [])})
        for gname, members in results.get('privileged_groups', {}).items():
            for m in members:
                self.submit({'type': 'privileged_account', 'account_name': m.get('name', '?'),
                            'account_type': 'user', 'domain': results.get('domain_name', ''),
                            'groups': [gname], 'is_admin': 1 if 'Admin' in gname else 0, 'notes': f"Member of {gname}"})
        for s in results.get('spn_accounts', []):
            self.submit({'type': 'privileged_account', 'account_name': s.get('name', '?'),
                        'account_type': 'service', 'domain': results.get('domain_name', ''),
                        'spn': s.get('spn'), 'is_admin': 0, 'notes': f"Kerberoastable: {s.get('spn','')}"})

        self.progress(100, "AD enumeration complete")
        return {'domain': results.get('domain_name'), 'dcs': len(results.get('domain_controllers',[])),
                'trusts': len(results.get('trusts',[])), 'spn_accounts': len(results.get('spn_accounts',[]))}

    def _to_dn(self, domain):
        return ','.join(f'DC={p}' for p in domain.split('.')) if domain else ''

    def _ldap(self, target, user, pw, domain, base, filt, attrs=''):
        if not self.tool_available('ldapsearch'): return ''
        bind = f"{domain}\\{user}" if domain else user
        rc, out, _ = self.run_command(f"ldapsearch -x -H ldap://{target} -D '{bind}' -w '{pw}' -b '{base}' '{filt}' {attrs} 2>/dev/null", timeout=30)
        return out if rc == 0 else ''

    def _query_root_dse(self, target):
        info = {}
        if self.tool_available('ldapsearch'):
            rc, out, _ = self.run_command(f"ldapsearch -x -H ldap://{target} -s base '(objectClass=*)' 2>/dev/null", timeout=15)
            if rc == 0 and out:
                m = re.search(r'defaultNamingContext:\s*(.+)', out)
                if m:
                    parts = re.findall(r'DC=([^,]+)', m.group(1), re.I)
                    if parts: info['domain_name'] = '.'.join(parts)
                m = re.search(r'rootDomainNamingContext:\s*(.+)', out)
                if m:
                    parts = re.findall(r'DC=([^,]+)', m.group(1), re.I)
                    if parts: info['forest_name'] = '.'.join(parts)
                m = re.search(r'domainFunctionality:\s*(\d+)', out)
                if m:
                    lvls = {'0':'Win2000','1':'Win2003i','2':'Win2003','3':'Win2008','4':'Win2008R2','5':'Win2012','6':'Win2012R2','7':'Win2016'}
                    info['functional_level'] = lvls.get(m.group(1), f'Level {m.group(1)}')
        return info

    def _enum_dcs(self, t, u, p, d, dn):
        if not dn: return []
        out = self._ldap(t, u, p, d, dn, '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', 'cn')
        return [m.group(1).strip() for m in re.finditer(r'cn:\s*(.+)', out)]

    def _enum_trusts(self, t, u, p, d, dn):
        if not dn: return []
        out = self._ldap(t, u, p, d, f'CN=System,{dn}', '(objectClass=trustedDomain)', 'cn trustDirection trustType')
        trusts, cur = [], {}
        dirs = {'1':'Inbound','2':'Outbound','3':'Bidirectional'}
        for line in out.split('\n'):
            if line.startswith('cn:'):
                if cur.get('name'): trusts.append(cur)
                cur = {'name': line.split(':',1)[1].strip()}
            elif line.startswith('trustDirection:'): cur['direction'] = dirs.get(line.split(':',1)[1].strip(),'?')
        if cur.get('name'): trusts.append(cur)
        return trusts

    def _enum_ous(self, t, u, p, d, dn):
        if not dn: return []
        out = self._ldap(t, u, p, d, dn, '(objectClass=organizationalUnit)', 'ou')
        return [m.group(1).strip() for m in re.finditer(r'ou:\s*(.+)', out)]

    def _enum_priv_groups(self, t, u, p, d, dn):
        if not dn: return {}
        groups = {}
        for g in ['Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','DnsAdmins']:
            if self.is_stopped(): break
            out = self._ldap(t, u, p, d, dn, f'(&(objectClass=group)(cn={g}))', 'member')
            members = [{'name': m.group(1).strip()} for m in re.finditer(r'member:\s*CN=([^,]+)', out)]
            if members: groups[g] = members
        return groups

    def _enum_spns(self, t, u, p, d, dn):
        if not dn: return []
        out = self._ldap(t, u, p, d, dn, '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))', 'sAMAccountName servicePrincipalName')
        accts, name = [], None
        for line in out.split('\n'):
            if line.startswith('sAMAccountName:'): name = line.split(':',1)[1].strip()
            elif line.startswith('servicePrincipalName:') and name:
                if not name.endswith('$'):
                    accts.append({'name': name, 'spn': line.split(':',1)[1].strip()})
                name = None
        return accts

    def _count_objects(self, t, u, p, d, dn):
        if not dn: return {}
        out_u = self._ldap(t, u, p, d, dn, '(&(objectCategory=person)(objectClass=user))', 'dn')
        out_c = self._ldap(t, u, p, d, dn, '(objectCategory=computer)', 'dn')
        return {'total_users': out_u.count('dn:'), 'total_computers': out_c.count('dn:')}
