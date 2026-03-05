#!/usr/bin/env python3
"""
BloodHound AD Mapper — maps Active Directory attack paths using bloodhound-python.

Collects AD relationships (users, groups, computers, sessions, ACLs, trusts)
and identifies privilege escalation paths (e.g., who can reach Domain Admin).

Uses bloodhound-python (BloodHound.py) as the ingestor — pure Python, no need
to run SharpHound on a Windows host.

Install:  pip install bloodhound
Requires: DNS resolution to DC, valid domain credentials.
"""

import json
import logging
import os
import shutil
import tempfile
import glob as glob_mod

from modules.base_scanner import BaseScanner

logger = logging.getLogger('blue-reccoon.bloodhound')


class BloodHoundMapper(BaseScanner):
    def run(self):
        target = self.target
        if not target:
            return {'error': 'No target DC specified'}

        creds = self.config.get('credentials', {})
        username = creds.get('username', '')
        password = creds.get('password', '')
        domain = creds.get('domain', '')

        if not username or not password or not domain:
            return {'error': 'BloodHound requires domain credentials (username, password, domain)'}

        self.progress(0, "Starting BloodHound AD mapping")

        # Determine collection method
        collection_method = self.config.get('collection_method', 'Default')
        # Default collects: Group, LocalAdmin, Session, Trusts, ACL, ObjectProps, Container
        # Other options: All, DCOnly, Group, LocalAdmin, Session, Trusts, ACL, ObjectProps, Container

        results = {
            'domain': domain,
            'users': 0,
            'groups': 0,
            'computers': 0,
            'relationships': 0,
            'attack_paths': [],
            'kerberoastable': 0,
            'as_rep_roastable': 0,
            'unconstrained_delegation': 0,
            'admin_to': 0,
        }

        # Try bloodhound-python (pip package)
        if self._try_bloodhound_python(target, username, password, domain,
                                        collection_method, results):
            self.progress(100, "BloodHound mapping complete")
            return results

        # Fallback: try bloodhound-python CLI
        if self._try_bloodhound_cli(target, username, password, domain,
                                     collection_method, results):
            self.progress(100, "BloodHound mapping complete")
            return results

        return {'error': 'bloodhound-python not available. Install with: pip install bloodhound'}

    def _try_bloodhound_python(self, target, username, password, domain,
                                collection_method, results):
        """Use bloodhound-python as a library."""
        try:
            from bloodhound import BloodHound
            from bloodhound.ad.utils import ADUtils
            from bloodhound.ad.domain import AD
            from bloodhound.ad.authentication import ADAuthentication
        except ImportError:
            logger.info("bloodhound-python library not installed")
            return False

        self.progress(5, "Initializing BloodHound.py ingestor")
        self.log_tool('bloodhound-python', f'bloodhound-python -d {domain} -u {username} -dc {target} -c {collection_method}',
                      f"Running BloodHound.py against {domain} (DC: {target})",
                      target_ip=target)

        output_dir = tempfile.mkdtemp(prefix='bh_')
        try:
            auth = ADAuthentication(username=username, password=password, domain=domain)
            ad = AD(auth=auth, domain=domain, nameserver=target, dns_tcp=False)

            self.progress(10, "Connecting to domain controller")
            ad.dns_resolve(domain=domain)

            self.progress(15, "Authenticating to LDAP")
            bh = BloodHound(ad)
            bh.connect()

            self.progress(20, "Collecting AD objects and relationships")

            # Map collection method string to collectors
            collect_methods = self._parse_collection_methods(collection_method)
            bh.run(collect=collect_methods, num_workers=5, disable_pooling=False,
                   dns_tcp=False, computerfile=None, cachefile=None)

            self.progress(70, "Processing collected data")

            # BloodHound outputs JSON files in the current directory
            # We need to find and parse them
            self._process_bh_output(output_dir, domain, results)

        except Exception as e:
            logger.error(f"BloodHound.py library error: {e}")
            # Fall through to CLI method
            return False
        finally:
            # Clean up temp dir
            shutil.rmtree(output_dir, ignore_errors=True)

        return True

    def _try_bloodhound_cli(self, target, username, password, domain,
                             collection_method, results):
        """Use bloodhound-python as a CLI tool."""
        if not self.tool_available('bloodhound-python'):
            # Also check for 'bloodhound' command
            if not self.tool_available('bloodhound'):
                return False

        output_dir = tempfile.mkdtemp(prefix='bh_')
        try:
            cmd_name = 'bloodhound-python' if self.tool_available('bloodhound-python') else 'bloodhound'

            self.progress(10, f"Running {cmd_name} CLI")

            # Build command — credentials are sanitized in log_action
            cmd = (f"{cmd_name} -d '{domain}' -u '{username}' -p '{password}' "
                   f"-ns {target} -dc {target} -c {collection_method} "
                   f"--zip -op '{output_dir}/bh_output' 2>&1")

            self.log_send(target, 389, 'ldap',
                          f"BloodHound LDAP collection against {domain}",
                          tool=cmd_name)

            rc, out, err = self.run_command(cmd, timeout=600)

            if rc != 0:
                logger.error(f"BloodHound CLI failed (rc={rc}): {err}")
                return False

            self.progress(60, "Processing BloodHound output files")
            self._process_bh_output(output_dir, domain, results)

        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

        return True

    def _parse_collection_methods(self, method_str):
        """Parse collection method string into a set for bloodhound-python."""
        valid = {'group', 'localadmin', 'session', 'trusts', 'acl',
                 'objectprops', 'container', 'dcom', 'rdp', 'psremote'}
        if method_str.lower() == 'all':
            return valid
        if method_str.lower() == 'default':
            return {'group', 'localadmin', 'session', 'trusts', 'acl',
                    'objectprops', 'container'}
        if method_str.lower() == 'dconly':
            return {'group', 'trusts', 'acl', 'objectprops', 'container'}
        return {m.strip().lower() for m in method_str.split(',') if m.strip().lower() in valid}

    def _process_bh_output(self, output_dir, domain, results):
        """Parse BloodHound JSON output files and submit results."""
        # Find all JSON files (bloodhound outputs *_users.json, *_groups.json, etc.)
        json_files = glob_mod.glob(os.path.join(output_dir, '*.json'))

        # Also check current directory (library mode sometimes writes here)
        json_files.extend(glob_mod.glob(f'*_{domain.replace(".", "_")}*.json'))
        json_files.extend(glob_mod.glob(f'*_bloodhound*.json'))

        # Deduplicate
        json_files = list(set(json_files))

        users_data = []
        groups_data = []
        computers_data = []
        domains_data = []
        relationships = []

        for jf in json_files:
            try:
                with open(jf, 'r') as f:
                    data = json.load(f)

                meta = data.get('meta', {})
                data_type = meta.get('type', '').lower()
                items = data.get('data', [])

                if data_type == 'users':
                    users_data.extend(items)
                elif data_type == 'groups':
                    groups_data.extend(items)
                elif data_type == 'computers':
                    computers_data.extend(items)
                elif data_type == 'domains':
                    domains_data.extend(items)

            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to parse BH output {jf}: {e}")

        results['users'] = len(users_data)
        results['groups'] = len(groups_data)
        results['computers'] = len(computers_data)

        self.progress(75, f"Processing {len(users_data)} users, {len(groups_data)} groups, {len(computers_data)} computers")

        # Process users
        for user in users_data:
            props = user.get('Properties', {})
            aces = user.get('Aces', [])
            member_of = user.get('MemberOf', []) if 'MemberOf' in user else []

            # Track kerberoastable
            if props.get('hasspn', False):
                results['kerberoastable'] += 1

            # Track AS-REP roastable
            if props.get('dontreqpreauth', False):
                results['as_rep_roastable'] += 1

            # Submit relationships
            for group_ref in member_of:
                gid = group_ref if isinstance(group_ref, str) else group_ref.get('ObjectIdentifier', '')
                if gid:
                    relationships.append({
                        'source_name': props.get('name', ''),
                        'source_type': 'User',
                        'target_name': gid,
                        'target_type': 'Group',
                        'relationship': 'MemberOf',
                        'is_inherited': False,
                    })

            # Process ACEs for attack paths
            for ace in aces:
                right = ace.get('RightName', '')
                principal = ace.get('PrincipalSID', '') or ace.get('PrincipalName', '')
                if right in ('GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl',
                             'ForceChangePassword', 'AddMember', 'AllExtendedRights',
                             'DCSync'):
                    relationships.append({
                        'source_name': principal,
                        'source_type': ace.get('PrincipalType', 'Unknown'),
                        'target_name': props.get('name', ''),
                        'target_type': 'User',
                        'relationship': right,
                        'is_inherited': ace.get('IsInherited', False),
                    })

        # Process groups
        for group in groups_data:
            props = group.get('Properties', {})
            members = group.get('Members', [])
            aces = group.get('Aces', [])

            for member in members:
                mid = member.get('ObjectIdentifier', '') if isinstance(member, dict) else str(member)
                mtype = member.get('ObjectType', 'Unknown') if isinstance(member, dict) else 'Unknown'
                relationships.append({
                    'source_name': mid,
                    'source_type': mtype,
                    'target_name': props.get('name', ''),
                    'target_type': 'Group',
                    'relationship': 'MemberOf',
                    'is_inherited': False,
                })

            for ace in aces:
                right = ace.get('RightName', '')
                principal = ace.get('PrincipalSID', '') or ace.get('PrincipalName', '')
                if right in ('GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl',
                             'AddMember', 'AllExtendedRights'):
                    relationships.append({
                        'source_name': principal,
                        'source_type': ace.get('PrincipalType', 'Unknown'),
                        'target_name': props.get('name', ''),
                        'target_type': 'Group',
                        'relationship': right,
                        'is_inherited': ace.get('IsInherited', False),
                    })

        # Process computers
        for computer in computers_data:
            props = computer.get('Properties', {})
            local_admins = computer.get('LocalAdmins', [])
            aces = computer.get('Aces', [])

            # Track unconstrained delegation
            if props.get('unconstraineddelegation', False):
                results['unconstrained_delegation'] += 1

            for admin in local_admins:
                admin_name = admin.get('ObjectIdentifier', '') if isinstance(admin, dict) else str(admin)
                admin_type = admin.get('ObjectType', 'Unknown') if isinstance(admin, dict) else 'Unknown'
                results['admin_to'] += 1
                relationships.append({
                    'source_name': admin_name,
                    'source_type': admin_type,
                    'target_name': props.get('name', ''),
                    'target_type': 'Computer',
                    'relationship': 'AdminTo',
                    'is_inherited': False,
                })

            for ace in aces:
                right = ace.get('RightName', '')
                principal = ace.get('PrincipalSID', '') or ace.get('PrincipalName', '')
                if right in ('GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl',
                             'AllExtendedRights', 'ReadLAPSPassword'):
                    relationships.append({
                        'source_name': principal,
                        'source_type': ace.get('PrincipalType', 'Unknown'),
                        'target_name': props.get('name', ''),
                        'target_type': 'Computer',
                        'relationship': right,
                        'is_inherited': ace.get('IsInherited', False),
                    })

        results['relationships'] = len(relationships)

        self.progress(85, "Analyzing attack paths")

        # Identify critical attack paths
        attack_paths = self._find_attack_paths(relationships, groups_data)
        results['attack_paths'] = attack_paths

        self.progress(90, "Submitting results to database")

        # Submit AD relationships to DB
        for rel in relationships:
            self.submit({
                'type': 'ad_relationship',
                'source_name': rel['source_name'],
                'source_type': rel['source_type'],
                'target_name': rel['target_name'],
                'target_type': rel['target_type'],
                'relationship': rel['relationship'],
                'is_inherited': 1 if rel.get('is_inherited') else 0,
            })

        # Submit identified attack paths
        for path in attack_paths:
            self.submit({
                'type': 'ad_attack_path',
                'path_title': path['title'],
                'path_description': path['description'],
                'severity': path['severity'],
                'source_name': path['source'],
                'target_name': path['target'],
                'relationship_chain': json.dumps(path.get('chain', [])),
                'mitre_technique': path.get('mitre', ''),
            })

        # Submit domain info update (supplements existing ad_enum data)
        if domains_data:
            d = domains_data[0]
            dprops = d.get('Properties', {})
            self.submit({
                'type': 'domain_info',
                'domain_name': dprops.get('name', domain),
                'forest_name': dprops.get('forest', ''),
                'functional_level': dprops.get('functionallevel', ''),
                'domain_controllers': [],
                'trusts': [],
                'ous': [],
                'gpos': [],
            })

        # Submit privileged accounts found via BloodHound
        for user in users_data:
            props = user.get('Properties', {})
            if props.get('hasspn', False):
                spn_value = props.get('serviceprincipalnames', [''])[0] if props.get('serviceprincipalnames') else ''
                self.submit({
                    'type': 'privileged_account',
                    'account_name': props.get('name', '').split('@')[0],
                    'account_type': 'service',
                    'domain': domain,
                    'spn': spn_value,
                    'is_admin': 0,
                    'notes': f"Kerberoastable (BloodHound): {spn_value}",
                })

            if props.get('dontreqpreauth', False):
                self.submit({
                    'type': 'privileged_account',
                    'account_name': props.get('name', '').split('@')[0],
                    'account_type': 'user',
                    'domain': domain,
                    'is_admin': 0,
                    'notes': 'AS-REP Roastable — does not require Kerberos pre-authentication (BloodHound)',
                })

        # Clean up any BH JSON files in cwd
        for jf in glob_mod.glob(f'*_{domain.replace(".", "_")}*.json'):
            try:
                os.remove(jf)
            except OSError:
                pass
        for jf in glob_mod.glob('*_bloodhound*.json'):
            try:
                os.remove(jf)
            except OSError:
                pass

    def _find_attack_paths(self, relationships, groups_data):
        """Analyze relationships to identify critical attack paths."""
        paths = []

        # Build lookup structures
        da_groups = set()
        ea_groups = set()
        for g in groups_data:
            props = g.get('Properties', {})
            name = (props.get('name', '') or '').upper()
            if 'DOMAIN ADMINS' in name:
                da_groups.add(props.get('name', ''))
                da_groups.add(props.get('objectid', ''))
            if 'ENTERPRISE ADMINS' in name:
                ea_groups.add(props.get('name', ''))
                ea_groups.add(props.get('objectid', ''))

        high_value_targets = da_groups | ea_groups

        # Find direct paths to Domain Admins
        for rel in relationships:
            target_upper = (rel.get('target_name', '') or '').upper()

            # Direct admin group membership abuse
            if rel['relationship'] in ('GenericAll', 'GenericWrite', 'WriteOwner',
                                       'WriteDacl', 'AddMember', 'ForceChangePassword'):
                if any(hv.upper() in target_upper for hv in high_value_targets if hv):
                    paths.append({
                        'title': f"{rel['relationship']} on {rel['target_name']}",
                        'description': (f"{rel['source_name']} ({rel['source_type']}) has "
                                        f"{rel['relationship']} rights on {rel['target_name']} "
                                        f"({rel['target_type']}), enabling privilege escalation to Domain Admin."),
                        'severity': 'critical',
                        'source': rel['source_name'],
                        'target': rel['target_name'],
                        'chain': [rel['relationship']],
                        'mitre': 'T1078.002',  # Valid Accounts: Domain Accounts
                    })

            # DCSync detection
            if rel['relationship'] == 'DCSync':
                paths.append({
                    'title': f"DCSync rights: {rel['source_name']}",
                    'description': (f"{rel['source_name']} has DCSync (Replicating Directory Changes) rights, "
                                    f"enabling credential extraction from all domain accounts."),
                    'severity': 'critical',
                    'source': rel['source_name'],
                    'target': rel['target_name'],
                    'chain': ['DCSync'],
                    'mitre': 'T1003.006',  # OS Credential Dumping: DCSync
                })

        # AdminTo paths (local admin on machines)
        admin_to_count = sum(1 for r in relationships if r['relationship'] == 'AdminTo')
        if admin_to_count > 0:
            # Find users/groups with many AdminTo relationships
            admin_sources = {}
            for rel in relationships:
                if rel['relationship'] == 'AdminTo':
                    src = rel['source_name']
                    admin_sources[src] = admin_sources.get(src, 0) + 1

            for src, count in admin_sources.items():
                if count >= 5:
                    paths.append({
                        'title': f"Widespread local admin: {src}",
                        'description': (f"{src} has local admin rights on {count} computers. "
                                        f"Compromising this account enables lateral movement across the domain."),
                        'severity': 'high' if count >= 10 else 'medium',
                        'source': src,
                        'target': f'{count} computers',
                        'chain': ['AdminTo'] * min(count, 3),
                        'mitre': 'T1021.006',  # Remote Services: Windows Remote Management
                    })

        # Unconstrained delegation paths
        for rel in relationships:
            if rel.get('relationship') == 'AllowedToDelegate':
                paths.append({
                    'title': f"Delegation abuse: {rel['source_name']}",
                    'description': (f"{rel['source_name']} has delegation rights to {rel['target_name']}. "
                                    f"This can be abused for privilege escalation."),
                    'severity': 'high',
                    'source': rel['source_name'],
                    'target': rel['target_name'],
                    'chain': ['AllowedToDelegate'],
                    'mitre': 'T1558.001',  # Steal or Forge Kerberos Tickets
                })

        # ReadLAPSPassword
        for rel in relationships:
            if rel['relationship'] == 'ReadLAPSPassword':
                paths.append({
                    'title': f"LAPS password readable: {rel['source_name']}",
                    'description': (f"{rel['source_name']} can read LAPS passwords on {rel['target_name']}, "
                                    f"exposing local administrator credentials."),
                    'severity': 'high',
                    'source': rel['source_name'],
                    'target': rel['target_name'],
                    'chain': ['ReadLAPSPassword'],
                    'mitre': 'T1552.004',  # Unsecured Credentials
                })

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        paths.sort(key=lambda p: severity_order.get(p['severity'], 99))

        return paths
