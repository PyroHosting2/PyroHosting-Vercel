import os
import sys
import time
import threading
import sqlite3
import json
import requests  # pip install requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import random
from datetime import datetime, timedelta
from urllib.parse import urlencode
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this'  # Required for sessions

# Discord OAuth2 Configuration
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID', '1451636370077384864')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET', 'RcJcZmbogWTp0gG1kdMdfoMv1HDR_Jlk')
DISCORD_REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI', 'https://pyrohosting.io/auth/callback')
DISCORD_API_BASE_URL = 'https://discord.com/api'
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', 'https://ptb.discord.com/api/webhooks/1451662239072256030/mUu0s_aldK-cBF8K9d1K3EdXmkTHxykuvmGa1NoHHOE7kSBsjLELwd1Q9r2bUiSMr1Qw')
ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'pyro_secret_123')

# Load Admin IDs from JSON
try:
    with open('admins.json', 'r') as f:
        raw_ids = json.load(f)
        # Robust loading: Ensure list, convert all to string, strip whitespace
        if isinstance(raw_ids, list):
            ADMIN_IDS = [str(uid).strip() for uid in raw_ids if uid]
        else:
            print("Warnung: admins.json ist keine Liste!")
            ADMIN_IDS = []
            
except Exception as e:
    print(f"Fehler beim Laden von admins.json: {e}")
    ADMIN_IDS = []

# Proxmox Configuration
PROXMOX_USER = os.getenv('PROXMOX_USER', 'root')
PROXMOX_PASSWORD = os.getenv('PROXMOX_PASSWORD', 'Luan2010.2391234')

RYZEN_HOST = 'https://5.175.221.2:8006'
# INTEL_HOST = 'https://5.175.192.225:8006'

NODE = os.getenv('NODE', 'ryzen01') # Default node
RYZEN_NODE = 'ryzen01'
# INTEL_NODE = 'xeon01'

RYZEN_GW = '5.175.221.1'
# INTEL_GW = '5.175.192.1'
GW = RYZEN_GW
NETMASK = os.getenv('NETMASK', '24')

TEMPLATES = {
    'Ubuntu 22.04': 100,
    'Debian 13': 109,
    'Windows Server 2022': 106
}

RYZEN_TEMPLATES = {
    'Ubuntu 22.04': 900,
    'Debian 13': 901,
    'Windows Server 2022': 902
}

SERVER_CONFIGS = {
    # 'Intel Starter': {'cores': 2, 'memory': 4096, 'disk': '40G'},
    # 'Intel Basic': {'cores': 4, 'memory': 8192, 'disk': '80G'},
    # 'Intel Standard': {'cores': 6, 'memory': 16384, 'disk': '120G'},
    # 'Intel Advanced': {'cores': 8, 'memory': 24576, 'disk': '160G'},
    # 'Intel Pro': {'cores': 12, 'memory': 32768, 'disk': '240G'},
    # 'Intel Business': {'cores': 14, 'memory': 40960, 'disk': '320G'},
    'Ryzen Starter': {'cores': 2, 'memory': 4096, 'disk': '40G'},
    'Ryzen Basic': {'cores': 4, 'memory': 8192, 'disk': '80G'},
    'Ryzen Standard': {'cores': 6, 'memory': 16384, 'disk': '120G'},
    'Ryzen Advanced': {'cores': 8, 'memory': 24576, 'disk': '160G'},
    'Ryzen Pro': {'cores': 12, 'memory': 32768, 'disk': '240G'},
    'Ryzen Business': {'cores': 14, 'memory': 40960, 'disk': '320G'}
}

SERVER_PRICES = {
    # 'Intel Starter': 0.00,
    # 'Intel Basic': 4.99,
    # 'Intel Standard': 9.99,
    # 'Intel Advanced': 13.99,
    # 'Intel Pro': 18.99,
    # 'Intel Business': 24.99,
    'Ryzen Starter': 0.00, # If applicable
    'Ryzen Basic': 8.99,
    'Ryzen Standard': 14.99,
    'Ryzen Advanced': 19.99,
    'Ryzen Pro': 34.99,
    'Ryzen Business': 39.99
}

IP_POOL = ['5.175.192.226', '5.175.192.229', '5.175.192.230', '5.175.192.232', '5.175.192.233']

DB_PATH = 'data.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_admin_ids():
    try:
        with open('admins.json', 'r') as f:
            raw_ids = json.load(f)
            if isinstance(raw_ids, list):
                result = [str(uid).strip() for uid in raw_ids if uid]
                print(f"DEBUG: Loaded admin IDs: {result}")
                return result
    except Exception as e:
        print(f"DEBUG: Error loading admins.json: {e}")
    return []

@app.context_processor
def inject_admin_status():
    user = session.get('user')
    is_admin = False
    if user:
        uid = str(user.get('id')).strip()
        # Reload admins execution-time to allow updates without restart
        current_admins = get_admin_ids()
        print(f"DEBUG: Checking user ID '{uid}' against admins {current_admins}")
        if uid in current_admins:
            is_admin = True
            print(f"DEBUG: User '{uid}' IS admin")
        else:
            print(f"DEBUG: User '{uid}' is NOT admin")
    return dict(is_admin=is_admin)

class ProxmoxManager:
    def __init__(self, user, password):
        self.user = user
        self.password = password
        self.hosts = {
            # 'pve': INTEL_HOST,
            'ryzen01': RYZEN_HOST
        }
        self.auth_data = {} # {host: {'token': ..., 'csrf': ...}}
        self.last_error = ""

    def _get_host_for_node(self, node):
        # Default mapping
        return self.hosts.get(node, self.hosts['ryzen01'])

    def _find_vm_node(self, vmid):
        """Scans all known hosts to find which node currently has this VMID."""
        vmid_str = str(vmid)
        # Try all hosts because any host's resource list has the full cluster state
        for host_url in self.hosts.values():
            try:
                if host_url not in self.auth_data:
                    if not self._authenticate(host_url): continue
                
                url = f"{host_url}/api2/json/cluster/resources?type=vm"
                headers = self._get_headers(host_url)
                if not headers: continue
                
                response = requests.get(url, headers=headers, verify=False, timeout=5)
                if response.status_code == 200:
                    resources = response.json().get('data', [])
                    for res in resources:
                        if str(res.get('vmid')) == vmid_str:
                            return res.get('node'), host_url
            except Exception:
                continue
        return None, None

    def _authenticate(self, host):
        try:
            url = f"{host}/api2/json/access/ticket"
            response = requests.post(url, data={
                'username': f"{self.user}@pam",
                'password': self.password
            }, verify=False, timeout=10)
            
            if response.status_code == 401:
                self.last_error = f"Ungültige Anmeldedaten für {host}"
                return False
                
            response.raise_for_status()
            data = response.json()['data']
            self.auth_data[host] = {
                'token': f"PVEAuthCookie={data['ticket']}",
                'csrf': data['CSRFPreventionToken']
            }
            return True
        except Exception as e:
            self.last_error = f"Auth Fehler ({host}): {str(e)}"
            return False

    def _get_headers(self, host):
        if host not in self.auth_data:
            if not self._authenticate(host):
                return {}
        return {
            'Cookie': self.auth_data[host]['token'],
            'CSRFPreventionToken': self.auth_data[host]['csrf']
        }

    def get_next_vmid(self, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        
        # Try primary host first, then fall back to ANY other host in cluster
        hosts_to_try = [host] + [h for h in self.hosts.values() if h != host]
        
        for try_host in hosts_to_try:
            try:
                url = f"{try_host}/api2/json/cluster/nextid"
                response = requests.get(url, headers=self._get_headers(try_host), verify=False, timeout=10)
                response.raise_for_status()
                return response.json()['data']
            except Exception as e:
                self.last_error = f"NextID Fehler ({try_host}): {str(e)}"
                continue
        return None

    def wait_for_task(self, upid, node=None, timeout=300):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        import time
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/tasks/{upid}/status"
                response = requests.get(url, headers=self._get_headers(host), verify=False, timeout=10)
                response.raise_for_status()
                status = response.json()['data']['status']
                if status == 'stopped':
                    exitstatus = response.json()['data'].get('exitstatus', 'OK')
                    return exitstatus == 'OK'
            except Exception as e:
                print(f"Error checking task status: {e}")
            time.sleep(2)
        return False

    def clone_vm(self, template_id, new_vmid, name, node=None, cores=None, memory=None):
        target_node = node or 'ryzen'
        primary_host = self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        
        for host in hosts_to_try:
            try:
                print(f"[DEBUG] Attempting clone on {host}, node {target_node}, template {template_id} to VMID {new_vmid}")
                url = f"{host}/api2/json/nodes/{target_node}/qemu/{template_id}/clone"
                data = {
                    'newid': new_vmid,
                    'name': name,
                    'full': 1
                }
                # Note: cores and memory are set after clone via update_vm_resources
                print(f"[DEBUG] Clone data: {data}")
                response = requests.post(url, headers=self._get_headers(host), data=data, verify=False, timeout=15)
                print(f"[DEBUG] Response status: {response.status_code}, text: {response.text}")
                response.raise_for_status()
                upid = response.json()['data']
                print(f"[DEBUG] Clone successful, UPID: {upid}")
                return upid # Returns UPID
            except Exception as e:
                self.last_error = f"Clone Fehler ({host}): {str(e)}"
                print(f"[DEBUG] Clone failed on {host}: {str(e)}")
                continue
        return None

    def configure_cloudinit(self, vmid, ip, username="root", password="pyro_password", node=None, gw=None):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'ryzen01'
        target_gw = gw or RYZEN_GW
        # if target_node == 's237': target_gw = RYZEN_GW
        
        primary_host = found_host or self._get_host_for_node(target_node)
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/config"
                ip_config = f"ip={ip}/{NETMASK},gw={target_gw}"
                data = {
                    'ipconfig0': ip_config,
                    'ciuser': username,
                    'cipassword': password,
                    'nameserver': '8.8.8.8 1.1.1.1'
                }
                response = requests.post(url, headers=self._get_headers(host), data=data, verify=False, timeout=10)
                response.raise_for_status()
                return True
            except Exception as e:
                self.last_error = f"CI Fehler ({host}): {str(e)}"
                continue
        return False

    def update_vm_resources(self, vmid, cores, memory, node=None):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'ryzen01'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        for host in hosts_to_try:
            try:
                print(f"[DEBUG] Updating resources on {host}, node {target_node}, VM {vmid}: cores={cores}, memory={memory}")
                url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/config"
                data = {
                    'cores': cores,
                    'memory': memory
                }
                response = requests.post(url, headers=self._get_headers(host), data=data, verify=False, timeout=10)
                print(f"[DEBUG] Update resources response: {response.status_code}, {response.text}")
                response.raise_for_status()
                print(f"[DEBUG] Resources updated successfully for VM {vmid}")
                return True
            except Exception as e:
                self.last_error = f"Update Fehler ({host}): {str(e)}"
                print(f"[DEBUG] Update resources failed on {host}: {str(e)}")
                continue
        return False

    def get_node_status(self, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            url = f"{host}/api2/json/nodes/{target_node}/status"
            response = requests.get(url, headers=self._get_headers(host), verify=False, timeout=10)
            response.raise_for_status()
            return response.json()['data']
        except Exception as e:
            self.last_error = f"Node Status Fehler ({host}): {str(e)}"
            return None

    def get_primary_disk(self, vmid, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/config"
            response = requests.get(url, headers=self._get_headers(host), verify=False, timeout=10)
            response.raise_for_status()
            config = response.json().get('data', {})
            import re
            
            # Helper to check if a regular disk
            def is_disk(val):
                return 'media=cdrom' not in str(val).lower()

            # Priority 1: scsi0 or virtio0 (Standard for Linux/Windows)
            for key, val in config.items():
                if re.match(r'^(scsi|virtio)0$', key) and is_disk(val): 
                    return key
            
            # Priority 2: any scsi/virtio
            for key, val in config.items():
                if re.match(r'^(scsi|virtio)\d+$', key) and is_disk(val):
                    return key
                    
            # Priority 3: sata/ide harddisks (rare but possible)
            for key, val in config.items():
                if re.match(r'^(sata|ide)\d+$', key) and is_disk(val):
                    return key

            return "scsi0" # Fallback
        except:
            return "scsi0"

    def resize_disk(self, vmid, target_size_str, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            # 1. Parse Target Size (e.g. "40G" -> 40)
            target_gb = int(target_size_str.upper().replace('G', '').strip())
            
            # 2. Get Current Size
            stats = self.get_vm_stats(vmid, node=target_node)
            if not stats or stats == 'deleted':
                 self.last_error = f"VM nicht gefunden oder gelöscht ({host})"
                 return False
            
            # maxdisk is in bytes
            current_bytes = stats.get('maxdisk', 0)
            current_gb = int(current_bytes / (1024**3))
            
            if current_gb >= target_gb:
                # Already large enough
                return True
                
            diff_gb = target_gb - current_gb
            
            # 3. Find Disk
            disk = self.get_primary_disk(vmid, node=target_node)
            
            # 4. Resize
            url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/resize"
            data = {
                'disk': disk,
                'size': f"+{diff_gb}G"
            }
            response = requests.put(url, headers=self._get_headers(host), data=data, verify=False, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            self.last_error = f"Resize Fehler ({host}): {str(e)}"
            return False

    def add_network_interface(self, vmid, net_id, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/config"
            data = {
                f'net{net_id}': 'virtio,bridge=vmbr0'
            }
            response = requests.post(url, headers=self._get_headers(host), data=data, verify=False, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            self.last_error = f"Netzwerk Fehler ({host}): {str(e)}"
            return False

    def configure_additional_ip(self, vmid, net_id, ip, node=None, gw=None):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'ryzen01'
        target_gw = gw or RYZEN_GW
        
        primary_host = found_host or self._get_host_for_node(target_node)
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/config"
                data = {
                    f'ipconfig{net_id}': f'ip={ip}/{NETMASK},gw={target_gw}'
                }
                response = requests.post(url, headers=self._get_headers(host), data=data, verify=False, timeout=10)
                response.raise_for_status()
                return True
            except Exception as e:
                self.last_error = f"IP Config Fehler ({host}): {str(e)}"
                continue
        return False

    def remove_network_interface(self, vmid, net_id, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/config"
            # Delete both the interface and its ipconfig
            data = {
                'delete': f'net{net_id},ipconfig{net_id}'
            }
            response = requests.post(url, headers=self._get_headers(host), data=data, verify=False, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            self.last_error = f"Netzwerk Lösch-Fehler ({host}): {str(e)}"
            return False

    def suspend_vm(self, vmid, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/status/suspend"
            response = requests.post(url, headers=self._get_headers(host), verify=False, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            self.last_error = f"Suspend Fehler ({host}): {str(e)}"
            return False

    def resume_vm(self, vmid, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/status/resume"
            response = requests.post(url, headers=self._get_headers(host), verify=False, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            self.last_error = f"Resume Fehler ({host}): {str(e)}"
            return False

    def get_all_vms(self, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            url = f"{host}/api2/json/nodes/{target_node}/qemu"
            response = requests.get(url, headers=self._get_headers(host), verify=False, timeout=10)
            if response.status_code == 200:
                return response.json().get('data', [])
            return []
        except Exception as e:
            self.last_error = f"VM Liste Fehler ({host}): {str(e)}"
            return []

    def get_cluster_resources(self):
        # Try all hosts until one works, as they all share cluster state
        for host in self.hosts.values():
            try:
                url = f"{host}/api2/json/cluster/resources"
                response = requests.get(url, headers=self._get_headers(host), verify=False, timeout=8)
                if response.status_code == 200:
                    return response.json().get('data', [])
            except Exception:
                continue
        return []

    def get_vm_config(self, vmid, node=None, v_type='qemu'):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/{v_type}/{vmid}/config"
                response = requests.get(url, headers=self._get_headers(host), verify=False, timeout=10)
                if response.status_code == 200:
                    return response.json().get('data', {})
            except Exception:
                continue
        return {}

    def get_vm_status(self, vmid, node=None):
        target_node = node or self.node
        stats = self.get_vm_stats(vmid, node=target_node)
        if stats == 'deleted': return 'deleted'
        status = stats.get('status', 'unknown')
        if status == 'paused': return 'suspended'
        return status

    def get_vm_stats(self, vmid, node=None):
        # 1. Try to find the actual node if not provided or to be sure
        actual_node, host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        host = host or self._get_host_for_node(target_node)
        
        status_404_qemu = False
        status_404_lxc = False
        host_reachable = False
        
        # Try QEMU first
        try:
            url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/status/current"
            response = requests.get(url, headers=self._get_headers(host), verify=False, timeout=8)
            host_reachable = True
            if response.status_code == 200: return response.json().get('data', {})
            if response.status_code == 404: status_404_qemu = True
            
            # Try LXC
            url_lxc = f"{host}/api2/json/nodes/{target_node}/lxc/{vmid}/status/current"
            response_lxc = requests.get(url_lxc, headers=self._get_headers(host), verify=False, timeout=8)
            if response_lxc.status_code == 200: return response_lxc.json().get('data', {})
            if response_lxc.status_code == 404: status_404_lxc = True

            if status_404_qemu and status_404_lxc:
                return 'deleted'
            return {}
        except Exception as e:
            # If the specific host is down, but we found the VM via cluster resources earlier, 
            # we know it exists but isn't reachable.
            if host_reachable:
                self.last_error = f"VM Stats Fehler ({host}): {str(e)}"
            return {}

    def get_vm_rrd_stats(self, vmid, timeframe='hour', node=None):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/qemu/{vmid}/rrddata"
                params = {'timeframe': timeframe}
                response = requests.get(url, headers=self._get_headers(host), params=params, verify=False, timeout=10)
                if response.status_code == 200:
                    return response.json()['data']
            except Exception:
                continue
        return []

    def start_vm(self, vmid, node=None, v_type='qemu'):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/{v_type}/{vmid}/status/start"
                response = requests.post(url, headers=self._get_headers(host), verify=False, timeout=10)
                response.raise_for_status()
                return True
            except Exception as e:
                self.last_error = f"Start Fehler ({host}): {str(e)}"
                continue
        return False

    def stop_vm(self, vmid, node=None, v_type='qemu'):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/{v_type}/{vmid}/status/stop"
                response = requests.post(url, headers=self._get_headers(host), verify=False, timeout=10)
                response.raise_for_status()
                return True
            except Exception as e:
                self.last_error = f"Stop Fehler ({host}): {str(e)}"
                continue
        return False

    def reboot_vm(self, vmid, node=None, v_type='qemu'):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/{v_type}/{vmid}/status/reboot"
                response = requests.post(url, headers=self._get_headers(host), verify=False, timeout=10)
                if response.status_code == 200:
                    return True
            except Exception:
                continue
        return False

    def create_vnc_proxy(self, vmid, node=None, v_type='qemu'):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/{v_type}/{vmid}/vncproxy"
                data = {'websocket': 1}
                response = requests.post(url, headers=self._get_headers(host), data=data, verify=False, timeout=10)
                if response.status_code == 200:
                    return response.json().get('data', {})
            except Exception:
                continue
        return {}

    def get_vnc_proxy(self, vmid, node=None, v_type='qemu'):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        for host in hosts_to_try:
            try:
                url = f"{host}/api2/json/nodes/{target_node}/{v_type}/{vmid}/vncproxy"
                headers = self._get_headers(host)
                response = requests.post(url, headers=headers, data={'websocket': 1}, verify=False, timeout=10)
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    pve_ticket = headers.get('Cookie', '').replace('PVEAuthCookie=', '')
                    protocol = 'wss' if 'https://' in host else 'ws'

                    return {
                        'success': True,
                        'ticket': data.get('ticket'),
                        'port': data.get('port'),
                        'pve_ticket': pve_ticket,
                        'node': target_node,
                        'host': host.replace('https://', '').replace('http://', '').split(':')[0],
                        'protocol': protocol
                    }
            except Exception:
                continue
        return {'success': False, 'message': 'VNC Proxy could not be established on any host'}

    def delete_vm(self, vmid, node=None, v_type='qemu'):
        actual_node, found_host = self._find_vm_node(vmid)
        target_node = actual_node or node or 'pve'
        primary_host = found_host or self._get_host_for_node(target_node)
        
        hosts_to_try = [primary_host] + [h for h in self.hosts.values() if h != primary_host]
        
        for host in hosts_to_try:
            try:
                # Ensure it's stopped first
                self.stop_vm(vmid, node=target_node, v_type=v_type)
                import time
                time.sleep(2)
                
                url = f"{host}/api2/json/nodes/{target_node}/{v_type}/{vmid}"
                response = requests.delete(url, headers=self._get_headers(host), verify=False, timeout=10)
                if response.status_code == 200:
                    upid = response.json()['data']
                    self._wait_for_task(upid, node=target_node)
                    return True
            except Exception as e:
                self.last_error = f"Delete Fehler ({host}): {str(e)}"
                continue
        return False

    def _wait_for_task(self, upid, node=None):
        target_node = node or 'pve'
        host = self._get_host_for_node(target_node)
        try:
            # Simple polling wait
            import time
            status = "running"
            while status == "running":
                url = f"{host}/api2/json/nodes/{target_node}/tasks/{upid}/status"
                res = requests.get(url, headers=self._get_headers(host), verify=False, timeout=5)
                data = res.json().get('data', {})
                status = data.get('status', 'stopped')
                if status == 'running':
                     time.sleep(1)
            return True
        except:
             return False

proxmox = ProxmoxManager(PROXMOX_USER, PROXMOX_PASSWORD)




def generate_password(length=12):
    import string
    import secrets
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def _provision_vm_async(vmid, user_id, tier, os_name, ip, price, series='Ryzen'):
    """Start VM provisioning asynchronously - returns immediately after starting clone"""
    print(f"[DEBUG] _provision_vm_async called for VMID {vmid}, Tier {tier}, OS {os_name}, Series {series}")
    import threading
    
    # Determine Node, GW and Templates based on series
    if series == 'Ryzen':
        target_node = RYZEN_NODE
        target_gw = RYZEN_GW
        target_templates = RYZEN_TEMPLATES
    # else:
    #     target_node = INTEL_NODE
    #     target_gw = INTEL_GW
    #     target_templates = TEMPLATES

    config = SERVER_CONFIGS.get(tier, SERVER_CONFIGS['Ryzen Starter'])
    template_id = target_templates.get(os_name, target_templates['Ubuntu 22.04'])
    password = generate_password()
    
    print(f"[DEBUG] Config: {config}, Template ID: {template_id}, Target Node: {target_node}")
    
    # Create a pending server entry in database
    created_at = datetime.now().strftime('%d.%m.%Y')
    expiry_date = (datetime.now() + timedelta(days=30)).strftime('%d.%m.%Y %H:%M')
    if price == "Kostenlos":
        expiry_date = (datetime.now() + timedelta(hours=24)).strftime('%d.%m.%Y %H:%M')
    
    res_string = f"{config['cores']} vCore CPU - {config['memory']//1024}GB RAM <br><small style=\"color:var(--muted)\">{config['disk']} NVMe</small>"
    
    with get_db() as conn:
        conn.execute('''
            INSERT INTO servers (id, user_id, name, os, ip, status, resources, price, expiry, created_at, password, provisioning_status, cpu_series)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (str(vmid), user_id, tier, os_name, ip, 'Provisioning', res_string, price, expiry_date, created_at, password, 'cloning', series))
        conn.execute('UPDATE ips SET used = 1 WHERE ip = ?', (ip,))
        conn.commit()
    
    # Start provisioning in background thread
    def provision_background():
        print(f"[DEBUG] Starting background provisioning for VMID {vmid}")
        try:
            upid = proxmox.clone_vm(template_id, vmid, f"vs{vmid}", node=target_node)
            print(f"[DEBUG] Clone result UPID: {upid}")
            if upid and proxmox.wait_for_task(upid, node=target_node):
                print(f"[DEBUG] Clone successful for VMID {vmid}")
                import time
                time.sleep(5)  # Wait for lock to be released
                
                # Update status to configuring
                with get_db() as conn:
                    conn.execute('UPDATE servers SET provisioning_status = ? WHERE id = ?', ('configuring', str(vmid)))
                    conn.commit()
                # Resize disk - node handled via self.node if not passed, but let's be safe
                # Note: proxmox.resize_disk doesn't take node yet, let's fix that if needed
                # For now assuming resize_disk uses self.node which we might need to set or update method
                
                # Update: resize_disk uses self.node. I should update resize_disk too.
                # Actually, I'll update resize_disk and other methods in a separate chunk to be cleaner.
                
                ci_user = "Administrator" if "Windows" in os_name else "root"
                proxmox.configure_cloudinit(vmid, ip, username=ci_user, password=password, node=target_node, gw=target_gw)
                
                # Update status to starting
                with get_db() as conn:
                    conn.execute('UPDATE servers SET provisioning_status = ? WHERE id = ?', ('starting', str(vmid)))
                    conn.commit()
                
                # Apply configured resources
                print(f"[DEBUG] Updating VM resources for {vmid}: cores={config['cores']}, memory={config['memory']}")
                if not proxmox.update_vm_resources(vmid, config['cores'], config['memory'], node=target_node):
                    print(f"[DEBUG] update_vm_resources failed for {vmid}: {proxmox.last_error}")
                else:
                    print(f"[DEBUG] update_vm_resources successful for {vmid}")
                
                if not proxmox.resize_disk(vmid, config['disk'], node=target_node):
                    print(f"Resize failed for {vmid}: {proxmox.last_error}")
                
                print(f"[DEBUG] Starting VM {vmid}")
                if not proxmox.start_vm(vmid, node=target_node):
                    print(f"[DEBUG] start_vm failed for {vmid}: {proxmox.last_error}")
                else:
                    print(f"[DEBUG] start_vm successful for {vmid}")
                
                # Mark as complete
                with get_db() as conn:
                    conn.execute('UPDATE servers SET status = ?, provisioning_status = ? WHERE id = ?', 
                                ('Online', 'complete', str(vmid)))
                    conn.commit()
                print(f"[DEBUG] Provisioning complete for VMID {vmid}")
            else:
                print(f"[DEBUG] Clone failed for VMID {vmid}, Error: {proxmox.last_error}")
                # Clone failed
                with get_db() as conn:
                    conn.execute('UPDATE servers SET status = ?, provisioning_status = ? WHERE id = ?', 
                                ('Error', 'failed', str(vmid)))
                    conn.commit()
        except Exception as e:
            print(f"[DEBUG] Provisioning error for {vmid}: {e}")
            with get_db() as conn:
                conn.execute('UPDATE servers SET status = ?, provisioning_status = ? WHERE id = ?', 
                           ('Error', 'failed', str(vmid)))
                conn.commit()
    
    thread = threading.Thread(target=provision_background, daemon=True)
    thread.start()
    return True

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT,
                balance REAL DEFAULT 0.00
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_data (
                user_id TEXT PRIMARY KEY,
                firstname TEXT,
                lastname TEXT,
                company TEXT,
                vat TEXT,
                street TEXT,
                houseno TEXT,
                zip TEXT,
                city TEXT,
                country TEXT,
                phone TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                name TEXT,
                os TEXT,
                ip TEXT,
                status TEXT,
                resources TEXT,
                price TEXT,
                expiry TEXT,
                created_at TEXT,
                password TEXT,
                provisioning_status TEXT DEFAULT 'complete',
                cpu_series TEXT DEFAULT 'Intel',
                type TEXT DEFAULT 'qemu'
            )
        ''')
        
        # Migrations
        cursor = conn.execute('PRAGMA table_info(servers)')
        columns = [row[1] for row in cursor.fetchall()]
        if 'password' not in columns:
            conn.execute('ALTER TABLE servers ADD COLUMN password TEXT')
        if 'created_at' not in columns:
            conn.execute('ALTER TABLE servers ADD COLUMN created_at TEXT')
        if 'suspended' not in columns:
            conn.execute('ALTER TABLE servers ADD COLUMN suspended INTEGER DEFAULT 0')
        if 'provisioning_status' not in columns:
            conn.execute('ALTER TABLE servers ADD COLUMN provisioning_status TEXT DEFAULT "complete"')
        if 'cpu_series' not in columns:
            conn.execute('ALTER TABLE servers ADD COLUMN cpu_series TEXT DEFAULT "Intel"')
        if 'type' not in columns:
            conn.execute('ALTER TABLE servers ADD COLUMN type TEXT DEFAULT "qemu"')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                date TEXT,
                description TEXT,
                status TEXT,
                amount REAL,
                type TEXT, -- 'pos' or 'neg'
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                user_id TEXT,
                command TEXT,
                result TEXT,
                details TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS server_additional_ips (
                server_id TEXT,
                ip TEXT,
                net_id INTEGER,
                PRIMARY KEY (server_id, ip),
                FOREIGN KEY (server_id) REFERENCES servers (id),
                FOREIGN KEY (ip) REFERENCES ips (ip)
            )
        ''')
        # Migration for net_id
        cursor = conn.execute('PRAGMA table_info(server_additional_ips)')
        columns = [row[1] for row in cursor.fetchall()]
        if 'net_id' not in columns:
            conn.execute('ALTER TABLE server_additional_ips ADD COLUMN net_id INTEGER')
            # Initialize with reasonable defaults based on row order if any exist
            server_ids = conn.execute('SELECT DISTINCT server_id FROM server_additional_ips').fetchall()
            for sid in [row[0] for row in server_ids]:
                rows = conn.execute('SELECT rowid FROM server_additional_ips WHERE server_id = ? ORDER BY rowid', (sid,)).fetchall()
                for i, r in enumerate(rows):
                    conn.execute('UPDATE server_additional_ips SET net_id = ? WHERE rowid = ?', (i+1, r[0]))
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS ips (
                ip TEXT PRIMARY KEY,
                used INTEGER DEFAULT 0
            )
        ''')
        # Pre-populate IP Pool if empty
        existing_ips = conn.execute('SELECT COUNT(*) as count FROM ips').fetchone()['count']
        if existing_ips == 0:
            for ip in IP_POOL:
                conn.execute('INSERT INTO ips (ip, used) VALUES (?, ?)', (ip, 0))
        cursor = conn.execute('PRAGMA table_info(users)')
        user_columns = [row[1] for row in cursor.fetchall()]
        if 'has_claimed_free' not in user_columns:
            conn.execute('ALTER TABLE users ADD COLUMN has_claimed_free INTEGER DEFAULT 0')
        conn.commit()

init_db()

def check_expirations():
    with get_db() as conn:
        servers = conn.execute('SELECT * FROM servers WHERE status != "Deleted"').fetchall()
        for s in servers:
            try:
                expiry = datetime.strptime(s['expiry'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                 # Try fallback format if seconds missing or different
                try:
                    expiry = datetime.strptime(s['expiry'], '%d.%m.%Y %H:%M')
                except:
                    continue # Skip invalid dates

            now = datetime.now()
            
            # 1. Auto-Renewal / Expiry Check
            if now > expiry:
                # Calculate Price
                price_str = s['price'].replace('€', '').strip()
                try:
                    price = float(price_str)
                except:
                     price = 0.0 # Free or invalid
                
                # Auto-Renew if not Free and User has balance
                renewed = False
                if price > 0:
                    user = conn.execute('SELECT balance FROM users WHERE id = ?', (s['user_id'],)).fetchone()
                    if user and user['balance'] >= price:
                        # Auto-Renew
                        new_expiry = (expiry + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
                        conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (price, s['user_id']))
                        conn.execute('UPDATE servers SET expiry = ?, suspended = 0 WHERE id = ?', (new_expiry, s['id']))
                        # Ensure Unsuspend in Proxmox
                        if s['suspended']:
                            target_node = RYZEN_NODE
                            proxmox.resume_vm(s['id'], node=target_node)
                        
                        conn.execute('INSERT INTO transactions (user_id, amount, description, date, status, type) VALUES (?, ?, ?, ?, ?, ?)',
                                     (s['user_id'], price, f"Auto-Renewal: {s['name']}", now.strftime('%d.%m.%Y'), 'Erfolgreich', 'neg'))
                        renewed = True
                        print(f"Server {s['id']} auto-renewed.")

                if not renewed:
                    # 2. Suspend if expired and not suspended
                    if not s['suspended']:
                        print(f"Suspending expired server {s['id']}")
                        target_node = RYZEN_NODE
                        proxmox.suspend_vm(s['id'], node=target_node)
                        conn.execute('UPDATE servers SET suspended = 1 WHERE id = ?', (s['id'],))
                    
                    # 3. Delete if expired > 2 days
                    if now > expiry + timedelta(days=2):
                        print(f"Deleting expired server {s['id']} (Values > 48h)")
                        target_node = RYZEN_NODE
                        proxmox.delete_vm(s['id'], node=target_node)
                        conn.execute('DELETE FROM servers WHERE id = ?', (s['id'],))
                        conn.execute('UPDATE ips SET used = 0 WHERE ip = ?', (s['ip'],))
                        conn.execute('DELETE FROM server_additional_ips WHERE server_id = ?', (s['id'],))
        conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/servers')
def servers():
    return render_template('servers.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/support')
def support():
    return render_template('support.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/server/<server_id>')
def server_manage(server_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    user_session = session.get('user')
    user_id = user_session.get('id')
    
    server_id = server_id.replace('#', '')
    
    with get_db() as conn:
        user_row = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        server_row = conn.execute('SELECT * FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
        additional_ips_rows = conn.execute('SELECT ip FROM server_additional_ips WHERE server_id = ?', (server_id,)).fetchall()
        additional_ips = [row['ip'] for row in additional_ips_rows]
    
    if not server_row:
        flash("Fehler: Server nicht gefunden oder keine Zugriffsberechtigung!", "error")
        return redirect(url_for('dashboard'))
    
    # Node Determination
    series = server_row['cpu_series'] if 'cpu_series' in server_row.keys() else 'Ryzen'
    target_node = RYZEN_NODE
    target_gw = RYZEN_GW

    # Verify with Proxmox
    v_type = server_row['type'] if 'type' in server_row.keys() else 'qemu'
    prox_stats = proxmox.get_vm_stats(server_id, node=target_node)
    
    # If not found on expected node, re-scan cluster before giving up
    if prox_stats == 'deleted':
        all_res = proxmox.get_cluster_resources()
        found = next((r for r in all_res if str(r.get('vmid')) == str(server_id)), None)
        
        if found:
            # Server moved or was mislabeled
            new_node = found.get('node')
            new_series = 'Ryzen' if new_node == RYZEN_NODE else 'Intel'
            new_type = found.get('type', 'qemu')
            with get_db() as conn_fix:
                conn_fix.execute('UPDATE servers SET cpu_series = ?, type = ? WHERE id = ?', 
                                 (new_series, new_type, server_id))
                conn_fix.commit()
            return redirect(url_for('server_manage', server_id=server_id))
        else:
            # Truly not in Proxmox? DO NOT DELETE from DB. Just show status.
            real_status = 'deleted_from_proxmox'
    else:
        real_status = prox_stats.get('status', 'unknown') if isinstance(prox_stats, dict) else 'unknown'

    server = dict(server_row)
    server['additional_ips'] = additional_ips
    server['status'] = 'Online' if real_status == 'running' else 'Offline'
    if real_status == 'deleted_from_proxmox':
        server['status'] = 'Geloescht (Proxmox)'

    user_session['balance'] = user_row['balance'] if user_row else 10.00
    
    # Live Sync server data from Proxmox
    update_needed = False
    # Pull Config for IP
    config = proxmox.get_vm_config(server_id, node=target_node)
    if config:
        ipconfig0 = config.get('ipconfig0', '')
        if 'ip=' in ipconfig0:
            new_ip = ipconfig0.split('ip=')[1].split(',')[0].split('/')[0]
            if new_ip.lower() != 'dhcp' and new_ip != server.get('ip'):
                server['ip'] = new_ip
                update_needed = True
        
        if server.get('os') == 'Manual':
            server['os'] = 'Proxmox'
            update_needed = True

    # Pull Stats for Resources
    if prox_stats != 'deleted':
        mem = int(prox_stats.get('maxmem', 0) / (1024**3))
        cpus = prox_stats.get('cpus', 0)
        disk = int(prox_stats.get('maxdisk', 0) / (1024**3))
        new_resources = f"<b>{cpus}</b> Kerne, <b>{mem}</b> GB RAM, <b>{disk}</b> GB Disk"
        if new_resources != server.get('resources'):
            server['resources'] = new_resources
            update_needed = True

    if update_needed:
        with get_db() as conn:
            conn.execute('UPDATE servers SET ip = ?, os = ?, resources = ? WHERE id = ?', 
                         (server['ip'], server['os'], server['resources'], server_id))
            conn.commit()
    
    # Live Uptime
    uptime_sec = prox_stats.get('uptime', 0)
    if uptime_sec > 0:
        d = uptime_sec // 86400
        h = (uptime_sec % 86400) // 3600
        m = (uptime_sec % 3600) // 60
        if d > 0: server['uptime_str'] = f"{d} Tage, {h} Std"
        else: server['uptime_str'] = f"{h} Std, {m} Min"
    else:
        server['uptime_str'] = "0 Std, 0 Min"

    # Live usage
    server['cpu_usage'] = round(prox_stats.get('cpu', 0) * 100, 1)
    max_mem = prox_stats.get('maxmem', 1)
    cur_mem = prox_stats.get('mem', 0)
    server['ram_usage'] = round((cur_mem / max_mem) * 100, 1)

    # Historical Stats for Charts
    rrd_stats = proxmox.get_vm_rrd_stats(server_id, timeframe='hour', node=target_node)
    # Filter and format rrd_stats if needed, or pass as is
    # We'll pass a simplified version to make it easier for Chart.js
    server['history'] = []
    for entry in rrd_stats:
        if 'time' in entry:
            dt = datetime.fromtimestamp(entry['time']).strftime('%H:%M')
            server['history'].append({
                'time': dt,
                'cpu': round(entry.get('cpu', 0) * 100, 1),
                'mem': round((entry.get('mem', 0) / entry.get('maxmem', 1)) * 100, 1) if entry.get('maxmem') else 0,
                'netin': round(entry.get('netin', 0) / 1024 / 1024, 2), # MB
                'netout': round(entry.get('netout', 0) / 1024 / 1024, 2) # MB
            })

    # Node Info
    server['node'] = target_node.upper()

    # Calculate Remaining Time (Laufzeit)
    now = datetime.now()
    try:
        expiry_date = datetime.strptime(server['expiry'], '%d.%m.%Y %H:%M')
        delta = expiry_date - now
        if delta.total_seconds() <= 0:
            remaining = "Abgelaufen"
        else:
            days = delta.days
            hours = delta.seconds // 3600
            if days > 0:
                remaining = f"{days} Tage, {hours} Std"
            else:
                remaining = f"{hours} Std"
    except:
        remaining = "Unbekannt"

    return render_template('manage_server.html', user=user_session, server=server, remaining=remaining, suspended=server.get('suspended', 0))

@app.route('/server/<server_id>/vnc')
def server_vnc(server_id):
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    
    server_id = server_id.replace('#', '')
    user_id = session.get('user').get('id')
    
    with get_db() as conn:
        server_row = conn.execute('SELECT * FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
    
    if not server_row:
        return jsonify({'success': False, 'message': 'Server nicht gefunden'})
    
    if server_row['suspended']:
        return jsonify({'success': False, 'message': 'Server ist gesperrt und kann nicht verwaltet werden.'})
    
    series = server['cpu_series'] if 'cpu_series' in server.keys() else 'Ryzen'
    target_node = RYZEN_NODE
    v_type = server['type'] if 'type' in server.keys() else 'qemu'
    
    vnc_data = proxmox.get_vnc_proxy(server_id, node=target_node, v_type=v_type)
    if not vnc_data['success']:
        return jsonify({'success': False, 'message': 'VNC konnte nicht gestartet werden: ' + (vnc_data.get('message') or proxmox.last_error or 'Interner Fehler')})
    
    # We return the proxy data. The frontend can use this to build a connection.
    # Note: For real noVNC, we'd need a proxy on our side or direct login.
    # We'll return the full Proxmox URL for now as a fallback/convenience.
    vnc_url = f"{PROXMOX_HOST}/?console=kvm&novnc=1&vmid={server_id}&node={target_node}&view=system"
    return jsonify({'success': True, 'data': vnc_data, 'proxmox_url': vnc_url})



@app.route('/server/<server_id>/reinstall', methods=['POST'])
def server_reinstall(server_id):
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    
    data = request.json
    new_os = data.get('os')
    server_id = server_id.replace('#', '')
    user_id = session.get('user').get('id')
    with get_db() as conn:
        server_row = conn.execute('SELECT * FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
        if not server_row:
            return jsonify({'success': False, 'message': 'Server nicht gefunden'})
        
        if server_row['suspended']:
            return jsonify({'success': False, 'message': 'Server ist gesperrt.'})
        
        server = dict(server_row)
        
        # Get server plan configuration
        server_tier = server['name']
        series = server.get('cpu_series', 'Ryzen')
        target_node = RYZEN_NODE
        target_gw = RYZEN_GW
        target_templates = RYZEN_TEMPLATES

        config = SERVER_CONFIGS.get(server_tier, SERVER_CONFIGS['Ryzen Starter'])
        password = generate_password()
        
        template_id = target_templates.get(new_os)
        if not template_id:
            return jsonify({'success': False, 'message': 'Ungültiges Betriebssystem'})

        v_type = server.get('type', 'qemu')
        # Proxmox Reinstall: Delete and Recreate with same VMID and IP
        proxmox.delete_vm(server_id, node=target_node, v_type=v_type)
        # Reinstall currently only supports QEMU cloning from templates
        upid = proxmox.clone_vm(template_id, server_id, f"vs{server_id}", node=target_node)
        if upid:
            if proxmox.wait_for_task(upid, node=target_node):
                import time
                time.sleep(5) # Delay for Proxmox locking
                
                if not proxmox.resize_disk(server_id, config['disk'], node=target_node):
                    print(f"Reinstall Resize failed for {server_id}: {proxmox.last_error}")
                
                ci_user = "Administrator" if "Windows" in new_os else "root"
                proxmox.configure_cloudinit(server_id, server['ip'], username=ci_user, password=password, node=target_node, gw=target_gw)
                proxmox.start_vm(server_id, node=target_node)
                
                conn.execute('UPDATE servers SET os = ?, password = ? WHERE id = ?', (new_os, password, server_id))
                conn.commit()
                return jsonify({'success': True, 'os': new_os})
            else:
                return jsonify({'success': False, 'message': 'Clone Task fehlgeschlagen'})
        else:
            return jsonify({'success': False, 'message': f'Proxmox Reinstall Fehler: {proxmox.last_error}'})

@app.route('/server/<server_id>/pw-reset', methods=['POST'])
def server_pw_reset(server_id):
    if 'user' not in session: return jsonify({'success': False})
    server_id = server_id.replace('#', '')
    user_id = session.get('user').get('id')
    
    with get_db() as conn:
        server = conn.execute('SELECT * FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
        if not server: return jsonify({'success': False, 'message': 'Nicht gefunden'})
        server = dict(server)
        if server['suspended']: return jsonify({'success': False, 'message': 'Server ist gesperrt.'})
        
        new_password = generate_password()
        
        series = server.get('cpu_series', 'Ryzen')
        target_node = RYZEN_NODE
        target_gw = RYZEN_GW

        # Proxmox Reset: Just update CI and reboot
        v_type = server.get('type', 'qemu')
        proxmox.stop_vm(server_id, node=target_node, v_type=v_type)
        import time
        time.sleep(2)
        
        ci_user = "Administrator" if "Windows" in server['os'] else "root"
        proxmox.configure_cloudinit(server_id, server['ip'], username=ci_user, password=new_password, node=target_node, gw=target_gw)
        proxmox.start_vm(server_id, node=target_node, v_type=v_type)
        
        conn.execute('UPDATE servers SET password = ? WHERE id = ?', (new_password, server_id))
        conn.commit()
        
    return jsonify({'success': True, 'password': new_password})

@app.route('/server/<server_id>/start', methods=['POST'])
def server_start(server_id):
    if 'user' not in session: return jsonify({'success': False})
    server_id = server_id.replace('#', '')
    user_id = session['user']['id']
    with get_db() as conn:
        server = conn.execute('SELECT suspended, cpu_series, type FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
        if not server: return jsonify({'success': False, 'message': 'Nicht gefunden'})
        if server['suspended']: return jsonify({'success': False, 'message': 'Server ist gesperrt.'})
        
        target_node = RYZEN_NODE
        v_type = server['type'] if 'type' in server.keys() else 'qemu'
        
    if proxmox.start_vm(server_id, node=target_node, v_type=v_type):
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': proxmox.last_error})

@app.route('/server/<server_id>/stop', methods=['POST'])
def server_stop(server_id):
    if 'user' not in session: return jsonify({'success': False})
    server_id = server_id.replace('#', '')
    user_id = session['user']['id']
    with get_db() as conn:
        server = conn.execute('SELECT suspended, cpu_series, type FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
        if not server: return jsonify({'success': False, 'message': 'Nicht gefunden'})
        if server['suspended']: return jsonify({'success': False, 'message': 'Server ist gesperrt.'})
        
        target_node = RYZEN_NODE
        v_type = server['type'] if 'type' in server.keys() else 'qemu'
        
    if proxmox.stop_vm(server_id, node=target_node, v_type=v_type):
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': proxmox.last_error})

@app.route('/server/<server_id>/restart', methods=['POST'])
def server_restart(server_id):
    if 'user' not in session: return jsonify({'success': False})
    server_id = server_id.replace('#', '')
    user_id = session['user']['id']
    with get_db() as conn:
        server = conn.execute('SELECT suspended, cpu_series, type FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
        if not server: return jsonify({'success': False, 'message': 'Nicht gefunden'})
        if server['suspended']: return jsonify({'success': False, 'message': 'Server ist gesperrt.'})
        
        target_node = RYZEN_NODE
        v_type = server['type'] if 'type' in server.keys() else 'qemu'
        
    if proxmox.reboot_vm(server_id, node=target_node, v_type=v_type):
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': proxmox.last_error})

@app.route('/server/<server_id>/upgrade', methods=['POST'])
def server_upgrade(server_id):
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    
    user_id = session.get('user').get('id')
    data = request.json
    new_tier = data.get('tier')
    
    if not new_tier or new_tier not in SERVER_CONFIGS:
        return jsonify({'success': False, 'message': 'Ungültiger Tier'})
    
    with get_db() as conn:
        # Get server and user info
        server = conn.execute('SELECT * FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
        user = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not server:
            return jsonify({'success': False, 'message': 'Server nicht gefunden'})
        
        current_tier = server['name']
        current_price = float(server['price'].replace('€', '').strip())
        
        # Determine series
        series = dict(server).get('cpu_series', 'Intel')
        if series == 'Ryzen':
            new_tier_name = f"Ryzen {new_tier.replace('Intel ', '')}"
        else:
            new_tier_name = new_tier
        
        # Get new price
        new_price = SERVER_PRICES.get(new_tier_name, 0.00)
        price_diff = new_price - current_price
        
        # Apply 20% premium for upgrades
        if price_diff > 0:
            upgrade_cost = price_diff * 1.2
            if user['balance'] < upgrade_cost:
                return jsonify({'success': False, 'message': f'Nicht genügend Guthaben! Benötigt: {upgrade_cost:.2f}€'})
        else:
            # Downgrade - refund the difference
            upgrade_cost = price_diff  # Negative value
        
        # Get new config
        new_config = SERVER_CONFIGS.get(new_tier, SERVER_CONFIGS['Ryzen Starter'])
        target_node = RYZEN_NODE
        
        try:
            # Step 1: Stop the VM
            if not proxmox.stop_vm(server_id, node=target_node):
                return jsonify({'success': False, 'message': 'Fehler beim Stoppen des Servers'})
            
            # Wait for VM to stop
            import time
            time.sleep(5)
            
            # Step 2: Update resources
            if not proxmox.update_vm_resources(server_id, new_config['cores'], new_config['memory'], node=target_node):
                return jsonify({'success': False, 'message': 'Fehler beim Aktualisieren der Ressourcen'})
            
            # Step 3: Resize disk
            if not proxmox.resize_disk(server_id, new_config['disk'], node=target_node):
                return jsonify({'success': False, 'message': 'Fehler beim Resizen der Disk'})
            
            # Step 4: Start the VM
            if not proxmox.start_vm(server_id, node=target_node):
                return jsonify({'success': False, 'message': 'Fehler beim Starten des Servers'})
            
            # Step 5: Update database
            new_resources = f"{new_config['cores']} vCore CPU - {new_config['memory']//1024}GB RAM <br><small style=\"color:var(--muted)\">{new_config['disk']} NVMe</small>"
            
            conn.execute('''
                UPDATE servers 
                SET name = ?, price = ?, resources = ? 
                WHERE id = ?
            ''', (new_tier_name, f"{new_price:.2f}€", new_resources, server_id))
            
            # Step 6: Update balance and add transaction
            conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (upgrade_cost, user_id))
            
            action_type = "Upgrade" if price_diff > 0 else "Downgrade"
            conn.execute('''
                INSERT INTO transactions (user_id, amount, description) 
                VALUES (?, ?, ?)
            ''', (user_id, -upgrade_cost, f"{action_type}: {current_tier} → {new_tier_name}"))
            
            conn.commit()
            
            return jsonify({
                'success': True, 
                'message': f'Server erfolgreich auf {new_tier_name} {"upgraded" if price_diff > 0 else "downgraded"}!',
                'new_balance': user['balance'] - upgrade_cost
            })
            
        except Exception as e:
            return jsonify({'success': False, 'message': f'Fehler: {str(e)}'})


@app.route('/balance')
def balance():
    if 'user' not in session:
        return redirect(url_for('login'))
    user_session = session.get('user')
    user_id = user_session.get('id')
    
    with get_db() as conn:
        user_row = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        transaction_rows = conn.execute('SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 10', (user_id,)).fetchall()
        
    if user_row:
        user_session['balance'] = user_row['balance']
    
    transactions = [dict(t) for t in transaction_rows]
        
    return render_template('balance.html', user=user_session, transactions=transactions)

@app.route('/login')
def login():
    auth_url = f"{DISCORD_API_BASE_URL}/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={DISCORD_REDIRECT_URI}&response_type=code&scope=identify%20email"
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    if not code:
        return "Error: No code returned from Discord"

    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    token_response = requests.post(f'{DISCORD_API_BASE_URL}/oauth2/token', data=data, headers=headers)
    
    if token_response.status_code != 200:
        return f"Error fetching token: {token_response.text}"
        
    tokens = token_response.json()
    access_token = tokens.get('access_token')
    
    user_response = requests.get(f'{DISCORD_API_BASE_URL}/users/@me', headers={
        'Authorization': f'Bearer {access_token}'
    })
    
    if user_response.status_code != 200:
        return f"Error fetching user: {user_response.text}"
        
    user_data = user_response.json()
    user_id = user_data.get('id')
    username = user_data.get('username')
    
    with get_db() as conn:
        user_row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user_row:
            conn.execute('INSERT INTO users (id, username, balance) VALUES (?, ?, ?)', (user_id, username, 0.00))
            conn.commit()
            user_data['balance'] = 0.00
        else:
            user_data['balance'] = user_row['balance']
    
    session['user'] = user_data
    return redirect(url_for('dashboard'))

@app.route('/profile')
def profile():
    if 'user' not in session: return redirect(url_for('login'))
    user_id = session['user']['id']
    
    with get_db() as conn:
        # Original profile logic (adjusted)
        user_session = session.get('user')
        row = conn.execute('SELECT balance FROM users WHERE id = ?', (user_session.get('id'),)).fetchone()
        if row:
            user_session['balance'] = row['balance']
    return render_template('profile.html', user=user_session)

@app.route('/balance/notify', methods=['POST'])
def balance_notify():
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    
    data = request.json
    user = session.get('user')
    amount = data.get('amount')
    pp_name = data.get('pp_name')
    
    webhook_data = {
        "embeds": [{
            "title": "💰 Neue Guthaben-Anfrage",
            "color": 13382399, # Purple
            "fields": [
                {"name": "User", "value": f"{user.get('username')} ({user.get('id')})", "inline": True},
                {"name": "PayPal Name", "value": pp_name, "inline": True},
                {"name": "Betrag", "value": f"{amount}€", "inline": True}
            ],
            "description": f"Klicke unten, um die Zahlung zu verarbeiten.\n\n"
                           f"[✅ Genehmigen](http://127.0.0.1:5000/admin/approve_balance?user_id={user.get('id')}&amount={amount}&token={ADMIN_SECRET}) | "
                           f"[❌ Ablehnen](http://127.0.0.1:5000/admin/cancel_balance?user_id={user.get('id')}&token={ADMIN_SECRET})"
        }]
    }
    
    if DISCORD_WEBHOOK_URL:
        try:
            requests.post(DISCORD_WEBHOOK_URL, json=webhook_data)
        except:
            pass
            
    return jsonify({'success': True})

@app.route('/admin/approve_balance')
def approve_balance():
    user_id = request.args.get('user_id')
    amount_str = request.args.get('amount', '0')
    token = request.args.get('token')
    
    try:
        amount = float(amount_str)
    except ValueError:
        return "Ungültiger Betrag", 400
    
    if token != ADMIN_SECRET:
        return "Unauthorized", 401
    
    with get_db() as conn:
        # Check if user exists
        user_exists = conn.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user_exists:
            return f"Fehler: User {user_id} existiert nicht in der Datenbank!", 404
            
        conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, user_id))
        
        # Log Transaction
        date_str = datetime.now().strftime('%d.%m.%Y')
        conn.execute('''
            INSERT INTO transactions (user_id, date, description, status, amount, type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, date_str, "Gutschrift (PayPal)", "Erfolgreich", amount, "pos"))
        
        conn.commit()
        
        new_balance_row = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
    
    return f"Erfolgreich! {amount}€ wurden User {user_id} gutgeschrieben. Aktueller Stand: {new_balance_row['balance'] if new_balance_row else '?' }€"

@app.route('/admin/cancel_balance')
def cancel_balance():
    token = request.args.get('token')
    if token != ADMIN_SECRET:
        return "Unauthorized", 401
    return "Zahlung wurde abgelehnt."

@app.route('/profile/data', methods=['GET', 'POST'])
def profile_data():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_session = session.get('user')
    user_id = user_session.get('id')
    
    with get_db() as conn:
        user_row = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        saved_data_row = conn.execute('SELECT * FROM user_data WHERE user_id = ?', (user_id,)).fetchone()
        
    user_session['balance'] = user_row['balance'] if user_row else 10.00
    saved_data = dict(saved_data_row) if saved_data_row else None
    
    if request.method == 'POST':
        if saved_data:
            return redirect(url_for('profile_data'))
            
        address_data = (
            user_id,
            request.form.get('firstname'),
            request.form.get('lastname'),
            request.form.get('company'),
            request.form.get('vat'),
            request.form.get('street'),
            request.form.get('houseno'),
            request.form.get('zip'),
            request.form.get('city'),
            request.form.get('country'),
            request.form.get('phone')
        )
        with get_db() as conn:
            conn.execute('''
                INSERT INTO user_data (user_id, firstname, lastname, company, vat, street, houseno, zip, city, country, phone)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', address_data)
            conn.commit()
        return redirect(url_for('profile_data'))

    return render_template('profile_data.html', user=user_session, saved_data=saved_data)

@app.route('/free-server')
def free_server_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    user_session = session.get('user')
    user_id = user_session.get('id')
    
    with get_db() as conn:
        user_row = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        server_row = conn.execute('SELECT id FROM servers WHERE user_id = ? AND price = "Kostenlos"', (user_id,)).fetchone()
        
    user_session['balance'] = user_row['balance'] if user_row else 10.00
    claimed = True if server_row else False
    
    return render_template('free_server.html', user=user_session, claimed=claimed)

@app.route('/domains', methods=['GET', 'POST'])
def domains_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session.get('user')
    
    with get_db() as conn:
        row = conn.execute('SELECT balance FROM users WHERE id = ?', (user.get('id'),)).fetchone()
        if row:
            user['balance'] = row['balance']
    
    search_term = ""
    results = []
    
    if request.method == 'POST':
        search_term = request.form.get('domain_name', '').strip().lower()
        if search_term:
            import socket
            import concurrent.futures
            
            def check_domain(domain):
                status = 'available'
                try:
                    socket.gethostbyname(domain)
                    status = 'taken'
                except socket.gaierror:
                    status = 'available'
                except Exception:
                    status = 'unknown'
                
                base_price = 9.99
                if domain.endswith('.de'): base_price = 4.99
                elif domain.endswith('.com'): base_price = 11.99
                elif domain.endswith('.net'): base_price = 9.99
                elif domain.endswith('.org'): base_price = 10.99
                elif domain.endswith('.eu'): base_price = 6.99
                elif domain.endswith('.io'): base_price = 39.99
                elif domain.endswith('.me'): base_price = 14.99
                elif domain.endswith('.info'): base_price = 12.99
                elif domain.endswith('.biz'): base_price = 13.99
                elif domain.endswith('.co'): base_price = 24.99
                elif domain.endswith('.app'): base_price = 19.99
                elif domain.endswith('.dev'): base_price = 18.99
                elif domain.endswith('.xyz'): base_price = 2.99
                elif domain.endswith('.online'): base_price = 4.99
                elif domain.endswith('.site'): base_price = 1.99
                elif domain.endswith('.store'): base_price = 7.99
                elif domain.endswith('.tech'): base_price = 8.99
                elif domain.endswith('.cloud'): base_price = 15.99
                elif domain.endswith('.shop'): base_price = 5.99
                elif domain.endswith('.rich'): base_price = 199.99
                elif domain.endswith('.luxury'): base_price = 500.00
                elif domain.endswith('.auto'): base_price = 60.00
                
                discounted_price = base_price * 0.10
                if base_price > 50.00:
                    return None
                
                return {
                    'name': domain,
                    'status': status,
                    'original_price': f"{base_price:.2f}",
                    'price': f"{discounted_price:.2f}",
                    'can_buy': True
                }

            if '.' in search_term:
                domains_to_check = [search_term]
            else:
                base_name = search_term
                tlds = [
                    '.de', '.com', '.net', '.org', '.eu', '.info', '.biz', '.co', '.me', '.io',
                    '.online', '.store', '.tech', '.site', '.xyz', '.cloud', '.app', '.dev', '.shop', 
                    '.rich', '.auto', '.luxury'
                ]
                domains_to_check = [f"{base_name}{tld}" for tld in tlds]

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                results = [r for r in executor.map(check_domain, domains_to_check) if r is not None]
            
    return render_template('domains.html', user=user, search_term=search_term, results=results)

@app.route('/claim_free_server')
def claim_free_server():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user_session = session.get('user')
    user_id = user_session.get('id')
    
    with get_db() as conn:
        existing_free = conn.execute('SELECT id FROM servers WHERE user_id = ? AND price = "Kostenlos"', (user_id,)).fetchone()
        if existing_free:
            return jsonify({'success': False, 'message': 'Du hast bereits einen Gratis-Server erhalten!'})
            
        # Check if already has ANY active server (Anti-Hoarding) - Optional enforcement
        # existing_any = conn.execute('SELECT COUNT(*) as count FROM servers WHERE user_id = ?', (user_id,)).fetchone()
        # if existing_any['count'] > 0:
        #      return jsonify({'success': False, 'message': 'Du hast bereits aktive Server.'})

        # Check Lifetime Limit
        user_row = conn.execute('SELECT has_claimed_free FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_row and user_row['has_claimed_free']:
             return jsonify({'success': False, 'message': 'Du hast deinen kostenlosen Server bereits einmal beansprucht.'})
             
        # Mark as claimed (Wait until success? Ideally yes, but let's do it here to prevent race conditions or do it after success)
        # We will do it AFTER successful provisioning to be fair.
        
        # IP Management
        # Free servers are Intel by default
        free_ip_row = conn.execute("SELECT ip FROM ips WHERE used = 0 AND ip NOT LIKE '5.175.221.%' LIMIT 1").fetchone()
        if not free_ip_row:
            return jsonify({'success': False, 'message': 'Keine freien IPs verfügbar!'})
        
        ip_to_use = free_ip_row['ip']
        vmid = proxmox.get_next_vmid(node=RYZEN_NODE)
        if not vmid:
            return jsonify({'success': False, 'message': f'Proxmox API Fehler: {proxmox.last_error}'})
            
        os_name = request.args.get('os', 'Ubuntu 22.04')
        if os_name not in TEMPLATES: os_name = 'Ubuntu 22.04'

        if _provision_vm_async(vmid, user_id, 'Intel Starter', os_name, ip_to_use, 'Kostenlos', series='Intel'):
            with get_db() as conn:
                conn.execute('UPDATE users SET has_claimed_free = 1 WHERE id = ?', (user_id,))
                conn.commit()
            return jsonify({'success': True, 'vmid': vmid})
        else:
            return jsonify({'success': False, 'message': f'Provisioning Fehler: {proxmox.last_error}'})

@app.route('/buy_server', methods=['POST'])
def buy_server():
    print("[DEBUG] buy_server called")
    if 'user' not in session: return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    data = request.json
    tier = data.get('tier')
    series = data.get('series', 'Ryzen')
    if series not in ['Ryzen']: series = 'Ryzen'
    
    # Adjust tier name for price lookup if it's Ryzen
    lookup_tier = tier
    if series == 'Ryzen' and tier.startswith('Intel '):
        lookup_tier = tier.replace('Intel ', 'Ryzen ')
    
    price = SERVER_PRICES.get(lookup_tier)
    
    if price is None: return jsonify({'success': False, 'message': 'Ungültiges Paket'})
    
    user_id = session.get('user').get('id')
    with get_db() as conn:
        user = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user: return jsonify({'success': False, 'message': 'User nicht gefunden'})
        
        if user['balance'] < price:
            return jsonify({'success': False, 'message': 'Nicht genügend Guthaben!'})
            
        # IP Management
        free_ip_row = conn.execute("SELECT ip FROM ips WHERE used = 0 AND ip LIKE '5.175.221.%' LIMIT 1").fetchone()

        if not free_ip_row:
            return jsonify({'success': False, 'message': f'Keine freien {series} IPs verfügbar!'})
            
        ip_to_use = free_ip_row['ip']
        target_node = RYZEN_NODE
        vmid = proxmox.get_next_vmid(node=target_node)
        if not vmid:
            return jsonify({'success': False, 'message': f'Proxmox API Fehler: {proxmox.last_error}'})
        
        print(f"[DEBUG] Got VMID: {vmid}, IP: {ip_to_use}, Tier: {tier}, Series: {series}")
        
        # Pre-provisioning cleanup: Remove any orphaned database records for this VMID
        existing_server = conn.execute('SELECT id, ip FROM servers WHERE id = ?', (str(vmid),)).fetchone()
        if existing_server:
            # Free the old IP and delete the orphaned record
            conn.execute('UPDATE ips SET used = 0 WHERE ip = ?', (existing_server['ip'],))
            conn.execute('DELETE FROM servers WHERE id = ?', (str(vmid),))
            conn.execute('DELETE FROM server_additional_ips WHERE server_id = ?', (str(vmid),))
            conn.commit()
            
        # Deduct balance
        conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (price, user_id))
        
        # Rename Tier if Ryzen
        display_tier = tier  # Already correct for Ryzen
        
        conn.execute('INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)',
                     (user_id, -price, f"Kauf: {display_tier} Server"))
        conn.commit()
        
    os_name = data.get('os', 'Ubuntu 22.04')
    if os_name not in TEMPLATES: os_name = 'Ubuntu 22.04'
    
    # Rename Tier if Ryzen
    display_tier = tier  # Already correct
    
    print(f"[DEBUG] Starting provisioning for VMID {vmid}, OS: {os_name}, Display Tier: {display_tier}")
    if _provision_vm_async(vmid, user_id, display_tier, os_name, ip_to_use, f"{price:.2f}€", series=series):
        return jsonify({'success': True, 'vmid': vmid})
    else:
        # Refund if failed? In real world yes.
        return jsonify({'success': False, 'message': f'Provisioning Fehler: {proxmox.last_error}'})

@app.route('/buy_custom_server', methods=['POST'])
def buy_custom_server():
    if 'user' not in session: return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    data = request.json
    
    try:
        cpu = int(data.get('cpu', 2))
        ram = int(data.get('ram', 4))
        disk = int(data.get('disk', 20))
        os_name = data.get('os', 'Ubuntu 22.04')
    except:
        return jsonify({'success': False, 'message': 'Ungültige Daten'})
        
    # Validation
    if not (1 <= cpu <= 32): return jsonify({'success': False, 'message': 'Ungültige CPU Anzahl'})
    if not (2 <= ram <= 64): return jsonify({'success': False, 'message': 'Ungültiger RAM'})
    if not (10 <= disk <= 500): return jsonify({'success': False, 'message': 'Ungültiger Speicher'})
    
    # OS Specific Requirements
    if 'Windows' in os_name:
        if cpu < 2: return jsonify({'success': False, 'message': 'Windows benötigt mindestens 2 vCores.'})
        if ram < 4: return jsonify({'success': False, 'message': 'Windows benötigt mindestens 4 GB RAM.'})
        if disk < 40: return jsonify({'success': False, 'message': 'Windows benötigt mindestens 40 GB Speicher.'})

    series = data.get('series', 'Ryzen')
    if series not in ['Ryzen']: series = 'Ryzen'

    # Calculate Price (Must match frontend)
    # Base: 1.00, CPU: 0.25, RAM: 0.50, Disk: 0.05
    # For Ryzen, let's add a premium (e.g. 1.5x)
    multiplier = 1.0
    if series == 'Ryzen':
        multiplier = 1.6 # User said "Ryzen ist natürlich teurer"
    
    price = (1.00 + (cpu * 0.25) + (ram * 0.50) + (disk * 0.05)) * multiplier
    
    user_id = session.get('user').get('id')
    with get_db() as conn:
        user = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user: return jsonify({'success': False, 'message': 'User nicht gefunden'})
        
        if user['balance'] < price:
            return jsonify({'success': False, 'message': 'Nicht genügend Guthaben!'})
            
        # IP Management
        free_ip_row = conn.execute("SELECT ip FROM ips WHERE used = 0 AND ip LIKE '5.175.221.%' LIMIT 1").fetchone()

        if not free_ip_row:
            return jsonify({'success': False, 'message': f'Keine freien {series} IPs verfügbar!'})
            
        ip_to_use = free_ip_row['ip']
        target_node = RYZEN_NODE
        vmid = proxmox.get_next_vmid(node=target_node)
        if not vmid:
            return jsonify({'success': False, 'message': f'Proxmox API Fehler: {proxmox.last_error}'})
        
        # Pre-provisioning cleanup: Remove any orphaned database records for this VMID
        existing_server = conn.execute('SELECT id, ip FROM servers WHERE id = ?', (str(vmid),)).fetchone()
        if existing_server:
            # Free the old IP and delete the orphaned record
            conn.execute('UPDATE ips SET used = 0 WHERE ip = ?', (existing_server['ip'],))
            conn.execute('DELETE FROM servers WHERE id = ?', (str(vmid),))
            conn.execute('DELETE FROM server_additional_ips WHERE server_id = ?', (str(vmid),))
            conn.commit()
            
        # Deduct balance
        conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (price, user_id))
        display_name = f"Custom {series} Server"
        conn.execute('INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)',
                     (user_id, -price, f"Kauf: {display_name} ({cpu}C/{ram}G/{disk}G)"))
        conn.commit()
        
    if os_name not in TEMPLATES: os_name = 'Ubuntu 22.04'
    
    return _provision_custom_vm_async(vmid, user_id, cpu, ram, disk, os_name, ip_to_use, f"{price:.2f}€", series=series)

def _provision_custom_vm_async(vmid, user_id, cpu, ram, disk, os_name, ip, price_str, series='Intel'):
    import threading
    
    # Determine Node, GW and Templates based on series
    if series == 'Ryzen':
        target_node = RYZEN_NODE
        target_gw = RYZEN_GW
        target_templates = RYZEN_TEMPLATES
    # else:
    #     target_node = INTEL_NODE
    #     target_gw = INTEL_GW
    #     target_templates = TEMPLATES

    template_id = target_templates.get(os_name, target_templates['Ubuntu 22.04'])
    password = generate_password()
    
    # Create DB Entry
    created_at = datetime.now().strftime('%d.%m.%Y')
    expiry_date = (datetime.now() + timedelta(days=30)).strftime('%d.%m.%Y %H:%M')
    
    res_string = f"{cpu} vCore CPU - {ram}GB RAM <br><small style=\"color:var(--muted)\">{disk}GB NVMe</small>"
    
    display_name = f"Custom {series} Server"
    
    with get_db() as conn:
        conn.execute('''
            INSERT INTO servers (id, user_id, name, os, ip, status, resources, price, expiry, created_at, password, provisioning_status, cpu_series)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (str(vmid), user_id, display_name, os_name, ip, 'Provisioning', res_string, price_str, expiry_date, created_at, password, 'cloning', series))
        conn.execute('UPDATE ips SET used = 1 WHERE ip = ?', (ip,))
        conn.commit()
        
    def provision_background():
        try:
            upid = proxmox.clone_vm(template_id, vmid, f"vs{vmid}", node=target_node)
            if upid and proxmox.wait_for_task(upid, node=target_node):
                import time
                time.sleep(5)
                
                with get_db() as conn:
                    conn.execute('UPDATE servers SET provisioning_status = ? WHERE id = ?', ('configuring', str(vmid)))
                    conn.commit()
                if not proxmox.resize_disk(vmid, f"{disk}G", node=target_node):
                    print(f"Resize failed for {vmid}: {proxmox.last_error}")
                
                ci_user = "Administrator" if "Windows" in os_name else "root"
                proxmox.configure_cloudinit(vmid, ip, username=ci_user, password=password, node=target_node, gw=target_gw)
                
                with get_db() as conn:
                    conn.execute('UPDATE servers SET provisioning_status = ? WHERE id = ?', ('starting', str(vmid)))
                    conn.commit()
                    
                proxmox.start_vm(vmid, node=target_node)
                
                with get_db() as conn:
                    conn.execute('UPDATE servers SET status = ?, provisioning_status = ? WHERE id = ?', 
                               ('Online', 'complete', str(vmid)))
                    conn.commit()
            else:
                with get_db() as conn:
                    conn.execute('UPDATE servers SET status = ?, provisioning_status = ? WHERE id = ?', 
                               ('Error', 'failed', str(vmid)))
                    conn.commit()
        except Exception as e:
            print(f"Provisioning error for {vmid}: {e}")
            with get_db() as conn:
                conn.execute('UPDATE servers SET status = ?, provisioning_status = ? WHERE id = ?', 
                           ('Error', 'failed', str(vmid)))
                conn.commit()
    
    thread = threading.Thread(target=provision_background, daemon=True)
    thread.start()
    return jsonify({'success': True, 'vmid': vmid})

@app.route('/server/<server_id>/provision_status')
def check_provision_status(server_id):
    """Endpoint to poll provisioning status"""
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    
    user_id = session.get('user').get('id')
    
    with get_db() as conn:
        server = conn.execute(
            'SELECT provisioning_status, status FROM servers WHERE id = ? AND user_id = ?',
            (server_id, user_id)
        ).fetchone()
        
        if not server:
            return jsonify({'success': False, 'message': 'Server nicht gefunden'})
        
        prov_status = server['provisioning_status'] or 'complete'
        
        return jsonify({
            'success': True,
            'provisioning_status': prov_status,
            'status': server['status'],
            'complete': prov_status == 'complete',
            'failed': prov_status == 'failed'
        })


@app.route('/dashboard')
@app.route('/dashboard/<tab>')
@app.route('/dashboard/<tab>/<sub>')
def dashboard(tab='home', sub=None):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    # Periodic check (could be optimized to run background task, but this works for simple app)
    check_expirations()
    
    user_session = session.get('user')
    user_id = user_session.get('id')
    
    with get_db() as conn:
        user_row = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        server_rows = conn.execute('SELECT * FROM servers WHERE user_id = ?', (user_id,)).fetchall()
        
    user_session['balance'] = user_row['balance'] if user_row else 10.00
    
    servers = []
    deleted_servers = []  # Track servers to delete
    
    for row in server_rows:
        s = dict(row)
        target_node = RYZEN_NODE
        
        # Live Sync for every server
        prox_stats = proxmox.get_vm_stats(s['id'], node=target_node)
        if prox_stats == 'deleted' or not prox_stats:
            deleted_servers.append({'id': s['id'], 'ip': s['ip']})
            continue
        
        real_status = prox_stats.get('status', 'unknown')
        if s.get('suspended'):
            s['status'] = 'Gesperrt'
        else:
            s['status'] = 'Online' if real_status == 'running' else 'Offline'
            
        # Refresh components from Proxmox
        config = proxmox.get_vm_config(s['id'], node=target_node)
        update_needed = False
        if config:
            # IP Sync
            ipconfig0 = config.get('ipconfig0', '')
            if 'ip=' in ipconfig0:
                new_ip = ipconfig0.split('ip=')[1].split(',')[0].split('/')[0]
                if new_ip.lower() != 'dhcp' and new_ip != s.get('ip'):
                    s['ip'] = new_ip
                    update_needed = True
            
            # Resources Sync
            mem = int(prox_stats.get('maxmem', 0) / (1024**3))
            cpus = prox_stats.get('cpus', 0)
            disk = int(prox_stats.get('maxdisk', 0) / (1024**3))
            new_resources = f"<b>{cpus}</b> Kerne, <b>{mem}</b> GB RAM, <b>{disk}</b> GB Disk"
            if new_resources != s.get('resources'):
                s['resources'] = new_resources
                update_needed = True
        
        if update_needed:
            with get_db() as conn_upd:
                conn_upd.execute('UPDATE servers SET ip = ?, resources = ? WHERE id = ?', 
                                 (s['ip'], s['resources'], s['id']))
                # Auto-Sync: Mark IP as used if it's a real IP
                if s['ip'] and s['ip'].lower() != 'dhcp' and s['ip'] != 'Manual':
                     conn_upd.execute('UPDATE ips SET used = 1 WHERE ip = ?', (s['ip'],))
                conn_upd.commit()
        else:
             # Also ensure existing IP is marked used even if no update needed
             if s.get('ip') and s['ip'].lower() != 'dhcp' and s['ip'] != 'Manual':
                 with get_db() as conn_sync:
                     conn_sync.execute('UPDATE ips SET used = 1 WHERE ip = ?', (s['ip'],))
                     conn_sync.commit()

        servers.append(s)
    
    # Cleanup deleted servers in a single transaction
    if deleted_servers:
        with get_db() as conn:
            for deleted in deleted_servers:
                conn.execute('UPDATE ips SET used = 0 WHERE ip = ?', (deleted['ip'],))
                conn.execute('DELETE FROM servers WHERE id = ?', (deleted['id'],))
                # Also cleanup additional IPs
                conn.execute('DELETE FROM server_additional_ips WHERE server_id = ?', (deleted['id'],))
            conn.commit()
        
    total_monthly_costs = 0
    for s in servers:
        price_str = s.get('price', '0.00').replace('€', '').strip()
        try:
            total_monthly_costs += float(price_str)
        except:
            pass
            
    return render_template('dashboard.html', 
                          user=user_session, 
                          servers=servers, 
                          total_costs=f"{total_monthly_costs:.2f}",
                          active_count=len(servers),
                          active_tab=tab,
                          active_sub=sub)

@app.route('/admin/data')
def admin_data():
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False, 'message': 'Zugriff verweigert'})
    
    with get_db() as conn:
        # Users with potential email from user_data if exists, else placeholder
        users = conn.execute('''
            SELECT u.id, u.username, u.balance, ud.firstname, ud.lastname 
            FROM users u 
            LEFT JOIN user_data ud ON u.id = ud.user_id
        ''').fetchall()
        
        servers_raw = conn.execute('SELECT * FROM servers').fetchall()
        ips = conn.execute('SELECT * FROM ips').fetchall()
        
        servers = []
        deleted_servers = []  # Track servers to delete
        
        for s in servers_raw:
            s_dict = dict(s)
            add_ips = conn.execute('SELECT ip FROM server_additional_ips WHERE server_id = ?', (s['id'],)).fetchall()
            s_dict['additional_ips'] = [row['ip'] for row in add_ips]
            
            target_node = RYZEN_NODE
            
            # Real-time status for admin - with cleanup logic
            vm_stats = proxmox.get_vm_stats(s['id'], node=target_node)
            
            if vm_stats == 'deleted' or not vm_stats:
                deleted_servers.append({'id': s['id'], 'ip': s['ip']})
                continue

            s_dict['real_status'] = vm_stats.get('status', 'offline') if vm_stats else 'offline'
            servers.append(s_dict)
            
        # Unmanaged Servers Logic - Use Cluster Resources for maximum visibility (QEMU + LXC)
        all_res = proxmox.get_cluster_resources()
        managed_vmid = [str(s['id']) for s in servers_raw]
        
        unmanaged_servers = []
        for res in all_res:
            v_type = res.get('type')
            if v_type not in ['qemu', 'lxc']: continue
            
            vmid_str = str(res.get('vmid'))
            if vmid_str not in managed_vmid and not res.get('template'):
                node = res.get('node', 'unknown')
                unmanaged_servers.append({
                    'id': vmid_str,
                    'name': res.get('name', 'Unknown'),
                    'status': res.get('status', 'unknown'),
                    'node': node.upper(),
                    'type': v_type,
                    'cpu': round(res.get('cpu', 0) * 100, 1),
                    'mem': round((res.get('mem', 0) / res.get('maxmem', 1)) * 100, 1) if res.get('maxmem') else 0
                })
    
    # Cleanup deleted servers in a single transaction
    if deleted_servers:
        with get_db() as conn:
            for deleted in deleted_servers:
                conn.execute('UPDATE ips SET used = 0 WHERE ip = ?', (deleted['ip'],))
                conn.execute('DELETE FROM servers WHERE id = ?', (deleted['id'],))
                # Also cleanup additional IPs
                conn.execute('DELETE FROM server_additional_ips WHERE server_id = ?', (deleted['id'],))
            conn.commit()
            
    return jsonify({
        'success': True,
        'users': [dict(row) for row in users],
        'servers': servers,
        'unmanaged': unmanaged_servers,
        'ips': [dict(row) for row in ips]
    })

@app.route('/admin/user/<user_id>/update_balance', methods=['POST'])
def admin_update_balance(user_id):
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False})
    amount = request.json.get('amount')
    with get_db() as conn:
        conn.execute('UPDATE users SET balance = ? WHERE id = ?', (amount, user_id))
        conn.commit()
    return jsonify({'success': True})

@app.route('/admin/server/<server_id>/action', methods=['POST'])
def admin_server_action(server_id):
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False, 'message': 'Nicht autorisiert'})
    
    action = request.json.get('action')
    success = False
    
    with get_db() as conn:
        server = conn.execute('SELECT cpu_series, type FROM servers WHERE id = ?', (server_id,)).fetchone()
    
    target_node = RYZEN_NODE
    v_type = server['type'] if server else 'qemu' # Default to qemu if not found

    if action == 'start': success = proxmox.start_vm(server_id, node=target_node, v_type=v_type)
    elif action == 'stop': success = proxmox.stop_vm(server_id, node=target_node, v_type=v_type)
    elif action == 'restart': success = proxmox.reboot_vm(server_id, node=target_node, v_type=v_type)
    elif action == 'suspend': 
        proxmox.suspend_vm(server_id, node=target_node, v_type=v_type)
        with get_db() as conn:
            conn.execute('UPDATE servers SET suspended = 1 WHERE id = ?', (server_id,))
            conn.commit()
        success = True
    elif action == 'resume': 
        proxmox.resume_vm(server_id, node=target_node, v_type=v_type)
        with get_db() as conn:
            conn.execute('UPDATE servers SET suspended = 0 WHERE id = ?', (server_id,))
            conn.commit()
        success = True
    elif action == 'delete': 
        if proxmox.delete_vm(server_id, node=target_node, v_type=v_type):
            success = True
            with get_db() as conn:
                # Free main IP
                server = conn.execute('SELECT ip FROM servers WHERE id = ?', (server_id,)).fetchone()
                if server:
                    conn.execute('UPDATE ips SET used = 0 WHERE ip = ?', (server['ip'],))
                
                # Free additional IPs
                add_ips = conn.execute('SELECT ip FROM server_additional_ips WHERE server_id = ?', (server_id,)).fetchall()
                for row in add_ips:
                    conn.execute('UPDATE ips SET used = 0 WHERE ip = ?', (row['ip'],))
                
                conn.execute('DELETE FROM server_additional_ips WHERE server_id = ?', (server_id,))
                conn.execute('DELETE FROM servers WHERE id = ?', (server_id,))
                conn.commit()
        else:
            success = False

    return jsonify({
        'success': success, 
        'message': proxmox.last_error if not success else f"Aktion {action} erfolgreich."
    })

@app.route('/admin/server/<server_id>/credentials')
def admin_get_credentials(server_id):
    """Admin-only endpoint to view server credentials"""
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False, 'message': 'Zugriff verweigert'})
    
    with get_db() as conn:
        server = conn.execute('SELECT os, password FROM servers WHERE id = ?', (server_id,)).fetchone()
        
        if not server:
            return jsonify({'success': False, 'message': 'Server nicht gefunden'})
        
        # Determine username based on OS
        username = "Administrator" if "Windows" in server['os'] else "root"
        
        return jsonify({
            'success': True,
            'username': username,
            'password': server['password'],
            'os': server['os']
        })


@app.route('/server/<server_id>/renew', methods=['POST'])
def renew_server(server_id):
    print(f"DEBUG: Renewable route hit for {server_id}") # FORCE PRINT
    if 'user' not in session: return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    user_id = session.get('user').get('id')
    
    with get_db() as conn:
        server = conn.execute('SELECT * FROM servers WHERE id = ? AND user_id = ?', (server_id, user_id)).fetchone()
        if not server: return jsonify({'success': False, 'message': 'Server nicht gefunden'})
        
        # Calculate Price
        # First try to look up current price based on Tier (server['name'])
        tier_name = server['name'].strip()
        current_tier_price = SERVER_PRICES.get(tier_name)
        
        print(f"Renewal Debug: Server ID {server_id} Name: '{server['name']}' -> Strip: '{tier_name}'")
        print(f"Renewal Debug: Lookup Result: {current_tier_price}")
        
        price = None
        
        if current_tier_price is not None:
             price = float(current_tier_price)
             if price == 0:
                 return jsonify({'success': False, 'message': 'Kostenlose Server können nicht manuell verlängert werden.'})
        else:
            # Fallback 2: Match Resources (Smart Recovery)
            # If name lookup failed (e.g. custom name), try to match Config
            try:
                target_node = RYZEN_NODE
                vm_stats = proxmox.get_vm_stats(server_id, node=target_node, v_type=server['type'] if 'type' in server.keys() else 'qemu')
                print(f"Renewal Debug: VM Stats for {server_id}: {vm_stats}")
                
                if vm_stats and vm_stats != 'deleted' and isinstance(vm_stats, dict):
                    # Proxmox returns maxmem in Bytes
                    p_cores = vm_stats.get('cpus', 0)
                    p_mem_mb = int(vm_stats.get('maxmem', 0) / (1024 * 1024))
                    
                    print(f"Renewal Debug: Matching Resources: {p_cores} Cores, {p_mem_mb} MB RAM")
                    
                    matched_tier = None
                    for tier, conf in SERVER_CONFIGS.items():
                        # Allow small tolerance for memory (sometimes Proxmox reports slightly less)
                        if conf['cores'] == p_cores and abs(conf['memory'] - p_mem_mb) < 512:
                            matched_tier = tier
                            break
                    
                    if matched_tier:
                        recovered_price = SERVER_PRICES.get(matched_tier)
                        print(f"Renewal Debug: Matched Tier '{matched_tier}' -> Price {recovered_price}")
                        if recovered_price is not None:
                             price = float(recovered_price)
                             if price == 0:
                                 return jsonify({'success': False, 'message': 'Kostenlose Server können nicht manuell verlängert werden.'})

            except Exception as e:
                print(f"Renewal Debug: Resource matching failed: {e}")

            if price is None:
                # Fallback 3: Parse 'price' string from DB (Last Resort)
                print("Renewal Debug: Falling back to DB Price string")
                price_str = server['price'].replace('€', '').strip()
                try:
                    price = float(price_str)
                    print(f"Renewal Debug: Server {server_id} Price String: '{server['price']}' -> Parsed: {price}")
                except:
                     return jsonify({'success': False, 'message': 'Kostenlose Server können nicht manuell verlängert werden.'})
        
        print(f"DEBUG: Final Price to deduct: {price}")
        
        user = conn.execute('SELECT balance FROM users WHERE id = ?', (user_id,)).fetchone()
        if user['balance'] < price:
            return jsonify({'success': False, 'message': 'Nicht genügend Guthaben!'})
            
        # Renew
        try:
             current_expiry = datetime.strptime(server['expiry'], '%Y-%m-%d %H:%M:%S')
        except:
             current_expiry = datetime.now()

        # If already expired, start from NOW. If not, add to existing.
        if current_expiry < datetime.now():
             new_expiry = datetime.now() + timedelta(days=30)
        else:
             new_expiry = current_expiry + timedelta(days=30)
             
        new_expiry_str = new_expiry.strftime('%Y-%m-%d %H:%M:%S')
        
        conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (price, user_id))
        conn.execute('UPDATE servers SET expiry = ?, suspended = 0 WHERE id = ?', (new_expiry_str, server_id))
        
        if server['suspended']:
            target_node = RYZEN_NODE if server['cpu_series'] == 'Ryzen' else INTEL_NODE
            proxmox.resume_vm(server_id, node=target_node, v_type=server['type'] if 'type' in server.keys() else 'qemu')
            
        conn.execute('INSERT INTO transactions (user_id, amount, description, date, status, type) VALUES (?, ?, ?, ?, ?, ?)',
                     (user_id, price, f"Manuelle Verlängerung: {server['name']}", datetime.now().strftime('%d.%m.%Y'), 'Erfolgreich', 'neg'))
        conn.commit()
        
    return jsonify({'success': True, 'new_expiry': new_expiry_str, 'message': 'Server erfolgreich verlängert!'})

@app.route('/admin/node/stats')
def admin_node_stats():
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False, 'message': 'Unauthorized'})
        
    intel_stats = proxmox.get_node_status(node=INTEL_NODE)
    ryzen_stats = proxmox.get_node_status(node=RYZEN_NODE)
    
    return jsonify({
        'success': True, 
        'intel': intel_stats,
        'ryzen': ryzen_stats
    })

@app.route('/admin/server/assign', methods=['POST'])
def admin_server_assign():
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False, 'message': 'Zugriff verweigert'})
    
    data = request.json
    vmid = data.get('vmid')
    user_id = data.get('user_id')
    
    if not vmid or not user_id:
        return jsonify({'success': False, 'message': 'Fehlende Daten'})

    # Find VM in cluster resources (Support QEMU + LXC)
    all_res = proxmox.get_cluster_resources()
    target_vm = next((r for r in all_res if str(r.get('vmid')) == str(vmid) and r.get('type') in ['qemu', 'lxc']), None)
    
    if not target_vm:
        return jsonify({'success': False, 'message': f'VMID {vmid} wurde in Proxmox (QEMU oder LXC) nicht gefunden.'})
    
    target_node = target_vm.get('node')
    v_type = target_vm.get('type')
    vm_name = target_vm.get('name', f"{v_type.upper()} {vmid}")
    
    # Pull Config for IP
    config = proxmox.get_vm_config(vmid, node=target_node, v_type=v_type)
    ip_addr = "Manual"
    if v_type == 'qemu':
        ipconfig0 = config.get('ipconfig0', '')
        if 'ip=' in ipconfig0:
            ip_addr = ipconfig0.split('ip=')[1].split(',')[0].split('/')[0]
    else: # LXC
        net0 = config.get('net0', '')
        if 'ip=' in net0:
            ip_addr = net0.split('ip=')[1].split(',')[0].split('/')[0]

    # Resources string
    mem = int(target_vm.get('maxmem', 0) / (1024**3))
    cpus = target_vm.get('cpus', 0)
    disk = int(target_vm.get('maxdisk', 0) / (1024**3))
    resources_str = f"<b>{cpus}</b> Kerne, <b>{mem}</b> GB RAM, <b>{disk}</b> GB Disk"
    
    cpu_series = 'Ryzen' if target_node == RYZEN_NODE else 'Intel'
    
    with get_db() as conn:
        exists = conn.execute('SELECT id FROM servers WHERE id = ?', (str(vmid),)).fetchone()
        if exists:
            return jsonify({'success': False, 'message': 'Dieser Server ist bereits im Panel registriert.'})
        
        created_at = datetime.now().strftime('%d.%m.%Y')
        expiry = (datetime.now() + timedelta(days=30)).strftime('%d.%m.%Y %H:%M')
        
        conn.execute('''
            INSERT INTO servers (id, user_id, name, os, ip, status, resources, price, expiry, created_at, password, provisioning_status, cpu_series, type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (str(vmid), user_id, vm_name, f'Proxmox {v_type.upper()}', ip_addr, 'Online', resources_str, '14.99€', expiry, created_at, 'N/A', 'complete', cpu_series, v_type))
        conn.commit()
    
    return jsonify({'success': True, 'message': 'Server erfolgreich zugewiesen!'})

@app.route('/server/<server_id>/complete_setup', methods=['POST'])
def complete_server_setup(server_id):
    """Endpoint to manually set OS and generate credentials if detection failed or is missing."""
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    
    user_id = session.get('user').get('id')
    data = request.json
    selected_os = data.get('os')
    
    if not selected_os:
        return jsonify({'success': False, 'message': 'Kein Betriebssystem gewählt'})
        
    # Check if user is admin
    is_admin = user_id in get_admin_ids()

    with get_db() as conn:
        # Check ownership (or admin access)
        if is_admin:
            server = conn.execute('SELECT id FROM servers WHERE id = ?', (server_id,)).fetchone()
        else:
            server = conn.execute('SELECT id, ip, resources, password FROM servers WHERE id = ? AND user_id = ?', 
                                (server_id, user_id)).fetchone()
        
        if not server:
            return jsonify({'success': False, 'message': 'Server nicht gefunden'})
            
        # ADMIN SPECIAL CASE: Just update OS, no touchy touchy
        if is_admin:
             conn.execute('UPDATE servers SET os = ? WHERE id = ?', (selected_os, server_id))
             conn.commit()
             return jsonify({'success': True, 'message': 'OS aktualisiert (Admin: Kein Reboot/Reset)'})

        # REGULAR USER: DO FULL SETUP
        
        # Generate new password if none exists or if it's "null"
        password = server['password']
        if not password or password == 'null':
            password = generate_password()
            
        # Determine username based on selected OS
        username = "Administrator" if "Windows" in selected_os else "root"
        
        target_node = RYZEN_NODE if server.get('cpu_series') == 'Ryzen' else INTEL_NODE
        target_gw = RYZEN_GW if server.get('cpu_series') == 'Ryzen' else INTEL_GW

        # Configure Cloud-Init on Proxmox
        try:
            # We need to authenticate as admin/system since regular users don't have PVE access
            # The session cookie is for the Flask app, Proxmox access uses the global `proxmox` object
            success = proxmox.configure_cloudinit(server_id, server['ip'], username=username, password=password, node=target_node, gw=target_gw)
            if not success:
                print(f"Warning: Cloud-Init configuration failed during setup for VM {server_id}")
                # We continue anyway, hoping for the best or manual intervention
        except Exception as e:
            print(f"Error executing Cloud-Init setup: {e}")
            
        # Force reboot to apply cloud-init? 
        # Ideally yes, but let's ask user to restart or do it automatically
        proxmox.reboot_vm(server_id, node=target_node)

        # Update Database
        conn.execute('UPDATE servers SET os = ?, password = ? WHERE id = ?', (selected_os, password, server_id))
        conn.commit()
        
    return jsonify({'success': True, 'message': 'Einrichtung abgeschlossen! Server wird neu gestartet.'})

@app.route('/server/<server_id>/console', methods=['GET'])
def server_console(server_id):
    if 'user' not in session:
        return jsonify({'success': False, 'message': 'Nicht eingeloggt'})
    
    user_id = session.get('user').get('id')
    is_admin = user_id in get_admin_ids()

    # Check ownership
    with get_db() as conn:
        if is_admin:
            server = conn.execute('SELECT id, name, cpu_series FROM servers WHERE id = ?', (server_id,)).fetchone()
        else:
            server = conn.execute('SELECT id, name, cpu_series FROM servers WHERE id = ? AND user_id = ?', 
                                (server_id, user_id)).fetchone()
    
    if not server:
        return jsonify({'success': False, 'message': 'Server nicht gefunden'})
        
    target_node = RYZEN_NODE if server['cpu_series'] == 'Ryzen' else INTEL_NODE

    # Get Proxy Ticket
    # For direct access, use the standard NoVNC URL without ticket
    # Users will need to log in to Proxmox directly
    full_url = f"{RYZEN_HOST}/?console=kvm&novnc=1&vmid={server_id}&node={target_node}&view=console"
    
    return jsonify({'success': True, 'url': full_url})

@app.route('/admin/ip/add', methods=['POST'])
def admin_add_ip():
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False})
    
    ip = request.json.get('ip')
    if not ip: return jsonify({'success': False, 'message': 'Keine IP angegeben'})
    
    with get_db() as conn:
        try:
            conn.execute('INSERT INTO ips (ip, used) VALUES (?, 0)', (ip,))
            conn.commit()
            return jsonify({'success': True})
        except sqlite3.IntegrityError:
            return jsonify({'success': False, 'message': 'IP existiert bereits'})

@app.route('/admin/ip/delete', methods=['POST'])
def admin_delete_ip():
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False})
    
    ip = request.json.get('ip')
    if not ip: return jsonify({'success': False, 'message': 'Keine IP angegeben'})
    
    with get_db() as conn:
        # Safety Check
        is_used = conn.execute('SELECT used FROM ips WHERE ip = ?', (ip,)).fetchone()
        if not is_used:
             return jsonify({'success': False, 'message': 'IP nicht gefunden'})
        
        if is_used['used']:
             return jsonify({'success': False, 'message': 'Diese IP wird gerade verwendet und kann nicht gelöscht werden!'})
             
        conn.execute('DELETE FROM ips WHERE ip = ?', (ip,))
        conn.commit()
        
    return jsonify({'success': True, 'message': 'IP erfolgreich gelöscht.'})

@app.route('/admin/server/<server_id>/add_ip', methods=['POST'])
def admin_server_add_ip(server_id):
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False})
    
    with get_db() as conn:
        server = conn.execute('SELECT cpu_series FROM servers WHERE id = ?', (server_id,)).fetchone()
        cpu_series = server['cpu_series'] if server and server['cpu_series'] else 'Intel'
        
        # Find a free IP based on Series
        if cpu_series == 'Ryzen':
            free_ip_row = conn.execute("SELECT ip FROM ips WHERE used = 0 AND ip LIKE '5.175.221.%' LIMIT 1").fetchone()
        else:
            free_ip_row = conn.execute("SELECT ip FROM ips WHERE used = 0 AND ip NOT LIKE '5.175.221.%' LIMIT 1").fetchone()
            
        if not free_ip_row:
            return jsonify({'success': False, 'message': f'Keine freien {cpu_series} IPs verfügbar'})
        
        ip_to_add = free_ip_row['ip']
        target_node = RYZEN_NODE if server and server['cpu_series'] == 'Ryzen' else INTEL_NODE
        target_gw = RYZEN_GW if server and server['cpu_series'] == 'Ryzen' else INTEL_GW

        # Proxmox Logic:
        # 1. Check how many IPs we have
        max_net_row = conn.execute('SELECT MAX(net_id) as max_id FROM server_additional_ips WHERE server_id = ?', (server_id,)).fetchone()
        max_net = max_net_row['max_id'] if max_net_row else 0
        net_id = (max_net if max_net is not None else 0) + 1
        
        if proxmox.add_network_interface(server_id, net_id, node=target_node):
            if proxmox.configure_additional_ip(server_id, net_id, ip_to_add, node=target_node, gw=target_gw):
                conn.execute('INSERT INTO server_additional_ips (server_id, ip, net_id) VALUES (?, ?, ?)', (server_id, ip_to_add, net_id))
                conn.execute('UPDATE ips SET used = 1 WHERE ip = ?', (ip_to_add,))
                conn.commit()
                return jsonify({'success': True, 'ip': ip_to_add})
            else:
                return jsonify({'success': False, 'message': f'IP Config Fehler: {proxmox.last_error}'})
        else:
            return jsonify({'success': False, 'message': f'Netzwerk Fehler: {proxmox.last_error}'})

@app.route('/admin/server/<server_id>/remove_ip', methods=['POST'])
def admin_server_remove_ip(server_id):
    if 'user' not in session or session['user']['id'] not in get_admin_ids():
        return jsonify({'success': False})
    
    ip_to_remove = request.json.get('ip')
    if not ip_to_remove: return jsonify({'success': False, 'message': 'Keine IP angegeben'})
    
    with get_db() as conn:
        assoc = conn.execute('SELECT net_id FROM server_additional_ips WHERE server_id = ? AND ip = ?', (server_id, ip_to_remove)).fetchone()
        if not assoc:
            return jsonify({'success': False, 'message': 'IP ist diesem Server nicht zugewiesen'})
        
        net_id = assoc['net_id']
        
        server = conn.execute('SELECT cpu_series FROM servers WHERE id = ?', (server_id,)).fetchone()
        target_node = RYZEN_NODE if server and server['cpu_series'] == 'Ryzen' else INTEL_NODE

        if proxmox.remove_network_interface(server_id, net_id, node=target_node):
            conn.execute('DELETE FROM server_additional_ips WHERE server_id = ? AND ip = ?', (server_id, ip_to_remove))
            conn.execute('UPDATE ips SET used = 0 WHERE ip = ?', (ip_to_remove,))
            conn.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': f'Proxmox Fehler: {proxmox.last_error}'})

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/tos')
def tos():
    return render_template('tos.html')

def start_auto_restart():
    def restart_loop():
        print("Auto-Restart Scheduler gestartet. Neustart in 30 Minuten.")
        time.sleep(1800) # 30 Minuten
        print("Führe geplanten Neustart durch...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

    thread = threading.Thread(target=restart_loop, daemon=True)
    thread.start()

if __name__ == '__main__':
    init_db()
    start_auto_restart()
    app.run(debug=True, host='0.0.0.0', port=5000)
