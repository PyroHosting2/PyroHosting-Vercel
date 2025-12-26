import requests
import urllib3
import os

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = 'https://5.175.221.2:8006'
USER = 'root'
PASS = 'Luan2010.2391234'

def get_auth():
    url = f"{HOST}/api2/json/access/ticket"
    data = {'username': f"{USER}@pam", 'password': PASS}
    response = requests.post(url, data=data, verify=False, timeout=10)
    res_data = response.json()['data']
    return res_data['ticket'], res_data['CSRFPreventionToken']

def list_vms(node, ticket, csrf, type='qemu'):
    url = f"{HOST}/api2/json/nodes/{node}/{type}"
    headers = {
        'Cookie': f'PVEAuthCookie={ticket}',
        'CSRFPreventionToken': csrf
    }
    response = requests.get(url, headers=headers, verify=False, timeout=10)
    if response.status_code == 200:
        return response.json().get('data', [])
    else:
        print(f"Error for node {node} ({type}): {response.status_code} - {response.text}")
        return []

def list_cluster_resources(ticket, csrf):
    url = f"{HOST}/api2/json/cluster/resources"
    headers = {
        'Cookie': f'PVEAuthCookie={ticket}',
        'CSRFPreventionToken': csrf
    }
    response = requests.get(url, headers=headers, verify=False, timeout=10)
    if response.status_code == 200:
        return response.json().get('data', [])
    return []

try:
    ticket, csrf = get_auth()
    print("Authentication successful.")
    
    print("\n--- Node Specific Checks ---")
    for node in ['pve', 's237']:
        for v_type in ['qemu', 'lxc']:
            vms = list_vms(node, ticket, csrf, v_type)
            print(f"Node {node} has {len(vms)} {v_type} items.")
            for vm in vms:
                print(f"  - [{v_type}] VMID: {vm['vmid']}, Name: {vm.get('name')}, Status: {vm.get('status')}")

    print("\n--- All Cluster Resources ---")
    resources = list_cluster_resources(ticket, csrf)
    print(f"Total resources found: {len(resources)}")
    for res in resources:
        print(f"  - Type: {res.get('type')}, VMID: {res.get('vmid')}, Node: {res.get('node')}, Name: {res.get('name')}, Status: {res.get('status')}")

except Exception as e:
    print(f"An error occurred: {e}")
