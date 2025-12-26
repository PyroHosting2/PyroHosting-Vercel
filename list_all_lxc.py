import requests
import urllib3
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

ticket, csrf = get_auth()
headers = {'Cookie': f'PVEAuthCookie={ticket}', 'CSRFPreventionToken': csrf}

nodes_url = f"{HOST}/api2/json/nodes"
nodes = [n['node'] for n in requests.get(nodes_url, headers=headers, verify=False).json()['data']]

print(f"Cluster nodes: {nodes}")

for node in nodes:
    url = f"{HOST}/api2/json/nodes/{node}/lxc"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json().get('data', [])
        print(f"Node {node} LXC list ({len(data)} items):")
        for item in data:
            print(f"  - VMID: {item['vmid']}, Name: {item.get('name')}, Status: {item.get('status')}")
    else:
        print(f"Node {node} LXC error: {response.status_code} - {response.text}")
