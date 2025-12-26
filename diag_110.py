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

for v_type in ['qemu', 'lxc']:
    url = f"{HOST}/api2/json/nodes/s237/{v_type}/110/status/current"
    print(f"Checking {v_type} 110...")
    response = requests.get(url, headers=headers, verify=False)
    print(f"  Response: {response.status_code}")
    if response.status_code == 200:
        print(f"  Data: {response.json().get('data')}")
    else:
        print(f"  Error: {response.text}")
