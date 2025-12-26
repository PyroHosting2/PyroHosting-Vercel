import requests
import urllib3
import json
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

url = f"{HOST}/api2/json/cluster/resources"
response = requests.get(url, headers=headers, verify=False)
data = response.json().get('data', [])

print(f"Total entries: {len(data)}")
for res in data:
    if str(res.get('vmid')) == '110' or '110' in str(res.get('id', '')):
        print(f"MATCH: {json.dumps(res, indent=2)}")

# Also print next ID
print(f"Next ID: {requests.get(f'{HOST}/api2/json/cluster/nextid', headers=headers, verify=False).json().get('data')}")
