import axios from "axios";
import https from "https";

export class ProxmoxManager {
  constructor({ user, password, hosts }) {
    this.user = user;
    this.password = password;
    this.hosts = hosts; // { nodeName: hostUrl }
    this.auth = new Map(); // hostUrl -> { cookie, csrf }
    this.lastError = "";
    this.http = axios.create({
      timeout: 15000,
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      validateStatus: (s) => s >= 200 && s < 500
    });
  }

  _hostForNode(node) {
    return this.hosts[node] || Object.values(this.hosts)[0];
  }

  async _authenticate(host) {
    try {
      const url = `${host}/api2/json/access/ticket`;
      const resp = await this.http.post(url, new URLSearchParams({
        username: `${this.user}@pam`,
        password: this.password
      }));
      if (resp.status === 401) {
        this.lastError = `Ungültige Anmeldedaten für ${host}`;
        return false;
      }
      if (resp.status >= 300) {
        this.lastError = `Auth Fehler (${host}): HTTP ${resp.status}`;
        return false;
      }
      const data = resp.data?.data;
      if (!data?.ticket || !data?.CSRFPreventionToken) {
        this.lastError = `Auth Fehler (${host}): ungültige Antwort`;
        return false;
      }
      this.auth.set(host, {
        cookie: `PVEAuthCookie=${data.ticket}`,
        csrf: data.CSRFPreventionToken
      });
      return true;
    } catch (e) {
      this.lastError = `Auth Fehler (${host}): ${e?.message || String(e)}`;
      return false;
    }
  }

  async _headers(host, method) {
    const auth = this.auth.get(host);
    if (!auth) return {};
    const h = { Cookie: auth.cookie };
    if (method !== "GET") h.CSRFPreventionToken = auth.csrf;
    return h;
  }

  async _request({ host, method, path, data }) {
    // Ensure auth
    if (!this.auth.get(host)) {
      const ok = await this._authenticate(host);
      if (!ok) return null;
    }
    const url = `${host}${path}`;
    const headers = await this._headers(host, method);
    const body = data instanceof URLSearchParams ? data : (data ? new URLSearchParams(data) : undefined);

    const resp = await this.http.request({ method, url, headers, data: body });
    // Re-auth once on forbidden/unauth
    if (resp.status === 401 || resp.status === 403) {
      this.auth.delete(host);
      const ok = await this._authenticate(host);
      if (!ok) return null;
      const headers2 = await this._headers(host, method);
      const resp2 = await this.http.request({ method, url, headers: headers2, data: body });
      if (resp2.status >= 300) {
        this.lastError = `Proxmox Fehler: HTTP ${resp2.status} (${path})`;
        return null;
      }
      return resp2.data?.data ?? null;
    }
    if (resp.status >= 300) {
      this.lastError = `Proxmox Fehler: HTTP ${resp.status} (${path})`;
      return null;
    }
    return resp.data?.data ?? null;
  }

  async findVmNode(vmid) {
    const vmidStr = String(vmid);
    for (const [node, host] of Object.entries(this.hosts)) {
      const data = await this._request({ host, method: "GET", path: "/api2/json/cluster/resources?type=vm" });
      if (!data) continue;
      const found = data.find(r => String(r.vmid) === vmidStr);
      if (found?.node) return { node: found.node, host };
    }
    return null;
  }

  async getNextVmid({ node }) {
    const host = this._hostForNode(node);
    const data = await this._request({ host, method: "GET", path: "/api2/json/cluster/nextid" });
    if (!data) return null;
    return Number(data);
  }

  async cloneVm({ templateVmid, newVmid, name, node }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${templateVmid}/clone`;
    const data = await this._request({
      host, method: "POST", path,
      data: {
        newid: String(newVmid),
        name: name,
        full: "1"
      }
    });
    return data !== null;
  }

  async updateVmResources({ vmid, node, cores, memoryMb }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${vmid}/config`;
    const data = await this._request({
      host, method: "POST", path,
      data: { cores: String(cores), memory: String(memoryMb) }
    });
    return data !== null;
  }

  async resizeDisk({ vmid, node, sizeGb }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${vmid}/resize`;
    // Common disk name in Proxmox cloud-init templates is "scsi0". This mirrors typical setups.
    const data = await this._request({
      host, method: "PUT", path,
      data: { disk: "scsi0", size: `${sizeGb}G` }
    });
    return data !== null;
  }

  async configureCloudinit({ vmid, node, ip, gw, netmask, username, password }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${vmid}/config`;
    const ipcfg = `ip=${ip}/${netmask},gw=${gw}`;
    const data = await this._request({
      host, method: "POST", path,
      data: {
        ciuser: username,
        cipassword: password,
        ipconfig0: ipcfg
      }
    });
    return data !== null;
  }

  async startVm({ vmid, node }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${vmid}/status/start`;
    const data = await this._request({ host, method: "POST", path });
    return data !== null;
  }

  async stopVm({ vmid, node }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${vmid}/status/stop`;
    const data = await this._request({ host, method: "POST", path });
    return data !== null;
  }

  async rebootVm({ vmid, node }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${vmid}/status/reboot`;
    const data = await this._request({ host, method: "POST", path });
    return data !== null;
  }

  async getVmStatus({ vmid, node }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${vmid}/status/current`;
    return await this._request({ host, method: "GET", path });
  }

  async getVmConfig({ vmid, node }) {
    const host = this._hostForNode(node);
    const path = `/api2/json/nodes/${encodeURIComponent(node)}/qemu/${vmid}/config`;
    return await this._request({ host, method: "GET", path });
  }
}
