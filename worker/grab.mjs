#!/usr/bin/env node
/**
 * CAM OCI 抢机 worker — 零依赖 Node 20+ 脚本 (替代原 Go 二进制)
 *
 * 协议 (与 cloud-assets-manager Worker 端一致):
 *   GET  {SERVER}/api/v1/worker/task?worker_id=X[&task_id=N]   X-Worker-Token
 *   POST {SERVER}/api/v1/worker/report                          X-Worker-Token
 *
 * env: OCI_SERVER_URL / OCI_WORKER_TOKEN / TASK_ID
 */
import net from "node:net";
import tls from "node:tls";

const SERVER = (process.env.OCI_SERVER_URL || "").replace(/\/+$/, "");
const BOOTSTRAP = process.env.BOOTSTRAP_CODE || "";
const TASK_ID = process.env.TASK_ID || "";
const WORKER_ID = `worker-${process.env.GITHUB_RUN_ID || "local"}-${process.pid}`;
const DEADLINE = Date.now() + 340 * 60 * 1000; // < workflow 的 350m timeout

const b64e = (u8) => Buffer.from(u8).toString("base64");
const b64d = (s) => new Uint8Array(Buffer.from(s, "base64"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(`[${new Date().toISOString()}]`, ...a);

if (!SERVER || !BOOTSTRAP || !TASK_ID) {
  console.error("OCI_SERVER_URL / BOOTSTRAP_CODE / TASK_ID required");
  process.exit(2);
}

// 一次性兑换码 → 会话 token (兑换码用后服务器侧即刻作废)
let TOKEN = "";
async function bootstrap() {
  const r = await fetch(`${SERVER}/api/v1/worker/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ task_id: +TASK_ID, code: BOOTSTRAP }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.data?.worker_token) {
    throw new Error(`bootstrap exchange failed ${r.status}: ${j.message || ""}`);
  }
  TOKEN = j.data.worker_token;
  console.log(`::add-mask::${TOKEN}`);
  log("session token acquired");
}

// ================= 面板协议 =================
async function getTask() {
  let url = `${SERVER}/api/v1/worker/task?worker_id=${encodeURIComponent(WORKER_ID)}`;
  if (TASK_ID) url += `&task_id=${TASK_ID}`;
  const r = await fetch(url, { headers: { "X-Worker-Token": TOKEN } });
  if (r.status === 204) return null;
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`panel ${r.status}: ${JSON.stringify(j).slice(0, 200)}`);
  if (!j || j.code !== 0 || !j.data?.task_id) return null;
  return j.data;
}

async function report(status, logMsg, extra = {}) {
  try {
    await fetch(`${SERVER}/api/v1/worker/report`, {
      method: "POST",
      headers: { "X-Worker-Token": TOKEN, "Content-Type": "application/json" },
      body: JSON.stringify({
        task_id: +TASK_ID || extra.task_id || 0,
        status, log: logMsg, worker_id: WORKER_ID,
        instance_id: extra.instance_id || "",
        instance_name: extra.instance_name || "",
        public_ip: extra.public_ip || "",
        private_ip: extra.private_ip || "",
      }),
    });
  } catch (e) { log("report failed:", e.message); }
}

// ================= OCI 签名 (WebCrypto) =================
function pkcs1ToPkcs8(der) {
  const len = (n) => {
    if (n < 0x80) return [n];
    const b = [];
    for (let v = n; v > 0; v >>= 8) b.unshift(v & 0xff);
    return [0x80 | b.length, ...b];
  };
  const algid = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const octet = [0x04, ...len(der.length), ...der];
  const content = [0x02, 0x01, 0x00, ...algid, ...octet];
  return new Uint8Array([0x30, ...len(content.length), ...content]);
}

async function importPrivateKey(pem) {
  const marker = pem.match(/-----BEGIN ([A-Z ]*PRIVATE KEY)-----/);
  if (!marker) throw new Error("invalid private key PEM");
  const body = pem
    .replace(/^[\s\S]*?-----BEGIN [A-Z ]*PRIVATE KEY-----/, "")
    .replace(/-----END [A-Z ]*PRIVATE KEY-----[\s\S]*$/, "")
    .split(/\r?\n/)
    .map((l) => l.replace(/[^\x20-\x7e]/g, "").trim())
    .filter((l) => /^[A-Za-z0-9+/]+={0,2}$/.test(l))
    .join("");
  let der = b64d(body);
  if (marker[1] === "RSA PRIVATE KEY") der = pkcs1ToPkcs8(der);
  return crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}

// ================= HTTP 层 (直连或 CONNECT/SOCKS5 代理) =================
function openTunnel(targetHost, proxy) {
  // proxy: {type:'http'|'socks5', host, port} — 返回已建立 TLS 的 socket
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxy.port, proxy.host, () => {
      if (proxy.type === "socks5") {
        sock.write(Buffer.from([0x05, 0x01, 0x00])); // greeting: no-auth
        const chunks = [];
        sock.once("data", (g) => {
          if (g[1] !== 0x00) return reject(new Error("socks5 auth required"));
          const host = Buffer.from(targetHost);
          const req = Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]), host,
            Buffer.from([0x01, 0xbb]), // port 443
          ]);
          sock.write(req);
          sock.once("data", (r2) => {
            if (r2[1] !== 0x00) return reject(new Error(`socks5 connect fail ${r2[1]}`));
            resolve(wrapTls(sock, targetHost));
          });
        });
      } else {
        sock.write(`CONNECT ${targetHost}:443 HTTP/1.1\r\nHost: ${targetHost}:443\r\n\r\n`);
        let buf = "";
        sock.on("data", function onData(d) {
          buf += d.toString();
          const i = buf.indexOf("\r\n\r\n");
          if (i === -1) return;
          sock.off("data", onData);
          if (!/^HTTP\/1\.[01] 200/.test(buf)) return reject(new Error(`CONNECT fail: ${buf.split("\r\n")[0]}`));
          resolve(wrapTls(sock, targetHost));
        });
      }
    });
    sock.on("error", reject);
    sock.setTimeout(30000, () => { sock.destroy(); reject(new Error("proxy timeout")); });
  });
}
function wrapTls(sock, host) {
  return new Promise((resolve, reject) => {
    const t = tls.connect({ socket: sock, servername: host }, () => resolve(t));
    t.on("error", reject);
  });
}

// 统一请求出口: 无代理走 fetch; 有代理走 CONNECT/SOCKS5 隧道上的手写 HTTP/1.1
async function httpReq(url, { method = "GET", headers = {}, body, proxy } = {}) {
  if (!proxy) return fetch(url, { method, headers, body });
  const u = new URL(url);
  const sock = await openTunnel(u.hostname, proxy);
  const raw = `${method} ${u.pathname}${u.search} HTTP/1.1\r\n` +
    `Host: ${u.host}\r\n` +
    Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join("") +
    `Connection: close\r\n\r\n`;
  sock.write(raw);
  if (body !== undefined) sock.write(typeof body === "string" ? body : Buffer.from(body));
  return new Promise((resolve, reject) => {
    const chunks = [];
    sock.on("data", (d) => chunks.push(d));
    sock.on("end", () => {
      const all = Buffer.concat(chunks);
      const headEnd = all.indexOf("\r\n\r\n");
      const head = all.slice(0, headEnd).toString();
      const status = +(head.split(" ")[1] || 0);
      let payload = all.slice(headEnd + 4);
      if (/transfer-encoding:\s*chunked/i.test(head)) {
        const out = [];
        let p = 0;
        while (p < payload.length) {
          const nl = payload.indexOf("\r\n", p);
          const size = parseInt(payload.slice(p, nl).toString(), 16);
          if (!size) break;
          out.push(payload.slice(nl + 2, nl + 2 + size));
          p = nl + 2 + size + 2;
        }
        payload = Buffer.concat(out);
      }
      const hs = {};
      head.split("\r\n").slice(1).forEach((l) => { const i = l.indexOf(":"); if (i > 0) hs[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim(); });
      resolve({
        ok: status >= 200 && status < 300,
        status,
        headers: { get: (k) => hs[k.toLowerCase()] ?? null },
        text: async () => payload.toString(),
        json: async () => JSON.parse(payload.toString()),
      });
    });
    sock.on("error", reject);
  });
}

// ================= OCI 客户端 =================
class Oci {
  constructor(creds, proxy) {
    this.creds = creds; // {tenancy_ocid,user_ocid,fingerprint,region,private_key}
    this.proxy = proxy;
    this.key = null;
    this.tenancy = creds.tenancy_ocid;
    this.compartment = creds.tenancy_ocid; // 默认 root compartment (与老代码一致)
  }
  async init() { this.key = await importPrivateKey(this.creds.private_key); }

  host(service) {
    const suffix = { iaas: "", identity: "", mysql: ".ocp", limits: ".oci" }[service] ?? "";
    return `${service}.${this.creds.region}${suffix}.oraclecloud.com`;
  }
  async req(method, path, body, service = "iaas") {
    const host = this.host(service);
    const date = new Date().toUTCString();
    const lines = [`(request-target): ${method.toLowerCase()} ${path}`, `date: ${date}`, `host: ${host}`];
    let names = "(request-target) date host";
    const headers = { date, host };
    let payload;
    if (body !== undefined) {
      payload = typeof body === "string" ? body : JSON.stringify(body);
      const sha = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
      headers["x-content-sha256"] = b64e(new Uint8Array(sha));
      headers["content-type"] = "application/json";
      headers["content-length"] = String(new TextEncoder().encode(payload).length);
      lines.push(`x-content-sha256: ${headers["x-content-sha256"]}`, `content-type: application/json`, `content-length: ${headers["content-length"]}`);
      names += " x-content-sha256 content-type content-length";
    }
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", this.key, new TextEncoder().encode(lines.join("\n")));
    headers["Authorization"] = `Signature version="1",keyId="${this.creds.tenancy_ocid}/${this.creds.user_ocid}/${this.creds.fingerprint}",algorithm="rsa-sha256",headers="${names}",signature="${b64e(new Uint8Array(sig))}"`;
    // POST/PUT/PATCH 空 body 也要带体头 (OCI 签名要求)
    if (payload === undefined && ["POST", "PUT", "PATCH"].includes(method)) {
      return this.req(method, path, "", service);
    }
    const res = await httpReq(`https://${host}${path}`, { method, headers, body: payload, proxy: this.proxy });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      const e = new Error(`OCI ${method} ${path.slice(0, 40)} ${res.status}: ${t.slice(0, 200)}`);
      e.status = res.status;
      throw e;
    }
    if (res.status === 204) return null;
    return res.json();
  }
  get(path, service) { return this.req("GET", path, undefined, service); }
  post(path, body, service) { return this.req("POST", path, body ?? "", service); }
  put(path, body, service) { return this.req("PUT", path, body ?? "", service); }

  // identity
  listADs() { return this.get(`/20160918/availabilityDomains?compartmentId=${this.compartment}`, "identity"); }
  // compute/images
  async findImage(os, osVersion, shape) {
    const q = `compartmentId=${this.compartment}&operatingSystem=${encodeURIComponent(os)}&operatingSystemVersion=${encodeURIComponent(osVersion)}`;
    const items = await this.get(`/20160918/images?${q}`);
    const avail = (items || []).filter((i) => i.lifecycleState === "AVAILABLE");
    const isArm = /A1|Ampere/.test(shape);
    const pick = avail.find((i) => (isArm ? /AARCH64/i.test(i.displayName) : !/AARCH64/i.test(i.displayName))) || avail[0];
    return pick || null;
  }
  // network — findOrCreate 语义与老项目一致: 同名优先, 否则复用任意可用项避免配额
  async findOrCreateVcn(name, cidr) {
    const items = await this.get(`/20160918/vcns?compartmentId=${this.compartment}`);
    const avail = (items || []).filter((v) => v.lifecycleState === "AVAILABLE");
    const hit = avail.find((v) => v.displayName === name) || avail[0];
    if (hit) return hit;
    return this.post(`/20160918/vcns`, { compartmentId: this.compartment, displayName: name, cidrBlock: cidr });
  }
  async findOrCreateIgw(vcnId, name) {
    const items = await this.get(`/20160918/internetGateways?compartmentId=${this.compartment}&vcnId=${vcnId}`);
    const hit = (items || []).find((i) => i.lifecycleState === "AVAILABLE");
    if (hit) return hit;
    return this.post(`/20160918/internetGateways`, { compartmentId: this.compartment, vcnId, displayName: name, isEnabled: true });
  }
  async ensureRouteTable(rtId, igwId) {
    try {
      const rt = await this.get(`/20160918/routeTables/${rtId}`);
      if ((rt.routeRules || []).some((r) => r.destination === "0.0.0.0/0")) return;
      await this.put(`/20160918/routeTables/${rtId}`, {
        routeRules: [...rt.routeRules, { destination: "0.0.0.0/0", networkEntityId: igwId }],
      });
    } catch (e) { log("route table warn:", e.message); }
  }
  async ensureSecurityList(slId) {
    try {
      const sl = await this.get(`/20160918/securityLists/${slId}`);
      if ((sl.ingressSecurityRules || []).length && (sl.egressSecurityRules || []).length) return;
      await this.put(`/20160918/securityLists/${slId}`, {
        ingressSecurityRules: [{ source: "0.0.0.0/0", protocol: "all" }],
        egressSecurityRules: [{ destination: "0.0.0.0/0", protocol: "all" }],
      });
    } catch (e) { log("sec list warn:", e.message); }
  }
  async findOrCreateSubnet(vcnId, name, cidr, ad) {
    const items = await this.get(`/20160918/subnets?compartmentId=${this.compartment}&vcnId=${vcnId}`);
    const avail = (items || []).filter((s) => s.lifecycleState === "AVAILABLE");
    const hit = avail.find((s) => s.displayName === name) || avail[0];
    if (hit) return hit;
    return this.post(`/20160918/subnets`, {
      compartmentId: this.compartment, vcnId, displayName: name, cidrBlock: cidr, availabilityDomain: ad,
    });
  }
  async launch(task, imageId, subnetId, ad) {
    const meta = {};
    if (task.ssh_key) meta.ssh_authorized_keys = task.ssh_key;
    if (task.root_password) meta.user_data = b64e(new TextEncoder().encode(cloudInit(task.root_password)));
    const body = {
      compartmentId: this.compartment,
      availabilityDomain: ad,
      displayName: task._displayName || (/A1/.test(task.shape) ? `ARM-${mmdd()}` : `AMD-${mmdd()}`),
      shape: task.shape,
      sourceDetails: { sourceType: "image", imageId, bootVolumeSizeInGBs: task.disk_size },
      createVnicDetails: { subnetId, assignPublicIp: true },
      metadata: meta,
    };
    if (/Flex/.test(task.shape)) body.shapeConfig = { ocpus: task.ocpu, memoryInGBs: task.memory };
    return this.post(`/20160918/instances`, body);
  }
  async publicIps(instanceId) {
    const atts = await this.get(`/20160918/vnicAttachments?compartmentId=${this.compartment}&instanceId=${instanceId}`);
    if (!atts?.length) return {};
    const vnic = await this.get(`/20160918/vnics/${atts[0].vnicId}`);
    return { publicIp: vnic.publicIp, privateIp: vnic.privateIp };
  }
}

const mmdd = () => {
  const d = new Date();
  return `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};

function cloudInit(rootPassword) {
  return `#!/bin/bash
echo root:${rootPassword} | chpasswd root
rm -rf /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
sed -i 's/^.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
service sshd restart
`;
}

// ================= 任务辅助 =================
function resolveADs(all, task) {
  const match = (req) => all.filter((a) => a === req || a.endsWith(req) || a.includes(req));
  let cands;
  if (task.ad_mode === "single") cands = match((task.ad_list || "").split(/[,;\s]+/)[0]);
  else if (task.ad_mode === "list") cands = (task.ad_list || "").split(/[,;\n\r]+/).map((s) => s.trim()).filter(Boolean).flatMap(match);
  else cands = [...all];
  if (!cands.length) cands = [...all];
  if (task.ad_order === "random") cands.sort(() => Math.random() - 0.5);
  else if (task.ad_order === "round_robin" && cands.length > 1) {
    const off = (task.retry_count || 0) % cands.length;
    cands = [...cands.slice(off), ...cands.slice(0, off)];
  }
  return cands;
}

const RETRYABLE = ["Out of capacity", "Out of host capacity", "capacity", "TooManyRequests", "ServiceUnavailable", "provisioning disabled"];
const FATAL = ["LimitExceeded", "QuotaExceeded", "NotAuthorized", "InvalidParameter", "NotAuthenticated"];
const isRetryable = (m) => RETRYABLE.some((r) => m.includes(r));
const isFatal = (m) => FATAL.some((f) => m.includes(f));
const is429 = (e) => e.status === 429 || /TooManyRequests/i.test(e.message);

function inTimeWindow(task) {
  if (!task.time_window_enabled || !task.time_window_start || !task.time_window_end) return true;
  const now = new Date();
  const cur = now.getUTCHours() * 60 + now.getUTCMinutes();
  const [sh, sm] = task.time_window_start.split(":").map(Number);
  const [eh, em] = task.time_window_end.split(":").map(Number);
  const s = sh * 60 + sm, e = eh * 60 + em;
  return s <= e ? cur >= s && cur <= e : cur >= s || cur <= e;
}

function parseProxy(task) {
  if (!task.proxy_enabled || !task.proxy_address) return null;
  const m = task.proxy_address.match(/^(https?|socks5):\/\/([^:/]+):(\d+)/);
  if (!m) { log("proxy address unparsable, direct"); return null; }
  return { type: m[1] === "socks5" ? "socks5" : "http", host: m[2], port: +m[3] };
}

const rand = (min, max) => min + Math.random() * (max - min);

// ================= 主循环 =================
async function main() {
  log(`worker ${WORKER_ID} start, task=${TASK_ID || "(poll)"}, server=${SERVER}`);
  await bootstrap();

  // 拉任务 (允许面板侧 running 传播延迟)
  let task = null;
  for (let i = 0; i < 30 && !task; i++) {
    try { task = await getTask(); } catch (e) { log("getTask err:", e.message); }
    if (!task) await sleep(10000);
  }
  if (!task) { log("no task assigned, exit"); return; }
  log(`claimed task #${task.task_id} "${task.name}" ${task.shape} ${task.ocpu}C/${task.memory}G @${task.region}`);

  if (!task.private_key) { await report("failed", "no private_key in task payload"); process.exit(1); }
  const proxy = parseProxy(task);
  const oci = new Oci({ ...task, private_key: task.private_key }, proxy);
  try { await oci.init(); } catch (e) { await report("failed", `key import: ${e.message}`); process.exit(1); }

  let attempt = 0;
  while (Date.now() < DEADLINE) {
    attempt++;
    if (!inTimeWindow(task)) {
      log("outside time window, sleep 60s");
      await sleep(60000);
      continue;
    }
    try {
      // AD 列表 (每轮重取, 防区域 AD 变化)
      const adResp = await oci.listADs();
      const allAds = (adResp || []).map((a) => a.name).filter(Boolean);
      const ads = resolveADs(allAds, task);
      log(`attempt #${attempt}: ADs=${ads.join(",")}`);

      // 镜像 + 网络 (首个 AD 建网, 后续复用)
      const image = await oci.findImage(task.os, task.os_version, task.shape);
      if (!image) {
        await report("running", `no image for ${task.os} ${task.os_version} (${task.shape})`);
        await sleep(rand(task.min_interval, task.max_interval) * 60000);
        continue;
      }

      const errs = [];
      let rateLimited = false;
      for (let ai = 0; ai < ads.length; ai++) {
        const ad = ads[ai];
        try {
          const vcn = await oci.findOrCreateVcn(`oci-manager-vcn-${task.tenant_id}`, "10.0.0.0/16");
          const igw = await oci.findOrCreateIgw(vcn.id, `oci-manager-vcn-${task.tenant_id}-igw`);
          await oci.ensureRouteTable(vcn.defaultRouteTableId, igw.id);
          await oci.ensureSecurityList(vcn.defaultSecurityListId);
          const subnet = await oci.findOrCreateSubnet(vcn.id, `oci-manager-subnet-${task.tenant_id}`, "10.0.0.0/24", ad);
          task._displayName = /A1/.test(task.shape) ? `ARM-${mmdd()}` : `AMD-${mmdd()}`;
          const inst = await oci.launch(task, image.id, subnet.id, ad);
          log(`LAUNCHED ${inst.id} @${ad}`);

          // 轮询公网 IP (12×5s)
          let ips = {};
          for (let i = 0; i < 12; i++) {
            await sleep(5000);
            try { ips = await oci.publicIps(inst.id); } catch {}
            if (ips.publicIp) break;
          }
          await report("success", `Instance created: ${task._displayName}`, {
            task_id: task.task_id, instance_id: inst.id, instance_name: task._displayName,
            public_ip: ips.publicIp || "", private_ip: ips.privateIp || "",
          });
          log(`DONE ip=${ips.publicIp || "?"}/${ips.privateIp || "?"}`);
          return;
        } catch (e) {
          if (is429(e)) { rateLimited = true; break; }
          errs.push(`${ad}: ${e.message}`);
          log(`AD ${ad} failed: ${e.message.slice(0, 140)}`);
          if (isFatal(e.message)) {
            await report("failed", `fatal: ${e.message.slice(0, 200)}`, { task_id: task.task_id });
            process.exit(1);
          }
          if (ai < ads.length - 1) await sleep(rand(task.ad_interval_min_ms, task.ad_interval_max_ms));
        }
      }

      const waitSec = rateLimited
        ? task.ad_429_backoff_seconds
        : rand(task.min_interval, task.max_interval) * 60;
      const msg = rateLimited
        ? `429 rate limited, backoff ${waitSec}s`
        : `抢机失败: ${errs.join(" | ").slice(0, 300)}; 第${attempt}次, ${Math.round(waitSec)}s后重试`;
      await report("running", msg, { task_id: task.task_id });
      await sleep(waitSec * 1000);
    } catch (e) {
      if (isFatal(e.message)) {
        await report("failed", `fatal: ${e.message.slice(0, 200)}`, { task_id: task.task_id });
        process.exit(1);
      }
      await report("running", `loop error: ${e.message.slice(0, 200)}`, { task_id: task.task_id });
      await sleep(60000);
    }
  }
  await report("stopped", "worker deadline reached", { task_id: task.task_id });
  log("deadline reached");
}

main().catch(async (e) => {
  log("fatal:", e);
  await report("failed", `worker crash: ${e.message}`, {});
  process.exit(1);
});
