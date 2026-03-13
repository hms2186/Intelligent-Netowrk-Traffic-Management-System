import { useState, useEffect, useRef, useCallback, useMemo } from "react";

/* ═══════════════════════════════════════════════════════════════
   INTMS v2 — Full Production Frontend
   All features: Multi-Network · IPS · DPI · Threats · Z-Score
═══════════════════════════════════════════════════════════════ */

// ─── UTILS ────────────────────────────────────────────────────────
const R = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = arr => arr[Math.floor(Math.random() * arr.length)];
const ip = (p = "192.168.1") => `${p}.${R(2, 254)}`;
const nowTs = () => new Date().toTimeString().slice(0, 8);
const μ = arr => arr.reduce((s, v) => s + v, 0) / (arr.length || 1);
const σ = arr => { const m = μ(arr); return Math.sqrt(arr.reduce((s,v)=>s+(v-m)**2,0)/(arr.length||1)); };
const z = (v, arr) => { const s = σ(arr); return s < 0.001 ? 0 : (v - μ(arr)) / s; };
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const fmt = n => n >= 1000 ? `${(n/1000).toFixed(1)}k` : String(n);

// ─── NETWORKS ─────────────────────────────────────────────────────
const NETS = [
  { id:"main",   label:"SRM Main",    subnet:"192.168.1.0/24",  pfx:"192.168.1", color:"#00f5c4", base:[35,70]  },
  { id:"hostel", label:"Hostel Block",subnet:"10.10.0.0/24",    pfx:"10.10.0",   color:"#f5c400", base:[15,40]  },
  { id:"admin",  label:"Admin Net",   subnet:"172.16.0.0/24",   pfx:"172.16.0",  color:"#f54040", base:[5,18]   },
  { id:"lab",    label:"CS Lab",      subnet:"10.20.0.0/24",    pfx:"10.20.0",   color:"#a855f7", base:[55,120] },
];

// ─── IPS RULES ────────────────────────────────────────────────────
const IPS_RULES = [
  { id:"R01", name:"PPS Rate Limiter",     cond:"z(pps) > 3σ",           action:"RATE_LIMIT", sev:"high"   },
  { id:"R02", name:"SYN Cookie Enforcer",  cond:"syn_ratio > 0.9",       action:"SYN_PROXY",  sev:"high"   },
  { id:"R03", name:"Port Scan Blocker",    cond:"unique_ports > 20/s",   action:"BLOCK_IP",   sev:"medium" },
  { id:"R04", name:"DNS Amp Guard",        cond:"udp_dns_ratio > 0.6",   action:"RRL",        sev:"high"   },
  { id:"R05", name:"ICMP Flood Shield",    cond:"icmp_pps > 100",        action:"DROP_ICMP",  sev:"medium" },
  { id:"R06", name:"Slow HTTP Timeout",    cond:"conn_duration > 60s",   action:"TIMEOUT",    sev:"low"    },
  { id:"R07", name:"Geo-block Suspicious", cond:"asn_rep < 20",          action:"GEO_DROP",   sev:"medium" },
  { id:"R08", name:"Entropy Analyzer",     cond:"payload_entropy > 7.2", action:"DPI_FLAG",   sev:"high"   },
];

const ACTION_COLORS = {
  RATE_LIMIT:"#f5c400", BLOCK_IP:"#ff4560", SYN_PROXY:"#00f5c4",
  RRL:"#a3e635", DROP_ICMP:"#fb923c", TIMEOUT:"#a855f7", GEO_DROP:"#f87171", DPI_FLAG:"#ff4560",
};

// ─── DPI PROTOS ───────────────────────────────────────────────────
const PROTOS = [
  { p:"TCP",   col:"#00f5c4", port:null, fields:["Flags","Seq","Ack","Window","Checksum"] },
  { p:"UDP",   col:"#f5c400", port:null, fields:["Length","Checksum","Payload","Entropy","Frag"] },
  { p:"HTTP",  col:"#a855f7", port:80,   fields:["Method","Host","User-Agent","Status","Content-Type"] },
  { p:"HTTPS", col:"#a3e635", port:443,  fields:["TLS Ver","Cipher","SNI","Cert CN","ALPN"] },
  { p:"DNS",   col:"#fb923c", port:53,   fields:["Query","Type","TTL","Answer","Flags"] },
  { p:"ICMP",  col:"#f87171", port:null, fields:["Type","Code","Checksum","Seq","TTL"] },
];

// ─── THREAT DICT (40) ─────────────────────────────────────────────
const THREATS = [
  // Volumetric
  {cat:"Volumetric",icon:"🌊",n:"UDP Flood",       sigma:"pps > 4σ",  cve:"—",              d:"High-rate UDP datagrams exhaust bandwidth. Source IPs are spoofed to bypass per-IP filters. Identified via BPS spike + low entropy payload pattern.",m:"NULL route upstream / rate-limit per-source"},
  {cat:"Volumetric",icon:"📟",n:"ICMP Flood",      sigma:"icmp% > 3σ",cve:"CVE-1999-0513",  d:"Ping storm exhausts CPU interrupt handlers. Smurf variant amplifies via directed broadcast. Detected when ICMP ratio exceeds 15% of total PPS.",m:"Disable IP directed broadcast / filter ICMP rate"},
  {cat:"Volumetric",icon:"⏱️",n:"NTP Amplification",sigma:"ntp > 4σ", cve:"CVE-2013-5211",  d:"Monlist command returns up to 600 entries per query — 206× amplification factor. Exploits open NTP servers with spoofed victim source.",m:"Disable monlist / upgrade ntpd >= 4.2.7p26"},
  {cat:"Volumetric",icon:"📡",n:"DNS Amplification",sigma:"dns > 5σ", cve:"CVE-2014-3148",  d:"Small spoofed ANY queries return 60× response. Exploits open resolvers at ISP and university level. Detected via amplification ratio.",m:"RRL on resolvers / disable ANY queries / BCP38"},
  {cat:"Volumetric",icon:"💥",n:"Fraggle Attack",  sigma:"udp ref > 2σ",cve:"—",            d:"UDP reflection using ports 7/19 to amplify traffic ~6×. Victim IP is spoofed as source so all replies hit them.",m:"Block chargen/echo ports 7,19 outbound"},
  {cat:"Volumetric",icon:"🔗",n:"ACK Flood",       sigma:"ack% > 4σ", cve:"—",              d:"Stateless ACK packets bypass stateful firewalls since no SYN handshake entry is required. Hard to block without connection tracking.",m:"Stateless ACL at upstream / BGP blackhole"},
  {cat:"Volumetric",icon:"🔮",n:"Memcached Amp",   sigma:"udp 11211",  cve:"CVE-2018-1000115",d:"11,000× amplification using UDP port 11211. The most powerful known DDoS vector; used in record 1.7Tbps attacks.",m:"Disable UDP on Memcached / firewall port 11211"},
  // Protocol
  {cat:"Protocol",  icon:"🤝",n:"SYN Flood",       sigma:"syn% > 4σ", cve:"CVE-1996-0628",  d:"Half-open TCP connections fill the server SYN queue. At 100k+ PPS the queue fills in milliseconds causing legitimate connections to be dropped.",m:"SYN cookies kernel option / reduce SYN_RECV timeout"},
  {cat:"Protocol",  icon:"💣",n:"Smurf Attack",    sigma:"icmp bc > 3σ",cve:"—",            d:"ICMP echo to subnet broadcast with spoofed victim source. Every host on the segment replies simultaneously overwhelming the victim.",m:"Disable directed broadcasts on all routers"},
  {cat:"Protocol",  icon:"💀",n:"Ping of Death",   sigma:"icmp size > 3σ",cve:"CVE-1996-4223",d:"Oversized ICMP packet (>65535 bytes) causes buffer overflow on vulnerable TCP/IP stack implementations.",m:"Patch kernel / enforce fragment reassembly limits"},
  {cat:"Protocol",  icon:"🪓",n:"LAND Attack",     sigma:"src=dst > 1σ",cve:"CVE-1997-0016", d:"Packet with identical src/dst IP+port causes target to reply to itself infinitely, locking CPU in some stack implementations.",m:"Filter src==dst at perimeter firewall / patch OS"},
  {cat:"Protocol",  icon:"🔀",n:"Teardrop Attack", sigma:"frag overlap", cve:"CVE-1997-0324", d:"Overlapping IP fragment offsets corrupt reassembly buffer causing kernel panic on Windows NT/95 and older Linux kernels.",m:"Patch TCP/IP stack / filter malformed fragments"},
  {cat:"Protocol",  icon:"🎭",n:"ARP Spoofing",    sigma:"arp rate > 3σ",cve:"—",            d:"Gratuitous ARP poisons switch MAC tables redirecting traffic through attacker's host. Enables silent MITM on LAN segment.",m:"Dynamic ARP Inspection (DAI) / static ARP entries"},
  {cat:"Protocol",  icon:"🛤️",n:"BGP Hijacking",  sigma:"route churn > 3σ",cve:"—",         d:"Illegitimate BGP AS path announcement diverts traffic at the routing level. Can affect entire ASes and last hours.",m:"RPKI ROA validation / BGP community filters"},
  // Application
  {cat:"Application",icon:"🌐",n:"HTTP Flood",     sigma:"req/s > 4σ", cve:"—",              d:"Layer 7 GET/POST flood exhausts web server thread pool and DB connection pool. Indistinguishable from legitimate traffic without behavioral analysis.",m:"WAF + per-URI rate limit / CAPTCHA on threshold"},
  {cat:"Application",icon:"🐌",n:"Slowloris",      sigma:"conn age > 3σ",cve:"CVE-2007-6750", d:"Keeps HTTP connections open with partial headers sent every 15s. A single machine with 1Mbps can kill Apache.",m:"Set server min receive rate / use nginx or Caddy"},
  {cat:"Application",icon:"🕷️",n:"Slow POST",      sigma:"body rate < -3σ",cve:"—",          d:"Sends HTTP body at 1 byte/second consuming worker threads indefinitely. Harder to detect than Slowloris.",m:"Client body timeout / rate-limit body recv speed"},
  {cat:"Application",icon:"💉",n:"SQL Injection",  sigma:"payload > 3σ", cve:"CWE-89",        d:"Malicious SQL in input fields. Boolean-blind, time-based, or UNION-based data extraction. Detected via payload entropy analysis.",m:"Parameterized queries / WAF SQLi ruleset"},
  {cat:"Application",icon:"📜",n:"XSS Attack",     sigma:"script > 2σ",  cve:"CWE-79",        d:"Reflected/stored script injection steals cookies, redirects users, or keyloggs victims. CSP violations trigger DPI alert.",m:"CSP headers / DOMPurify / WAF XSS rules"},
  {cat:"Application",icon:"🔑",n:"Credential Stuffing",sigma:"auth fail > 4σ",cve:"—",       d:"Automated login with leaked username/password pairs from public breach databases. Low per-IP rate evades simple blocks.",m:"Rate-limit /login endpoint / enforce MFA"},
  {cat:"Application",icon:"🤖",n:"Bot Swarm",      sigma:"ua entropy < -2σ",cve:"—",         d:"Headless browser bots mimic human behavior including JS execution and mouse events, evading simple user-agent filters.",m:"JS challenge / browser fingerprinting / behavior scoring"},
  // Recon
  {cat:"Recon",     icon:"🔍",n:"Port Scan",       sigma:"ports > 4σ", cve:"—",              d:"Sequential or randomized port probing to map open services. nmap -sS (SYN scan) sends half-open connections that leave no log on non-firewalled hosts.",m:"Silently drop + auto-block sequential scanners"},
  {cat:"Recon",     icon:"🗺️",n:"OS Fingerprint",  sigma:"p0f match > 2σ",cve:"—",          d:"TCP/IP stack quirks (TTL, window size, option order, IP ID increment) used to identify OS without authentication.",m:"Normalize TCP options at perimeter / randomize TTL"},
  {cat:"Recon",     icon:"📸",n:"Banner Grabbing", sigma:"multi-svc > 3σ",cve:"—",           d:"Sequential connections to common ports to read version banners. Used to cross-reference public CVE databases for known exploits.",m:"Suppress service banners / use generic responses"},
  // Lateral
  {cat:"Lateral",   icon:"🐍",n:"Pass-the-Hash",   sigma:"auth anomaly > 3σ",cve:"CVE-2012-0007",d:"NTLM hash replay without cracking the password. Enables lateral movement across Windows domain without ever knowing plaintext credentials.",m:"Enforce Kerberos / disable NTLMv1 / credential guard"},
  {cat:"Lateral",   icon:"🔗",n:"SMB Relay",        sigma:"smb > 3σ",  cve:"CVE-2017-0144",  d:"NTLM challenge-response relay to a third host. Escalates to SYSTEM on unpatched machines via EternalBlue-style SMB exploit.",m:"SMB signing mandatory / disable LLMNR+NBT-NS"},
  {cat:"Lateral",   icon:"🌑",n:"Darknet Traffic",  sigma:"dark dst > 2σ",cve:"—",           d:"Packets to unallocated /dark address space indicate misconfigured hosts, infected machines scanning, or deliberate DPI evasion.",m:"Blackhole route / block at BGP edge / RTBH trigger"},
  // C2/Exfil
  {cat:"C2/Exfil",  icon:"🤖",n:"Botnet C2",        sigma:"jitter < -2σ",cve:"—",            d:"Periodic beaconing to C2 server with timing jitter < 10%. Automated intervals are statistically distinct from human-driven traffic patterns.",m:"C2 domain sinkhole / DNS RPZ / beacon detection ML"},
  {cat:"C2/Exfil",  icon:"📤",n:"DNS Exfiltration", sigma:"dns len > 3σ",cve:"—",            d:"Sensitive data encoded in DNS query subdomains (up to 63 chars each). Bypasses all DLP solutions that don't inspect DNS.",m:"DNS query length filter / DNSSEC + full query logging"},
  {cat:"C2/Exfil",  icon:"🕳️",n:"ICMP Tunneling",  sigma:"icmp payload > 3σ",cve:"—",       d:"Data carried covertly in ICMP echo payload using ping -p. Completely invisible to firewalls that only filter by port/protocol.",m:"Deep-inspect ICMP payload entropy / block ICMP ext data"},
  {cat:"C2/Exfil",  icon:"🔐",n:"Crypto Miner",     sigma:"stratum > 1σ",cve:"—",            d:"Stratum mining protocol to pool on port 3333/4444. Sustained high CPU + asymmetric outbound bandwidth. Detected by traffic pattern + port.",m:"Block stratum mining ports / endpoint EDR detection"},
  // Advanced
  {cat:"Advanced",  icon:"🛸",n:"Zero-Day",         sigma:"behavior > 4σ",cve:"Unknown",      d:"Unknown vulnerability exploited in the wild. No signature match possible. Detected purely via behavioral heuristics — 4σ deviation from all known baselines.",m:"3σ isolation + quarantine sandbox + vendor alert"},
  {cat:"Advanced",  icon:"💧",n:"Watering Hole",    sigma:"js entropy > 3σ",cve:"—",          d:"Attacker compromises websites frequented by target organization and injects drive-by download payload into trusted JS bundles.",m:"Content Security Policy / safe browsing API / SRI hashes"},
  {cat:"Advanced",  icon:"🎣",n:"Spear Phishing",   sigma:"email anomaly > 2σ",cve:"—",       d:"Targeted email with custom payload referencing victim's role and contacts. Bypasses generic spam filters trained on bulk phishing campaigns.",m:"DMARC + DKIM + SPF / sandbox email attachments"},
  {cat:"Advanced",  icon:"📉",n:"Deathline",        sigma:"state table > 4σ",cve:"—",         d:"State table exhaustion via crafted packets that create but never resolve TCP connection state, consuming conntrack memory.",m:"Tune nf_conntrack_max / aggressive TCP state timeouts"},
  {cat:"Advanced",  icon:"🔬",n:"Protocol Fuzzing", sigma:"malformed > 3σ",cve:"CWE-20",      d:"Random field mutation in protocol headers testing for parser bugs. Detected by unusually high malformed packet ratio per source.",m:"Protocol normalization / strict parser limits at WAF"},
  {cat:"Advanced",  icon:"🧩",n:"Supply Chain",     sigma:"dep hash mismatch",cve:"—",        d:"Compromised dependency injected into build pipeline. Affects all downstream deployments. Detected via SBOM hash mismatch at deploy time.",m:"SCA scanning / signed builds + SBOM verification"},
  {cat:"Advanced",  icon:"🪞",n:"Reflection Amp",   sigma:"amp ratio > 3σ",cve:"—",           d:"Generic amplification using any stateless UDP service. Amplification ratio varies — Memcached 11000×, DNS 60×, NTP 206×, SSDP 30×.",m:"Block amplifiable UDP services externally / BCP38"},
  {cat:"Advanced",  icon:"🆔",n:"IP Spoofing",      sigma:"spoofed > 2σ",cve:"—",             d:"Forged source addresses evade IP reputation systems and enable reflection attacks. Detected via uRPF asymmetric routing check.",m:"BCP38 ingress filtering / uRPF strict mode at edge"},
  {cat:"Advanced",  icon:"🎭",n:"Deep Fake Exfil",  sigma:"video bps > 3σ",cve:"—",           d:"Sensitive data steganographically encoded in video streams to cloud services. Bypasses all text-based DLP controls completely.",m:"Baseline media upload volumes / outbound DPI + ML"},
];

const CATS = ["All", ...new Set(THREATS.map(t => t.cat))];

// ─── SIMULATION ENGINE ────────────────────────────────────────────
function makeNetState(net) {
  return {
    pps: Array.from({length:60}, () => R(...net.base)),
    alerts: [],
    zPPS: 0,
  };
}

function genPacket() {
  const proto = pick(PROTOS);
  const attack = Math.random() > 0.78;
  const fieldMap = {
    TCP:   () => [pick(["SYN","ACK","RST","FIN","SYN+ACK"]), R(1e6,4e9), R(0,4e9), R(512,65535), attack?"BAD":"OK"],
    UDP:   () => [R(8,1472), attack?"BAD":"OK", R(0,1400), attack?(6+Math.random()*2).toFixed(2):(2+Math.random()*3).toFixed(2), "NO"],
    HTTP:  () => [pick(["GET","POST","PUT","DELETE"]), "campus.srm.edu", attack?"python-requests/2.31":"Mozilla/5.0", pick(["text/html","application/json"]), pick([200,404,500,302,403])],
    HTTPS: () => [pick(["TLS 1.2","TLS 1.3"]), pick(["AES-256-GCM","CHACHA20-POLY1305"]), "campus.srm.edu", attack?"SELF-SIGNED":"SRM-CA", pick(["h2","http/1.1"])],
    DNS:   () => [attack?"malicious-c2-beacon.xyz":"google.com", pick(["A","AAAA","MX","TXT","ANY"]), attack?0:R(300,86400), attack?"NXDOMAIN":"1.1.1.1", pick(["RD","RA+RD","AA"])],
    ICMP:  () => [R(0,18), R(0,8), R(0,65535), R(1,9999), R(32,128)],
  };
  const fields = (fieldMap[proto.p] || fieldMap.TCP)();
  const anomalyIdx = attack ? [R(0, proto.fields.length-1)] : [];
  return {
    proto: proto.p, col: proto.col,
    ts: nowTs(), src: ip(), dst: "10.0.0.254",
    sport: R(1024,65535), dport: proto.port || R(1,1024),
    size: R(40,1500), ttl: attack ? R(32,48) : R(60,128),
    fields, anomalyIdx,
    entropy: attack ? (6+Math.random()*2).toFixed(2) : (2+Math.random()*3).toFixed(2),
    flagged: attack,
  };
}

// ═══════════════════════════════════════════════════════════════════
// SUB-COMPONENTS
// ═══════════════════════════════════════════════════════════════════

// ─── SPARKLINE ────────────────────────────────────────────────────
function Spark({ data, threshold, color, height=140 }) {
  if (!data || data.length < 2) return null;
  const W=480, H=height, pad=4;
  const max = Math.max(...data, threshold+10);
  const min = 0;
  const px = i => (i/(data.length-1))*W;
  const py = v => H - ((v-min)/(max-min+0.001))*(H-pad*2) - pad;
  const pts = data.map((v,i) => [px(i), py(v)]);
  const line = pts.map((p,i) => `${i?"L":"M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const fill = `${line} L${W},${H} L0,${H} Z`;
  const thY = py(threshold);
  const last = data[data.length-1];
  const hot = last >= threshold;
  const lineCol = hot ? "#ff4560" : color;
  const gid = `sg${color.replace(/\W/g,"")}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{width:"100%",height}}>
      <defs>
        <linearGradient id={gid} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={lineCol} stopOpacity="0.35"/>
          <stop offset="85%" stopColor={lineCol} stopOpacity="0.02"/>
        </linearGradient>
        <filter id="gw"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      {[0.25,0.5,0.75].map(f=><line key={f} x1="0" x2={W} y1={H*f} y2={H*f} stroke="#ffffff07" strokeWidth="1"/>)}
      <path d={fill} fill={`url(#${gid})`}/>
      <line x1="0" x2={W} y1={thY} y2={thY} stroke="#ff4560" strokeWidth="1.5" strokeDasharray="7 4" opacity="0.7"/>
      <path d={line} fill="none" stroke={lineCol} strokeWidth="2" filter="url(#gw)"/>
      <circle cx={pts.at(-1)[0]} cy={pts.at(-1)[1]} r="4" fill={lineCol} filter="url(#gw)"/>
    </svg>
  );
}

// ─── MINI SPARK (for network cards) ───────────────────────────────
function MiniSpark({ data, color, height=48 }) {
  if (!data || data.length < 2) return null;
  const W=200, H=height;
  const max = Math.max(...data)+1, min=0;
  const px = i => (i/(data.length-1))*W;
  const py = v => H - ((v-min)/(max-min))*H;
  const pts = data.map((v,i)=>[px(i),py(v)]);
  const line = pts.map((p,i)=>`${i?"L":"M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const fill = `${line} L${W},${H} L0,${H} Z`;
  const gid = `ms${color.replace(/\W/g,"")}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{width:"100%",height}}>
      <defs>
        <linearGradient id={gid} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.4"/>
          <stop offset="100%" stopColor={color} stopOpacity="0.01"/>
        </linearGradient>
      </defs>
      <path d={fill} fill={`url(#${gid})`}/>
      <path d={line} fill="none" stroke={color} strokeWidth="1.5"/>
    </svg>
  );
}

// ─── Z GAUGE ──────────────────────────────────────────────────────
function ZGauge({ val, label, color }) {
  const cl = clamp(val, -5, 5);
  const pct = (cl+5)/10;
  const col = Math.abs(val)>4?"#ff4560":Math.abs(val)>3?"#f5c400":Math.abs(val)>2?"#fbbf24":color||"#00f5c4";
  const arc = pct * 125.66;
  return (
    <div style={{textAlign:"center",flex:1}}>
      <svg viewBox="0 0 100 58" width="90">
        <path d="M 12 52 A 38 38 0 0 1 88 52" fill="none" stroke="#1a2535" strokeWidth="7" strokeLinecap="round"/>
        <path d="M 12 52 A 38 38 0 0 1 88 52" fill="none" stroke={col} strokeWidth="7"
          strokeLinecap="round" strokeDasharray={`${arc} 200`}
          style={{filter:`drop-shadow(0 0 5px ${col}88)`}}/>
        <text x="50" y="50" textAnchor="middle" fill={col} fontSize="13" fontWeight="700" fontFamily="monospace">
          {val >= 0 ? "+" : ""}{val.toFixed(1)}σ
        </text>
      </svg>
      <div style={{fontSize:9,color:"#3a5060",letterSpacing:1.5,marginTop:-4}}>{label}</div>
    </div>
  );
}

// ─── ENTROPY BAR ──────────────────────────────────────────────────
function EntropyBar({ value, color }) {
  const pct = clamp(parseFloat(value)/8, 0, 1)*100;
  const col = pct > 81 ? "#ff4560" : color;
  return (
    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:7}}>
      <div style={{flex:1,height:5,background:"#0f1825",borderRadius:3}}>
        <div style={{width:`${pct}%`,height:"100%",background:col,borderRadius:3,boxShadow:`0 0 6px ${col}88`,transition:"width 0.4s ease"}}/>
      </div>
      <span style={{fontSize:10,color:col,fontFamily:"monospace",minWidth:28,textAlign:"right",fontWeight:700}}>{value}</span>
    </div>
  );
}

// ─── IPS TOGGLE ROW ───────────────────────────────────────────────
function IPSRow({ entry, onToggle }) {
  const ac = ACTION_COLORS[entry.rule.action] || "#00f5c4";
  const sevCol = {high:"#ff4560",medium:"#f5c400",low:"#a3e635"}[entry.rule.sev];
  return (
    <div style={{
      display:"flex",alignItems:"center",gap:12,
      padding:"11px 14px",borderRadius:8,marginBottom:7,
      background: entry.fired && entry.enabled ? "#1a0a10" : "#080e18",
      border:`1px solid ${entry.fired && entry.enabled ? "#ff456030" : "#0f1e2e"}`,
      transition:"all 0.2s",
    }}>
      <div style={{width:6,height:6,borderRadius:"50%",flexShrink:0,
        background:entry.enabled?(entry.fired?"#ff4560":"#00f5c4"):"#1a2535",
        boxShadow:entry.enabled?(entry.fired?"0 0 8px #ff4560":"0 0 8px #00f5c488"):"none"}}/>
      <div style={{flex:1,minWidth:0}}>
        <div style={{fontSize:12,color:"#c8dce8",fontWeight:600,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{entry.rule.name}</div>
        <div style={{fontSize:10,color:"#2a3d52",fontFamily:"monospace",marginTop:2}}>{entry.rule.cond}</div>
      </div>
      <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:3}}>
        <div style={{fontSize:9,padding:"1px 7px",background:`${ac}18`,color:ac,borderRadius:4,fontFamily:"monospace",fontWeight:700,letterSpacing:0.5}}>{entry.rule.action}</div>
        <div style={{fontSize:9,color:sevCol,letterSpacing:0.5}}>{entry.rule.sev} · {entry.fires}</div>
      </div>
      {/* Toggle */}
      <div onClick={()=>onToggle(entry.rule.id)} style={{
        width:30,height:16,borderRadius:8,flexShrink:0,cursor:"pointer",position:"relative",
        background:entry.enabled?"#00f5c425":"#0f1e2e",
        border:`1px solid ${entry.enabled?"#00f5c450":"#1a2535"}`,transition:"all 0.2s",
      }}>
        <div style={{position:"absolute",top:2,left:entry.enabled?13:2,width:10,height:10,borderRadius:"50%",
          background:entry.enabled?"#00f5c4":"#2a3d52",transition:"left 0.2s"}}/>
      </div>
    </div>
  );
}

// ─── DPI PACKET CARD ──────────────────────────────────────────────
function PacketCard({ pkt }) {
  if (!pkt) return null;
  const proto = PROTOS.find(p => p.p === pkt.proto) || PROTOS[0];
  return (
    <div style={{
      background:"#050c14",border:`1px solid ${pkt.flagged?"#ff456025":proto.col+"18"}`,
      borderLeft:`3px solid ${pkt.flagged?"#ff4560":proto.col}`,
      borderRadius:8,padding:"12px 14px",marginBottom:8,
      fontFamily:"monospace",fontSize:11,animation:"fadeIn 0.3s ease",
    }}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:9}}>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <span style={{color:proto.col,fontWeight:700,fontSize:12,letterSpacing:1}}>{pkt.proto}</span>
          {pkt.flagged && <span style={{fontSize:9,color:"#ff4560",background:"#ff456015",padding:"1px 6px",borderRadius:4,letterSpacing:1}}>⚠ ANOMALY</span>}
        </div>
        <span style={{fontSize:9,color:"#2a4050"}}>{pkt.ts} · {pkt.size}B · TTL {pkt.ttl}</span>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"5px 14px",marginBottom:8}}>
        <div><span style={{color:"#1a3048"}}>SRC </span><span style={{color:"#8db8cc"}}>{pkt.src}:{pkt.sport}</span></div>
        <div><span style={{color:"#1a3048"}}>DST </span><span style={{color:"#8db8cc"}}>{pkt.dst}:{pkt.dport}</span></div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"3px 14px"}}>
        {proto.fields.map((f,i) => (
          <div key={f}>
            <span style={{color:"#1a3048"}}>{f}: </span>
            <span style={{color: pkt.anomalyIdx?.includes(i) ? "#ff4560" : "#6a9ab0"}}>{pkt.fields[i] ?? "—"}</span>
          </div>
        ))}
        <div><span style={{color:"#1a3048"}}>Entropy: </span><span style={{color: parseFloat(pkt.entropy)>6.5?"#ff4560":"#6a9ab0"}}>{pkt.entropy}</span></div>
      </div>
    </div>
  );
}

// ─── ALERT ROW ────────────────────────────────────────────────────
function AlertRow({ alert, netColor, isFirst, isHot }) {
  return (
    <div style={{
      display:"flex",gap:14,alignItems:"center",
      padding:"10px 14px",borderRadius:7,
      background: isFirst&&isHot?"#140810":"transparent",
      borderLeft:`2px solid ${isFirst&&isHot?"#ff4560":netColor+"60"}`,
      marginBottom:5, animation:"fadeIn 0.4s ease",
    }}>
      <div style={{fontSize:10,fontWeight:700,color:isFirst&&isHot?"#ff4560":netColor,minWidth:72}}>
        {isFirst&&isHot?"🔴 ONGOING":"🟢 LOGGED"}
      </div>
      <div style={{flex:1}}>
        <div style={{fontSize:12,color:"#b8d0e0",fontFamily:"monospace"}}>{alert.src}</div>
        <div style={{fontSize:10,color:"#2a3d52",marginTop:1}}>z = {alert.z}σ · {alert.reason || "PPS threshold breach"}</div>
      </div>
      <div style={{fontSize:11,color:"#ff4560",fontFamily:"monospace",fontWeight:700}}>{alert.pps} PPS</div>
      <div style={{fontSize:10,color:"#2a3d52"}}>{alert.ts}</div>
    </div>
  );
}

// ─── MATRIX STREAM ────────────────────────────────────────────────
function MatrixStream({ logs }) {
  const ref = useRef();
  return (
    <div ref={ref} style={{
      fontFamily:"monospace",fontSize:10,lineHeight:1.65,
      background:"#030710",color:"#00f5c4",
      padding:"12px 14px",borderRadius:8,height:260,overflowY:"auto",
      border:"1px solid #0a1828",textShadow:"0 0 8px #00f5c466",
    }}>
      {logs.map((l,i) => (
        <div key={i} style={{color:l.hot?"#ff4560":"#00f5c4",opacity:1-i*0.04}}>
          <span style={{color:"#0a2030"}}>[{l.ts}] </span>
          <span style={{color:l.hot?"#ff6b80":"#26d990"}}>{l.src}</span>
          <span style={{color:"#0a2030"}}> → </span>
          <span style={{color:"#1a4060"}}>10.0.0.254</span>
          <span style={{marginLeft:8,color:l.hot?"#ff456060":"#00f5c430"}}>{l.hot?"⚠ FLOOD":"✓"}</span>
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════════════
export default function INTMS() {
  const [page, setPage]     = useState("monitoring");
  const [selNet, setSelNet] = useState("main");

  // Per-network state
  const [netState, setNetState] = useState(() =>
    Object.fromEntries(NETS.map(n => [n.id, makeNetState(n)]))
  );

  // IPS
  const [ipsEntries, setIpsEntries] = useState(() =>
    IPS_RULES.map(r => ({ rule:r, enabled:true, fires:0, fired:false }))
  );
  const [ipsLog, setIpsLog] = useState([]);

  // DPI
  const [dpiPkts, setDpiPkts]     = useState(() => Array.from({length:12}, genPacket));
  const [dpiFilter, setDpiFilter] = useState("ALL");

  // Stream logs
  const [streamLogs, setStreamLogs] = useState([]);

  // Threat dict
  const [threatCat, setThreatCat]     = useState("All");
  const [activeThreat, setActiveThreat] = useState(null);

  // Misc
  const [mitigated, setMitigated] = useState({});
  const [escalated, setEscalated] = useState(false);

  const THRESH = 230;

  // ── TICK ──────────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      const now = nowTs();

      setNetState(prev => {
        const next = { ...prev };
        for (const net of NETS) {
          const isSpike = Math.random() > 0.86;
          const newPps = isSpike ? R(280, 720) : R(...net.base);
          const arr = [...prev[net.id].pps.slice(1), newPps];
          const zv = parseFloat(z(newPps, arr).toFixed(2));
          const newAlerts = isSpike
            ? [{ ts:now, src:`45.${R(1,255)}.${R(1,255)}.${R(1,255)}`, pps:newPps, z:zv, reason:`+${zv.toFixed(1)}σ PPS flood detected` }, ...prev[net.id].alerts].slice(0,10)
            : prev[net.id].alerts;
          next[net.id] = { pps:arr, alerts:newAlerts, zPPS:zv };
        }
        return next;
      });

      // DPI packets
      const pkts = Array.from({length: R(1,3)}, genPacket);
      setDpiPkts(p => [...pkts, ...p].slice(0, 50));

      // IPS
      setIpsEntries(prev => prev.map(e => {
        const fired = e.enabled && Math.random() > 0.91;
        return {...e, fires: e.fires + (fired?1:0), fired};
      }));
      setIpsLog(prev => {
        const newEntries = ipsEntries
          .filter(e=>e.enabled && Math.random()>0.88)
          .map(e=>({ ts:now, rule:e.rule.name, action:e.rule.action, src:`${R(45,200)}.${R(1,254)}.${R(1,254)}.${R(1,254)}` }));
        return [...newEntries, ...prev].slice(0,40);
      });

      // Stream logs
      setStreamLogs(prev => {
        const all = NETS.map(net => ({
          ts:now,
          src:ip(net.pfx),
          hot: netState[net.id]?.pps.at(-1) >= THRESH,
        }));
        return [...all, ...prev].slice(0,30);
      });

    }, 1700);
    return () => clearInterval(id);
  }, [ipsEntries, netState]);

  // ── COMPUTED ──────────────────────────────────────────────────
  const net = NETS.find(n => n.id === selNet);
  const nd  = netState[selNet];
  const curPps = nd.pps.at(-1);
  const isAtk  = curPps >= THRESH;
  const curZ   = nd.zPPS;
  const avgPps = Math.round(μ(nd.pps));
  const stdPps = σ(nd.pps).toFixed(1);
  const peakPps = Math.max(...nd.pps);
  const curKBs = Math.round(curPps * R(1200,2000) / 1024);

  const filteredPkts = dpiFilter === "ALL" ? dpiPkts : dpiPkts.filter(p => p.proto === dpiFilter);
  const filteredThreats = threatCat === "All" ? THREATS : THREATS.filter(t => t.cat === threatCat);

  // All-network summary
  const netSummary = NETS.map(n => ({
    ...n,
    pps: netState[n.id].pps.at(-1),
    z:   netState[n.id].zPPS,
    atk: netState[n.id].pps.at(-1) >= THRESH,
    alerts: netState[n.id].alerts.length,
  }));

  const attackNets = netSummary.filter(n=>n.atk).length;
  const totalAlerts = Object.values(netState).reduce((s,v)=>s+v.alerts.length,0);

  // ── STYLES ────────────────────────────────────────────────────
  const C = { bg:"#060c14", card:"#08101c", border:"#0d1e2e", text:"#9bbdd0", dim:"#1e3048", acc:net.color };

  const card = (ex={}) => ({
    background:C.card, border:`1px solid ${C.border}`, borderRadius:12, padding:"18px 20px", ...ex
  });

  const navBtn = (id) => ({
    display:"flex",alignItems:"center",gap:9,
    padding:"9px 13px",borderRadius:8,cursor:"pointer",
    fontSize:12,fontWeight:600,letterSpacing:0.3,
    color: page===id ? C.acc : C.dim,
    background: page===id ? `${C.acc}12` : "transparent",
    border: page===id ? `1px solid ${C.acc}28` : "1px solid transparent",
    transition:"all 0.15s",fontFamily:"'Syne', sans-serif",
  });

  const tag = (label, color) => (
    <span style={{fontSize:9,padding:"2px 8px",borderRadius:4,
      background:`${color}18`,color,fontFamily:"monospace",letterSpacing:0.5,fontWeight:700}}>
      {label}
    </span>
  );

  const verdictText = Math.abs(curZ)>4?"CRITICAL":Math.abs(curZ)>3?"ELEVATED":Math.abs(curZ)>2?"WARNING":"BASELINE";
  const verdictCol  = Math.abs(curZ)>4?"#ff4560":Math.abs(curZ)>3?"#f5c400":Math.abs(curZ)>2?"#fbbf24":"#00f5c4";

  // ── RENDER ────────────────────────────────────────────────────
  return (
    <div style={{display:"flex",minHeight:"100vh",background:C.bg,color:C.text,fontFamily:"'Syne',sans-serif"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:3px;height:3px}
        ::-webkit-scrollbar-track{background:#060c14}
        ::-webkit-scrollbar-thumb{background:#0d1e2e;border-radius:3px}
        @keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.4)}}
        @keyframes glow{0%,100%{box-shadow:0 0 6px currentColor}50%{box-shadow:0 0 18px currentColor}}
        .nav-lnk:hover{color:#e2f0f8!important;border-color:#1a3048!important}
        .hov-row:hover{background:#0c1828!important}
        .threat-tile{cursor:pointer;transition:all 0.15s}
        .threat-tile:hover{border-color:var(--tc)!important;background:#0c1820!important;transform:translateY(-2px)}
        .btn-act{cursor:pointer;transition:all 0.15s}
        .btn-act:hover{filter:brightness(1.3);transform:translateY(-1px)}
        .net-pill:hover{opacity:1!important}
      `}</style>

      {/* ══ SIDEBAR ════════════════════════════════════════════ */}
      <aside style={{
        width:214,minHeight:"100vh",background:"#050b12",
        borderRight:`1px solid ${C.border}`,padding:"22px 12px",
        display:"flex",flexDirection:"column",gap:3,
        position:"sticky",top:0,height:"100vh",overflowY:"auto",flexShrink:0,
      }}>
        {/* Logo */}
        <div style={{marginBottom:26,paddingLeft:2}}>
          <div style={{fontSize:20,fontWeight:800,color:"#e2f0f8",letterSpacing:-1}}>
            INTMS<span style={{color:C.acc}}>.</span>
          </div>
          <div style={{fontSize:8,color:C.dim,letterSpacing:3,marginTop:1}}>COMMAND CENTER v2</div>
        </div>

        <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,paddingLeft:3,marginBottom:6}}>NAVIGATION</div>
        {[
          ["monitoring","◉","Monitoring"],
          ["networks",  "▦","Multi-Network"],
          ["ips",       "⬡","IPS Engine"],
          ["dpi",       "◎","Deep Inspection"],
          ["incidents", "⚡","Incidents"],
          ["dictionary","◈","Threat Dict"],
        ].map(([id,ic,lb]) => (
          <div key={id} className="nav-lnk" style={navBtn(id)} onClick={()=>setPage(id)}>
            <span style={{fontFamily:"monospace",fontSize:13}}>{ic}</span>
            <span>{lb}</span>
            {id==="incidents" && totalAlerts>0 && (
              <span style={{marginLeft:"auto",fontSize:9,background:"#ff456020",color:"#ff4560",padding:"1px 6px",borderRadius:8,fontFamily:"monospace"}}>{totalAlerts}</span>
            )}
          </div>
        ))}

        {/* Network Pills */}
        <div style={{marginTop:18,borderTop:`1px solid ${C.border}`,paddingTop:16}}>
          <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,marginBottom:9}}>NETWORKS</div>
          {NETS.map(n => {
            const ns = netState[n.id];
            const hot = ns.pps.at(-1) >= THRESH;
            const active = selNet === n.id;
            return (
              <div key={n.id} className="net-pill" onClick={()=>{setSelNet(n.id);setPage("monitoring");}}
                style={{display:"flex",alignItems:"center",gap:7,padding:"6px 8px",borderRadius:7,
                  cursor:"pointer",marginBottom:3,opacity:active?1:0.6,
                  background:active?`${n.color}0e`:"transparent",
                  border:active?`1px solid ${n.color}28`:"1px solid transparent",transition:"all 0.15s"}}>
                <div style={{width:7,height:7,borderRadius:"50%",background:hot?"#ff4560":n.color,flexShrink:0,
                  boxShadow:active?(hot?`0 0 7px #ff4560`:`0 0 7px ${n.color}`):"none",
                  animation:hot?"pulse 1s infinite":"none"}}/>
                <div style={{flex:1}}>
                  <div style={{fontSize:10,color:active?n.color:C.dim,fontWeight:600,lineHeight:1.2}}>{n.label}</div>
                  <div style={{fontSize:8,color:C.dim,fontFamily:"monospace",letterSpacing:0.5}}>{n.subnet}</div>
                </div>
                {hot && <span style={{fontSize:8,color:"#ff4560",fontFamily:"monospace"}}>⚠</span>}
              </div>
            );
          })}
        </div>

        {/* Global status */}
        <div style={{marginTop:"auto",paddingTop:16,borderTop:`1px solid ${C.border}`}}>
          <div style={{display:"flex",alignItems:"center",gap:7,marginBottom:8}}>
            <div style={{width:7,height:7,borderRadius:"50%",animation:"pulse 1.5s infinite",
              background:attackNets>0?"#ff4560":"#00f5c4",
              boxShadow:attackNets>0?"0 0 9px #ff4560":"0 0 9px #00f5c488"}}/>
            <span style={{fontSize:10,fontWeight:700,color:attackNets>0?"#ff4560":"#00f5c4",letterSpacing:0.5}}>
              {attackNets>0?`${attackNets} NET UNDER ATTACK`:"ALL NETS NOMINAL"}
            </span>
          </div>
          <div style={{fontSize:9,color:C.dim,fontFamily:"JetBrains Mono,monospace",lineHeight:1.7}}>
            SRM Campus Net<br/>
            <span style={{color:"#1a3a28"}}>▸ heuristic engine on</span>
          </div>
        </div>
      </aside>

      {/* ══ MAIN ════════════════════════════════════════════════ */}
      <main style={{flex:1,padding:"26px 30px",overflowX:"hidden",animation:"fadeIn 0.3s ease"}}>

        {/* ══════════════════════════════════════════════════════
            PAGE: MONITORING
        ══════════════════════════════════════════════════════ */}
        {page==="monitoring" && (
          <div>
            {/* Header */}
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:24}}>
              <div>
                <h1 style={{fontSize:24,fontWeight:800,color:"#e2f0f8",letterSpacing:-0.8,marginBottom:3}}>
                  {net.label} <span style={{color:C.acc,fontSize:13,fontWeight:400}}>/ live monitoring</span>
                </h1>
                <div style={{fontSize:11,color:C.dim,fontFamily:"JetBrains Mono,monospace"}}>
                  {net.subnet} · 3σ heuristic engine · refreshing 1.7s
                </div>
              </div>
              <div style={{display:"flex",gap:10,alignItems:"center"}}>
                {isAtk && (
                  <div style={{display:"flex",alignItems:"center",gap:7,padding:"7px 14px",borderRadius:8,background:"#ff456015",border:"1px solid #ff456040"}}>
                    <div style={{width:7,height:7,borderRadius:"50%",background:"#ff4560",animation:"pulse 0.8s infinite"}}/>
                    <span style={{fontSize:11,color:"#ff4560",fontWeight:700,letterSpacing:0.5}}>ATTACK ACTIVE</span>
                  </div>
                )}
                <button className="btn-act" onClick={()=>setEscalated(true)}
                  style={{padding:"8px 16px",borderRadius:8,border:"1px solid #ff456050",background:"#ff456015",color:"#ff4560",fontSize:11,fontWeight:700,letterSpacing:0.5}}>
                  🚨 Escalate
                </button>
              </div>
            </div>

            {escalated && (
              <div style={{...card({marginBottom:16,borderColor:"#ff456030",display:"flex",justifyContent:"space-between",alignItems:"center",padding:"12px 18px"})}}>
                <span style={{fontSize:12,color:"#ff4560"}}>⚠ Escalation dispatched to SOC admin — {nowTs()}</span>
                <span onClick={()=>setEscalated(false)} style={{cursor:"pointer",color:C.dim,fontSize:16}}>✕</span>
              </div>
            )}

            {/* KPI Row */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:18}}>
              {[
                {label:"Status",    val:isAtk?"ATTACK":"CLEAN",   col:isAtk?"#ff4560":C.acc, sub:isAtk?"Threshold breached":"Baseline normal"},
                {label:"Live PPS",  val:curPps,                    col:isAtk?"#ff4560":"#e2f0f8", sub:`z = ${curZ.toFixed(2)}σ`},
                {label:"Throughput",val:`${curKBs} KB/s`,          col:"#e2f0f8", sub:"live BPS estimate"},
                {label:"Alerts",    val:nd.alerts.length,          col:nd.alerts.length>0?"#ff4560":C.acc, sub:"this session"},
              ].map(k=>(
                <div key={k.label} style={card()}>
                  <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,textTransform:"uppercase",marginBottom:9}}>{k.label}</div>
                  <div style={{fontSize:26,fontWeight:800,color:k.col,fontFamily:"JetBrains Mono,monospace",lineHeight:1}}>{k.val}</div>
                  <div style={{fontSize:10,color:C.dim,marginTop:5}}>{k.sub}</div>
                </div>
              ))}
            </div>

            {/* 5-tuple */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:10,marginBottom:18}}>
              {["Src IP","Dst IP","Src Port","Dst Port","Proto"].map((lb,i) => {
                const vals = [isAtk?`45.${R(1,255)}.${R(1,255)}.${R(1,255)}`:ip(net.pfx), "10.0.0.254", R(1024,65535), pick([80,443,53,8080]), "TCP"];
                return (
                  <div key={lb} style={{background:"#050c14",border:`1px solid ${C.border}`,borderRadius:8,padding:"11px 14px"}}>
                    <div style={{fontSize:8,color:C.dim,letterSpacing:2,textTransform:"uppercase",marginBottom:6}}>{lb}</div>
                    <div style={{fontSize:13,fontWeight:700,color:C.acc,fontFamily:"JetBrains Mono,monospace"}}>{vals[i]}</div>
                  </div>
                );
              })}
            </div>

            {/* Chart + Z Gauges */}
            <div style={{display:"grid",gridTemplateColumns:"2fr 1fr",gap:16,marginBottom:18}}>
              <div style={card()}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
                  <div>
                    <div style={{fontSize:14,fontWeight:700,color:"#e2f0f8"}}>Traffic Volume · PPS</div>
                    <div style={{fontSize:10,color:C.dim,marginTop:2,fontFamily:"JetBrains Mono,monospace"}}>60-second rolling window</div>
                  </div>
                  <div style={{display:"flex",gap:14,fontSize:10}}>
                    <span style={{color:C.acc}}>● live</span>
                    <span style={{color:"#ff4560"}}>― threshold ({THRESH})</span>
                  </div>
                </div>
                <Spark data={nd.pps} threshold={THRESH} color={C.acc}/>
                <div style={{display:"flex",gap:20,marginTop:14,paddingTop:14,borderTop:`1px solid ${C.border}`}}>
                  {[
                    {l:"Mean",  v:avgPps,             c:"#e2f0f8"},
                    {l:"Std Dev",v:stdPps,             c:C.acc},
                    {l:"Peak",  v:`↑${peakPps}`,       c:"#ff4560"},
                    {l:"Z-score",v:`${curZ.toFixed(2)}σ`,c:verdictCol},
                    {l:"Verdict",v:verdictText,         c:verdictCol},
                  ].map(k=>(
                    <div key={k.l}>
                      <div style={{fontSize:8,color:C.dim,letterSpacing:1.5,marginBottom:3}}>{k.l}</div>
                      <div style={{fontSize:16,fontWeight:800,color:k.c,fontFamily:"JetBrains Mono,monospace"}}>{k.v}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div style={card()}>
                <div style={{fontSize:14,fontWeight:700,color:"#e2f0f8",marginBottom:16}}>Heuristic Gauges</div>
                <div style={{display:"flex",flexWrap:"wrap",justifyContent:"space-around",gap:8}}>
                  <ZGauge val={curZ} label="PPS" color={C.acc}/>
                  <ZGauge val={parseFloat((curZ*0.8+Math.random()-0.5).toFixed(2))} label="BPS" color={C.acc}/>
                  <ZGauge val={parseFloat((curZ*0.6+Math.random()-0.4).toFixed(2))} label="ENTROPY" color={C.acc}/>
                  <ZGauge val={parseFloat((curZ*0.45+Math.random()-0.3).toFixed(2))} label="CONN" color={C.acc}/>
                </div>
                <div style={{marginTop:14,padding:"10px 12px",borderRadius:7,
                  background:Math.abs(curZ)>3?"#140810":"#07100a",
                  border:`1px solid ${verdictCol}28`}}>
                  <div style={{fontSize:8,color:C.dim,letterSpacing:2,marginBottom:4}}>ENGINE VERDICT</div>
                  <div style={{fontSize:14,fontWeight:800,color:verdictCol,fontFamily:"JetBrains Mono,monospace"}}>{verdictText}</div>
                  <div style={{fontSize:10,color:C.dim,marginTop:3}}>
                    {Math.abs(curZ)>3?`Source ${ip(net.pfx)} flagged for review`:"All metrics within normal baseline"}
                  </div>
                </div>
              </div>
            </div>

            {/* Packet stream + Alerts */}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
              <div style={card()}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
                  <div style={{fontSize:14,fontWeight:700,color:"#e2f0f8"}}>Raw Packet Stream</div>
                  <div style={{fontSize:9,color:"#00f5c4",fontFamily:"monospace",letterSpacing:1.5}}>● LIVE</div>
                </div>
                <MatrixStream logs={streamLogs}/>
              </div>

              <div style={card()}>
                <div style={{fontSize:14,fontWeight:700,color:"#e2f0f8",marginBottom:12}}>Alert Stream</div>
                <div style={{maxHeight:260,overflowY:"auto"}}>
                  {nd.alerts.length===0
                    ? <div style={{fontSize:12,color:C.dim,textAlign:"center",padding:"40px 0"}}>No alerts for {net.label}</div>
                    : nd.alerts.map((a,i)=><AlertRow key={i} alert={a} netColor={C.acc} isFirst={i===0} isHot={isAtk}/>)
                  }
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════
            PAGE: MULTI-NETWORK
        ══════════════════════════════════════════════════════ */}
        {page==="networks" && (
          <div>
            <div style={{marginBottom:24}}>
              <h1 style={{fontSize:24,fontWeight:800,color:"#e2f0f8",letterSpacing:-0.8,marginBottom:3}}>Multi-Network Overview</h1>
              <div style={{fontSize:11,color:C.dim,fontFamily:"JetBrains Mono,monospace"}}>{NETS.length} segments · unified z-score baseline engine</div>
            </div>

            {/* Summary tiles */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:20}}>
              {[
                {l:"Total Alerts",   v:totalAlerts,     c:totalAlerts>0?"#ff4560":"#00f5c4"},
                {l:"Nets Monitored", v:NETS.length,     c:"#e2f0f8"},
                {l:"Under Attack",   v:attackNets,      c:attackNets>0?"#ff4560":"#00f5c4"},
                {l:"Anomalies 1m",   v:Object.values(netState).reduce((s,n)=>s+(Math.abs(n.zPPS)>2?1:0),0), c:"#f5c400"},
              ].map(k=>(
                <div key={k.l} style={card()}>
                  <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,marginBottom:9}}>{k.l}</div>
                  <div style={{fontSize:28,fontWeight:800,color:k.c,fontFamily:"JetBrains Mono,monospace"}}>{k.v}</div>
                </div>
              ))}
            </div>

            {/* Network cards */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:14,marginBottom:20}}>
              {netSummary.map(n=>(
                <div key={n.id} onClick={()=>{setSelNet(n.id);setPage("monitoring");}}
                  style={{...card({cursor:"pointer",borderColor:n.atk?"#ff456028":`${n.color}22`,
                    background: n.atk?"#100810":"#08101c",transition:"all 0.15s"})}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:14}}>
                    <div>
                      <div style={{fontSize:15,fontWeight:700,color:"#e2f0f8",marginBottom:2}}>{n.label}</div>
                      <div style={{fontSize:10,color:C.dim,fontFamily:"JetBrains Mono,monospace"}}>{n.subnet}</div>
                    </div>
                    <div style={{display:"flex",gap:7,flexDirection:"column",alignItems:"flex-end"}}>
                      <div style={{fontSize:9,fontWeight:700,padding:"3px 10px",borderRadius:10,
                        color:n.atk?"#ff4560":n.color,
                        background:n.atk?"#ff456015":`${n.color}15`}}>
                        {n.atk?"⚠ ATTACK":"● OK"}
                      </div>
                      <div style={{fontSize:10,color:Math.abs(n.z)>3?"#ff4560":C.dim,fontFamily:"JetBrains Mono,monospace"}}>
                        z = {n.z.toFixed(2)}σ
                      </div>
                    </div>
                  </div>
                  <MiniSpark data={netState[n.id].pps} color={n.atk?"#ff4560":n.color}/>
                  <div style={{display:"flex",justifyContent:"space-between",marginTop:12,paddingTop:10,borderTop:`1px solid ${C.border}`}}>
                    <div>
                      <div style={{fontSize:8,color:C.dim,marginBottom:3}}>CURRENT PPS</div>
                      <div style={{fontSize:18,fontWeight:800,color:n.atk?"#ff4560":n.color,fontFamily:"JetBrains Mono,monospace"}}>{n.pps}</div>
                    </div>
                    <div style={{textAlign:"right"}}>
                      <div style={{fontSize:8,color:C.dim,marginBottom:3}}>ALERTS</div>
                      <div style={{fontSize:18,fontWeight:800,color:n.alerts>0?"#ff4560":"#e2f0f8",fontFamily:"JetBrains Mono,monospace"}}>{n.alerts}</div>
                    </div>
                    <div style={{textAlign:"right"}}>
                      <div style={{fontSize:8,color:C.dim,marginBottom:3}}>PEAK</div>
                      <div style={{fontSize:18,fontWeight:800,color:"#e2f0f8",fontFamily:"JetBrains Mono,monospace"}}>↑{Math.max(...netState[n.id].pps)}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Cross-network alert table */}
            <div style={card()}>
              <div style={{fontSize:14,fontWeight:700,color:"#e2f0f8",marginBottom:16}}>Cross-Network Alert Feed · all segments</div>
              {Object.values(netState).every(n=>n.alerts.length===0)
                ? <div style={{textAlign:"center",color:C.dim,padding:"32px 0",fontSize:12}}>◉ &nbsp; All networks baseline nominal</div>
                : (
                  <table style={{width:"100%",borderCollapse:"collapse",fontSize:11,fontFamily:"JetBrains Mono,monospace"}}>
                    <thead>
                      <tr>{["Network","Source IP","PPS","Z-Score","Time","Action"].map(h=>(
                        <th key={h} style={{textAlign:"left",padding:"7px 12px",color:C.dim,fontSize:8,letterSpacing:2,textTransform:"uppercase",borderBottom:`1px solid ${C.border}`}}>{h}</th>
                      ))}</tr>
                    </thead>
                    <tbody>
                      {NETS.flatMap(n=>netState[n.id].alerts.slice(0,2).map((a,i)=>({...a,netLabel:n.label,netColor:n.color,key:`${n.id}-${i}`})))
                        .sort((a,b)=>parseFloat(b.z)-parseFloat(a.z)).slice(0,12).map(row=>(
                          <tr key={row.key} className="hov-row" style={{borderBottom:`1px solid ${C.border}10`}}>
                            <td style={{padding:"9px 12px"}}><span style={{color:row.netColor,fontWeight:700}}>●</span> <span style={{color:"#b0c8d8",fontFamily:"Syne,sans-serif",fontSize:12}}>{row.netLabel}</span></td>
                            <td style={{padding:"9px 12px",color:row.netColor}}>{row.src}</td>
                            <td style={{padding:"9px 12px",color:"#e2f0f8",fontWeight:700}}>{row.pps}</td>
                            <td style={{padding:"9px 12px",color:"#ff4560"}}>{row.z}σ</td>
                            <td style={{padding:"9px 12px",color:C.dim}}>{row.ts}</td>
                            <td style={{padding:"9px 12px"}}>{tag("REVIEW","#f5c400")}</td>
                          </tr>
                        ))
                      }
                    </tbody>
                  </table>
                )
              }
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════
            PAGE: IPS
        ══════════════════════════════════════════════════════ */}
        {page==="ips" && (
          <div>
            <div style={{marginBottom:24}}>
              <h1 style={{fontSize:24,fontWeight:800,color:"#e2f0f8",letterSpacing:-0.8,marginBottom:3}}>IPS Engine</h1>
              <div style={{fontSize:11,color:C.dim,fontFamily:"JetBrains Mono,monospace"}}>8 rule chains · kernel-level enforcement · live toggle</div>
            </div>

            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:20}}>
              {[
                {l:"Rules Active",  v:ipsEntries.filter(e=>e.enabled).length,  c:"#00f5c4"},
                {l:"Total Fires",   v:ipsEntries.reduce((s,e)=>s+e.fires,0),    c:"#f5c400"},
                {l:"IPs Blocked",   v:ipsEntries.filter(e=>e.rule.action==="BLOCK_IP").reduce((s,e)=>s+e.fires,0), c:"#ff4560"},
                {l:"Auto-Mitigated",v:ipsEntries.filter(e=>e.enabled&&e.fires>0).length, c:"#a3e635"},
              ].map(k=>(
                <div key={k.l} style={card()}>
                  <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,marginBottom:9}}>{k.l}</div>
                  <div style={{fontSize:28,fontWeight:800,color:k.c,fontFamily:"JetBrains Mono,monospace"}}>{k.v}</div>
                </div>
              ))}
            </div>

            <div style={{display:"grid",gridTemplateColumns:"1.3fr 1fr",gap:16}}>
              <div>
                <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,marginBottom:12}}>RULE CHAINS</div>
                {ipsEntries.map(entry => (
                  <IPSRow key={entry.rule.id} entry={entry}
                    onToggle={id=>setIpsEntries(prev=>prev.map(e=>e.rule.id===id?{...e,enabled:!e.enabled}:e))}/>
                ))}
              </div>

              <div>
                <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,marginBottom:12}}>LIVE ENFORCEMENT LOG</div>
                <div style={{...card({padding:0,overflow:"hidden"})}}>
                  <div style={{fontFamily:"JetBrains Mono,monospace",fontSize:10,padding:14,height:430,overflowY:"auto",background:"#03080f",lineHeight:1.7}}>
                    {ipsLog.slice(0,25).map((l,i)=>(
                      <div key={i} style={{marginBottom:3,animation:"fadeIn 0.3s ease"}}>
                        <span style={{color:"#0a2030"}}>[{l.ts}] </span>
                        <span style={{color:ACTION_COLORS[l.action]||"#00f5c4"}}>[{l.action}] </span>
                        <span style={{color:"#3a6080"}}>{l.rule} — </span>
                        <span style={{color:"#6090a8"}}>{l.src}</span>
                      </div>
                    ))}
                    {ipsLog.length===0 && Array.from({length:10},(_,i)=>(
                      <div key={i} style={{color:"#0a1c28",marginBottom:3}}>[{nowTs()}] [PASS] flow cleared · {ip()}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════
            PAGE: DPI
        ══════════════════════════════════════════════════════ */}
        {page==="dpi" && (
          <div>
            <div style={{marginBottom:24}}>
              <h1 style={{fontSize:24,fontWeight:800,color:"#e2f0f8",letterSpacing:-0.8,marginBottom:3}}>Deep Packet Inspection</h1>
              <div style={{fontSize:11,color:C.dim,fontFamily:"JetBrains Mono,monospace"}}>Layer 7 dissection · payload entropy scoring · protocol breakdown</div>
            </div>

            {/* Proto filter pills */}
            <div style={{display:"flex",gap:8,marginBottom:20,flexWrap:"wrap"}}>
              {["ALL",...PROTOS.map(p=>p.p)].map(p=>{
                const meta = PROTOS.find(x=>x.p===p);
                const col  = meta?.col||C.acc;
                const sel  = dpiFilter===p;
                return (
                  <div key={p} onClick={()=>setDpiFilter(p)}
                    style={{padding:"5px 14px",borderRadius:20,cursor:"pointer",
                      fontSize:11,fontWeight:700,fontFamily:"JetBrains Mono,monospace",
                      border:`1px solid ${sel?col+"70":C.border}`,
                      background:sel?`${col}18`:"transparent",
                      color:sel?col:C.dim,transition:"all 0.15s",letterSpacing:0.5}}>
                    {p}
                  </div>
                );
              })}
              <div style={{marginLeft:"auto",fontSize:10,color:C.dim,fontFamily:"JetBrains Mono,monospace",alignSelf:"center"}}>
                {filteredPkts.length} packets
              </div>
            </div>

            <div style={{display:"grid",gridTemplateColumns:"1.1fr 0.9fr",gap:16}}>
              {/* Live packets */}
              <div>
                <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,marginBottom:12}}>LIVE PACKET STREAM</div>
                <div style={{height:620,overflowY:"auto"}}>
                  {filteredPkts.slice(0,14).map((p,i)=><PacketCard key={i} pkt={p}/>)}
                </div>
              </div>

              {/* Stats */}
              <div>
                <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,marginBottom:12}}>PAYLOAD ENTROPY DISTRIBUTION</div>
                <div style={{...card({marginBottom:16})}}>
                  <div style={{fontSize:13,fontWeight:700,color:"#e2f0f8",marginBottom:14}}>Shannon Entropy Scores</div>
                  {filteredPkts.slice(0,12).map((p,i)=>{
                    const meta = PROTOS.find(x=>x.p===p.proto)||PROTOS[0];
                    return (
                      <div key={i} style={{display:"flex",alignItems:"center",gap:10,marginBottom:8}}>
                        <span style={{fontSize:9,color:meta.col,fontFamily:"JetBrains Mono,monospace",width:42,fontWeight:700}}>{p.proto}</span>
                        <EntropyBar value={p.entropy} color={meta.col}/>
                      </div>
                    );
                  })}
                  <div style={{marginTop:12,padding:"8px 12px",background:"#03080f",borderRadius:6,fontSize:10,color:C.dim,fontFamily:"JetBrains Mono,monospace",lineHeight:1.6}}>
                    entropy &gt; 6.5 → encrypted / compressed / malicious
                  </div>
                </div>

                <div style={card()}>
                  <div style={{fontSize:13,fontWeight:700,color:"#e2f0f8",marginBottom:14}}>Protocol Mix</div>
                  {PROTOS.map(meta=>{
                    const cnt = dpiPkts.filter(p=>p.proto===meta.p).length;
                    const pct = dpiPkts.length ? (cnt/dpiPkts.length*100) : 0;
                    return (
                      <div key={meta.p} style={{display:"flex",alignItems:"center",gap:10,marginBottom:9}}>
                        <span style={{fontSize:9,color:meta.col,fontFamily:"JetBrains Mono,monospace",width:42,fontWeight:700}}>{meta.p}</span>
                        <div style={{flex:1,height:5,background:C.border,borderRadius:3}}>
                          <div style={{width:`${pct}%`,height:"100%",background:meta.col,borderRadius:3,boxShadow:`0 0 5px ${meta.col}88`,transition:"width 0.6s ease"}}/>
                        </div>
                        <span style={{fontSize:9,color:C.dim,width:28,textAlign:"right",fontFamily:"JetBrains Mono,monospace"}}>{pct.toFixed(0)}%</span>
                      </div>
                    );
                  })}

                  <div style={{marginTop:14,borderTop:`1px solid ${C.border}`,paddingTop:14}}>
                    <div style={{fontSize:13,fontWeight:700,color:"#e2f0f8",marginBottom:10}}>Anomaly Summary</div>
                    {[
                      {l:"Flagged packets",  v:dpiPkts.filter(p=>p.flagged).length, c:"#ff4560"},
                      {l:"High entropy (>6.5)",v:dpiPkts.filter(p=>parseFloat(p.entropy)>6.5).length, c:"#f5c400"},
                      {l:"Anomalous fields",  v:dpiPkts.filter(p=>p.anomalyIdx?.length>0).length, c:"#fb923c"},
                    ].map(k=>(
                      <div key={k.l} style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                        <span style={{fontSize:11,color:C.dim}}>{k.l}</span>
                        <span style={{fontSize:12,fontWeight:700,color:k.c,fontFamily:"JetBrains Mono,monospace"}}>{k.v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════
            PAGE: INCIDENTS
        ══════════════════════════════════════════════════════ */}
        {page==="incidents" && (
          <div>
            <div style={{marginBottom:24}}>
              <h1 style={{fontSize:24,fontWeight:800,color:"#e2f0f8",letterSpacing:-0.8,marginBottom:3}}>Incidents</h1>
              <div style={{fontSize:11,color:C.dim,fontFamily:"JetBrains Mono,monospace"}}>All networks · {totalAlerts} total alerts · deterministic event log</div>
            </div>

            {/* Hero banner */}
            <div style={{...card({marginBottom:22,borderColor:attackNets>0?"#ff456025":"#00f5c420",
              background:attackNets>0?"#0f080c":"#070f0a",padding:"28px 32px",position:"relative",overflow:"hidden"})}}>
              <div style={{position:"absolute",right:32,top:"50%",transform:"translateY(-50%)",fontSize:72,opacity:0.05}}>⚡</div>
              <div style={{fontSize:20,fontWeight:800,color:"#e2f0f8",marginBottom:6}}>
                <span style={{color:attackNets>0?"#ff4560":"#00f5c4"}}>{totalAlerts}</span> incidents logged this session
              </div>
              <div style={{fontSize:12,color:C.dim}}>{attackNets} active · {NETS.length-attackNets} resolved · heuristic engine 3σ baseline</div>
            </div>

            <div style={{display:"grid",gridTemplateColumns:"1.6fr 1fr",gap:18}}>
              {/* Incident list */}
              <div>
                {NETS.map(n => {
                  const alts = netState[n.id].alerts;
                  const hot  = netState[n.id].pps.at(-1) >= THRESH;
                  if (alts.length===0) return (
                    <div key={n.id} style={{...card({marginBottom:12,padding:"14px 18px"}),display:"flex",gap:12,alignItems:"center"}}>
                      <div style={{width:7,height:7,borderRadius:"50%",background:n.color,opacity:0.5}}/>
                      <span style={{fontSize:12,color:C.dim}}>{n.label} — baseline nominal</span>
                    </div>
                  );
                  return (
                    <div key={n.id} style={{marginBottom:18}}>
                      <div style={{display:"flex",alignItems:"center",gap:9,marginBottom:10}}>
                        <div style={{width:8,height:8,borderRadius:"50%",background:n.color,boxShadow:hot?`0 0 8px ${n.color}`:"none"}}/>
                        <span style={{fontSize:13,fontWeight:700,color:n.color}}>{n.label}</span>
                        <span style={{fontSize:10,color:C.dim}}>· {alts.length} events</span>
                        {hot && <span style={{fontSize:9,color:"#ff4560",background:"#ff456015",padding:"2px 8px",borderRadius:6}}>ONGOING</span>}
                      </div>
                      {alts.map((a,i)=><AlertRow key={i} alert={a} netColor={n.color} isFirst={i===0} isHot={hot}/>)}
                    </div>
                  );
                })}
              </div>

              {/* Mitigation panel */}
              <div>
                <div style={{fontSize:8,color:C.dim,letterSpacing:2.5,marginBottom:12}}>MITIGATION PANEL</div>
                {(() => {
                  const all = NETS.flatMap(n=>netState[n.id].alerts.map(a=>({...a,nc:n.color,net:n.label})));
                  if (all.length===0) return (
                    <div style={{...card({textAlign:"center",padding:48}),color:C.dim}}>
                      <div style={{fontSize:28,marginBottom:10}}>◉</div>All networks stable
                    </div>
                  );
                  const top = all[0];
                  const done = mitigated[top.src];
                  return (
                    <>
                      <div style={card({marginBottom:12})}>
                        <div style={{fontSize:8,color:C.dim,letterSpacing:2,marginBottom:8}}>ROOT CAUSE</div>
                        <div style={{fontSize:15,fontWeight:700,color:"#ff4560",marginBottom:10}}>Volumetric PPS Flood</div>
                        <p style={{fontSize:11,color:C.dim,lineHeight:1.8}}>
                          Source <span style={{color:"#b8d0e0",fontFamily:"JetBrains Mono,monospace"}}>{top.src}</span> deviated{" "}
                          <span style={{color:"#ff4560",fontWeight:700}}>+{top.z}σ</span> from {top.net} rolling baseline.
                          Consistent with DoS/DDoS profile — volumetric PPS flood.
                        </p>
                      </div>
                      <div style={{...card({marginBottom:12}),borderLeft:"3px solid #00f5c4"}}>
                        <div style={{fontSize:8,color:"#00f5c4",letterSpacing:2,marginBottom:10}}>KERNEL MITIGATION</div>
                        <div style={{background:"#030710",borderRadius:7,padding:"13px 15px",fontFamily:"JetBrains Mono,monospace",fontSize:11,color:"#00f5c4",lineHeight:1.9,border:`1px solid ${C.border}`}}>
                          <span style={{color:C.dim}}># drop at NIC layer</span><br/>
                          iptables -A INPUT \<br/>
                          &nbsp;&nbsp;-s {top.src} \<br/>
                          &nbsp;&nbsp;-j DROP
                        </div>
                        <p style={{fontSize:10,color:C.dim,marginTop:10,lineHeight:1.6}}>
                          Discards all frames from this origin at the driver layer immediately.
                        </p>
                      </div>
                      {done
                        ? <div style={{...card({borderColor:"#00f5c430",textAlign:"center",padding:"14px"}),color:"#00f5c4",fontSize:13,fontWeight:700}}>
                            ✓ Rule active · {top.src} blocked
                          </div>
                        : <button className="btn-act" onClick={()=>setMitigated(m=>({...m,[top.src]:true}))}
                            style={{width:"100%",padding:"12px",borderRadius:8,border:"1px solid #00f5c440",
                              background:"#00f5c415",color:"#00f5c4",fontSize:12,fontWeight:700,letterSpacing:0.5}}>
                            🚀 Deploy Mitigation
                          </button>
                      }
                    </>
                  );
                })()}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════
            PAGE: THREAT DICTIONARY
        ══════════════════════════════════════════════════════ */}
        {page==="dictionary" && (
          <div>
            <div style={{marginBottom:24}}>
              <h1 style={{fontSize:24,fontWeight:800,color:"#e2f0f8",letterSpacing:-0.8,marginBottom:3}}>Threat Dictionary</h1>
              <div style={{fontSize:11,color:C.dim,fontFamily:"JetBrains Mono,monospace"}}>{THREATS.length} indexed attack vectors · {CATS.length-1} categories · σ detection tags</div>
            </div>

            {/* Category filter */}
            <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:20}}>
              {CATS.map(c=>{
                const sel = threatCat===c;
                return (
                  <div key={c} onClick={()=>setThreatCat(c)}
                    style={{padding:"5px 14px",borderRadius:20,cursor:"pointer",
                      fontSize:11,fontWeight:600,
                      border:`1px solid ${sel?C.acc+"60":C.border}`,
                      background:sel?`${C.acc}18`:"transparent",
                      color:sel?C.acc:C.dim,transition:"all 0.15s"}}>
                    {c}
                  </div>
                );
              })}
              <div style={{marginLeft:"auto",fontSize:10,color:C.dim,fontFamily:"JetBrains Mono,monospace",alignSelf:"center"}}>
                {filteredThreats.length} vectors
              </div>
            </div>

            {/* Threat grid */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:9,marginBottom:22}}>
              {filteredThreats.map(t=>{
                const sel = activeThreat?.n===t.n;
                return (
                  <div key={t.n} className="threat-tile" style={{"--tc":C.acc,
                    background:sel?"#0c1a1e":C.card,
                    border:`1px solid ${sel?C.acc+"50":C.border}`,
                    borderRadius:10,padding:"13px 15px"}}
                    onClick={()=>setActiveThreat(sel?null:t)}>
                    <div style={{fontSize:20,marginBottom:8}}>{t.icon}</div>
                    <div style={{fontSize:11,fontWeight:700,color:"#e2f0f8",marginBottom:3,lineHeight:1.2}}>{t.n}</div>
                    <div style={{fontSize:8,color:C.dim,marginBottom:6}}>{t.cat}</div>
                    <div style={{fontSize:8,color:C.acc,fontFamily:"JetBrains Mono,monospace",letterSpacing:0.3}}>{t.sigma}</div>
                  </div>
                );
              })}
            </div>

            {/* Detail panel */}
            {activeThreat ? (
              <div style={{...card({borderColor:`${C.acc}35`,animation:"fadeIn 0.25s ease"})}}>
                <div style={{display:"flex",alignItems:"center",gap:18,marginBottom:20,paddingBottom:18,borderBottom:`1px solid ${C.border}`}}>
                  <div style={{fontSize:42}}>{activeThreat.icon}</div>
                  <div style={{flex:1}}>
                    <div style={{fontSize:20,fontWeight:800,color:"#e2f0f8",marginBottom:8}}>{activeThreat.n}</div>
                    <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                      {tag(activeThreat.cat, C.acc)}
                      {tag(activeThreat.cve, "#ff4560")}
                      {tag(activeThreat.sigma, "#f5c400")}
                    </div>
                  </div>
                  <button className="btn-act" onClick={()=>setActiveThreat(null)}
                    style={{background:"transparent",border:"none",color:C.dim,fontSize:20,cursor:"pointer"}}>✕</button>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:24}}>
                  <div>
                    <div style={{fontSize:8,color:C.dim,letterSpacing:2,textTransform:"uppercase",marginBottom:10}}>Behavioral Description</div>
                    <p style={{fontSize:12,color:C.text,lineHeight:1.85}}>{activeThreat.d}</p>
                  </div>
                  <div>
                    <div style={{fontSize:8,color:C.dim,letterSpacing:2,textTransform:"uppercase",marginBottom:10}}>Heuristic Trigger</div>
                    <div style={{background:"#030810",borderRadius:8,padding:"14px 16px",border:`1px solid ${C.border}`,marginBottom:10}}>
                      <div style={{fontSize:9,color:C.dim,letterSpacing:1.5,marginBottom:6}}>DETECTION RULE</div>
                      <div style={{fontSize:14,fontWeight:800,color:"#f5c400",fontFamily:"JetBrains Mono,monospace"}}>{activeThreat.sigma}</div>
                    </div>
                    <p style={{fontSize:10,color:C.dim,lineHeight:1.7}}>Rolling 60-second window · z-score vs established network baseline σ</p>
                  </div>
                  <div>
                    <div style={{fontSize:8,color:C.dim,letterSpacing:2,textTransform:"uppercase",marginBottom:10}}>Recommended Mitigation</div>
                    <div style={{background:"#030810",borderRadius:8,padding:"14px 16px",border:`1px solid ${C.acc}28`}}>
                      <div style={{fontSize:9,color:C.acc,letterSpacing:1.5,marginBottom:6}}>ACTION</div>
                      <div style={{fontSize:12,color:C.acc,fontFamily:"JetBrains Mono,monospace",lineHeight:1.7,fontWeight:600}}>{activeThreat.m}</div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div style={{textAlign:"center",color:C.dim,fontSize:12,paddingTop:8,fontFamily:"JetBrains Mono,monospace"}}>
                ↑ click a threat tile to load its intelligence report
              </div>
            )}
          </div>
        )}

      </main>
    </div>
  );
}
