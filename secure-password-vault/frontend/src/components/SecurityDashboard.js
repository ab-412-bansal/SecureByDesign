import React, { useEffect, useState, useCallback } from "react";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const TOKEN_KEY   = "vw_access_token";
const EMAIL_KEY   = "vw_email";
const ENCKEY_KEY  = "vw_enc_key_b64";

// ── Session ───────────────────────────────────────────────
const saveSession = (token, email, encKeyB64) => {
  localStorage.setItem(TOKEN_KEY,  token);
  localStorage.setItem(EMAIL_KEY,  email);
  localStorage.setItem(ENCKEY_KEY, encKeyB64);
};
const loadSession = () => ({
  token:     localStorage.getItem(TOKEN_KEY),
  email:     localStorage.getItem(EMAIL_KEY),
  encKeyB64: localStorage.getItem(ENCKEY_KEY),
});
const clearSession = () => [TOKEN_KEY, EMAIL_KEY, ENCKEY_KEY].forEach(k => localStorage.removeItem(k));

// ── Bitwarden crypto (correct implementation) ─────────────
// Reference: https://bitwarden.com/help/bitwarden-security-white-paper/
// The vault symmetric key is stored encrypted in /api/sync under profile.key
// We derive the master key via PBKDF2, then use it to decrypt the profile.key
// which gives us the actual 64-byte symmetric key (32 enc + 32 mac)

// ── Correct Bitwarden crypto ──────────────────────────────
// Reference: https://bitwarden.com/help/bitwarden-security-white-paper/
//
// Flow:
//   password + email  →  PBKDF2(600k)  →  masterKey (32 bytes)
//   masterKey         →  HKDF-expand   →  stretchedKey (64 bytes: 32 enc + 32 mac)
//   stretchedKey[0:32] used as AES-CBC key to decrypt profile.key
//   profile.key decrypts to symKey (64 bytes: 32 enc + 32 mac)
//   symKey[0:32] used as AES-CBC key to decrypt all vault items

async function pbkdf2(password, salt, iterations, keyLen) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    typeof password === "string" ? enc.encode(password) : password,
    "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: typeof salt === "string" ? enc.encode(salt) : salt,
      iterations,
      hash: "SHA-256"
    },
    keyMaterial, keyLen * 8
  );
  return new Uint8Array(bits);
}

async function hkdfExpand(keyBytes, info, length) {
  // HKDF-Expand using HMAC-SHA256
  // Used to stretch master key into enc + mac keys
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const enc = new TextEncoder();
  const infoBytes = enc.encode(info);
  // T(1) = HMAC(key, "" || info || 0x01)
  const data = new Uint8Array(infoBytes.length + 1);
  data.set(infoBytes);
  data[infoBytes.length] = 1;
  const result = await crypto.subtle.sign("HMAC", key, data);
  return new Uint8Array(result).slice(0, length);
}

// Decrypt AES-CBC cipher string "2.<iv_b64>|<ct_b64>|<mac_b64>"
async function decryptString(cipherString, encKeyBytes) {
  if (!cipherString || !cipherString.startsWith("2.")) return null;
  try {
    const parts = cipherString.slice(2).split("|");
    if (parts.length < 2) return null;
    const iv  = Uint8Array.from(atob(parts[0]), c => c.charCodeAt(0));
    const ct  = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
    // Import raw key bytes each time (avoids extractable issues)
    const key = await crypto.subtle.importKey("raw", encKeyBytes, "AES-CBC", false, ["decrypt"]);
    const dec = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ct);
    return new TextDecoder().decode(dec);
  } catch {
    return null;
  }
}

async function deriveEncryptionKeys(password, email, profileKeyStr) {
  // Step 1: Master key via PBKDF2
  const masterKey = await pbkdf2(password, email.toLowerCase().trim(), 600000, 32);
  console.log("[DEBUG] masterKey derived, length:", masterKey.length);

  // Step 2: Stretch using HKDF-Expand into 32-byte enc key + 32-byte mac key
  const stretchedEncKey = await hkdfExpand(masterKey, "enc", 32);
  const stretchedMacKey = await hkdfExpand(masterKey, "mac", 32);
  console.log("[DEBUG] stretchedEncKey length:", stretchedEncKey.length);

  // Step 3: Decrypt profile.key using stretchedEncKey
  // profile.key format: "2.<iv>|<ct>|<mac>"
  // ct decrypts to 64-byte symmetric key
  let symEncKey = stretchedEncKey; // fallback

  if (profileKeyStr && profileKeyStr.startsWith("2.")) {
    try {
      const parts = profileKeyStr.slice(2).split("|");
      const iv = Uint8Array.from(atob(parts[0]), c => c.charCodeAt(0));
      const ct = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
      const aesKey = await crypto.subtle.importKey("raw", stretchedEncKey, "AES-CBC", false, ["decrypt"]);
      const decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, ct);
      const symKeyBytes = new Uint8Array(decrypted);
      console.log("[DEBUG] profile.key decrypted! symKey length:", symKeyBytes.length);
      // First 32 bytes = enc key, last 32 = mac key
      symEncKey = symKeyBytes.slice(0, 32);
      console.log("[DEBUG] symEncKey (first 8 bytes):", Array.from(symEncKey.slice(0,8)));
    } catch(e) {
      console.error("[DEBUG] profile.key decryption failed:", e.message, "— using stretched key");
    }
  }

  return { symEncKey };
}

// ── UI helpers ────────────────────────────────────────────
const RISK_COLORS = { critical:"#FF2244", high:"#FF8042", medium:"#FFBB28", low:"#00C49F" };

function RiskBadge({ level }) {
  const color = RISK_COLORS[level] || "#aaa";
  return (
    <span style={{
      padding:"2px 10px", borderRadius:20, fontSize:11, fontWeight:700,
      background:color+"22", color, border:`1px solid ${color}44`,
      textTransform:"uppercase", letterSpacing:1
    }}>{level}</span>
  );
}

function ScoreRing({ score, size=80 }) {
  const color = score>=80?"#00C49F":score>=50?"#FFBB28":score>=30?"#FF8042":"#FF2244";
  const r = (size/2)-8, circ=2*Math.PI*r, dash=(score/100)*circ;
  return (
    <svg width={size} height={size} style={{ transform:"rotate(-90deg)" }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1a1a2e" strokeWidth={8}/>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={8}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"/>
      <text x="50%" y="50%" textAnchor="middle" dy="0.35em"
        style={{ transform:"rotate(90deg)", transformOrigin:"center", fill:color, fontSize:size*0.22, fontWeight:800 }}>
        {score}
      </text>
    </svg>
  );
}

function StatCard({ label, value, color="#fff" }) {
  return (
    <div style={{ ...s.card, textAlign:"center", minWidth:100 }}>
      <div style={{ fontSize:32, fontWeight:800, color }}>{value}</div>
      <div style={{ color:"#555", fontSize:12, marginTop:4 }}>{label}</div>
    </div>
  );
}

function LoginForm({ onLogin, error, loading }) {
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");
  return (
    <div style={s.page}>
      <div style={s.loginBox}>
        <div style={{ fontSize:48, textAlign:"center" }}>🔐</div>
        <h2 style={s.loginTitle}>SecureVault Dashboard</h2>
        <p style={s.loginSub}>Login once — session remembered in browser.</p>
        <input style={s.input} type="email" placeholder="Vaultwarden Email"
          value={email} onChange={e => setEmail(e.target.value)}/>
        <input style={s.input} type="password" placeholder="Master Password"
          value={password} onChange={e => setPassword(e.target.value)}
          onKeyDown={e => e.key==="Enter" && onLogin(email,password)}/>
        <button style={{ ...s.btn, opacity:loading?0.7:1 }}
          onClick={() => onLogin(email,password)} disabled={loading}>
          {loading?"Logging in…":"Login & Analyse Vault"}
        </button>
        {error && <p style={s.errText}>{error}</p>}
      </div>
    </div>
  );
}

function ItemReportRow({ item, index }) {
  const [open, setOpen] = useState(false);
  if (item.skipped) return (
    <tr style={index%2===0?s.trEven:{}}>
      <td style={s.td}>{index+1}</td>
      <td style={s.td}>{item.name}</td>
      <td style={s.td}><span style={s.typeBadge}>{item.type}</span></td>
      <td style={s.td} colSpan={4}><span style={{ color:"#444",fontSize:12 }}>Not a login item</span></td>
    </tr>
  );
  const color = RISK_COLORS[item.risk_level]||"#aaa";
  return (
    <>
      <tr style={{ ...(index%2===0?s.trEven:{}), cursor:"pointer" }} onClick={()=>setOpen(o=>!o)}>
        <td style={s.td}>{index+1}</td>
        <td style={s.td}>
          <span style={{ color:"#fff" }}>{item.name}</span>
          {item.username&&<div style={{ color:"#444",fontSize:11 }}>{item.username}</div>}
        </td>
        <td style={s.td}><span style={s.typeBadge}>{item.type}</span></td>
        <td style={s.td}><RiskBadge level={item.risk_level}/></td>
        <td style={s.td}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ flex:1, background:"#1a1a2e", borderRadius:4, height:6, minWidth:80 }}>
              <div style={{ width:`${item.strength_score}%`, background:color, height:"100%", borderRadius:4 }}/>
            </div>
            <span style={{ color, fontSize:12, fontWeight:700, minWidth:28 }}>{item.strength_score}</span>
          </div>
        </td>
        <td style={s.td}>
          <span style={{ color:["instant","seconds"].includes(item.estimated_crack_time)?"#FF2244":"#aaa", fontSize:12 }}>
            {item.estimated_crack_time}
          </span>
        </td>
        <td style={s.td}>
          {item.is_reused&&<span style={s.issuePill}>♻️ Reused</span>}
          {item.is_breached&&<span style={{ ...s.issuePill, background:"#FF224422", color:"#FF2244", borderColor:"#FF224444" }}>💀 Breached</span>}
          <span style={{ color:"#444", fontSize:11, marginLeft:4 }}>{open?"▲":"▼"}</span>
        </td>
      </tr>
      {open&&(
        <tr>
          <td colSpan={7} style={{ ...s.td, background:"#0a0a18", padding:"16px 24px" }}>
            <div style={s.detailGrid}>
              {[["Entropy",`${item.entropy} bits`],["Length",`${item.length} chars`],
                ["Uppercase",item.has_upper?"✓":"✗"],["Numbers",item.has_digit?"✓":"✗"],
                ["Symbols",item.has_symbol?"✓":"✗"]
              ].map(([label,val])=>(
                <div key={label} style={s.detailCard}>
                  <div style={{ color:"#fff", fontWeight:700, fontSize:18 }}>{val}</div>
                  <div style={{ color:"#444", fontSize:11, marginTop:4 }}>{label}</div>
                </div>
              ))}
            </div>
            {item.issues?.length>0?(
              <div style={{ marginTop:12 }}>
                <div style={{ color:"#555", fontSize:12, marginBottom:6 }}>Issues found:</div>
                <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
                  {item.issues.map((iss,i)=><span key={i} style={s.issuePill}>⚠️ {iss}</span>)}
                </div>
              </div>
            ):(
              <div style={{ color:"#00C49F", fontSize:13, marginTop:8 }}>✅ No issues — strong password!</div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// ── Main Dashboard ────────────────────────────────────────
export default function SecurityDashboard() {
  const [token,        setToken]        = useState(null);
  const [email,        setEmail]        = useState(null);
  const [encKey,       setEncKey]       = useState(null);
  const [report,       setReport]       = useState(null);
  const [loginError,   setLoginError]   = useState(null);
  const [loginLoading, setLoginLoading] = useState(false);
  const [fetching,     setFetching]     = useState(false);
  const [lastUpdated,  setLastUpdated]  = useState(null);
  const [activeTab,    setActiveTab]    = useState("overview");
  const [sortBy,       setSortBy]       = useState("risk");
  const [filterRisk,   setFilterRisk]   = useState("all");

  // Restore session on mount
  useEffect(() => {
    // Restore session on mount — re-import raw key bytes
    const { token:t, email:e, encKeyB64 } = loadSession();
    if (t && e && encKeyB64) {
      setToken(t); setEmail(e);
      // encKeyB64 stores raw 32-byte AES key as base64
      const raw = Uint8Array.from(atob(encKeyB64), c => c.charCodeAt(0));
      // Store as raw bytes in state (not CryptoKey — we import fresh each decrypt)
      setEncKey(raw);    }
  }, []);

  // Fetch + decrypt vault
  const fetchAndAnalyse = useCallback(async (t, ek) => {
    if (!t || !ek) return;
    setFetching(true);
    try {
      const rawRes = await fetch("/vw-api/ciphers", {
        headers: { Authorization: `Bearer ${t}` }
      });
      if (rawRes.status === 401) {
        clearSession(); setToken(null); setReport(null);
        setLoginError("Session expired. Please login again."); return;
      }
      const rawBody = await rawRes.json();
      const ciphers = rawBody.data || rawBody.Data || [];

      console.log("[DEBUG] ciphers count:", ciphers.length);
      if (ciphers[0]) console.log("[DEBUG] first cipher type:", ciphers[0].type, "name:", ciphers[0].name?.slice(0,20));

      const typeMap = { 1:"Login", 2:"Secure Note", 3:"Card", 4:"Identity" };

      // Decrypt each item
      const decrypted = await Promise.all(ciphers.map(async (c) => {
        const type = typeMap[c.type] || "Unknown";
        const name = (await decryptString(c.name, ek)) || `${type} Item`;

        console.log("[DEBUG] item", c.id, "type:", type, "name decrypted:", name);

        if (c.type !== 1) {
          return { id:c.id, name, type, password:null, username:null };
        }
        // c.data has the encrypted fields from sync endpoint
        const pwField = c.data?.password || c.login?.password || null;
        const unField = c.data?.username || c.login?.username || null;
        const password = await decryptString(pwField, ek);
        const username = await decryptString(unField, ek);

        console.log("[DEBUG] pwField:", pwField?.slice(0,25), "decrypted:", password ? "OK len="+password.length : "FAILED");

        return { id:c.id, name, type, password, username };
      }));

      // Send to backend for analysis
      const analysisRes = await fetch("/api/analyze-vault", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({ items: decrypted })
      });
      const analysis = await analysisRes.json();
      console.log("[DEBUG] analysis result:", analysis);
      setReport(analysis);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("fetchAndAnalyse error:", err);
    } finally {
      setFetching(false);
    }
  }, []);

  useEffect(() => {
    if (!token || !encKey) return;
    fetchAndAnalyse(token, encKey);
    const id = setInterval(()=>fetchAndAnalyse(token,encKey), 30000);
    return ()=>clearInterval(id);
  }, [token, encKey, fetchAndAnalyse]);

  // Login
  const handleLogin = async (emailVal, passwordVal) => {
    if (!emailVal||!passwordVal) { setLoginError("Enter email and password."); return; }
    setLoginLoading(true); setLoginError(null);
    try {
      // Step 1: Get access token
      const res = await fetch("/api/vault/login", {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ email:emailVal, password:passwordVal })
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail||"Login failed");
      const accessToken = json.access_token;

      // Step 2: Fetch /sync to get the encrypted profile key
      const syncRes = await fetch("/vw-api/sync?excludeDomains=true", {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const syncData = await syncRes.json();
      const profileKey = syncData?.Profile?.Key || syncData?.profile?.key;
      console.log("[DEBUG] profileKey:", profileKey?.slice(0,30));

      // Step 3: Derive encryption keys using master password + profile key
      const { symEncKey } = await deriveEncryptionKeys(passwordVal, emailVal, profileKey);
      // symEncKey is raw Uint8Array — store as base64 in localStorage
      const encKeyB64 = btoa(String.fromCharCode(...symEncKey));

      saveSession(accessToken, emailVal, encKeyB64);
      setToken(accessToken); setEmail(emailVal);
      setEncKey(symEncKey); // store raw bytes in state
    } catch (err) {
      console.error("Login error:", err);
      setLoginError(err.message);
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = () => {
    clearSession(); setToken(null); setEmail(null); setEncKey(null); setReport(null);
  };

  // Guards
  if (!token || !encKey) return <LoginForm onLogin={handleLogin} error={loginError} loading={loginLoading}/>;
  if (!report) return (
    <div style={s.page}>
      <div style={{ color:"#aaa", textAlign:"center" }}>
        <div style={{ fontSize:40, marginBottom:16 }}>🔍</div>
        Decrypting and analysing vault…
      </div>
    </div>
  );

  const loginItems = (report.items||[]).filter(i=>!i.skipped);
  const filtered = loginItems
    .filter(i=>filterRisk==="all"||i.risk_level===filterRisk)
    .sort((a,b)=>{
      if (sortBy==="risk") { const o={critical:0,high:1,medium:2,low:3}; return (o[a.risk_level]??4)-(o[b.risk_level]??4); }
      if (sortBy==="score") return a.strength_score-b.strength_score;
      if (sortBy==="name")  return a.name.localeCompare(b.name);
      return 0;
    });

  const PIE_COLORS = ["#FF2244","#FF8042","#FFBB28","#00C49F"];
  const pieData = [
    { name:"Critical", value:loginItems.filter(i=>i.risk_level==="critical").length },
    { name:"High",     value:loginItems.filter(i=>i.risk_level==="high").length },
    { name:"Medium",   value:loginItems.filter(i=>i.risk_level==="medium").length },
    { name:"Low",      value:loginItems.filter(i=>i.risk_level==="low").length },
  ].filter(d=>d.value>0);

  const scoreColor = report.vault_score>=80?"#00C49F":report.vault_score>=50?"#FFBB28":report.vault_score>=30?"#FF8042":"#FF2244";

  return (
    <div style={s.root}>
      {/* Sidebar */}
      <div style={s.sidebar}>
        <div style={{ textAlign:"center", fontSize:36, marginBottom:4 }}>🔐</div>
        <div style={s.sideTitle}>SecureVault</div>
        <nav style={s.nav}>
          {[["overview","📊","Overview"],["report","📋","Security Report"],["tools","🛠️","Tools"]].map(([tab,icon,label])=>(
            <button key={tab} style={{ ...s.navBtn, ...(activeTab===tab?s.navActive:{}) }}
              onClick={()=>setActiveTab(tab)}>{icon} {label}</button>
          ))}
        </nav>
        <div style={s.sideBottom}>
          <div style={s.emailChip}>👤 {email}</div>
          <button style={s.logoutBtn} onClick={handleLogout}>Logout</button>
          <a href="https://localhost:9443" target="_blank" rel="noreferrer" style={s.vaultLink}>Open Vaultwarden ↗</a>
        </div>
      </div>

      {/* Main */}
      <div style={s.main}>
        <div style={s.topbar}>
          <h1 style={s.pageTitle}>
            {activeTab==="overview"?"Security Overview":activeTab==="report"?"Security Report":"Tools"}
          </h1>
          <div style={s.topRight}>
            {lastUpdated&&<span style={s.updated}>Updated {lastUpdated.toLocaleTimeString()} · auto-refreshes every 30s</span>}
            <button style={s.refreshBtn} onClick={()=>fetchAndAnalyse(token,encKey)} disabled={fetching}>
              {fetching?"…":"🔄 Refresh"}
            </button>
          </div>
        </div>

        {/* OVERVIEW */}
        {activeTab==="overview"&&(
          <>
            <div style={s.cardRow}>
              <div style={{ ...s.card, display:"flex", alignItems:"center", gap:20, minWidth:200 }}>
                <ScoreRing score={report.vault_score} size={90}/>
                <div>
                  <div style={{ color:scoreColor, fontSize:22, fontWeight:800 }}>
                    {report.vault_score>=80?"Excellent":report.vault_score>=60?"Good":report.vault_score>=40?"Fair":"Poor"}
                  </div>
                  <div style={{ color:"#444", fontSize:12 }}>Vault Security Score</div>
                </div>
              </div>
              <StatCard label="Total Items"   value={report.total}          color="#4f46e5"/>
              <StatCard label="Login Items"   value={report.total_logins}   color="#00C49F"/>
              <StatCard label="Weak/Critical" value={report.weak_count}     color="#FF8042"/>
              <StatCard label="Breached"      value={report.breached_count} color="#FF2244"/>
              <StatCard label="Reused"        value={report.reused_count}   color="#FFBB28"/>
            </div>
            {pieData.length>0&&(
              <div style={s.card}>
                <h3 style={s.cardTitle}>Risk Distribution</h3>
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90}
                      label={({name,value})=>`${name}: ${value}`}>
                      {pieData.map((_,i)=><Cell key={i} fill={PIE_COLORS[i]}/>)}
                    </Pie>
                    <Tooltip/><Legend/>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}
            {report.total_logins===0&&(
              <div style={s.empty}>
                <div style={{ fontSize:40 }}>📭</div>
                <p>Decryption may have failed or no login items exist.</p>
                <p style={{ fontSize:13, color:"#444" }}>Check browser console (F12) for [DEBUG] logs.</p>
                <a href="https://localhost:9443" target="_blank" rel="noreferrer" style={s.link}>Open Vaultwarden ↗</a>
              </div>
            )}
          </>
        )}

        {/* SECURITY REPORT */}
        {activeTab==="report"&&(
          <div style={s.card}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", flexWrap:"wrap", gap:12, marginBottom:20 }}>
              <h3 style={{ ...s.cardTitle, margin:0 }}>Per-Item Report ({loginItems.length} login items)</h3>
              <div style={{ display:"flex", gap:10 }}>
                <select style={s.select} value={filterRisk} onChange={e=>setFilterRisk(e.target.value)}>
                  <option value="all">All Risk Levels</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select style={s.select} value={sortBy} onChange={e=>setSortBy(e.target.value)}>
                  <option value="risk">Sort: Risk</option>
                  <option value="score">Sort: Score</option>
                  <option value="name">Sort: Name</option>
                </select>
              </div>
            </div>
            <div style={{ overflowX:"auto" }}>
              <table style={s.table}>
                <thead>
                  <tr>{["#","Name / Username","Type","Risk","Strength","Crack Time","Flags"].map(h=><th key={h} style={s.th}>{h}</th>)}</tr>
                </thead>
                <tbody>
                  {filtered.map((item,i)=><ItemReportRow key={item.id} item={item} index={i}/>)}
                </tbody>
              </table>
            </div>
            {filtered.length===0&&<p style={{ color:"#444", marginTop:16 }}>No items match this filter.</p>}
            <div style={{ marginTop:12, color:"#444", fontSize:12 }}>💡 Click any row to expand details.</div>
          </div>
        )}

        {/* TOOLS */}
        {activeTab==="tools"&&<ToolsPanel/>}
      </div>
    </div>
  );
}

// ── Tools Panel ───────────────────────────────────────────
function ToolsPanel() {
  const [pw,setPw]=useState("");
  const [analysis,setAnalysis]=useState(null);
  const [genResult,setGenResult]=useState(null);
  const [genLen,setGenLen]=useState(16);
  const [loading,setLoading]=useState(false);

  const analyse=async()=>{
    if(!pw)return;setLoading(true);
    try{const res=await fetch("/api/analyze-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:pw})});setAnalysis(await res.json());}finally{setLoading(false);}
  };
  const generate=async()=>{
    setLoading(true);
    try{const res=await fetch("/api/generate-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({length:genLen,use_symbols:true,use_numbers:true,use_upper:true,use_lower:true})});setGenResult(await res.json());}finally{setLoading(false);}
  };
  const rColor=analysis?(RISK_COLORS[analysis.risk_level]||"#fff"):"#fff";

  return(
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={s.card}>
        <h3 style={s.cardTitle}>🔍 Password Strength Analyser</h3>
        <div style={{ display:"flex", gap:10, marginBottom:16 }}>
          <input style={{ ...s.input, flex:1 }} type="text" placeholder="Enter any password to analyse…"
            value={pw} onChange={e=>{setPw(e.target.value);setAnalysis(null);}}/>
          <button style={s.btn} onClick={analyse} disabled={loading||!pw}>Analyse</button>
        </div>
        {analysis&&(
          <>
            <div style={s.resultGrid}>
              {[["Risk",<RiskBadge level={analysis.risk_level}/>],["Score",<span style={{color:rColor,fontWeight:700}}>{analysis.strength_score}/100</span>],
                ["Entropy",`${analysis.entropy} bits`],["Crack Time",analysis.estimated_crack_time],
                ["Length",`${analysis.length} chars`],["Uppercase",analysis.has_upper?"✓":"✗"],
                ["Numbers",analysis.has_digit?"✓":"✗"],["Symbols",analysis.has_symbol?"✓":"✗"]
              ].map(([label,val])=>(
                <div key={label} style={s.resultCard}>
                  <div style={{ color:"#fff", fontWeight:600, fontSize:15 }}>{val}</div>
                  <div style={{ color:"#444", fontSize:11, marginTop:4 }}>{label}</div>
                </div>
              ))}
            </div>
            {analysis.issues?.length>0&&(
              <div style={{ marginTop:14 }}>
                <div style={{ color:"#555", fontSize:12, marginBottom:6 }}>Issues:</div>
                <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
                  {analysis.issues.map((iss,i)=><span key={i} style={s.issuePill}>⚠️ {iss}</span>)}
                </div>
              </div>
            )}
          </>
        )}
      </div>
      <div style={s.card}>
        <h3 style={s.cardTitle}>⚡ Secure Password Generator</h3>
        <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:16 }}>
          <label style={{ color:"#aaa" }}>Length:</label>
          <input style={{ ...s.input, width:70 }} type="number" min={8} max={64} value={genLen} onChange={e=>setGenLen(Number(e.target.value))}/>
          <button style={s.btn} onClick={generate} disabled={loading}>Generate</button>
        </div>
        {genResult&&(
          <div style={{ background:"#0a0a14", borderRadius:10, padding:16 }}>
            <code style={{ fontSize:16, color:"#00C49F", wordBreak:"break-all" }}>{genResult.password}</code>
            <div style={{ color:"#555", fontSize:12, marginTop:8 }}>Score: {genResult.strength_score}/100 · Entropy: {genResult.entropy} bits</div>
            <button style={{ ...s.btn, marginTop:10, padding:"6px 14px", background:"#1a1a2e", fontSize:13 }}
              onClick={()=>navigator.clipboard.writeText(genResult.password)}>📋 Copy</button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────
const s = {
  page:       { minHeight:"100vh", background:"#07070f", display:"flex", alignItems:"center", justifyContent:"center" },
  loginBox:   { background:"#12121f", borderRadius:16, padding:40, width:380, boxShadow:"0 8px 32px rgba(0,0,0,.5)", display:"flex", flexDirection:"column", gap:14 },
  loginTitle: { color:"#fff", fontSize:22, margin:0, textAlign:"center" },
  loginSub:   { color:"#555", fontSize:13, margin:0, textAlign:"center" },
  input:      { padding:"10px 14px", borderRadius:8, border:"1px solid #1a1a2e", background:"#0a0a14", color:"#fff", fontSize:14, outline:"none" },
  btn:        { padding:"10px 20px", borderRadius:8, border:"none", background:"#4f46e5", color:"#fff", fontSize:14, cursor:"pointer", fontWeight:600 },
  errText:    { color:"#FF4444", fontSize:13, margin:0, textAlign:"center" },
  root:       { display:"flex", minHeight:"100vh", background:"#07070f", color:"#fff" },
  sidebar:    { width:220, background:"#0e0e1a", display:"flex", flexDirection:"column", padding:"24px 16px", gap:8, borderRight:"1px solid #1a1a2e" },
  sideTitle:  { color:"#fff", fontWeight:700, fontSize:16, textAlign:"center", marginBottom:16 },
  nav:        { display:"flex", flexDirection:"column", gap:6, flex:1 },
  navBtn:     { padding:"10px 14px", borderRadius:8, border:"none", background:"transparent", color:"#666", cursor:"pointer", textAlign:"left", fontSize:14 },
  navActive:  { background:"#1a1a3a", color:"#fff" },
  sideBottom: { display:"flex", flexDirection:"column", gap:8 },
  emailChip:  { color:"#444", fontSize:12, textAlign:"center", wordBreak:"break-all" },
  logoutBtn:  { padding:8, borderRadius:8, border:"1px solid #1a1a2e", background:"transparent", color:"#555", cursor:"pointer", fontSize:13 },
  vaultLink:  { color:"#4f46e5", fontSize:12, textAlign:"center", textDecoration:"none" },
  main:       { flex:1, padding:32, overflowY:"auto" },
  topbar:     { display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:24, flexWrap:"wrap", gap:12 },
  pageTitle:  { margin:0, fontSize:22, fontWeight:700 },
  topRight:   { display:"flex", alignItems:"center", gap:12 },
  updated:    { color:"#333", fontSize:12 },
  refreshBtn: { padding:"6px 14px", borderRadius:8, border:"1px solid #4f46e5", background:"transparent", color:"#4f46e5", cursor:"pointer", fontSize:13 },
  cardRow:    { display:"flex", gap:16, flexWrap:"wrap", marginBottom:20 },
  card:       { background:"#12121f", borderRadius:12, padding:20, marginBottom:16 },
  cardTitle:  { margin:"0 0 16px", fontSize:16, fontWeight:600, color:"#fff" },
  empty:      { background:"#12121f", borderRadius:12, padding:40, textAlign:"center", color:"#555" },
  link:       { color:"#4f46e5", textDecoration:"none" },
  table:      { width:"100%", borderCollapse:"collapse" },
  th:         { textAlign:"left", padding:"10px 14px", color:"#444", fontSize:12, borderBottom:"1px solid #1a1a2e", whiteSpace:"nowrap" },
  td:         { padding:"12px 14px", fontSize:13, color:"#aaa", borderBottom:"1px solid #0f0f18" },
  trEven:     { background:"#0e0e1a" },
  typeBadge:  { padding:"2px 8px", borderRadius:20, fontSize:11, background:"#1a1a3a", color:"#4f46e5" },
  issuePill:  { padding:"2px 8px", borderRadius:20, fontSize:11, background:"#FF804222", color:"#FF8042", border:"1px solid #FF804244" },
  detailGrid: { display:"flex", gap:12, flexWrap:"wrap" },
  detailCard: { background:"#12121f", borderRadius:8, padding:"10px 16px", textAlign:"center" },
  select:     { padding:"6px 10px", borderRadius:8, border:"1px solid #1a1a2e", background:"#0a0a14", color:"#aaa", fontSize:13 },
  resultGrid: { display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10 },
  resultCard: { background:"#0a0a14", borderRadius:8, padding:12, textAlign:"center" },
};