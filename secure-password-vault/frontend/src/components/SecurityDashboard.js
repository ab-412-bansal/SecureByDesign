import React, { useEffect, useState, useCallback } from "react";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const COLORS = ["#4f46e5", "#00C49F", "#FFBB28", "#FF8042", "#FF4444"];
const TOKEN_KEY = "vw_access_token";
const EMAIL_KEY = "vw_email";

function saveSession(token, email) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(EMAIL_KEY, email);
}
function loadSession() {
  return {
    token: localStorage.getItem(TOKEN_KEY),
    email: localStorage.getItem(EMAIL_KEY),
  };
}
function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(EMAIL_KEY);
}

// ── Login Form ────────────────────────────────────────────
function LoginForm({ onLogin, error, loading }) {
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");

  return (
    <div style={s.page}>
      <div style={s.loginBox}>
        <div style={s.logo}>🔐</div>
        <h2 style={s.loginTitle}>Security Dashboard</h2>
        <p style={s.loginSub}>
          Login once with your Vaultwarden credentials.<br />
          Your session will be remembered in this browser.
        </p>
        <input
          style={s.input}
          type="email"
          placeholder="Vaultwarden Email"
          value={email}
          onChange={e => setEmail(e.target.value)}
        />
        <input
          style={s.input}
          type="password"
          placeholder="Master Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          onKeyDown={e => e.key === "Enter" && onLogin(email, password)}
        />
        <button
          style={{ ...s.btn, opacity: loading ? 0.7 : 1 }}
          onClick={() => onLogin(email, password)}
          disabled={loading}
        >
          {loading ? "Logging in…" : "Login & View Vault"}
        </button>
        {error && <p style={s.errorText}>{error}</p>}
        <p style={s.hint}>
          Don't have an account?{" "}
          <a href="https://localhost:9443" target="_blank" rel="noreferrer" style={s.link}>
            Create one in Vaultwarden →
          </a>
        </p>
      </div>
    </div>
  );
}

// ── Stat Card ─────────────────────────────────────────────
function StatCard({ label, value, color = "#fff", sub }) {
  return (
    <div style={{ ...s.statCard, borderColor: color }}>
      <div style={{ ...s.statNum, color }}>{value}</div>
      <div style={s.statLabel}>{label}</div>
      {sub && <div style={s.statSub}>{sub}</div>}
    </div>
  );
}

// ── Main Dashboard ────────────────────────────────────────
export default function SecurityDashboard() {
  const [token, setToken]           = useState(null);
  const [email, setEmail]           = useState(null);
  const [data, setData]             = useState(null);
  const [loginError, setLoginError] = useState(null);
  const [loginLoading, setLoginLoading] = useState(false);
  const [fetching, setFetching]     = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [activeTab, setActiveTab]   = useState("overview");

  // Restore session on mount
  useEffect(() => {
    const { token: t, email: e } = loadSession();
    if (t) { setToken(t); setEmail(e); }
  }, []);

  // Fetch stats
  const fetchStats = useCallback(async (t) => {
    setFetching(true);
    try {
      const res = await fetch("/api/security-score", {
        headers: { Authorization: `Bearer ${t}` }
      });
      if (res.status === 401) {
        clearSession(); setToken(null); setData(null);
        setLoginError("Session expired. Please login again.");
        return;
      }
      const json = await res.json();
      setData(json);
      setLastUpdated(new Date());
    } catch {
      // keep old data on network error
    } finally {
      setFetching(false);
    }
  }, []);

  // Auto-fetch every 15s when logged in
  useEffect(() => {
    if (!token) return;
    fetchStats(token);
    const id = setInterval(() => fetchStats(token), 15000);
    return () => clearInterval(id);
  }, [token, fetchStats]);

  // Login
  const handleLogin = async (emailVal, passwordVal) => {
    if (!emailVal || !passwordVal) {
      setLoginError("Please enter both email and password.");
      return;
    }
    setLoginLoading(true);
    setLoginError(null);
    try {
      const res = await fetch("/api/vault/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailVal, password: passwordVal })
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail || "Login failed");
      saveSession(json.access_token, emailVal);
      setToken(json.access_token);
      setEmail(emailVal);
    } catch (err) {
      setLoginError(err.message);
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = () => {
    clearSession(); setToken(null); setEmail(null); setData(null);
  };

  if (!token) return <LoginForm onLogin={handleLogin} error={loginError} loading={loginLoading} />;
  if (!data)  return <div style={s.loading}>🔍 Loading your vault…</div>;

  // Build pie data from item types
  const typeCounts = {};
  (data.items || []).forEach(item => {
    typeCounts[item.type] = (typeCounts[item.type] || 0) + 1;
  });
  const pieData = Object.entries(typeCounts).map(([name, value]) => ({ name, value }));

  const scoreColor = data.security_score >= 80 ? "#00C49F"
                   : data.security_score >= 50 ? "#FFBB28"
                   : "#FF8042";

  return (
    <div style={s.root}>

      {/* Sidebar */}
      <div style={s.sidebar}>
        <div style={s.sideLogoWrap}><span style={s.sideLogo}>🔐</span></div>
        <div style={s.sideTitle}>SecureVault</div>
        <nav style={s.nav}>
          {["overview", "items", "tools"].map(tab => (
            <button
              key={tab}
              style={{ ...s.navBtn, ...(activeTab === tab ? s.navBtnActive : {}) }}
              onClick={() => setActiveTab(tab)}
            >
              { tab === "overview" ? "📊 Overview"
              : tab === "items"    ? "🗂️ Vault Items"
              :                      "🛠️ Tools" }
            </button>
          ))}
        </nav>
        <div style={s.sideBottom}>
          <div style={s.emailChip}>👤 {email}</div>
          <button style={s.logoutBtn} onClick={handleLogout}>Logout</button>
          <a href="https://localhost:9443" target="_blank" rel="noreferrer" style={s.vaultLink}>
            Open Vaultwarden ↗
          </a>
        </div>
      </div>

      {/* Main */}
      <div style={s.main}>

        {/* Top bar */}
        <div style={s.topbar}>
          <h1 style={s.pageTitle}>
            { activeTab === "overview" ? "Security Overview"
            : activeTab === "items"    ? "Vault Items"
            :                            "Security Tools" }
          </h1>
          <div style={s.topbarRight}>
            {lastUpdated && (
              <span style={s.updated}>
                Updated {lastUpdated.toLocaleTimeString()} · auto-refreshes every 15s
              </span>
            )}
            <button style={s.refreshBtn} onClick={() => fetchStats(token)} disabled={fetching}>
              {fetching ? "…" : "🔄 Refresh"}
            </button>
          </div>
        </div>

        {/* ── OVERVIEW TAB ── */}
        {activeTab === "overview" && (
          <>
            {/* Score + stat cards */}
            <div style={s.cardRow}>
              <div style={{ ...s.scoreCard, borderColor: scoreColor }}>
                <div style={{ ...s.scoreNum, color: scoreColor }}>{data.security_score}</div>
                <div style={s.scoreLabel}>Security Score</div>
              </div>
              <StatCard label="Total Items"  value={data.total_passwords} color="#4f46e5" />
              <StatCard label="Login Items"  value={data.total_logins || 0} color="#00C49F" />
            </div>

            {data.total_passwords === 0 ? (
              <div style={s.empty}>
                <div style={s.emptyIcon}>📭</div>
                <p>Your vault is empty.</p>
                <a href="https://localhost:9443" target="_blank" rel="noreferrer" style={s.link}>
                  ➕ Add passwords in Vaultwarden →
                </a>
                <p style={s.emptyHint}>Then click 🔄 Refresh above.</p>
              </div>
            ) : (
              <>
                {pieData.length > 0 && (
                  <div style={s.chartCard}>
                    <h3 style={s.cardTitle}>Items by Type</h3>
                    <ResponsiveContainer width="100%" height={260}>
                      <PieChart>
                        <Pie data={pieData} dataKey="value" nameKey="name"
                          cx="50%" cy="50%" outerRadius={90}
                          label={({ name, value }) => `${name}: ${value}`}
                        >
                          {pieData.map((_, i) => (
                            <Cell key={i} fill={COLORS[i % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
                <div style={s.infoCard}>
                  <h3 style={s.cardTitle}>ℹ️ About Password Analysis</h3>
                  <p style={s.infoText}>
                    Vaultwarden uses <strong>end-to-end encryption</strong> — passwords are
                    encrypted on your device before being stored. The server (and this dashboard)
                    cannot read the actual password values, only metadata like item names and types.
                    <br /><br />
                    To analyse individual passwords, use the <strong>Tools</strong> tab to check
                    any password manually.
                  </p>
                </div>
              </>
            )}
          </>
        )}

        {/* ── ITEMS TAB ── */}
        {activeTab === "items" && (
          <div style={s.chartCard}>
            <h3 style={s.cardTitle}>All Vault Items ({data.total_passwords})</h3>
            {data.total_passwords === 0 ? (
              <p style={s.infoText}>No items yet. <a href="https://localhost:9443" target="_blank" rel="noreferrer" style={s.link}>Add some in Vaultwarden →</a></p>
            ) : (
              <table style={s.table}>
                <thead>
                  <tr>
                    <th style={s.th}>#</th>
                    <th style={s.th}>Name</th>
                    <th style={s.th}>Type</th>
                  </tr>
                </thead>
                <tbody>
                  {(data.items || []).map((item, i) => (
                    <tr key={i} style={i % 2 === 0 ? s.trEven : s.trOdd}>
                      <td style={s.td}>{i + 1}</td>
                      <td style={s.td}>{item.name}</td>
                      <td style={s.td}>
                        <span style={{
                          ...s.badge,
                          background: item.type === "Login" ? "#1a3a5c"
                                    : item.type === "Card"  ? "#1a3a2c"
                                    : "#2a1a3a"
                        }}>
                          { item.type === "Login"       ? "🔑 Login"
                          : item.type === "Card"        ? "💳 Card"
                          : item.type === "Secure Note" ? "📝 Note"
                          : item.type === "Identity"    ? "👤 Identity"
                          : item.type }
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ── TOOLS TAB ── */}
        {activeTab === "tools" && <ToolsPanel />}

      </div>
    </div>
  );
}

// ── Tools Panel ───────────────────────────────────────────
function ToolsPanel() {
  const [pw, setPw]         = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [genResult, setGenResult] = useState(null);
  const [genLen, setGenLen] = useState(16);
  const [loading, setLoading] = useState(false);

  const analysePassword = async () => {
    if (!pw) return;
    setLoading(true);
    try {
      const res = await fetch("/api/analyze-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw })
      });
      setAnalysis(await res.json());
    } finally { setLoading(false); }
  };

  const generatePassword = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/generate-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ length: genLen, use_symbols: true, use_numbers: true, use_upper: true, use_lower: true })
      });
      setGenResult(await res.json());
    } finally { setLoading(false); }
  };

  const riskColor = analysis
    ? analysis.risk_level === "low"  ? "#00C49F"
    : analysis.risk_level === "medium" ? "#FFBB28"
    : "#FF4444"
    : "#fff";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

      {/* Analyser */}
      <div style={s.chartCard}>
        <h3 style={s.cardTitle}>🔍 Password Strength Analyser</h3>
        <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
          <input
            style={{ ...s.input, flex: 1 }}
            type="text"
            placeholder="Enter any password to analyse…"
            value={pw}
            onChange={e => { setPw(e.target.value); setAnalysis(null); }}
          />
          <button style={s.btn} onClick={analysePassword} disabled={loading || !pw}>
            Analyse
          </button>
        </div>
        {analysis && (
          <div style={s.resultGrid}>
            <div style={s.resultItem}>
              <div style={{ ...s.resultVal, color: riskColor }}>
                {analysis.risk_level.toUpperCase()}
              </div>
              <div style={s.resultKey}>Risk Level</div>
            </div>
            <div style={s.resultItem}>
              <div style={s.resultVal}>{analysis.strength_score}/100</div>
              <div style={s.resultKey}>Strength Score</div>
            </div>
            <div style={s.resultItem}>
              <div style={s.resultVal}>{analysis.entropy}</div>
              <div style={s.resultKey}>Entropy (bits)</div>
            </div>
            <div style={s.resultItem}>
              <div style={{ ...s.resultVal, color: riskColor }}>
                {analysis.estimated_crack_time}
              </div>
              <div style={s.resultKey}>Est. Crack Time</div>
            </div>
          </div>
        )}
      </div>

      {/* Generator */}
      <div style={s.chartCard}>
        <h3 style={s.cardTitle}>⚡ Secure Password Generator</h3>
        <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 16 }}>
          <label style={{ color: "#aaa" }}>Length:</label>
          <input
            style={{ ...s.input, width: 70 }}
            type="number"
            min={8} max={64}
            value={genLen}
            onChange={e => setGenLen(Number(e.target.value))}
          />
          <button style={s.btn} onClick={generatePassword} disabled={loading}>
            Generate
          </button>
        </div>
        {genResult && (
          <div style={s.genResult}>
            <code style={s.genPw}>{genResult.password}</code>
            <div style={s.genMeta}>
              Strength: {genResult.strength_score}/100 · Entropy: {genResult.entropy} bits · Risk: {genResult.risk_level}
            </div>
            <button style={s.copyBtn} onClick={() => navigator.clipboard.writeText(genResult.password)}>
              📋 Copy
            </button>
          </div>
        )}
      </div>

    </div>
  );
}

// ── Styles ────────────────────────────────────────────────
const s = {
  page:        { minHeight: "100vh", background: "#07070f", display: "flex", alignItems: "center", justifyContent: "center" },
  loginBox:    { background: "#12121f", borderRadius: 16, padding: 40, width: 380, boxShadow: "0 8px 32px rgba(0,0,0,0.5)", display: "flex", flexDirection: "column", gap: 14 },
  logo:        { fontSize: 40, textAlign: "center" },
  loginTitle:  { color: "#fff", fontSize: 22, margin: 0, textAlign: "center" },
  loginSub:    { color: "#666", fontSize: 13, margin: 0, textAlign: "center", lineHeight: 1.5 },
  input:       { padding: "10px 14px", borderRadius: 8, border: "1px solid #2a2a3a", background: "#0a0a14", color: "#fff", fontSize: 14, outline: "none" },
  btn:         { padding: "10px 20px", borderRadius: 8, border: "none", background: "#4f46e5", color: "#fff", fontSize: 14, cursor: "pointer", fontWeight: 600 },
  errorText:   { color: "#FF4444", fontSize: 13, margin: 0, textAlign: "center" },
  hint:        { color: "#555", fontSize: 12, margin: 0, textAlign: "center" },
  link:        { color: "#4f46e5", textDecoration: "none" },
  loading:     { color: "#aaa", fontSize: 18, textAlign: "center", marginTop: 100 },
  root:        { display: "flex", minHeight: "100vh", background: "#07070f", color: "#fff" },
  sidebar:     { width: 220, background: "#0e0e1a", display: "flex", flexDirection: "column", padding: "24px 16px", gap: 8, borderRight: "1px solid #1a1a2e" },
  sideLogoWrap:{ textAlign: "center", marginBottom: 4 },
  sideLogo:    { fontSize: 32 },
  sideTitle:   { color: "#fff", fontWeight: 700, fontSize: 16, textAlign: "center", marginBottom: 16 },
  nav:         { display: "flex", flexDirection: "column", gap: 6, flex: 1 },
  navBtn:      { padding: "10px 14px", borderRadius: 8, border: "none", background: "transparent", color: "#888", cursor: "pointer", textAlign: "left", fontSize: 14 },
  navBtnActive:{ background: "#1a1a3a", color: "#fff" },
  sideBottom:  { display: "flex", flexDirection: "column", gap: 8 },
  emailChip:   { color: "#555", fontSize: 12, textAlign: "center", wordBreak: "break-all" },
  logoutBtn:   { padding: "8px", borderRadius: 8, border: "1px solid #2a2a3a", background: "transparent", color: "#666", cursor: "pointer", fontSize: 13 },
  vaultLink:   { color: "#4f46e5", fontSize: 12, textAlign: "center", textDecoration: "none" },
  main:        { flex: 1, padding: 32, overflowY: "auto" },
  topbar:      { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28, flexWrap: "wrap", gap: 12 },
  pageTitle:   { margin: 0, fontSize: 22, fontWeight: 700 },
  topbarRight: { display: "flex", alignItems: "center", gap: 12 },
  updated:     { color: "#444", fontSize: 12 },
  refreshBtn:  { padding: "6px 14px", borderRadius: 8, border: "1px solid #4f46e5", background: "transparent", color: "#4f46e5", cursor: "pointer", fontSize: 13 },
  cardRow:     { display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 24 },
  scoreCard:   { background: "#12121f", borderRadius: 12, border: "3px solid", padding: "20px 28px", textAlign: "center", minWidth: 110 },
  scoreNum:    { fontSize: 48, fontWeight: 800 },
  scoreLabel:  { color: "#666", fontSize: 12, marginTop: 4 },
  statCard:    { background: "#12121f", borderRadius: 12, border: "2px solid #1a1a2e", padding: "20px 28px", textAlign: "center", minWidth: 110 },
  statNum:     { fontSize: 36, fontWeight: 700 },
  statLabel:   { color: "#666", fontSize: 12, marginTop: 4 },
  statSub:     { color: "#444", fontSize: 11, marginTop: 2 },
  chartCard:   { background: "#12121f", borderRadius: 12, padding: 24, marginBottom: 20 },
  cardTitle:   { margin: "0 0 16px", fontSize: 16, fontWeight: 600 },
  infoCard:    { background: "#12121f", borderRadius: 12, padding: 24 },
  infoText:    { color: "#888", fontSize: 14, lineHeight: 1.7, margin: 0 },
  empty:       { background: "#12121f", borderRadius: 12, padding: 40, textAlign: "center", color: "#666" },
  emptyIcon:   { fontSize: 40, marginBottom: 12 },
  emptyHint:   { fontSize: 12, color: "#444", marginTop: 8 },
  table:       { width: "100%", borderCollapse: "collapse" },
  th:          { textAlign: "left", padding: "10px 14px", color: "#666", fontSize: 13, borderBottom: "1px solid #1a1a2e" },
  td:          { padding: "12px 14px", fontSize: 14, color: "#ccc" },
  trEven:      { background: "#0e0e1a" },
  trOdd:       { background: "transparent" },
  badge:       { padding: "3px 10px", borderRadius: 20, fontSize: 12, color: "#aaa" },
  resultGrid:  { display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12 },
  resultItem:  { background: "#0a0a14", borderRadius: 10, padding: "14px", textAlign: "center" },
  resultVal:   { fontSize: 22, fontWeight: 700, color: "#fff" },
  resultKey:   { fontSize: 11, color: "#555", marginTop: 4 },
  genResult:   { background: "#0a0a14", borderRadius: 10, padding: 16, display: "flex", flexDirection: "column", gap: 8 },
  genPw:       { fontSize: 16, color: "#00C49F", wordBreak: "break-all", letterSpacing: 1 },
  genMeta:     { color: "#666", fontSize: 12 },
  copyBtn:     { alignSelf: "flex-start", padding: "6px 14px", borderRadius: 8, border: "1px solid #2a2a3a", background: "transparent", color: "#aaa", cursor: "pointer", fontSize: 13 },
};