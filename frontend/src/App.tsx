import { useState, useEffect, useRef, type FormEvent } from "react";
import { scanDomain, listScans, getScan, deleteScan, type ScanResponse, type Finding, type Severity, type Grade, type HostResult, type ScanHistoryItem } from "./api";

// ─────────────────────────── constants / helpers ────────────────────────────

type PageView = "dashboard" | "scanning" | "result" | "history";

const SCAN_STEPS = [
  { id: "dns",      label: "DNS Resolution",      desc: "Resolving A, MX, NS and TXT records" },
  { id: "ip",       label: "IP Discovery",         desc: "Mapping resolved IP addresses to domain" },
  { id: "ports",    label: "Port 80 / 443 Check",  desc: "Probing HTTP and HTTPS endpoints" },
  { id: "web",      label: "Web Response Check",   desc: "Fetching headers and HTTP status codes" },
  { id: "geo",      label: "Geo / IP Information", desc: "Looking up location, ISP and ASN data" },
  { id: "analysis", label: "Security Analysis",    desc: "Scoring findings and generating report" },
];

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};

const SEV_DOT: Record<Severity, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
  info:     "bg-emerald-500",
};

const SEV_BADGE: Record<Severity, string> = {
  critical: "sev-critical",
  high:     "sev-high",
  medium:   "sev-medium",
  low:      "sev-low",
  info:     "sev-info",
};

const GRADE_RING: Record<Grade, string> = {
  "A+": "border-emerald-400 text-emerald-300 shadow-[0_0_32px_-4px_rgba(52,211,153,0.5)]",
  "A":  "border-emerald-400 text-emerald-300 shadow-[0_0_32px_-4px_rgba(52,211,153,0.5)]",
  "B":  "border-lime-400    text-lime-300    shadow-[0_0_32px_-4px_rgba(163,230,53,0.4)]",
  "C":  "border-yellow-400  text-yellow-300  shadow-[0_0_28px_-4px_rgba(234,179,8,0.4)]",
  "D":  "border-orange-400  text-orange-300  shadow-[0_0_28px_-4px_rgba(251,146,60,0.4)]",
  "F":  "border-red-500     text-red-300     shadow-[0_0_28px_-4px_rgba(239,68,68,0.45)]",
};

const GRADE_PILL: Record<Grade, string> = {
  "A+": "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  "A":  "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  "B":  "bg-lime-500/15    text-lime-300    border-lime-500/40",
  "C":  "bg-yellow-500/15  text-yellow-300  border-yellow-500/40",
  "D":  "bg-orange-500/15  text-orange-300  border-orange-500/40",
  "F":  "bg-red-500/15     text-red-300     border-red-500/40",
};

function getRisk(score: number): { label: string; cls: string } {
  if (score >= 85) return { label: "Low Risk",      cls: "text-emerald-400" };
  if (score >= 70) return { label: "Medium Risk",   cls: "text-yellow-400" };
  if (score >= 50) return { label: "High Risk",     cls: "text-orange-400" };
  return            { label: "Critical Risk",  cls: "text-red-400" };
}

function getScoreBar(score: number): string {
  if (score >= 85) return "bg-emerald-500";
  if (score >= 70) return "bg-yellow-500";
  if (score >= 50) return "bg-orange-500";
  return "bg-red-500";
}

function cleanDomain(v: string) {
  return v.replace(/^https?:\/\//,"").replace(/\/.*$/,"").trim().toLowerCase();
}

function fmtDate(iso: string) {
  try { return new Date(iso).toLocaleString(); }
  catch { return iso; }
}

// ─────────────────────────── scan history (server DB) ────────────────────────

interface HistoryEntry {
  scan_id: string;
  domain: string;
  score: number;
  grade: Grade;
  scanned_at: string;
  findings_count: number;
  mode: "single" | "full";
}

function itemToEntry(it: ScanHistoryItem): HistoryEntry {
  return {
    scan_id: it.scan_id,
    domain: it.domain,
    score: it.score,
    grade: it.grade,
    scanned_at: it.created_at,
    findings_count: it.findings_count,
    mode: it.mode,
  };
}

// ═══════════════════════════ shared UI pieces ═════════════════════════════

function NavBar({
  page, setPage, domain, hasResult,
}: {
  page: PageView;
  setPage: (p: PageView) => void;
  domain: string;
  hasResult: boolean;
}) {
  return (
    <header className="sticky top-0 z-50 border-b border-surface-border bg-surface/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
        {/* logo */}
        <button
          onClick={() => setPage("dashboard")}
          className="flex items-center gap-2.5 group"
        >
          <div className="relative flex h-8 w-8 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10">
            <span className="ping-slow absolute inset-0 rounded-lg border border-cyan-500/30" />
            <svg viewBox="0 0 24 24" className="h-4 w-4 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.4C17.25 22.15 21 17.25 21 12V7l-9-5z"/>
              <circle cx="12" cy="12" r="3" fill="currentColor" opacity=".7"/>
            </svg>
          </div>
          <span className="font-mono text-sm font-bold tracking-wider text-slate-100">
            SEC<span className="text-cyan-400">SCAN</span>
          </span>
        </button>

        {/* domain breadcrumb */}
        {domain && (page === "result" || page === "scanning") && (
          <div className="hidden sm:flex items-center gap-2 font-mono text-xs text-slate-500">
            <span>target:</span>
            <span className="rounded border border-cyan-500/20 bg-cyan-500/8 px-2 py-0.5 text-cyan-400">{domain}</span>
          </div>
        )}

        {/* nav links */}
        <nav className="flex items-center gap-1">
          {[
            { id: "dashboard" as PageView, label: "Scanner" },
            { id: "history"   as PageView, label: "History" },
            ...(hasResult ? [{ id: "result" as PageView, label: "Last Report" }] : []),
          ].map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setPage(id)}
              className={`rounded-lg px-3 py-1.5 font-mono text-xs font-medium transition ${
                page === id
                  ? "border border-cyan-500/30 bg-cyan-500/10 text-cyan-400"
                  : "text-slate-400 hover:text-slate-200 hover:bg-surface-raised"
              }`}
            >
              {label}
            </button>
          ))}
        </nav>
      </div>
    </header>
  );
}

function Card({ children, className = "", glow }: {
  children: React.ReactNode; className?: string;
  glow?: "cyan" | "green" | "red" | "none";
}) {
  const glowCls = {
    cyan:  "shadow-glow border-cyan-500/20",
    green: "shadow-glow-g border-emerald-500/20",
    red:   "shadow-glow-r border-red-500/20",
    none:  "border-surface-border",
  }[glow ?? "none"];
  return (
    <div className={`rounded-2xl border bg-surface-card ${glowCls} ${className}`}>
      {children}
    </div>
  );
}

function SevBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${SEV_BADGE[severity]}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[severity]}`} />
      {SEV_LABEL[severity]}
    </span>
  );
}

function ScoreBar({ score, className = "" }: { score: number; className?: string }) {
  return (
    <div className={`h-1.5 overflow-hidden rounded-full bg-surface-raised ${className}`}>
      <div
        className={`h-full rounded-full transition-all duration-700 ${getScoreBar(score)}`}
        style={{ width: `${score}%` }}
      />
    </div>
  );
}

// ═══════════════════════════ Dashboard page ═══════════════════════════════

const FEATURE_CARDS = [
  { icon: "⬡", color: "cyan",    title: "DNS Security",
    desc: "DNSSEC, SPF/DMARC/DKIM records, A/MX record integrity." },
  { icon: "🔒", color: "blue",    title: "TLS / HTTPS",
    desc: "Certificate validity, cipher strength, protocol versions." },
  { icon: "🛡", color: "violet",  title: "Security Headers",
    desc: "CSP, HSTS, X-Frame-Options, Referrer-Policy and more." },
  { icon: "✉",  color: "yellow",  title: "Email Security",
    desc: "SPF, DKIM and DMARC policies to prevent spoofing." },
  { icon: "🌐", color: "emerald", title: "IP Discovery",
    desc: "Host resolution, open ports, geo-location, ISP and ASN." },
];

const FEAT_COLOR: Record<string, string> = {
  cyan:    "border-cyan-500/25 bg-cyan-500/5 text-cyan-400",
  blue:    "border-blue-500/25 bg-blue-500/5 text-blue-400",
  violet:  "border-violet-500/25 bg-violet-500/5 text-violet-400",
  yellow:  "border-yellow-500/25 bg-yellow-500/5 text-yellow-400",
  emerald: "border-emerald-500/25 bg-emerald-500/5 text-emerald-400",
};

function DashboardPage({
  domain, setDomain, onScan, loading, error, recentHistory, onViewHistory,
  scanMode, setScanMode,
}: {
  domain: string; setDomain: (v: string) => void;
  onScan: (e: FormEvent) => void;
  loading: boolean; error: string | null;
  recentHistory: HistoryEntry[];
  onViewHistory: (e: HistoryEntry) => void;
  scanMode: "single" | "full";
  setScanMode: (m: "single" | "full") => void;
}) {
  return (
    <div className="fade-up min-h-screen bg-[#06080f] pb-20">
      {/* dot grid bg */}
      <div className="pointer-events-none fixed inset-0 bg-dot-grid opacity-40" />

      <div className="relative mx-auto max-w-5xl px-6 pt-14">
        {/* hero */}
        <div className="mb-14 text-center">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-cyan-500/25 bg-cyan-500/8 px-4 py-1.5 font-mono text-[11px] text-cyan-400 uppercase tracking-widest">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400" />
            Passive · Non-Intrusive · Public Data Only
          </div>

          <h1 className="mx-auto max-w-2xl text-4xl font-bold tracking-tight text-white sm:text-5xl leading-tight">
            AI-Assisted Domain{" "}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
              Security Checker
            </span>
          </h1>

          <p className="mx-auto mt-4 max-w-lg text-sm leading-relaxed text-slate-500">
            Analyze DNS, TLS/HTTPS, HTTP security headers, email policies and IP infrastructure —
            all from public data with zero intrusive probing.
          </p>
        </div>

        {/* scan input card */}
        <Card glow="cyan" className="mb-10 p-6">
          <label className="mb-2 block font-mono text-[10px] uppercase tracking-widest text-slate-500">
            Target Domain
          </label>
          <form onSubmit={onScan} className="flex gap-3 flex-col sm:flex-row">
            <div className="relative flex-1">
              <span className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 font-mono text-sm text-slate-600 select-none">
                ://
              </span>
              <input
                value={domain}
                onChange={e => setDomain(e.target.value)}
                placeholder="example.com"
                disabled={loading}
                className="h-12 w-full rounded-xl border border-surface-border bg-surface pl-11 pr-4 font-mono text-sm text-slate-200 outline-none transition
                  placeholder:text-slate-700 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/10 disabled:opacity-50"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="h-12 rounded-xl bg-cyan-500 px-7 font-mono text-sm font-bold text-slate-950 transition
                hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-cyan-800 disabled:text-slate-600 flex items-center gap-2 justify-center whitespace-nowrap"
            >
              {loading ? (
                <><Spinner size="sm" />Scanning…</>
              ) : (
                <><SearchIcon />Scan Domain</>
              )}
            </button>
          </form>

          {/* scan mode toggle */}
          <div className="mt-3 flex items-center gap-3">
            <button
              type="button"
              onClick={() => setScanMode(scanMode === "single" ? "full" : "single")}
              disabled={loading}
              className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none disabled:opacity-50 ${
                scanMode === "full" ? "bg-cyan-500" : "bg-slate-700"
              }`}
              role="switch"
              aria-checked={scanMode === "full"}
            >
              <span
                className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-lg transform transition-transform duration-200 ${
                  scanMode === "full" ? "translate-x-4" : "translate-x-0"
                }`}
              />
            </button>
            <span className="font-mono text-[11px] text-slate-400">
              Full domain scan
              {scanMode === "full" && (
                <span className="ml-2 text-cyan-400">— enumerates subdomains via crt.sh + DNS mining</span>
              )}
            </span>
          </div>

          {error && (
            <div className="mt-3 flex items-center gap-2 rounded-xl border border-red-500/20 bg-red-500/8 px-4 py-2.5 font-mono text-xs text-red-300">
              <span className="text-sm">⚠</span> {error}
            </div>
          )}

          {/* quick examples */}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] text-slate-600">Try:</span>
            {["google.com", "cloudflare.com", "github.com"].map(d => (
              <button
                key={d}
                onClick={() => setDomain(d)}
                className="font-mono text-[11px] text-slate-500 hover:text-cyan-400 transition"
              >
                {d}
              </button>
            ))}
          </div>
        </Card>

        {/* feature cards */}
        <div className="mb-12">
          <p className="mb-5 text-center font-mono text-[10px] uppercase tracking-widest text-slate-600">
            What we analyze
          </p>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURE_CARDS.map(fc => (
              <div
                key={fc.title}
                className={`rounded-xl border p-5 transition hover:brightness-110 ${FEAT_COLOR[fc.color]}`}
              >
                <div className="mb-3 text-2xl">{fc.icon}</div>
                <h3 className="font-mono text-sm font-semibold text-slate-100">{fc.title}</h3>
                <p className="mt-1 text-xs leading-relaxed text-slate-500">{fc.desc}</p>
              </div>
            ))}
            {/* info card */}
            <div className="rounded-xl border border-surface-border bg-surface-card p-5">
              <div className="mb-3 text-2xl">🎓</div>
              <h3 className="font-mono text-sm font-semibold text-slate-100">Senior Project</h3>
              <p className="mt-1 text-xs leading-relaxed text-slate-500">
                AI-Assisted Lightweight Domain Security Checker — university final-year project.
              </p>
            </div>
          </div>
        </div>

        {/* recent scans */}
        {recentHistory.length > 0 && (
          <div>
            <SectionTitle>Recent Scans</SectionTitle>
            <div className="space-y-2.5">
              {recentHistory.slice(0, 5).map(h => (
                <HistoryRow key={h.scan_id} entry={h} onView={onViewHistory} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════ Scanning page ═══════════════════════════════

function ScanningPage({ domain, progress, step }: {
  domain: string; progress: number; step: number;
}) {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#06080f] px-6">
      <div className="scanline" />
      <div className="pointer-events-none fixed inset-0 bg-dot-grid opacity-30" />

      <div className="relative z-10 w-full max-w-xl fade-up">
        {/* radar icon */}
        <div className="mb-8 flex justify-center">
          <div className="relative flex h-20 w-20 items-center justify-center">
            <span className="ping-slow absolute inset-0 rounded-full border border-cyan-500/30" />
            <span className="absolute inset-2 rounded-full border border-cyan-500/20 animate-ping" style={{ animationDuration: "3s" }} />
            <div className="relative flex h-full w-full items-center justify-center rounded-full border border-cyan-500/40 bg-cyan-500/10">
              <svg viewBox="0 0 32 32" className="h-8 w-8 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="16" cy="16" r="12" strokeOpacity=".3"/>
                <circle cx="16" cy="16" r="7"  strokeOpacity=".5"/>
                <circle cx="16" cy="16" r="3"  fill="currentColor"/>
                <path d="M16 16 L24 8" strokeLinecap="round"/>
              </svg>
            </div>
          </div>
        </div>

        {/* heading */}
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold text-white">Scanning Target</h1>
          <p className="mt-2 font-mono text-sm text-cyan-400">{domain}</p>
          <p className="mt-1 text-xs text-slate-600">Running passive security analysis — this takes 15–30 s</p>
        </div>

        {/* progress bar */}
        <div className="mb-6">
          <div className="mb-1.5 flex justify-between font-mono text-xs text-slate-500">
            <span>{SCAN_STEPS[Math.min(step, SCAN_STEPS.length - 1)].label}</span>
            <span className="text-cyan-400">{progress}%</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-surface-raised">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
          {/* segment pips */}
          <div className="mt-1.5 flex gap-1">
            {SCAN_STEPS.map((_, i) => (
              <div
                key={i}
                className={`h-0.5 flex-1 rounded-full transition-colors duration-500 ${
                  i < step ? "bg-emerald-500" : i === step ? "bg-cyan-400" : "bg-surface-raised"
                }`}
              />
            ))}
          </div>
        </div>

        {/* step cards */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {SCAN_STEPS.map((s, i) => {
            const done    = i < step || progress === 100;
            const active  = i === step && progress < 100;
            const waiting = !done && !active;
            return (
              <div
                key={s.id}
                className={`flex items-start gap-3 rounded-xl border p-3.5 transition-all duration-500 ${
                  active  ? "border-cyan-500/35 bg-cyan-500/8 shadow-glow"  :
                  done    ? "border-emerald-500/25 bg-emerald-500/6"         :
                  "border-surface-border bg-surface-card opacity-40"
                }`}
              >
                <div className="mt-0.5 flex-shrink-0">
                  {done    ? <CheckCircle className="text-emerald-400" />   :
                   active  ? <Spinner size="sm" className="text-cyan-400" /> :
                   <div className="h-4 w-4 rounded-full border border-slate-700" />}
                </div>
                <div>
                  <p className={`font-mono text-xs font-semibold ${
                    done ? "text-emerald-300" : active ? "text-cyan-300" : "text-slate-700"
                  }`}>{s.label}</p>
                  <p className={`text-[11px] mt-0.5 ${waiting ? "text-slate-700" : "text-slate-500"}`}>{s.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════ Result page ══════════════════════════════════

function ResultPage({
  result, onNewScan,
}: {
  result: ScanResponse; onNewScan: () => void;
}) {
  const risk = getRisk(result.score);
  const gradeRing = GRADE_RING[result.grade] ?? GRADE_RING["F"];

  const grouped: Record<Severity, Finding[]> = {
    critical: [], high: [], medium: [], low: [], info: [],
  };
  for (const f of result.findings) {
    grouped[f.severity]?.push(f);
  }

  const breakdown = result.breakdown ?? [];

  function parseARecordIPs(findings: Finding[]): string[] {
    const f = findings.find(x => x.id === "dns.a_record" && x.passed);
    if (!f?.evidence) return [];
    const after = f.evidence.replace(/^Resolves to:\s*/i, "");
    return after.split(",").map(s => s.trim()).filter(Boolean);
  }

  function findById(id: string): Finding | undefined {
    return result.findings.find(x => x.id === id);
  }

  const tlsHandshake   = findById("tls.handshake");
  const headersFetch   = findById("headers.fetch");
  const tlsCertValid   = findById("tls.cert_valid");

  const port443Open    = tlsHandshake?.passed ?? false;
  const webResponds    = headersFetch ? headersFetch.passed : port443Open;
  const tlsProtoStr    = (tlsHandshake?.passed && tlsHandshake?.evidence)
    ? tlsHandshake.evidence.replace(/^Negotiated:\s*/i, "")
    : null;
  const httpStatus: string = webResponds
    ? (port443Open ? "200 HTTPS" : "200 HTTP")
    : (headersFetch?.evidence?.split(":")[0] ?? "unreachable");

  interface IPRow {
    ip: string;
    hostname: string;
    status: "active" | "unresolved";
    port80: boolean;
    port443: boolean;
    openPorts: number[];
    webResponse: string;
    location: string;
    ispAsn: string;
    score?: number;
    grade?: Grade;
    findingsCount?: number;
  }

  const hosts: HostResult[] = result.hosts ?? [];

  let ipRows: IPRow[];

  if (result.mode === "full" && hosts.length > 0) {
    ipRows = hosts.map(h => {
      const ports = h.open_ports ?? [];
      const ispAsn = [h.isp, h.asn].filter(Boolean).join(" · ") || "—";
      const httpsUp = ports.includes(443) || h.findings.some(f => f.id === "tls.handshake" && f.passed);
      const httpUp  = ports.includes(80);
      return {
        ip:            h.ip,
        hostname:      h.host,
        status:        "active" as const,
        port80:        httpUp || ports.length === 0,
        port443:       httpsUp,
        openPorts:     ports,
        webResponse:   httpsUp ? "200 HTTPS" : "200 HTTP",
        location:      h.location || "—",
        ispAsn,
        score:         h.score,
        grade:         h.grade,
        findingsCount: h.findings.length,
      };
    });
  } else {
    const parsedIPs = parseARecordIPs(result.findings);
    const fallbackIPs = parsedIPs.length > 0 ? parsedIPs : [];
    ipRows = fallbackIPs.map((ip, idx) => ({
      ip,
      hostname:    idx === 0 ? result.domain : result.domain,
      status:      "active" as const,
      port80:      webResponds,
      port443:     port443Open,
      openPorts:   [...(webResponds ? [80] : []), ...(port443Open ? [443] : [])],
      webResponse: httpStatus,
      location:    "—",
      ispAsn:      "—",
    }));
  }

  const ipCount     = ipRows.length;
  const activeCount = ipRows.filter(r => r.status === "active").length;
  const webCount    = ipRows.filter(r => r.port443 || r.port80).length;

  return (
    <div className="fade-up min-h-screen bg-[#06080f] pb-20">
      <div className="pointer-events-none fixed inset-0 bg-dot-grid opacity-25" />
      <div className="relative mx-auto max-w-6xl px-6 pt-10">

        <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-widest text-slate-600">Security Report</p>
            <h1 className="mt-0.5 font-mono text-xl font-bold text-slate-100">{result.domain}</h1>
            {result.scanned_at && (
              <p className="mt-0.5 font-mono text-xs text-slate-600">{fmtDate(result.scanned_at)}</p>
            )}
          </div>
          <button
            onClick={onNewScan}
            className="rounded-xl border border-surface-border px-4 py-2 font-mono text-xs text-slate-400 transition hover:border-cyan-500/30 hover:text-cyan-400"
          >
            ← New Scan
          </button>
        </div>

        <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Card className="flex flex-col items-center justify-center p-8 text-center">
            <p className="mb-3 font-mono text-[10px] uppercase tracking-widest text-slate-600">Security Grade</p>
            <div className={`flex h-28 w-28 items-center justify-center rounded-full border-4 font-mono text-5xl font-black ${gradeRing}`}>
              {result.grade}
            </div>
          </Card>

          <Card className="flex flex-col justify-center p-6">
            <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-slate-600">Security Score</p>
            <div className="flex items-end gap-2">
              <span className="font-mono text-5xl font-black text-white">{result.score}</span>
              <span className="mb-1 text-sm text-slate-600">/ 100</span>
            </div>
            <ScoreBar score={result.score} className="mt-4" />
            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              {[
                { label: "Critical", count: grouped.critical.length, cls: "text-red-400" },
                { label: "High",     count: grouped.high.length,     cls: "text-orange-400" },
                { label: "Medium",   count: grouped.medium.length,   cls: "text-yellow-400" },
              ].map(({ label, count, cls }) => (
                <div key={label}>
                  <div className={`font-mono text-xl font-bold ${cls}`}>{count}</div>
                  <div className="font-mono text-[10px] text-slate-600">{label}</div>
                </div>
              ))}
            </div>
          </Card>

          <Card className="flex flex-col items-center justify-center p-6 text-center">
            <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-slate-600">Risk Level</p>
            <p className={`font-mono text-3xl font-black ${risk.cls}`}>{risk.label}</p>
            <p className="mt-2 font-mono text-xs text-slate-600">
              {result.findings.length} finding{result.findings.length !== 1 ? "s" : ""} total
            </p>
            {result.mode === "full" && result.domain_avg_score !== null && (
              <p className="mt-1 font-mono text-xs text-slate-600">
                Avg host score: <span className="text-slate-400">{result.domain_avg_score}/100</span>
              </p>
            )}
          </Card>
        </div>

        {result.summary && (
          <Card glow="cyan" className="mb-8 p-5">
            <div className="flex items-start gap-3">
              <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 font-mono text-xs font-bold text-cyan-400">
                AI
              </div>
              <div>
                <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-cyan-400/60">AI Security Summary</p>
                <p className="text-sm leading-relaxed text-slate-400">{result.summary}</p>
              </div>
            </div>
          </Card>
        )}

        {result.ai_summary && (
          <Card glow="cyan" className="mb-8 p-5">
            <div className="flex items-start gap-3">
              <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 font-mono text-xs font-bold text-cyan-400">
                AI
              </div>
              <div className="min-w-0 flex-1">
                <p className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-cyan-400/60">AI Risk Analysis</p>
                <p className="text-sm leading-relaxed text-slate-300">{result.ai_summary.risk_summary}</p>

                {result.ai_summary.top_issues.length > 0 && (
                  <div className="mt-4">
                    <p className="mb-2 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-orange-400/70">
                      <span className="h-1.5 w-1.5 rounded-full bg-orange-500" /> Top Issues
                    </p>
                    <ul className="space-y-1.5">
                      {result.ai_summary.top_issues.map((issue, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs leading-relaxed text-slate-400">
                          <span className="mt-1 text-orange-500">▸</span>
                          <span>{issue}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.ai_summary.positive_findings.length > 0 && (
                  <div className="mt-4">
                    <p className="mb-2 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-emerald-400/70">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> Done Well
                    </p>
                    <ul className="space-y-1.5">
                      {result.ai_summary.positive_findings.map((good, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs leading-relaxed text-slate-400">
                          <span className="mt-0.5 text-emerald-500">✓</span>
                          <span>{good}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </Card>
        )}

        {breakdown.length > 0 && (
          <section className="mb-8">
            <SectionTitle>Category Breakdown</SectionTitle>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              {breakdown.map(cat => {
                const pct = Math.round((cat.earned / cat.max) * 100);
                return (
                  <Card key={cat.name} className="p-4">
                    <p className="font-mono text-[10px] uppercase tracking-widest text-slate-600 mb-2">{cat.name}</p>
                    <div className="flex items-end gap-1 mb-2">
                      <span className="font-mono text-2xl font-bold text-slate-100">{cat.earned}</span>
                      <span className="mb-0.5 font-mono text-xs text-slate-600">/{cat.max}</span>
                    </div>
                    <ScoreBar score={pct} />
                  </Card>
                );
              })}
            </div>
          </section>
        )}

        <section className="mb-8">
          <SectionTitle sub="Network infrastructure discovered during scan">
            IP Discovery &amp; Host Infrastructure
          </SectionTitle>

          <div className="mb-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              { label: "Total IPs",       value: ipCount,                              cls: "text-cyan-400",    icon: "⬡" },
              { label: "Active Hosts",    value: activeCount,                          cls: "text-emerald-400", icon: "◎" },
              { label: "Web Services",    value: webCount,                             cls: "text-blue-400",    icon: "↗" },
              { label: "Port 443 Open",   value: ipRows.filter(r => r.port443).length, cls: "text-violet-400",  icon: "🔒" },
            ].map(({ label, value, cls, icon }) => (
              <Card key={label} className="p-4">
                <div className="mb-2 text-lg">{icon}</div>
                <div className={`font-mono text-3xl font-black ${cls}`}>{value}</div>
                <div className="mt-1 font-mono text-[10px] uppercase tracking-widest text-slate-600">{label}</div>
              </Card>
            ))}
          </div>

          {result.mode === "single" && (
            <div className="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <Card className="flex items-center gap-3 p-4">
                <div className={`flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg border font-mono text-sm ${
                  port443Open
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border-red-500/30 bg-red-500/10 text-red-400"
                }`}>
                  {port443Open ? "✓" : "✕"}
                </div>
                <div>
                  <p className="font-mono text-xs font-semibold text-slate-200">Port 443 (HTTPS)</p>
                  <p className="font-mono text-[11px] text-slate-500">
                    {port443Open ? (tlsProtoStr ? `Open · ${tlsProtoStr}` : "Open · TLS active") : "Closed or unreachable"}
                  </p>
                </div>
              </Card>

              <Card className="flex items-center gap-3 p-4">
                <div className={`flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg border font-mono text-sm ${
                  webResponds
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
                }`}>
                  {webResponds ? "✓" : "⚠"}
                </div>
                <div>
                  <p className="font-mono text-xs font-semibold text-slate-200">Web Response</p>
                  <p className="font-mono text-[11px] text-slate-500">{httpStatus}</p>
                </div>
              </Card>

              <Card className="flex items-center gap-3 p-4">
                <div className={`flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg border font-mono text-sm ${
                  tlsCertValid?.passed
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border-orange-500/30 bg-orange-500/10 text-orange-400"
                }`}>
                  🔒
                </div>
                <div className="min-w-0">
                  <p className="font-mono text-xs font-semibold text-slate-200">TLS Certificate</p>
                  <p className="truncate font-mono text-[11px] text-slate-500">
                    {tlsCertValid?.evidence ?? (port443Open ? "Certificate present" : "Not checked")}
                  </p>
                </div>
              </Card>
            </div>
          )}

          {ipRows.length === 0 ? (
            <Card className="p-8 text-center">
              <p className="font-mono text-sm text-slate-600">
                No A records resolved — domain may not have a public IP or the DNS query failed.
              </p>
              <p className="mt-1 font-mono text-xs text-slate-700">
                Check the DNS findings below for details.
              </p>
            </Card>
          ) : (
            <Card className="overflow-hidden">
              <div className="border-b border-surface-border px-5 py-3 flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500">
                  Discovered Hosts
                </span>
                <span className="font-mono text-[10px] text-slate-700">
                  {result.mode === "full" ? "Full scan — real host data" : "Single scan — derived from DNS records"}
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-sm">
                  <thead>
                    <tr className="border-b border-surface-border bg-surface/40">
                      {["IP Address", "Status", "Open Ports", "Web Response", "Location", "ISP / ASN",
                        ...(result.mode === "full" ? ["Score", "Grade"] : [])
                      ].map(h => (
                        <th key={h} className="whitespace-nowrap px-4 py-3 text-left font-mono text-[10px] uppercase tracking-widest text-slate-600">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {ipRows.map((row, i) => {
                      return (
                        <tr
                          key={`${row.ip}-${i}`}
                          className={`border-b border-surface-border/40 transition hover:bg-surface-raised ${i % 2 === 0 ? "" : "bg-surface/30"}`}
                        >
                          <td className="px-4 py-3">
                            <div className="font-mono text-xs text-cyan-400">{row.ip}</div>
                            {row.hostname && row.hostname !== row.ip && (
                              <div className="mt-0.5 font-mono text-[10px] text-slate-600">{row.hostname}</div>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] font-semibold ${
                              row.status === "active"
                                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                                : "border-slate-600/30 bg-slate-700/20 text-slate-500"
                            }`}>
                              <span className={`h-1.5 w-1.5 rounded-full ${row.status === "active" ? "bg-emerald-400" : "bg-slate-600"}`} />
                              {row.status === "active" ? "Active" : "Inactive"}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex gap-1 flex-wrap">
                              {row.openPorts.length > 0 ? (
                                row.openPorts.map(p => (
                                  <span
                                    key={p}
                                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${
                                      p === 443
                                        ? "border-violet-500/30 bg-violet-500/10 text-violet-300"
                                        : p === 80
                                        ? "border-blue-500/30 bg-blue-500/10 text-blue-300"
                                        : "border-slate-500/30 bg-slate-500/10 text-slate-300"
                                    }`}
                                  >
                                    {p}
                                  </span>
                                ))
                              ) : (
                                <span className="font-mono text-xs text-slate-600">—</span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`font-mono text-xs ${
                              row.webResponse.startsWith("200") ? "text-emerald-400"
                              : row.webResponse === "—" || row.webResponse === "unreachable" ? "text-slate-600"
                              : "text-yellow-400"
                            }`}>
                              {row.webResponse}
                            </span>
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-500">
                            {row.location && row.location !== "—" ? `≈ ${row.location}` : row.location}
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-slate-500">{row.ispAsn}</td>
                          {result.mode === "full" && (
                            <>
                              <td className="px-4 py-3">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-xs text-slate-300">{row.score}</span>
                                  <div className="w-14"><ScoreBar score={row.score ?? 0} /></div>
                                </div>
                              </td>
                              <td className="px-4 py-3">
                                {row.grade && (
                                  <span className={`rounded border px-2 py-0.5 font-mono text-xs font-bold ${GRADE_PILL[row.grade] ?? ""}`}>
                                    {row.grade}
                                  </span>
                                )}
                              </td>
                            </>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {result.mode === "single" && (
                <div className="border-t border-surface-border px-5 py-3">
                  <p className="font-mono text-[10px] text-slate-700">
                    ⓘ Location and ISP/ASN data require a geo-IP lookup service not yet integrated into the backend.
                    Port 80/443 status and web response are derived from the TLS and HTTP header scanner results.
                  </p>
                </div>
              )}
              {result.mode === "full" && (
                <div className="border-t border-surface-border px-5 py-3">
                  <p className="font-mono text-[10px] text-slate-700">
                    ⓘ Location is approximate (≈) — derived from IP geolocation (ip-api.com), which reflects the
                    registered network location, not the physical server. Country and ISP/ASN are reliable; city may
                    be off, and sites behind a CDN (e.g. Cloudflare) show the CDN edge rather than the origin server.
                  </p>
                </div>
              )}
            </Card>
          )}
        </section>

        <section>
          <SectionTitle sub={`${result.findings.length} findings across all categories`}>
            Security Findings
          </SectionTitle>

          {result.findings.length === 0 ? (
            <Card className="p-10 text-center">
              <div className="mb-3 text-4xl">✓</div>
              <p className="text-sm text-slate-500">No security findings — all checks passed.</p>
            </Card>
          ) : (
            <div className="space-y-6">
              {SEV_ORDER.filter(sev => grouped[sev].length > 0).map(sev => (
                <div key={sev}>
                  <div className="mb-3 flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${SEV_DOT[sev]}`} />
                    <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                      {SEV_LABEL[sev]} <span className="text-slate-700">({grouped[sev].length})</span>
                    </span>
                  </div>
                  <div className="space-y-2.5">
                    {grouped[sev].map((f, idx) => (
                      <FindingRow key={`${f.id}-${idx}`} finding={f} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <div className="mt-14 flex flex-wrap items-center justify-between gap-4 border-t border-surface-border pt-6 font-mono text-[10px] text-slate-700">
          <span>SECSCAN · AI-Assisted Domain Security Checker</span>
          {result.version && <span>v{result.version.app} · model {result.version.model}</span>}
          {result.scan_id && <span>ID: {result.scan_id}</span>}
        </div>
      </div>
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`rounded-xl border p-4 transition ${SEV_BADGE[finding.severity]}`}>
      <button
        className="flex w-full items-start gap-3 text-left"
        onClick={() => setOpen(o => !o)}
      >
        <span className={`mt-1 h-2 w-2 flex-shrink-0 rounded-full ${SEV_DOT[finding.severity]}`} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-slate-200">{finding.title}</span>
            <span className="font-mono text-[10px] uppercase text-slate-600 bg-surface-raised px-1.5 py-0.5 rounded">
              {finding.category}
            </span>
            <SevBadge severity={finding.severity} />
          </div>
          {!open && finding.evidence && (
            <p className="mt-1 truncate text-xs text-slate-500">{finding.evidence}</p>
          )}
        </div>
        <span className={`ml-2 mt-0.5 flex-shrink-0 font-mono text-xs text-slate-600 transition ${open ? "rotate-90" : ""}`}>›</span>
      </button>

      {open && (
        <div className="mt-3 space-y-2 pl-5">
          {finding.evidence && (
            <div className="rounded-lg bg-surface p-3">
              <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-slate-600">Evidence</p>
              <p className="font-mono text-xs text-slate-400 break-all">{finding.evidence}</p>
            </div>
          )}
          {finding.remediation && (
            <div className="rounded-lg bg-surface p-3">
              <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-emerald-600">Recommendation</p>
              <p className="text-xs text-slate-400">{finding.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════ History page ════════════════════════════════

function HistoryPage({
  history, onView, onDelete, onClear, onNewScan,
}: {
  history: HistoryEntry[];
  onView: (e: HistoryEntry) => void;
  onDelete: (scan_id: string) => void;
  onClear: () => void;
  onNewScan: () => void;
}) {
  return (
    <div className="fade-up min-h-screen bg-[#06080f] pb-20">
      <div className="pointer-events-none fixed inset-0 bg-dot-grid opacity-25" />
      <div className="relative mx-auto max-w-4xl px-6 pt-10">
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <SectionTitle>Scan History</SectionTitle>
            <p className="font-mono text-xs text-slate-600">Results stored on the server</p>
          </div>
          <div className="flex gap-2">
            {history.length > 0 && (
              <button
                onClick={() => { if (confirm("Clear all history?")) onClear(); }}
                className="rounded-lg border border-surface-border px-3 py-1.5 font-mono text-xs text-slate-600 hover:text-red-400 transition"
              >
                Clear All
              </button>
            )}
            <button
              onClick={onNewScan}
              className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 font-mono text-xs text-cyan-400 hover:bg-cyan-500/20 transition"
            >
              + New Scan
            </button>
          </div>
        </div>

        {history.length === 0 ? (
          <Card className="p-12 text-center">
            <div className="mb-4 text-4xl text-slate-700">◷</div>
            <p className="text-sm text-slate-600 font-mono">No scans yet.</p>
            <button
              onClick={onNewScan}
              className="mt-4 font-mono text-xs text-cyan-400 hover:text-cyan-300 transition"
            >
              Run your first scan →
            </button>
          </Card>
        ) : (
          <div className="space-y-3">
            {history.map((entry, i) => (
              <HistoryRow
                key={entry.scan_id}
                entry={entry}
                rank={i + 1}
                onView={onView}
                onDelete={() => onDelete(entry.scan_id)}
              />
            ))}
          </div>
        )}

        <p className="mt-8 text-center font-mono text-[10px] text-slate-700">
          Stored on the server · up to 50 recent scans
        </p>
      </div>
    </div>
  );
}

function HistoryRow({
  entry, rank, onView, onDelete,
}: {
  entry: HistoryEntry;
  rank?: number;
  onView: (e: HistoryEntry) => void;
  onDelete?: () => void;
}) {
  const risk = getRisk(entry.score);
  return (
    <Card className="flex flex-wrap items-center gap-4 p-4 transition hover:border-slate-600/50">
      {rank !== undefined && (
        <span className="w-5 flex-shrink-0 text-right font-mono text-xs text-slate-700">#{rank}</span>
      )}
      <div className={`flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg border font-mono text-base font-black ${GRADE_PILL[entry.grade] ?? ""}`}>
        {entry.grade}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm font-semibold text-slate-100 truncate">{entry.domain}</span>
          <span className="font-mono text-[10px] uppercase text-slate-700 border border-surface-border rounded px-1.5 py-0.5">
            {entry.mode}
          </span>
          {entry.findings_count > 0 && (
            <span className="font-mono text-[10px] text-slate-600">{entry.findings_count} findings</span>
          )}
        </div>
        <div className="mt-0.5 font-mono text-[11px] text-slate-600">{fmtDate(entry.scanned_at)}</div>
      </div>
      <div className="hidden sm:block w-24">
        <div className="mb-1 flex justify-between font-mono text-[10px]">
          <span className="text-slate-600">Score</span>
          <span className="text-slate-400">{entry.score}</span>
        </div>
        <ScoreBar score={entry.score} />
      </div>
      <span className={`w-24 text-right font-mono text-xs font-semibold flex-shrink-0 ${risk.cls}`}>{risk.label}</span>
      <div className="flex items-center gap-2 flex-shrink-0">
        <button
          onClick={() => onView(entry)}
          className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 px-3 py-1.5 font-mono text-xs text-cyan-400 hover:bg-cyan-500/15 transition"
        >
          View Report
        </button>
        {onDelete && (
          <button
            onClick={onDelete}
            className="rounded-lg border border-surface-border px-2 py-1.5 font-mono text-xs text-slate-600 hover:text-red-400 hover:border-red-500/30 transition"
            title="Delete"
          >
            ✕
          </button>
        )}
      </div>
    </Card>
  );
}

// ═══════════════════════════ small shared pieces ══════════════════════════

function SectionTitle({ children, sub }: { children: React.ReactNode; sub?: string }) {
  return (
    <div className="mb-5">
      <h2 className="flex items-center gap-2 font-mono text-base font-semibold text-slate-100">
        <span className="h-5 w-0.5 rounded-full bg-cyan-400" />
        {children}
      </h2>
      {sub && <p className="ml-3.5 mt-0.5 text-xs text-slate-600">{sub}</p>}
    </div>
  );
}

function Spinner({ size = "md", className = "" }: { size?: "sm" | "md"; className?: string }) {
  const s = size === "sm" ? "h-3.5 w-3.5 border" : "h-5 w-5 border-2";
  return (
    <div className={`${s} animate-spin rounded-full border-slate-600 border-t-current ${className}`} />
  );
}

function CheckCircle({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={`h-4 w-4 flex-shrink-0 ${className}`} fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="8" cy="8" r="7" />
      <path d="M5 8l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function SearchIcon() {
  return (
    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="6.5" cy="6.5" r="5" />
      <path d="M10.5 10.5L14 14" strokeLinecap="round" />
    </svg>
  );
}

// ═══════════════════════════ Root App ════════════════════════════════════

export default function App() {
  const [domain, setDomain] = useState("example.com");
  const [scanMode, setScanMode] = useState<"single" | "full">("single");
  const [pageView, setPageView] = useState<PageView>("dashboard");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [progress, setProgress] = useState(0);
  const [step, setStep] = useState(0);
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  const timerRef = useRef<number | undefined>(undefined);

  const refreshHistory = async () => {
    try { setHistory((await listScans()).map(itemToEntry)); }
    catch { /* server history unavailable */ }
  };

  // eslint-disable-next-line react-hooks/set-state-in-effect -- async load on mount; setState runs after await
  useEffect(() => { refreshHistory(); }, []);

  async function onScan(e: FormEvent) {
    e.preventDefault();
    const d = cleanDomain(domain);
    if (!d) { setError("Please enter a domain name."); return; }

    setDomain(d);
    setError(null);
    setProgress(0);
    setStep(0);
    setLoading(true);
    setPageView("scanning");

    const stepDurations = [3500, 3000, 3200, 3000, 2800, 3500];
    let currentStep = 0;
    let currentPct  = 0;

    timerRef.current = window.setInterval(() => {
      const stepTarget = Math.round(((currentStep + 1) / SCAN_STEPS.length) * 100);
      currentPct = Math.min(currentPct + Math.random() * 3 + 1, stepTarget - 1, 95);
      setProgress(Math.round(currentPct));

      const newStep = Math.min(
        Math.floor((currentPct / 100) * SCAN_STEPS.length),
        SCAN_STEPS.length - 1
      );
      if (newStep !== currentStep) {
        currentStep = newStep;
        setStep(newStep);
      }
    }, stepDurations[currentStep] / 30);

    try {
      const data = await scanDomain(d, scanMode);
      window.clearInterval(timerRef.current);
      setProgress(100);
      setStep(SCAN_STEPS.length);
      await new Promise(r => setTimeout(r, 600));

      setResult(data);

      // Backend already persisted this scan — refresh the list from the server.
      refreshHistory();

      setPageView("result");
    } catch (err) {
      window.clearInterval(timerRef.current);
      setError(err instanceof Error ? err.message : "Scan failed");
      setPageView("dashboard");
    } finally {
      setLoading(false);
    }
  }

  async function handleViewHistory(entry: HistoryEntry) {
    if (result && result.scan_id === entry.scan_id) {
      setPageView("result");
      return;
    }
    try {
      const full = await getScan(entry.scan_id);
      setResult({ ...full, scanned_at: entry.scanned_at });
      setPageView("result");
    } catch {
      setError("Could not load that scan from the server.");
      setPageView("dashboard");
    }
  }

  async function handleDeleteHistory(scan_id: string) {
    try { await deleteScan(scan_id); } catch { /* ignore */ }
    refreshHistory();
  }

  async function handleClearHistory() {
    try { await Promise.all(history.map(h => deleteScan(h.scan_id))); } catch { /* ignore */ }
    refreshHistory();
  }

  function handlePageNav(p: PageView) {
    if (p === "result" && !result) return;
    if (p === "history") refreshHistory();
    setPageView(p);
  }

  return (
    <div className="min-h-screen bg-[#06080f] text-slate-100">
      <NavBar
        page={pageView}
        setPage={handlePageNav}
        domain={domain}
        hasResult={!!result}
      />

      {pageView === "dashboard" && (
        <DashboardPage
          domain={domain}
          setDomain={setDomain}
          onScan={onScan}
          loading={loading}
          error={error}
          recentHistory={history}
          onViewHistory={handleViewHistory}
          scanMode={scanMode}
          setScanMode={setScanMode}
        />
      )}

      {pageView === "scanning" && (
        <ScanningPage domain={domain} progress={progress} step={step} />
      )}

      {pageView === "result" && result && (
        <ResultPage
          result={result}
          onNewScan={() => { setResult(null); setProgress(0); setStep(0); setPageView("dashboard"); }}
        />
      )}

      {pageView === "history" && (
        <HistoryPage
          history={history}
          onView={handleViewHistory}
          onDelete={handleDeleteHistory}
          onClear={handleClearHistory}
          onNewScan={() => setPageView("dashboard")}
        />
      )}
    </div>
  );
}
