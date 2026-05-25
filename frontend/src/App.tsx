import { useState, type FormEvent } from "react";
import { scanDomain, type ScanResponse, type Severity } from "./api";

type PageView = "dashboard" | "scanning" | "result" | "history";

const scanSteps = [
  {
    title: "DNS Configuration",
    desc: "Checking A records, MX records, SPF records",
  },
  {
    title: "TLS / HTTPS Setup",
    desc: "Validating SSL certificate and HTTPS configuration",
  },
  {
    title: "Security Headers",
    desc: "Checking CSP, HSTS, X-Frame-Options headers",
  },
  {
    title: "Email Security",
    desc: "Checking SPF, DKIM, and DMARC records",
  },
];

const severityStyle: Record<Severity, string> = {
  critical: "border-red-500/30 bg-red-500/10 text-red-300",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  medium: "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
  low: "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
  info: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
};

const gradeStyle: Record<string, string> = {
  "A+": "text-emerald-400 border-emerald-400 shadow-emerald-400/30",
  A: "text-emerald-400 border-emerald-400 shadow-emerald-400/30",
  B: "text-lime-400 border-lime-400 shadow-lime-400/30",
  C: "text-yellow-400 border-yellow-400 shadow-yellow-400/30",
  D: "text-orange-400 border-orange-400 shadow-orange-400/30",
  F: "text-red-400 border-red-400 shadow-red-400/30",
};

function cleanDomainInput(value: string) {
  return value
    .replace("https://", "")
    .replace("http://", "")
    .replaceAll("/", "")
    .trim();
}

function getRiskText(score: number) {
  if (score >= 85) return "Low Risk";
  if (score >= 70) return "Medium Risk";
  if (score >= 50) return "High Risk";
  return "Critical Risk";
}

function getRiskColor(score: number) {
  if (score >= 85) return "text-emerald-400";
  if (score >= 70) return "text-yellow-400";
  if (score >= 50) return "text-orange-400";
  return "text-red-400";
}

function getGradeBadge(score: number) {
  if (score >= 85) {
    return "border-emerald-500/50 bg-emerald-500/15 text-emerald-300";
  }

  if (score >= 70) {
    return "border-yellow-500/50 bg-yellow-500/15 text-yellow-300";
  }

  if (score >= 50) {
    return "border-orange-500/50 bg-orange-500/15 text-orange-300";
  }

  return "border-red-500/50 bg-red-500/15 text-red-300";
}

function getHighRiskCount(result: ScanResponse | null) {
  if (!result) return 0;

  return result.findings.filter(
    (finding) => finding.severity === "critical" || finding.severity === "high"
  ).length;
}

function getWarningCount(result: ScanResponse | null) {
  if (!result) return 0;

  return result.findings.filter(
    (finding) => finding.severity === "medium" || finding.severity === "low"
  ).length;
}

function getPassCount(result: ScanResponse | null) {
  if (!result) return 0;

  return result.findings.filter((finding) => finding.severity === "info").length;
}

function makeDemoHistory(): ScanResponse[] {
  return [
    {
      domain: "google.com",
      score: 95,
      grade: "A",
      findings: [],
      summary: "Excellent security posture",
      scan_id: "demo-1",
      version: { app: "1.0.0", model: "demo" },
    } as ScanResponse,
    {
      domain: "google.com",
      score: 45,
      grade: "D",
      findings: [],
      summary: "High risk detected",
      scan_id: "demo-2",
      version: { app: "1.0.0", model: "demo" },
    } as ScanResponse,
    {
      domain: "google.com",
      score: 40,
      grade: "D",
      findings: [],
      summary: "High risk detected",
      scan_id: "demo-3",
      version: { app: "1.0.0", model: "demo" },
    } as ScanResponse,
    {
      domain: "google.com",
      score: 92,
      grade: "A",
      findings: [],
      summary: "Low risk detected",
      scan_id: "demo-4",
      version: { app: "1.0.0", model: "demo" },
    } as ScanResponse,
    {
      domain: "google.com",
      score: 58,
      grade: "C",
      findings: [],
      summary: "Medium risk detected",
      scan_id: "demo-5",
      version: { app: "1.0.0", model: "demo" },
    } as ScanResponse,
  ];
}

export default function App() {
  const [domain, setDomain] = useState("example.com");
  const [loading, setLoading] = useState(false);
  const [pageView, setPageView] = useState<PageView>("dashboard");
  const [scanStep, setScanStep] = useState(0);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [history, setHistory] = useState<ScanResponse[]>([]);

  async function onScan(e: FormEvent) {
    e.preventDefault();

    const cleanedDomain = cleanDomainInput(domain);

    if (!cleanedDomain) {
      setError("Please enter a domain name.");
      return;
    }

    setDomain(cleanedDomain);
    setLoading(true);
    setError(null);
    setProgress(0);
    setScanStep(0);
    setPageView("scanning");

    let progressTimer: number | undefined;

    try {
      progressTimer = window.setInterval(() => {
        setProgress((prev) => {
          if (prev >= 95) return prev;

          const next = prev + Math.floor(Math.random() * 4) + 1;

          if (next >= 75) {
            setScanStep(3);
          } else if (next >= 50) {
            setScanStep(2);
          } else if (next >= 25) {
            setScanStep(1);
          } else {
            setScanStep(0);
          }

          return Math.min(next, 95);
        });
      }, 220);

      const data = await scanDomain(cleanedDomain);

      if (progressTimer) {
        window.clearInterval(progressTimer);
      }

      setProgress(100);
      setScanStep(scanSteps.length - 1);

      await new Promise((resolve) => setTimeout(resolve, 600));

      setResult(data);
      setHistory((prev) => [data, ...prev].slice(0, 10));
      setPageView("result");
    } catch (err) {
      if (progressTimer) {
        window.clearInterval(progressTimer);
      }

      setError(err instanceof Error ? err.message : "Scan failed");
      setPageView("dashboard");
    } finally {
      setLoading(false);
    }
  }

  const shownResult = result;
  const totalIssues = shownResult?.findings.length ?? 0;
  const avgScore = shownResult?.score ?? 66;
  const highRisk = getHighRiskCount(shownResult);
  const warningCount = getWarningCount(shownResult);
  const passCount = getPassCount(shownResult);

  if (pageView === "scanning") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#080a10] px-6 text-slate-100">
        <div className="w-full max-w-[650px]">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-5 w-fit rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-1 text-[11px] font-semibold uppercase tracking-widest text-emerald-300">
              Scanning in Progress
            </div>

            <h1 className="text-2xl font-bold text-white">
              Analyzing {domain}
            </h1>

            <p className="mt-2 text-sm text-slate-500">
              Running security checks across multiple modules
            </p>
          </div>

          <div className="mb-6">
            <div className="mb-2 flex justify-between text-xs text-slate-500">
              <span>Security scan progress</span>
              <span>{progress}%</span>
            </div>

            <div className="h-2 overflow-hidden rounded-full bg-[#151923]">
              <div
                className="h-full rounded-full bg-emerald-400 transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>

          <div className="space-y-3">
            {scanSteps.map((step, index) => {
              const isDone = index < scanStep || progress === 100;
              const isActive = index === scanStep && progress < 100;
              const isWaiting = index > scanStep && progress < 100;

              return (
                <div
                  key={step.title}
                  className={`flex items-center justify-between rounded-2xl border p-4 transition-all duration-500 ${
                    isActive
                      ? "border-emerald-500/30 bg-emerald-500/10 shadow-lg shadow-emerald-500/10"
                      : isDone
                      ? "border-emerald-500/20 bg-[#111722]"
                      : "border-white/5 bg-[#10131c] opacity-45"
                  }`}
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`flex h-9 w-9 items-center justify-center rounded-xl border text-sm ${
                        isDone
                          ? "border-emerald-500/30 bg-emerald-500/20 text-emerald-300"
                          : isActive
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                          : "border-white/10 bg-black/20 text-slate-500"
                      }`}
                    >
                      {isDone ? "✓" : isActive ? "◌" : "○"}
                    </div>

                    <div>
                      <div className="text-sm font-semibold text-white">
                        {step.title}
                      </div>
                      <div className="mt-1 text-xs text-slate-500">
                        {step.desc}
                      </div>
                    </div>
                  </div>

                  <div className="text-xs font-semibold">
                    {isDone && <span className="text-emerald-300">Done</span>}
                    {isActive && (
                      <span className="text-emerald-300">Scanning</span>
                    )}
                    {isWaiting && <span className="text-slate-600">Waiting</span>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  if (pageView === "history") {
    const demoHistory = history.length > 0 ? history : makeDemoHistory();

    return (
      <div className="min-h-screen bg-[#080a10] text-slate-100">
        <div className="mx-auto min-h-screen w-full max-w-[1280px] bg-[#0d1018] shadow-2xl shadow-black/40">
          <nav className="flex items-center justify-between border-b border-white/5 px-8 py-5">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
                🛡
              </div>

              <div>
                <div className="font-bold text-white">SecChecker</div>
                <div className="text-[10px] uppercase tracking-[0.22em] text-slate-600">
                  AI Domain Security
                </div>
              </div>
            </div>

            <div className="flex gap-8 text-sm font-semibold text-slate-400">
              <button
                onClick={() => setPageView("dashboard")}
                className="transition hover:text-emerald-400"
              >
                Dashboard
              </button>

              <button
                onClick={() => setPageView("history")}
                className="text-white transition hover:text-emerald-400"
              >
                History
              </button>
            </div>
          </nav>

          <main className="px-12 py-20">
            <div className="mb-10 flex items-end justify-between">
              <div>
                <h1 className="text-4xl font-black tracking-tight text-white">
                  Scan History
                </h1>
                <p className="mt-4 text-lg font-semibold text-slate-700">
                  {demoHistory.length} total scans
                </p>
              </div>

              <button
                onClick={() => {
                  setResult(null);
                  setPageView("dashboard");
                }}
                className="text-lg font-semibold text-emerald-400 transition hover:text-emerald-300"
              >
                + New Scan
              </button>
            </div>

            <div className="space-y-4">
              {demoHistory.map((item, index) => {
                const riskText = getRiskText(item.score);
                const riskClass = getRiskColor(item.score);
                const gradeBadge = getGradeBadge(item.score);

                const borderHighlight =
                  index === 2
                    ? "border border-orange-500/30"
                    : index === 3
                    ? "border-2 border-sky-500"
                    : "border border-transparent";

                return (
                  <div
                    key={`${item.scan_id}-${index}`}
                    className={`flex items-center justify-between rounded-3xl bg-[#14131d] px-8 py-6 ${borderHighlight}`}
                  >
                    <div className="flex items-center gap-6">
                      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-white/10 text-2xl text-slate-500">
                        🌐
                      </div>

                      <div>
                        <div className="text-xl font-semibold text-white">
                          {item.domain}
                        </div>
                        <div className="mt-1 text-sm text-slate-600">
                          Mar 13, 2026 ·{" "}
                          {index === 0
                            ? "13:36"
                            : index === 1
                            ? "07:23"
                            : index === 2
                            ? "06:51"
                            : "06:43"}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-6">
                      <div className={`text-lg font-bold ${riskClass}`}>
                        {riskText}
                      </div>

                      <div
                        className={`flex h-9 w-9 items-center justify-center rounded-lg border text-lg font-bold ${gradeBadge}`}
                      >
                        {item.grade}
                      </div>

                      <div className="text-lg text-slate-600">
                        {item.score}/100
                      </div>

                      <button
                        onClick={() => {
                          if (history.length > 0) {
                            setHistory((prev) =>
                              prev.filter((h) => h.scan_id !== item.scan_id)
                            );
                          }
                        }}
                        className="text-xl text-slate-600 transition hover:text-red-400"
                      >
                        🗑
                      </button>

                      <button
                        onClick={() => {
                          setResult(item);
                          setPageView("result");
                        }}
                        className="text-2xl text-slate-600 transition hover:text-emerald-400"
                      >
                        →
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </main>
        </div>
      </div>
    );
  }

  if (pageView === "result" && result) {
    const gradeClass =
      gradeStyle[result.grade] ??
      "text-slate-200 border-slate-400 shadow-slate-400/20";

    const firstColumnFindings = result.findings.slice(0, 4);
    const secondColumnFindings = result.findings.slice(4, 8);
    const thirdColumnFindings = result.findings.slice(8, 12);
    const fourthColumnFindings = result.findings.slice(12, 16);

    return (
      <div className="min-h-screen bg-[#080a10] px-6 py-7 text-slate-100">
        <div className="mx-auto max-w-[1280px]">
          <nav className="mb-7 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-500/15 text-xs text-emerald-400">
                ◎
              </div>
              <span className="font-bold text-white">SecChecker</span>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => setPageView("dashboard")}
                className="rounded-xl border border-white/10 px-4 py-2 text-xs font-semibold text-slate-300 transition hover:border-emerald-500/40 hover:text-emerald-300"
              >
                Dashboard
              </button>

              <button
                onClick={() => setPageView("history")}
                className="rounded-xl border border-white/10 px-4 py-2 text-xs font-semibold text-slate-300 transition hover:border-emerald-500/40 hover:text-emerald-300"
              >
                History
              </button>

              <button
                onClick={() => {
                  setResult(null);
                  setProgress(0);
                  setScanStep(0);
                  setPageView("dashboard");
                }}
                className="rounded-xl bg-emerald-500 px-5 py-2 text-xs font-bold text-[#06110c] transition hover:bg-emerald-400"
              >
                New Scan
              </button>
            </div>
          </nav>

          <section className="mb-7 rounded-3xl bg-[#121620] p-8 text-center shadow-2xl shadow-black/30">
            <div
              className={`mx-auto mb-4 flex h-32 w-32 items-center justify-center rounded-full border-4 text-5xl font-black shadow-xl ${gradeClass}`}
            >
              {result.grade}
            </div>

            <h1 className="text-2xl font-bold text-white">
              {result.score}/100
            </h1>

            <p className={`mt-2 text-sm ${getRiskColor(result.score)}`}>
              {getRiskText(result.score)}
            </p>

            <p className="mt-2 text-sm text-slate-500">
              Security result for {result.domain}
            </p>
          </section>

          <section className="mb-7 grid gap-4 md:grid-cols-4">
            <div className="rounded-2xl bg-[#121620] p-5">
              <div className="text-sm text-slate-500">Total Findings</div>
              <div className="mt-2 text-3xl font-bold text-white">
                {result.findings.length}
              </div>
            </div>

            <div className="rounded-2xl bg-[#121620] p-5">
              <div className="text-sm text-slate-500">Pass Items</div>
              <div className="mt-2 text-3xl font-bold text-emerald-400">
                {passCount}
              </div>
            </div>

            <div className="rounded-2xl bg-[#121620] p-5">
              <div className="text-sm text-slate-500">Warnings</div>
              <div className="mt-2 text-3xl font-bold text-yellow-400">
                {warningCount}
              </div>
            </div>

            <div className="rounded-2xl bg-[#121620] p-5">
              <div className="text-sm text-slate-500">High Risk</div>
              <div className="mt-2 text-3xl font-bold text-red-400">
                {highRisk}
              </div>
            </div>
          </section>

          <section className="grid gap-5 lg:grid-cols-2">
            <ResultCard title="DNS Configuration" findings={firstColumnFindings} />
            <ResultCard title="TLS / HTTPS" findings={secondColumnFindings} />
            <ResultCard title="Security Headers" findings={thirdColumnFindings} />
            <ResultCard title="Email Security" findings={fourthColumnFindings} />
          </section>

          <section className="mt-6 rounded-2xl bg-[#121620] p-5 shadow-xl shadow-black/20">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="font-bold text-white">AI Security Analysis</h2>
              <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] font-bold text-emerald-300">
                AI Report
              </span>
            </div>

            <p className="rounded-xl bg-[#0b0e15] p-4 text-sm leading-6 text-slate-400">
              {result.summary ||
                "This assessment summarizes the domain security posture based on DNS, TLS, HTTP security headers, and email security configuration."}
            </p>

            <div className="mt-4 space-y-3">
              {result.findings.slice(0, 5).map((finding, index) => (
                <div
                  key={`${finding.id}-${index}`}
                  className="rounded-xl bg-[#0b0e15] p-4"
                >
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-lg bg-emerald-500/10 text-xs text-emerald-300">
                      {index + 1}
                    </div>

                    <div>
                      <div className="font-semibold text-slate-200">
                        {finding.title}
                      </div>
                      <div className="mt-1 text-xs leading-5 text-slate-500">
                        {finding.remediation ||
                          finding.evidence ||
                          "Review this item to improve the domain security posture."}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#080a10] text-slate-100">
      <div className="mx-auto min-h-screen w-full max-w-[1280px] bg-[#0d1018] px-8 py-6 shadow-2xl shadow-black/40">
        <nav className="mb-14 flex items-center justify-between text-[12px]">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-emerald-500/15 text-[11px] text-emerald-400">
              ◎
            </div>
            <span className="font-semibold text-slate-200">SecChecker</span>
          </div>

          <div className="flex gap-8 text-slate-400">
            <button
              onClick={() => setPageView("dashboard")}
              className="transition hover:text-emerald-400"
            >
              Dashboard
            </button>

            <button
              onClick={() => setPageView("history")}
              className="transition hover:text-emerald-400"
            >
              History
            </button>
          </div>
        </nav>

        <header className="mb-10 text-center">
          <h1 className="text-3xl font-bold tracking-tight text-white md:text-5xl">
            AI-Assisted Domain{" "}
            <span className="text-emerald-400">Security Checker</span>
          </h1>

          <p className="mx-auto mt-4 max-w-xl text-sm leading-6 text-slate-500">
            Scan any domain for DNS, TLS, security headers, and email
            configuration vulnerabilities.
          </p>
        </header>

        <section className="mb-6 rounded-3xl bg-[#141722] p-7 shadow-lg shadow-black/20">
          <div className="mb-5 flex items-start gap-4">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
              ◎
            </div>

            <div>
              <h2 className="text-lg font-semibold text-white">
                Domain Security Scanner
              </h2>
              <p className="mt-1 text-sm text-slate-500">
                Analyze DNS, TLS, headers & email security.
              </p>
            </div>
          </div>

          <form onSubmit={onScan} className="flex flex-col gap-3 md:flex-row">
            <div className="relative flex-1">
              <span className="absolute left-5 top-1/2 -translate-y-1/2 text-sm text-slate-500">
                ⌕
              </span>

              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="Enter domain e.g. example.com"
                className="h-14 w-full rounded-2xl border border-black/40 bg-[#080a10] pl-12 pr-4 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/10"
              />
            </div>

            <button
              disabled={loading}
              className="h-14 rounded-2xl bg-emerald-500 px-9 text-sm font-bold text-[#06110c] transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? "Scanning..." : "Scan"}
            </button>
          </form>

          {error && (
            <div className="mt-4 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">
              {error}
            </div>
          )}
        </section>

        <section className="mb-7 grid grid-cols-2 gap-4 md:grid-cols-4">
          <DashboardStat
            icon="⚡"
            label="Total Issues"
            value={totalIssues}
            color="cyan"
          />
          <DashboardStat
            icon="◎"
            label="Avg Score"
            value={avgScore}
            color="emerald"
          />
          <DashboardStat
            icon="⚠"
            label="High Risk"
            value={highRisk}
            color="red"
          />
          <DashboardStat
            icon="◈"
            label="Scans"
            value={history.length > 0 ? history.length : 2}
            color="emerald"
          />
        </section>

        <section>
          <div className="mb-4 flex items-center gap-2">
            <span className="text-sm text-slate-400">◎</span>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-300">
              Recent Scans
            </h2>
          </div>

          <div className="space-y-3">
            {history.length > 0 ? (
              history.map((item, index) => (
                <HistoryItem
                  key={`${item.scan_id}-${index}`}
                  domain={item.domain}
                  score={item.score}
                  grade={item.grade}
                  subtitle={`Score ${item.score}/100 · ${item.findings.length} issue(s)`}
                  onClick={() => {
                    setResult(item);
                    setPageView("result");
                  }}
                />
              ))
            ) : (
              <>
                <HistoryItem
                  domain="google.com"
                  subtitle="May 24, 2026 · 16:20"
                  score={92}
                  grade="A"
                />
                <HistoryItem
                  domain="github.com"
                  subtitle="May 24, 2026 · 16:21"
                  score={76}
                  grade="B"
                />
                <HistoryItem
                  domain="mfu.ac.th"
                  subtitle="May 24, 2026 · 16:22"
                  score={88}
                  grade="A"
                />
                <HistoryItem
                  domain="openai.com"
                  subtitle="May 24, 2026 · 16:23"
                  score={85}
                  grade="A"
                />
              </>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

function DashboardStat({
  icon,
  label,
  value,
  color,
}: {
  icon: string;
  label: string;
  value: number;
  color: "cyan" | "emerald" | "red";
}) {
  const colorClass =
    color === "cyan"
      ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-300"
      : color === "red"
      ? "border-red-500/30 bg-red-500/10 text-red-300"
      : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";

  return (
    <div className="rounded-2xl bg-[#141722] p-5 shadow-lg shadow-black/10">
      <div
        className={`mb-4 flex h-8 w-8 items-center justify-center rounded-lg border text-xs ${colorClass}`}
      >
        {icon}
      </div>

      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="mt-1 text-xs text-slate-500">{label}</div>
    </div>
  );
}

function HistoryItem({
  domain,
  subtitle,
  score,
  grade,
  onClick,
}: {
  domain: string;
  subtitle: string;
  score: number;
  grade: string;
  onClick?: () => void;
}) {
  const badgeClass = getGradeBadge(score);

  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center justify-between rounded-2xl bg-[#141722] px-5 py-4 text-left transition hover:bg-[#181c29]"
    >
      <div className="flex items-center gap-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#080a10] text-xs text-slate-400">
          ◎
        </div>

        <div>
          <div className="text-sm font-semibold text-slate-200">{domain}</div>
          <div className="mt-1 text-xs text-slate-600">{subtitle}</div>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <span
          className={`rounded-lg border px-3 py-1 text-xs font-bold ${badgeClass}`}
        >
          {grade}
        </span>
        <span className="text-slate-600">›</span>
      </div>
    </button>
  );
}

function ResultCard({
  title,
  findings,
}: {
  title: string;
  findings: ScanResponse["findings"];
}) {
  return (
    <div className="rounded-2xl bg-[#121620] p-5 shadow-xl shadow-black/20">
      <h2 className="mb-4 font-bold text-white">{title}</h2>

      <div className="space-y-3">
        {findings.length > 0 ? (
          findings.map((finding, index) => (
            <div
              key={`${finding.id}-${index}`}
              className="rounded-xl border border-white/5 bg-[#0b0e15] p-4"
            >
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-500/10 text-xs text-emerald-300">
                    ✓
                  </div>

                  <div>
                    <div className="text-sm font-semibold text-slate-200">
                      {finding.title}
                    </div>
                    {finding.evidence && (
                      <div className="mt-1 text-xs leading-5 text-slate-500">
                        {finding.evidence}
                      </div>
                    )}
                  </div>
                </div>

                <span
                  className={`shrink-0 rounded-lg border px-2 py-1 text-[10px] font-bold uppercase ${
                    severityStyle[finding.severity]
                  }`}
                >
                  {finding.severity}
                </span>
              </div>

              {finding.remediation && (
                <div className="mt-3 rounded-lg bg-[#111722] p-3 text-xs leading-5 text-slate-500">
                  <span className="font-semibold text-slate-300">Fix:</span>{" "}
                  {finding.remediation}
                </div>
              )}
            </div>
          ))
        ) : (
          <div className="rounded-xl border border-white/5 bg-[#0b0e15] p-4 text-sm text-slate-500">
            No findings in this category.
          </div>
        )}
      </div>
    </div>
  );
}