// Thin API client – Vite proxy forwards /api/* to FastAPI on :8000 in dev.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";
export type ScanMode = "single" | "full";

export interface Finding {
  id: string;
  category: "tls" | "headers" | "email" | "dns";
  title: string;
  severity: Severity;
  passed: boolean;
  evidence: string;
  remediation: string;
}

export interface CheckScoreInfo {
  id: string;
  weight: number;
  earned: number;
  passed: boolean;
  present: boolean;
}

export interface CategoryScore {
  name: "tls" | "headers" | "email" | "dns";
  earned: number;
  max: number;
  checks: CheckScoreInfo[];
}

export interface HostResult {
  host: string;
  ip: string;
  score: number;
  grade: Grade;
  breakdown: CategoryScore[];
  findings: Finding[];
  // Geo-IP (populated by backend in mode="full")
  location: string | null;
  isp: string | null;
  asn: string | null;
  // Port scan (populated by backend in mode="full")
  open_ports: number[];
}

export interface AiSummary {
  risk_summary: string;
  top_issues: string[];
  positive_findings: string[];
}

export interface VersionInfo {
  app: string;
  model: string;
  rubric?: number;
}

export interface ScanResponse {
  scan_id: string;
  domain: string;
  mode: ScanMode;
  score: number;
  grade: Grade;
  summary: string;
  findings: Finding[];
  breakdown: CategoryScore[];
  version: VersionInfo;
  // multi-host (mode="full") — safe fallbacks applied in scanDomain()
  hosts: HostResult[];
  domain_score: number | null;
  domain_grade: Grade | null;
  domain_avg_score: number | null;
  hosts_scanned: number;
  hosts_failed: number;
  // AI Risk Analyzer output (mode="full", null if OPENAI_API_KEY unset)
  ai_summary: AiSummary | null;
  scanned_at: string; // injected client-side
}

export async function scanDomain(
  domain: string,
  mode: ScanMode = "single"
): Promise<ScanResponse> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, mode }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(
      err.detail?.[0]?.msg ?? err.detail ?? `HTTP ${res.status}`
    );
  }
  const data = await res.json();
  // Inject client-side timestamp + safe fallbacks for optional fields
  return {
    hosts: [],
    domain_score: null,
    domain_grade: null,
    domain_avg_score: null,
    hosts_scanned: 0,
    hosts_failed: 0,
    ai_summary: null,
    ...data,
    scanned_at: new Date().toISOString(),
  } as ScanResponse;
}

// ─────────────────────────── scan history (server DB) ───────────────────────

export interface ScanHistoryItem {
  scan_id: string;
  domain: string;
  mode: ScanMode;
  score: number;
  grade: Grade;
  findings_count: number;
  created_at: string;
}

function withFallbacks(data: Record<string, unknown>): ScanResponse {
  return {
    hosts: [],
    domain_score: null,
    domain_grade: null,
    domain_avg_score: null,
    hosts_scanned: 0,
    hosts_failed: 0,
    ai_summary: null,
    ...data,
    scanned_at: new Date().toISOString(),
  } as unknown as ScanResponse;
}

// List recent scans (newest first).
export async function listScans(): Promise<ScanHistoryItem[]> {
  const res = await fetch("/api/scans");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// Fetch one stored scan's full result.
export async function getScan(scanId: string): Promise<ScanResponse> {
  const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return withFallbacks(await res.json());
}

// Delete one stored scan.
export async function deleteScan(scanId: string): Promise<void> {
  const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}
