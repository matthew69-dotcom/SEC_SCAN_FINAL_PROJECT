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
    ...data,
    scanned_at: new Date().toISOString(),
  } as ScanResponse;
}
