// Thin API client. Vite proxy forwards /api/* to FastAPI on :8000 in dev.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  category: "tls" | "headers" | "email" | "dns";
  title: string;
  severity: Severity;
  passed: boolean;
  evidence: string;
  remediation: string;
}

export interface ScanResponse {
  scan_id: string;
  domain: string;
  score: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  summary: string;
  findings: Finding[];
  version: { app: string; model: string };
}

export async function scanDomain(domain: string): Promise<ScanResponse> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail?.[0]?.msg ?? `HTTP ${res.status}`);
  }
  return res.json();
}
