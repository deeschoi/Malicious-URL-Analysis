export function errorMessage(payload: unknown, fallback = "Request failed."): string {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail: unknown }).detail;
    if (typeof detail === "string" && detail.trim()) return detail;
    if (Array.isArray(detail)) {
      const parts = detail
        .map((item) =>
          item && typeof item === "object" && "msg" in item
            ? String((item as { msg: unknown }).msg)
            : "",
        )
        .filter(Boolean);
      if (parts.length) return parts.join("; ");
    }
  }
  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(path, { ...init, headers });
  const payload: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(errorMessage(payload, response.statusText || "Request failed."));
  }
  return payload as T;
}

export function scanUrl(url: string, timeout = 8) {
  return request<import("./types").ScanResult>("/api/scan", {
    method: "POST",
    body: JSON.stringify({ url, timeout }),
  });
}

export function fetchFindings() {
  return request<import("./types").Findings>("/api/findings");
}

export function fetchScans(limit = 50, offset = 0) {
  return request<import("./types").ScanList>(`/api/scans?limit=${limit}&offset=${offset}`);
}

export function fetchStats(days = 30) {
  return request<import("./types").ScanStats>(`/api/stats?days=${days}`);
}
