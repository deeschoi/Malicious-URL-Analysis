/** Visitor-supplied Groq key. sessionStorage so it dies with the tab. */

const STORAGE_KEY = "sphinx.groqApiKey";

function store(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function getGroqApiKey(): string {
  return store()?.getItem(STORAGE_KEY)?.trim() ?? "";
}

export function setGroqApiKey(key: string): void {
  const value = key.trim();
  const session = store();
  if (!session) return;
  if (value) session.setItem(STORAGE_KEY, value);
  else session.removeItem(STORAGE_KEY);
}

export function clearGroqApiKey(): void {
  store()?.removeItem(STORAGE_KEY);
}
