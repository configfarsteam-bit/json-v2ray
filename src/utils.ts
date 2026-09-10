export function decodeBase64(input: string): string {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function encodeBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function safeDecodeURIComponent(input: string): string {
  try { return decodeURIComponent(input); } catch { return input; }
}

export function getHashName(url: URL, fallback: string): string {
  const value = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash;
  return safeDecodeURIComponent(value) || fallback;
}

export function parseBool(value: string | null): boolean | undefined {
  if (value === null) return undefined;
  return value === '1' || value === 'true';
}

export function csv(value: string | null | undefined): string[] | undefined {
  if (!value) return undefined;
  return value.split(',').map(v => v.trim()).filter(Boolean);
}

export function quoteName(name: string): string { return encodeURIComponent(name); }

export function uniqueBy<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    const k = key(item);
    if (!seen.has(k)) { seen.add(k); out.push(item); }
  }
  return out;
}
