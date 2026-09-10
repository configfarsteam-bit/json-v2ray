import type { ParseIssue, ParseResult, ParsedNode, Protocol } from './types';
import { csv, decodeBase64, getHashName, parseBool, safeDecodeURIComponent } from './utils';

function issue(message: string, level: 'error' | 'warning' = 'error', field?: string): ParseIssue {
  return { level, message, field };
}

function requirePort(url: URL): number {
  const port = Number(url.port || '443');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
  return port;
}

function commonTls(url: URL): ParsedNode['tls'] {
  return {
    serverName: url.searchParams.get('sni') || undefined,
    fingerprint: url.searchParams.get('fp') || undefined,
    insecure: parseBool(url.searchParams.get('allowInsecure') ?? url.searchParams.get('insecure')),
    alpn: csv(url.searchParams.get('alpn')),
  };
}

function parseVless(url: URL, raw: string): ParsedNode {
  const userId = decodeURIComponent(url.username);
  if (!userId) throw new Error('VLESS UUID is missing');
  const network = (url.searchParams.get('type') || 'tcp') as ParsedNode['network'];
  const security = (url.searchParams.get('security') || 'none') as ParsedNode['security'];
  const node: ParsedNode = {
    protocol: 'vless', name: getHashName(url, `VLESS • ${url.hostname}`), server: url.hostname,
    port: requirePort(url), userId, flow: url.searchParams.get('flow') || undefined,
    encryption: url.searchParams.get('encryption') || 'none', security, network,
    raw, tls: security === 'tls' ? commonTls(url) : undefined,
    reality: security === 'reality' ? {
      publicKey: url.searchParams.get('pbk') || undefined,
      shortId: url.searchParams.get('sid') || undefined,
      serverName: url.searchParams.get('sni') || undefined,
      fingerprint: url.searchParams.get('fp') || undefined,
      spiderX: url.searchParams.get('spx') || undefined,
    } : undefined,
    transport: {
      path: url.searchParams.get('path') || undefined,
      host: url.searchParams.get('host') || undefined,
      serviceName: url.searchParams.get('serviceName') || undefined,
      authority: url.searchParams.get('authority') || undefined,
      mode: url.searchParams.get('mode') || undefined,
    },
    extras: Object.fromEntries(url.searchParams.entries()),
  };
  return node;
}

function parseTrojan(url: URL, raw: string): ParsedNode {
  const password = safeDecodeURIComponent(url.username);
  if (!password) throw new Error('Trojan password is missing');
  const security = (url.searchParams.get('security') || 'tls') as ParsedNode['security'];
  const network = (url.searchParams.get('type') || 'tcp') as ParsedNode['network'];
  return {
    protocol: 'trojan', name: getHashName(url, `Trojan • ${url.hostname}`), server: url.hostname,
    port: requirePort(url), password, security, network,
    tls: security === 'tls' ? commonTls(url) : undefined,
    reality: security === 'reality' ? {
      publicKey: url.searchParams.get('pbk') || undefined,
      shortId: url.searchParams.get('sid') || undefined,
      serverName: url.searchParams.get('sni') || undefined,
      fingerprint: url.searchParams.get('fp') || undefined,
      spiderX: url.searchParams.get('spx') || undefined,
    } : undefined,
    raw,
    transport: {
      path: url.searchParams.get('path') || undefined,
      host: url.searchParams.get('host') || undefined,
      serviceName: url.searchParams.get('serviceName') || undefined,
      authority: url.searchParams.get('authority') || undefined,
      mode: url.searchParams.get('mode') || undefined,
    },
    extras: Object.fromEntries(url.searchParams.entries()),
  };
}

function parseShadowsocks(url: URL, raw: string): ParsedNode {
  let method = '';
  let password = '';
  const username = url.username;
  if (url.password !== undefined) {
    method = safeDecodeURIComponent(username);
    password = safeDecodeURIComponent(url.password);
  } else if (username.includes(':')) {
    const decoded = safeDecodeURIComponent(username);
    const split = decoded.indexOf(':');
    method = decoded.slice(0, split);
    password = decoded.slice(split + 1);
  } else {
    const decoded = decodeBase64(username);
    const split = decoded.indexOf(':');
    if (split < 1) throw new Error('Invalid Shadowsocks credentials');
    method = decoded.slice(0, split);
    password = decoded.slice(split + 1);
  }
  if (!method || !password) throw new Error('Shadowsocks method/password is missing');
  return {
    protocol: 'shadowsocks', name: getHashName(url, `SS • ${url.hostname}`), server: url.hostname,
    port: requirePort(url), method, password, udp: parseBool(url.searchParams.get('udp')) ?? true,
    raw, extras: Object.fromEntries(url.searchParams.entries()),
  };
}

function parseVmess(raw: string): ParsedNode {
  const encoded = raw.slice(raw.indexOf('://') + 3).trim();
  const jsonText = decodeBase64(encoded);
  const json = JSON.parse(jsonText) as Record<string, any>;
  const network = (json.net || 'tcp') as ParsedNode['network'];
  const security = (json.tls || 'none') as ParsedNode['security'];
  const server = String(json.add || json.address || '');
  if (!server) throw new Error('VMess server is missing');
  const port = Number(json.port || 443);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid VMess port');
  const alpn = typeof json.alpn === 'string' ? json.alpn.split(',').map((v: string) => v.trim()).filter(Boolean) : undefined;
  return {
    protocol: 'vmess', name: String(json.ps || `VMess • ${server}`), server, port,
    userId: String(json.id || ''), encryption: String(json.scy || 'auto'), security, network,
    tls: security === 'tls' ? {
      serverName: json.sni || undefined, fingerprint: json.fp || undefined,
      insecure: Boolean(json.allowInsecure), alpn,
    } : undefined,
    transport: {
      path: json.path || undefined, host: json.host || undefined,
      serviceName: json.path || undefined, mode: json.type || undefined,
    },
    raw, extras: Object.fromEntries(Object.entries(json).map(([k, v]) => [k, String(v ?? '')])),
  };
}

function parseHysteria2(url: URL, raw: string): ParsedNode {
  const password = safeDecodeURIComponent(url.username || '');
  if (!password) throw new Error('Hysteria2 password is missing');
  return {
    protocol: 'hysteria2', name: getHashName(url, `Hysteria2 • ${url.hostname}`), server: url.hostname,
    port: requirePort(url), password, security: 'tls', network: 'quic',
    tls: { serverName: url.searchParams.get('sni') || undefined, insecure: parseBool(url.searchParams.get('insecure')) ?? false },
    udp: true, raw, extras: Object.fromEntries(url.searchParams.entries()),
  };
}

function parseTuic(url: URL, raw: string): ParsedNode {
  const userId = safeDecodeURIComponent(url.username || '');
  const password = safeDecodeURIComponent(url.password || '');
  if (!userId || !password) throw new Error('TUIC UUID/password is missing');
  return {
    protocol: 'tuic', name: getHashName(url, `TUIC • ${url.hostname}`), server: url.hostname,
    port: requirePort(url), userId, password, security: 'tls', network: 'quic', udp: true,
    tls: { serverName: url.searchParams.get('sni') || undefined, insecure: parseBool(url.searchParams.get('insecure')) ?? false },
    raw, extras: Object.fromEntries(url.searchParams.entries()),
  };
}

export function detectProtocol(raw: string): Protocol | null {
  const scheme = raw.trim().split('://', 1)[0].toLowerCase();
  const map: Record<string, Protocol> = { vless: 'vless', vmess: 'vmess', trojan: 'trojan', ss: 'shadowsocks', hysteria2: 'hysteria2', hy2: 'hysteria2', tuic: 'tuic' };
  return map[scheme] ?? null;
}

export function parseLink(raw: string, index = 0): ParseResult {
  const text = raw.trim();
  if (!text) return { index, raw, ok: false, issues: [issue('Empty line')] };
  const protocol = detectProtocol(text);
  if (!protocol) return { index, raw, ok: false, issues: [issue('Unsupported protocol')] };
  try {
    const node = protocol === 'vmess' ? parseVmess(text) :
      protocol === 'vless' ? parseVless(new URL(text), text) :
      protocol === 'trojan' ? parseTrojan(new URL(text), text) :
      protocol === 'shadowsocks' ? parseShadowsocks(new URL(text), text) :
      protocol === 'hysteria2' ? parseHysteria2(new URL(text.replace(/^hy2:\/\//i, 'hysteria2://')), text) :
      parseTuic(new URL(text), text);
    return { index, raw, ok: true, node, issues: validateNode(node) };
  } catch (error) {
    return { index, raw, ok: false, issues: [issue(error instanceof Error ? error.message : 'Failed to parse')] };
  }
}

export function parseInput(text: string): ParseResult[] {
  return text.split(/\r?\n/).map((line, i) => parseLink(line, i)).filter(r => r.raw.trim() !== '');
}

export function validateNode(node: ParsedNode): ParseIssue[] {
  const issues: ParseIssue[] = [];
  if (!node.server) issues.push(issue('Server is missing', 'error', 'server'));
  if (node.port < 1 || node.port > 65535) issues.push(issue('Port is out of range', 'error', 'port'));
  if ((node.protocol === 'vless' || node.protocol === 'vmess') && !node.userId) issues.push(issue('UUID is missing', 'warning', 'userId'));
  if (node.protocol === 'shadowsocks' && !node.method) issues.push(issue('Encryption method is missing', 'warning', 'method'));
  if (node.security === 'reality') {
    if (!node.reality?.publicKey) issues.push(issue('Reality public key is missing', 'warning', 'pbk'));
    if (!node.reality?.serverName) issues.push(issue('Reality SNI is missing', 'warning', 'sni'));
  }
  if (node.security === 'tls' && !node.tls?.serverName) issues.push(issue('TLS SNI is not set', 'warning', 'sni'));
  return issues;
}
