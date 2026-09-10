import type { ParsedNode, Protocol } from './types';
import { encodeBase64 } from './utils';

function streamSettings(node: ParsedNode) {
  const network = node.network || 'tcp';
  const security = node.security || 'none';
  const out: Record<string, any> = { network, security };
  if (security === 'tls') out.tlsSettings = {
    serverName: node.tls?.serverName,
    alpn: node.tls?.alpn,
    fingerprint: node.tls?.fingerprint,
    allowInsecure: node.tls?.insecure,
  };
  if (security === 'reality') out.realitySettings = {
    serverName: node.reality?.serverName,
    fingerprint: node.reality?.fingerprint,
    publicKey: node.reality?.publicKey,
    shortId: node.reality?.shortId,
    spiderX: node.reality?.spiderX,
  };
  if (network === 'ws') out.wsSettings = { path: node.transport?.path || '/', host: node.transport?.host };
  if (network === 'grpc') out.grpcSettings = { serviceName: node.transport?.serviceName || node.transport?.path || '', authority: node.transport?.authority, mode: node.transport?.mode };
  if (network === 'httpupgrade') out.httpupgradeSettings = { path: node.transport?.path || '/', host: node.transport?.host };
  if (network === 'xhttp') out.xhttpSettings = { path: node.transport?.path || '/', host: node.transport?.host, mode: node.transport?.mode };
  return out;
}

export function toXrayOutbound(node: ParsedNode) {
  if (node.protocol === 'hysteria2' || node.protocol === 'tuic') throw new Error(`${node.protocol} is not an Xray outbound protocol; export it as sing-box instead.`);
  switch (node.protocol) {
    case 'vless': return {
      protocol: 'vless', tag: node.name,
      settings: { vnext: [{ address: node.server, port: node.port, users: [{ id: node.userId, flow: node.flow, encryption: node.encryption || 'none' }] }] },
      streamSettings: streamSettings(node),
    };
    case 'vmess': return {
      protocol: 'vmess', tag: node.name,
      settings: { vnext: [{ address: node.server, port: node.port, users: [{ id: node.userId, security: node.encryption || 'auto' }] }] },
      streamSettings: streamSettings(node),
    };
    case 'trojan': return {
      protocol: 'trojan', tag: node.name,
      settings: { servers: [{ address: node.server, port: node.port, password: node.password }] },
      streamSettings: streamSettings(node),
    };
    case 'shadowsocks': return {
      protocol: 'shadowsocks', tag: node.name,
      settings: { servers: [{ address: node.server, port: node.port, method: node.method, password: node.password, uot: true }] },
    };
  }
}

function singboxTls(node: ParsedNode) {
  if (!node.tls && node.security !== 'tls' && node.security !== 'reality') return undefined;
  return {
    enabled: true,
    server_name: node.security === 'reality' ? node.reality?.serverName : node.tls?.serverName,
    insecure: node.security === 'reality' ? false : node.tls?.insecure,
    alpn: node.tls?.alpn,
    utls: node.tls?.fingerprint ? { enabled: true, fingerprint: node.tls.fingerprint } : undefined,
    reality: node.security === 'reality' ? {
      enabled: true, public_key: node.reality?.publicKey, short_id: node.reality?.shortId,
    } : undefined,
  };
}

export function toSingboxOutbound(node: ParsedNode) {
  const base: Record<string, any> = { tag: node.name, server: node.server, server_port: node.port };
  switch (node.protocol) {
    case 'vless': return { type: 'vless', ...base, uuid: node.userId, flow: node.flow || undefined, tls: singboxTls(node), packet_encoding: 'xudp' };
    case 'vmess': return { type: 'vmess', ...base, uuid: node.userId, security: node.encryption || 'auto', alter_id: 0, tls: singboxTls(node) };
    case 'trojan': return { type: 'trojan', ...base, password: node.password, tls: singboxTls(node) };
    case 'shadowsocks': return { type: 'shadowsocks', ...base, method: node.method, password: node.password };
    case 'hysteria2': return { type: 'hysteria2', ...base, password: node.password, tls: singboxTls(node), up_mbps: toNumber(node.extras.up_mbps), down_mbps: toNumber(node.extras.down_mbps) };
    case 'tuic': return { type: 'tuic', ...base, uuid: node.userId, password: node.password, congestion_control: node.extras.congestion_control || 'bbr', udp_relay_mode: node.extras.udp_relay_mode || 'native', tls: singboxTls(node) };
  }
}

function toNumber(v?: string): number | undefined { if (!v) return undefined; const n = Number(v); return Number.isFinite(n) ? n : undefined; }

function query(params: Record<string, string | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') q.set(k, v);
  return q.toString();
}

export function nodeToLink(node: ParsedNode): string {
  const hash = encodeURIComponent(node.name);
  if (node.protocol === 'vmess') {
    const obj = { v: '2', ps: node.name, add: node.server, port: String(node.port), id: node.userId || '', aid: '0', scy: node.encryption || 'auto', net: node.network || 'tcp', type: node.transport?.mode || 'none', host: node.transport?.host || '', path: node.transport?.path || '', tls: node.security === 'tls' ? 'tls' : '', sni: node.tls?.serverName || '' };
    return `vmess://${encodeBase64(JSON.stringify(obj))}`;
  }
  if (node.protocol === 'shadowsocks') {
    const user = `${node.method || ''}:${node.password || ''}`;
    return `ss://${encodeBase64(user)}@${node.server}:${node.port}#${hash}`;
  }
  if (node.protocol === 'vless') {
    const q = query({ type: node.network, security: node.security, encryption: node.encryption || 'none', flow: node.flow, sni: node.security === 'reality' ? node.reality?.serverName : node.tls?.serverName, fp: node.security === 'reality' ? node.reality?.fingerprint : node.tls?.fingerprint, pbk: node.reality?.publicKey, sid: node.reality?.shortId, spx: node.reality?.spiderX, path: node.transport?.path, host: node.transport?.host, serviceName: node.transport?.serviceName, authority: node.transport?.authority, mode: node.transport?.mode });
    return `vless://${encodeURIComponent(node.userId || '')}@${node.server}:${node.port}?${q}#${hash}`;
  }
  if (node.protocol === 'trojan') {
    const q = query({ type: node.network, security: node.security, sni: node.tls?.serverName || node.reality?.serverName, fp: node.tls?.fingerprint || node.reality?.fingerprint, pbk: node.reality?.publicKey, sid: node.reality?.shortId, path: node.transport?.path, host: node.transport?.host, serviceName: node.transport?.serviceName, authority: node.transport?.authority, mode: node.transport?.mode });
    return `trojan://${encodeURIComponent(node.password || '')}@${node.server}:${node.port}?${q}#${hash}`;
  }
  if (node.protocol === 'hysteria2') return `hysteria2://${encodeURIComponent(node.password || '')}@${node.server}:${node.port}?${query({ sni: node.tls?.serverName, insecure: node.tls?.insecure ? '1' : undefined })}#${hash}`;
  return `tuic://${encodeURIComponent(node.userId || '')}:${encodeURIComponent(node.password || '')}@${node.server}:${node.port}?${query({ sni: node.tls?.serverName, insecure: node.tls?.insecure ? '1' : undefined, congestion_control: node.extras.congestion_control, udp_relay_mode: node.extras.udp_relay_mode })}#${hash}`;
}

export function buildXrayConfig(nodes: ParsedNode[]) {
  const outbounds = nodes.filter(n => ['vless', 'vmess', 'trojan', 'shadowsocks'].includes(n.protocol)).map(toXrayOutbound);
  return {
    log: { loglevel: 'warning' },
    inbounds: [
      { tag: 'socks', listen: '127.0.0.1', port: 10808, protocol: 'socks', settings: { udp: true } },
      { tag: 'http', listen: '127.0.0.1', port: 10809, protocol: 'http', settings: {} },
    ],
    outbounds: [...outbounds, { tag: 'DIRECT', protocol: 'freedom' }, { tag: 'BLOCK', protocol: 'blackhole' }],
  };
}

export function buildSingboxConfig(nodes: ParsedNode[]) {
  return {
    log: { level: 'warn' },
    inbounds: [
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
    ],
    outbounds: [...nodes.map(toSingboxOutbound), { type: 'direct', tag: 'direct' }, { type: 'block', tag: 'block' }],
    route: { auto_detect_interface: true },
  };
}
