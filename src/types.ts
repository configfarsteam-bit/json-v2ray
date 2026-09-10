export type Protocol = 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'tuic';
export type Security = 'none' | 'tls' | 'reality';
export type Network = 'tcp' | 'ws' | 'grpc' | 'httpupgrade' | 'xhttp' | 'kcp' | 'quic';

export interface ParsedNode {
  protocol: Protocol;
  name: string;
  server: string;
  port: number;
  userId?: string;
  password?: string;
  method?: string;
  flow?: string;
  encryption?: string;
  security?: Security;
  network?: Network;
  tls?: {
    serverName?: string;
    fingerprint?: string;
    insecure?: boolean;
    alpn?: string[];
  };
  reality?: {
    publicKey?: string;
    shortId?: string;
    serverName?: string;
    fingerprint?: string;
    spiderX?: string;
  };
  transport?: {
    path?: string;
    host?: string;
    serviceName?: string;
    authority?: string;
    mode?: string;
  };
  udp?: boolean;
  raw: string;
  extras: Record<string, string>;
}

export interface ParseIssue {
  level: 'error' | 'warning';
  message: string;
  field?: string;
}

export interface ParseResult {
  index: number;
  raw: string;
  ok: boolean;
  node?: ParsedNode;
  issues: ParseIssue[];
}
