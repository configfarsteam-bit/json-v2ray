import { useMemo, useState } from 'react';
import { buildSingboxConfig, buildXrayConfig, nodeToLink, parseInput } from './core';
import type { ParsedNode, ParseResult } from './core';
import { Stat } from './components/Stat';

const demo = `vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws&security=tls&sni=example.com&path=%2Fws&host=example.com#Demo%20VLESS\n`;

function App() {
  const [input, setInput] = useState('');
  const [format, setFormat] = useState<'xray' | 'singbox' | 'links'>('xray');
  const [lang, setLang] = useState<'en' | 'fa'>('en');
  const [theme, setTheme] = useState<'dark' | 'light'>(() => (localStorage.getItem('vcs-theme') as any) || 'dark');
  const [dedupe, setDedupe] = useState(true);
  const results = useMemo(() => parseInput(input), [input]);
  const nodes = useMemo(() => {
    const valid = results.filter(r => r.ok && r.node).map(r => r.node!)
    if (!dedupe) return valid;
    const seen = new Set<string>();
    return valid.filter(n => { const k = `${n.protocol}|${n.server}|${n.port}|${n.userId || n.password || ''}|${n.name}`; if (seen.has(k)) return false; seen.add(k); return true; });
  }, [results, dedupe]);
  const errors = results.filter(r => !r.ok).length;
  const warnings = results.reduce((n, r) => n + r.issues.filter(i => i.level === 'warning').length, 0);
  const output = useMemo(() => {
    if (!nodes.length) return '';
    if (format === 'links') return nodes.map(nodeToLink).join('\n');
    const data = format === 'xray' ? buildXrayConfig(nodes) : buildSingboxConfig(nodes);
    return JSON.stringify(data, null, 2);
  }, [nodes, format]);
  const t = lang === 'fa' ? {
    title: 'V2Ray Config Studio', subtitle: 'پارسر، اعتبارسنج و مبدل کانفیگ — کاملاً لوکال', input: 'ورودی لینک‌ها', parse: 'پردازش خودکار', output: 'خروجی', copy: 'کپی', download: 'دانلود', clear: 'پاک کردن', demo: 'نمونه', nodes: 'نودها', errors: 'خطاها', warnings: 'هشدارها', dedupe: 'حذف موارد تکراری', xray: 'Xray JSON', singbox: 'Sing-box JSON', links: 'Share Links', protocol: 'پروتکل', server: 'سرور', port: 'پورت'
  } : {
    title: 'V2Ray Config Studio', subtitle: 'Parser, validator and converter — privacy-first & local', input: 'Input links', parse: 'Auto parse', output: 'Output', copy: 'Copy', download: 'Download', clear: 'Clear', demo: 'Demo', nodes: 'Nodes', errors: 'Errors', warnings: 'Warnings', dedupe: 'Remove duplicates', xray: 'Xray JSON', singbox: 'Sing-box JSON', links: 'Share Links', protocol: 'Protocol', server: 'Server', port: 'Port'
  };
  const isRtl = lang === 'fa';
  const changeTheme = () => { const next = theme === 'dark' ? 'light' : 'dark'; setTheme(next); localStorage.setItem('vcs-theme', next); };
  async function copyOutput() { if (output) await navigator.clipboard.writeText(output); }
  function downloadOutput() {
    if (!output) return;
    const ext = format === 'links' ? 'txt' : 'json';
    const blob = new Blob([output], { type: ext === 'json' ? 'application/json' : 'text/plain' });
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `v2ray-config-studio.${ext}`; a.click(); URL.revokeObjectURL(url);
  }
  function loadDemo() { setInput(demo); }
  return <div className={`app ${theme}`} dir={isRtl ? 'rtl' : 'ltr'}>
    <header className="topbar"><div className="brand"><div className="logo">V</div><div><div className="brand-title">{t.title}</div><div className="brand-subtitle">{t.subtitle}</div></div></div><div className="toolbar"><button onClick={() => setLang(lang === 'en' ? 'fa' : 'en')}>{lang === 'en' ? 'FA' : 'EN'}</button><button onClick={changeTheme}>{theme === 'dark' ? '☀️' : '🌙'}</button><a href="https://github.com/irOblivionSpark/v2ray-link-parser" target="_blank" rel="noreferrer">GitHub ↗</a></div></header>
    <main className="shell">
      <section className="hero"><div><span className="badge">v2.0 architecture</span><h1>{t.parse}</h1><p>VLESS · VMess · Trojan · Shadowsocks · Hysteria2 · TUIC</p></div><button className="secondary" onClick={loadDemo}>{t.demo}</button></section>
      <div className="stats"><Stat label={t.nodes} value={nodes.length} icon="◉"/><Stat label={t.errors} value={errors} icon="⚠"/><Stat label={t.warnings} value={warnings} icon="!"/><Stat label="Privacy" value="Local" icon="⌁"/></div>
      <section className="grid">
        <div className="panel"><div className="panel-head"><div><h2>{t.input}</h2><span>One link per line</span></div><div className="actions"><button onClick={loadDemo}>{t.demo}</button><button onClick={() => setInput('')}>{t.clear}</button></div></div>
          <textarea value={input} onChange={e => setInput(e.target.value)} placeholder="vless://...\nvmess://...\ntrojan://...\nss://...\nhysteria2://...\ntuic://..." spellCheck={false}/>
          <div className="under-input"><label><input type="checkbox" checked={dedupe} onChange={e => setDedupe(e.target.checked)}/>{t.dedupe}</label><span>{results.length} lines</span></div>
        </div>
        <div className="panel"><div className="panel-head"><div><h2>{t.output}</h2><span>{format === 'links' ? 'Rebuilt share links' : format === 'xray' ? 'Xray Core configuration' : 'sing-box configuration'}</span></div><div className="actions"><button onClick={copyOutput} disabled={!output}>{t.copy}</button><button onClick={downloadOutput} disabled={!output}>{t.download}</button></div></div>
          <div className="tabs"><button className={format === 'xray' ? 'active' : ''} onClick={() => setFormat('xray')}>{t.xray}</button><button className={format === 'singbox' ? 'active' : ''} onClick={() => setFormat('singbox')}>{t.singbox}</button><button className={format === 'links' ? 'active' : ''} onClick={() => setFormat('links')}>{t.links}</button></div>
          <pre className="output"><code>{output || '// Parse one or more links to generate output.'}</code></pre>
        </div>
      </section>
      <section className="panel results-panel"><div className="panel-head"><div><h2>Validation & nodes</h2><span>Transparent parsing feedback</span></div></div>
        <div className="table-wrap"><table><thead><tr><th>#</th><th>{t.protocol}</th><th>Name</th><th>{t.server}</th><th>{t.port}</th><th>Status</th></tr></thead><tbody>{results.length ? results.map((r: ParseResult) => <ResultRow key={r.index} result={r}/>) : <tr><td colSpan={6} className="empty">Paste links above to begin.</td></tr>}</tbody></table></div>
      </section>
      <footer>Built for local parsing. No configuration is uploaded by this frontend. • MIT-compatible architecture</footer>
    </main>
  </div>
}

function ResultRow({ result }: { result: ParseResult }) {
  const n: ParsedNode | undefined = result.node;
  const problems = result.issues.map(i => `${i.level}: ${i.message}`).join(' | ');
  return <tr><td>{result.index + 1}</td><td><span className="chip">{n?.protocol || 'unknown'}</span></td><td className="name-cell">{n?.name || '—'}</td><td>{n?.server || '—'}</td><td>{n?.port || '—'}</td><td>{result.ok ? <span className={`status ${result.issues.length ? 'warn' : 'ok'}`}>{result.issues.length ? '✓ parsed / review' : '✓ parsed'}</span> : <span className="status bad" title={problems}>✕ failed</span>}</td></tr>;
}

export default App;
