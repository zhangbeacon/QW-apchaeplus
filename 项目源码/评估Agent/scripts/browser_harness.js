#!/usr/bin/env node
/**
 * browser_harness.js —— CDP 浏览器取证钩子（零依赖，Node >= 21）
 *
 * 用途：接管一个已登录的 Chrome（--remote-debugging-port），在不改页面逻辑的前提下
 * 观察真实请求（URL / 方法 / 头部 / 请求体）、读取会话 Cookie、执行诊断脚本。
 *
 * 用法：
 *   node browser_harness.js <port> list
 *   node browser_harness.js <port> info      <targetId>
 *   node browser_harness.js <port> cookies   <targetId> [origin]
 *   node browser_harness.js <port> hook      <targetId> [seconds]
 *   node browser_harness.js <port> eval      <targetId> <exprFile>
 *
 * 设计约束：
 *   - 仅连接调用方显式给出的本地 CDP 端口；
 *   - 不做持久化，不落盘 Cookie 明文以外的敏感数据（默认输出到 stdout，由调用方决定保存策略）；
 *   - 只读：不导航、不点击写操作，除非调用方传入自定义表达式。
 */

const http = require('http');

const [port, cmd, targetId, arg] = process.argv.slice(2);

function cdps(port, path) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, res => {
      let buf = '';
      res.on('data', d => (buf += d));
      res.on('end', () => {
        try { resolve(JSON.parse(buf)); } catch (e) { reject(new Error('bad json: ' + buf.slice(0, 200))); }
      });
    }).on('error', reject);
  });
}

async function openWs(port, id) {
  const list = await cdps(port, '/json');
  const t = list.find(x => x.id === id);
  if (!t) throw new Error('target not found: ' + id);
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(t.webSocketDebuggerUrl);
    let seq = 0;
    const pending = new Map();
    ws.onopen = () => resolve({
      send(method, params = {}) {
        return new Promise((res, rej) => {
          const n = ++seq;
          pending.set(n, { res, rej });
          ws.send(JSON.stringify({ id: n, method, params }));
        });
      },
      close() { ws.close(); },
    });
    ws.onmessage = ev => {
      const m = JSON.parse(ev.data);
      if (m.id && pending.has(m.id)) {
        const p = pending.get(m.id);
        pending.delete(m.id);
        m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result);
      }
    };
    ws.onerror = e => reject(new Error('ws error'));
  });
}

const HOOK = `(async () => {
  const log = window.__harness_log = window.__harness_log || [];
  if (!window.__harness_hooked) {
    window.__harness_hooked = true;
    const OX = XMLHttpRequest.prototype.open, OS = XMLHttpRequest.prototype.send, OH = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.open = function (m, u) { this.__m = m; this.__u = u; return OX.apply(this, arguments); };
    XMLHttpRequest.prototype.setRequestHeader = function (k, v) { (this.__h = this.__h || {})[k] = v; return OH.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function (b) {
      try { log.push({ t: 'xhr', m: this.__m, u: this.__u, h: this.__h, b: typeof b === 'string' ? b.slice(0, 2000) : null }); } catch (e) {}
      return OS.apply(this, arguments);
    };
    if (window.fetch) {
      const OF = window.fetch;
      window.fetch = function (...a) {
        try {
          const req = a[0], opts = a[1] || {};
          log.push({ t: 'fetch', u: (req && req.url) || String(req).slice(0, 300), m: (opts.method || 'GET'), b: opts.body ? String(opts.body).slice(0, 2000) : null });
        } catch (e) {}
        return OF.apply(this, arguments);
      };
    }
  }
  return 'hooked';
})()`;

(async () => {
  try {
    if (!port || !cmd) { console.error('usage: node browser_harness.js <port> <list|info|cookies|hook|eval> [targetId] [arg]'); process.exit(2); }

    if (cmd === 'list') {
      const list = await cdps(port, '/json');
      for (const t of list.filter(x => x.type === 'page')) {
        console.log(`${t.id}\t${t.title}\t${t.url}`);
      }
      return;
    }

    const ws = await openWs(port, targetId);

    if (cmd === 'info') {
      const r = await ws.send('Runtime.evaluate', { expression: 'JSON.stringify({url:location.href,title:document.title})', returnByValue: true });
      console.log(r.result.value);
    } else if (cmd === 'cookies') {
      const origin = arg || null;
      const params = origin ? { urls: [origin] } : {};
      const r = await ws.send('Network.getCookies', params);
      for (const c of r.cookies) console.log(`${c.name}=${c.value}`);
    } else if (cmd === 'hook') {
      const seconds = Number(arg || 20);
      await ws.send('Runtime.evaluate', { expression: HOOK, awaitPromise: true, returnByValue: true });
      await new Promise(r => setTimeout(r, seconds * 1000));
      const r = await ws.send('Runtime.evaluate', { expression: 'JSON.stringify(window.__harness_log)', returnByValue: true });
      console.log(r.result.value);
    } else if (cmd === 'eval') {
      const fs = require('fs');
      const expr = fs.readFileSync(arg, 'utf8');
      const r = await ws.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) { console.error(JSON.stringify(r.exceptionDetails).slice(0, 800)); process.exit(1); }
      console.log(r.result.value !== undefined ? r.result.value : JSON.stringify(r));
    } else {
      console.error('unknown command: ' + cmd);
      process.exit(2);
    }
    ws.close();
    process.exit(0);
  } catch (e) {
    console.error('ERR: ' + e.message);
    process.exit(1);
  }
})();
