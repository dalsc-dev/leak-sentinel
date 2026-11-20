/**
 * server.js
 * Local HTTP server hosting the LeakSentinel dark-mode audit dashboard and live probe API.
 */

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exec } from 'node:child_process';
import { formatMarkdownReport } from './score-calculator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export function createRequestHandler(getReport, onRecheck, onWebrtcUpdate, webUiHtml) {
  return async function handleRequest(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const host = (req.headers && req.headers.host) || 'localhost';
    const url = new URL(req.url, `http://${host}`);
    const pathname = url.pathname;

    // Root UI
    if (pathname === '/' || pathname === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(webUiHtml);
      return;
    }

    // JSON Audit Report
    if (pathname === '/api/audit') {
      const report = await getReport();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(report, null, 2));
      return;
    }

    // Live Recheck
    if (pathname === '/api/recheck') {
      const report = onRecheck ? await onRecheck() : await getReport();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(report, null, 2));
      return;
    }

    // Export Markdown Report
    if (pathname === '/api/export') {
      const report = await getReport();
      const md = formatMarkdownReport(report);
      res.writeHead(200, {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Disposition': 'attachment; filename="leak-sentinel-report.md"'
      });
      res.end(md);
      return;
    }

    // Receive In-Browser WebRTC candidates from frontend
    if (pathname === '/api/webrtc-candidates' && req.method === 'POST') {
      await new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const parsed = JSON.parse(body || '{}');
            const candidates = parsed.candidates || [];
            if (onWebrtcUpdate) {
              await onWebrtcUpdate(candidates);
            }
            const updatedReport = await getReport();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, report: updatedReport }));
          } catch (err) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
          }
          resolve();
        });
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  };
}

export async function createAuditServer(reportGetter, options = {}) {
  const preferredPort = options.port || 8899;
  const host = options.host || '127.0.0.1';

  const htmlPath = join(__dirname, '..', 'public', 'index.html');
  const webUiHtml = existsSync(htmlPath) ? readFileSync(htmlPath, 'utf8') : getDefaultHtml();

  const requestHandler = createRequestHandler(
    reportGetter,
    options.onRecheck,
    options.onWebrtcUpdate,
    webUiHtml
  );

  const server = createServer(requestHandler);
  server.requestHandler = requestHandler;

  const port = await new Promise((resolve, reject) => {
    server.listen(preferredPort, host, () => resolve(preferredPort));
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        server.listen(0, host, () => resolve(server.address().port));
      } else {
        reject(err);
      }
    });
  });

  const url = `http://${host}:${port}`;

  if (options.openBrowser && !options.quiet) {
    const startCmd = process.platform === 'darwin' ? 'open' :
                     process.platform === 'win32' ? 'start' : 'xdg-open';
    exec(`${startCmd} ${url}`, () => {});
  }

  return {
    server,
    requestHandler,
    port,
    url,
    close: () => new Promise(resolve => server.close(resolve))
  };
}

function getDefaultHtml() {
  return `<!DOCTYPE html><html><head><title>leak-sentinel</title></head><body><h1>leak-sentinel</h1></body></html>`;
}
