// Minimal static file handler for the web app in /public.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { promisify } from 'node:util';

const gzip = promisify(zlib.gzip);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};
const COMPRESSIBLE = new Set(['.html', '.js', '.css', '.json', '.webmanifest', '.svg', '.txt']);

export function createStaticHandler(root) {
  const base = path.resolve(root);
  const compressed = new Map(); // file -> { etag, body }

  /** Serves the file for `pathname` and returns true, or returns false if there is none. */
  return async function serveStatic(req, res, pathname) {
    let relative;
    try {
      relative = decodeURIComponent(pathname);
    } catch {
      return false;
    }
    if (relative.includes('\0')) return false;
    if (relative.endsWith('/')) relative += 'index.html';

    const file = path.join(base, relative);
    if (!file.startsWith(base + path.sep)) return false; // escaped the public directory
    if (path.relative(base, file).split(path.sep).some((part) => part.startsWith('.'))) return false;

    const type = TYPES[path.extname(file).toLowerCase()];
    if (!type) return false;

    let stat;
    try {
      stat = await fs.stat(file);
    } catch {
      return false;
    }
    if (!stat.isFile()) return false;

    const etag = `W/"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`;
    res.setHeader('ETag', etag);
    // Always revalidate so an upgraded server is never paired with stale code.
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Content-Type', type);
    res.setHeader('Vary', 'Accept-Encoding');
    if (req.headers['if-none-match'] === etag) {
      res.statusCode = 304;
      res.end();
      return true;
    }

    let body = await fs.readFile(file);
    const ext = path.extname(file).toLowerCase();
    if (COMPRESSIBLE.has(ext) && body.length > 1024 && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
      let entry = compressed.get(file);
      if (!entry || entry.etag !== etag) {
        entry = { etag, body: await gzip(body) };
        compressed.set(file, entry);
      }
      body = entry.body;
      res.setHeader('Content-Encoding', 'gzip');
    }
    res.setHeader('Content-Length', body.length);
    res.statusCode = 200;
    res.end(req.method === 'HEAD' ? undefined : body);
    return true;
  };
}
