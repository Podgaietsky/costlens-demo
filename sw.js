/*
 * CostLens — acesso com senha em hospedagem estática.
 * Os arquivos do app ficam cifrados (AES-GCM) em vault/. A página de entrada deriva a chave da senha
 * (PBKDF2) e a guarda no IndexedDB deste navegador; este service worker decifra cada arquivo sob demanda
 * e serve o app em ./app/. Sem a chave, nada do app é entregue.
 */
const VAULT = new URL('./vault/', self.location).href;
const GATE = new URL('./', self.location).href;
const APP = new URL('./app/', self.location);

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

function readKey() {
  return new Promise((resolve) => {
    const req = indexedDB.open('costlens-gate', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('kv');
    req.onerror = () => resolve(null);
    req.onsuccess = () => {
      try {
        const get = req.result.transaction('kv').objectStore('kv').get('key');
        get.onsuccess = () => resolve(get.result ?? null);
        get.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    };
  });
}

async function decryptBlob(key, name, gz, fresh) {
  const res = await fetch(VAULT + name, fresh ? { cache: 'no-cache' } : {});
  if (!res.ok) throw new Error(`${name}: ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf.subarray(0, 12) },
    key,
    buf.subarray(12),
  );
  if (!gz) return plain;
  return new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
}

let session = null;
async function openSession() {
  const rec = await readKey();
  if (!rec || !rec.key || rec.exp < Date.now()) return (session = null);
  if (session && session.stamp === rec.stamp) return session;
  const manifest = JSON.parse(
    new TextDecoder().decode(await decryptBlob(rec.key, 'manifest.bin', false, true)),
  );
  session = { stamp: rec.stamp, key: rec.key, manifest, files: new Map() };
  return session;
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== APP.origin || !url.pathname.startsWith(APP.pathname)) return;
  e.respondWith(serve(e.request, url));
});

async function serve(req, url) {
  const s = await openSession().catch(() => null);
  if (!s) {
    // sem senha (ou expirada): volta para a entrada; o navegador mantém o #fragmento no redirecionamento
    if (req.mode === 'navigate') return Response.redirect(GATE, 302);
    return new Response('Acesso restrito', { status: 401 });
  }
  let path = decodeURIComponent(url.pathname.slice(APP.pathname.length));
  if (path === '' || path.endsWith('/')) path += 'index.html';
  let f = s.manifest.files[path];
  if (!f && req.mode === 'navigate') f = s.manifest.files[(path = 'index.html')];
  if (!f) return new Response('Não encontrado', { status: 404 });
  let body = s.files.get(path);
  if (!body) {
    body = await decryptBlob(s.key, f.blob, f.gz, false);
    s.files.set(path, body);
  }
  return new Response(body, { headers: { 'content-type': f.type, 'cache-control': 'no-store' } });
}
