// pages-lock service worker: serves a locked build's files decrypted (see lock.mjs).
// The page that registers it (the gate) puts the password-derived key where this worker can
// read it: in IndexedDB when the device is remembered, else in the tab's sessionStorage, which
// the worker asks open pages for. Without a key every navigation gets the gate.

const SCOPE = self.registration.scope;
const SCOPE_PATH = new URL(SCOPE).pathname;
const SLOT_AAD = new TextEncoder().encode('pages-lock/slot');

/** lock.json: { v, realm, salt, iterations, deploy, slots, public } */
let lock = null;
/** { deploy, enc, name, remembered } for the current deploy */
let keys = null;
/** A one-shot navigation pass, set when a tab unlocks for its session only. */
let passUntil = 0;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// ---- IndexedDB (one small key-value store per origin, shared by every locked build on it)

function idb() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('pages-lock', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('kv');
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

async function idbGet(key) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const req = db.transaction('kv').objectStore('kv').get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbDelete(key) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('kv', 'readwrite');
    tx.objectStore('kv').delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---- Keys

const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const fromHex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const toHex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');

async function loadLock(fresh) {
  if (lock && !fresh) return lock;
  try {
    const res = await fetch(`${SCOPE}lock.json`, { cache: fresh ? 'no-cache' : 'default' });
    if (res.ok) {
      const next = await res.json();
      if (keys && keys.deploy !== next.deploy) keys = null;
      lock = next;
    }
  } catch {
    // Offline: keep the last one.
  }
  return lock;
}

/** The deploy's content keys from a password-derived key, or null when it opens no slot. */
async function unwrap(kek, current, remembered) {
  for (const slot of current.slots) {
    const bytes = fromB64(slot);
    try {
      const secret = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: SLOT_AAD }, kek, bytes.subarray(12)));
      const enc = await crypto.subtle.importKey('raw', secret.subarray(0, 32), 'AES-GCM', false, ['decrypt']);
      const name = await crypto.subtle.importKey('raw', secret.subarray(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      return { deploy: current.deploy, enc, name, remembered };
    } catch {
      // Not this slot's password.
    }
  }
  return null;
}

async function fromRemembered(current) {
  if (keys && keys.remembered && keys.deploy === current.deploy) return keys;
  const kek = await idbGet(`kek:${current.realm}`).catch(() => undefined);
  if (!kek) return null;
  const k = await unwrap(kek, current, true);
  // A remembered key that opens nothing belongs to old passwords.
  if (!k) await idbDelete(`kek:${current.realm}`).catch(() => {});
  return k;
}

const importSessionKek = (hex) => crypto.subtle.importKey('raw', fromHex(hex), 'AES-GCM', false, ['decrypt']);

/** Asks open pages for their tab's session key (the worker forgets keys when the browser stops it). */
async function fromPages(current) {
  const pages = await self.clients.matchAll({ type: 'window' });
  for (const page of pages) {
    const hex = await new Promise((resolve) => {
      const channel = new MessageChannel();
      const timer = setTimeout(() => resolve(null), 1000);
      channel.port1.onmessage = (e) => {
        clearTimeout(timer);
        resolve(typeof e.data === 'string' ? e.data : null);
      };
      page.postMessage({ type: 'pages-lock:kek?', realm: current.realm }, [channel.port2]);
    });
    if (!hex) continue;
    const k = await unwrap(await importSessionKek(hex), current, false).catch(() => null);
    if (k) return k;
  }
  return null;
}

async function banned(current) {
  const a = await idbGet(`attempts:${current.realm}`).catch(() => undefined);
  return Boolean(a && a.banned);
}

// ---- Files

const TYPES = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', js: 'text/javascript', mjs: 'text/javascript', css: 'text/css',
  json: 'application/json', map: 'application/json', webmanifest: 'application/manifest+json', wasm: 'application/wasm',
  txt: 'text/plain; charset=utf-8', md: 'text/markdown; charset=utf-8', xml: 'application/xml', csv: 'text/csv',
  svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', avif: 'image/avif', gif: 'image/gif', ico: 'image/x-icon', ktx2: 'image/ktx2',
  woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf',
  mp3: 'audio/mpeg', ogg: 'audio/ogg', oga: 'audio/ogg', wav: 'audio/wav', m4a: 'audio/mp4', flac: 'audio/flac', opus: 'audio/ogg',
  mp4: 'video/mp4', webm: 'video/webm', glb: 'model/gltf-binary', gltf: 'model/gltf+json',
};
const typeOf = (path) => TYPES[path.slice(path.lastIndexOf('.') + 1).toLowerCase()] ?? 'application/octet-stream';

/** The decrypted file at `path` (relative to the scope), or null when the build has no such locked file. */
async function decrypted(path, k) {
  const name = toHex(await crypto.subtle.sign('HMAC', k.name, new TextEncoder().encode(path))).slice(0, 32);
  const res = await fetch(`${SCOPE}x/${name}`);
  if (!res.ok) return null;
  const bytes = new Uint8Array(await res.arrayBuffer());
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: new TextEncoder().encode(path) }, k.enc, bytes.subarray(12));
    return new Response(plain, { status: 200, headers: { 'Content-Type': typeOf(path) } });
  } catch {
    return null;
  }
}

const gate = () => fetch(`${SCOPE}index.html`, { cache: 'no-cache' });

async function navigate(request, path) {
  const current = await loadLock(true);
  if (!current || (await banned(current))) return gate();
  let k = null;
  if (keys && !keys.remembered && keys.deploy === current.deploy && Date.now() < passUntil) {
    passUntil = 0;
    k = keys;
  } else {
    k = await fromRemembered(current);
  }
  if (!k) return gate();
  keys = k;
  const file = path === '' || path.endsWith('/') ? `${path}index.html` : path;
  return (await decrypted(file, k)) ?? fetch(request);
}

/** One key lookup at a time: a page's burst of requests shares it. */
let finding = null;

async function resource(request, path) {
  const current = await loadLock(false);
  if (!current || current.public.includes(path)) return fetch(request);
  if (!keys || keys.deploy !== current.deploy) {
    finding ??= (async () => (await fromRemembered(current)) ?? (await fromPages(current)))().finally(() => (finding = null));
    keys = await finding;
  }
  if (!keys) return fetch(request);
  return (await decrypted(path, keys)) ?? fetch(request);
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET' || !request.url.startsWith(SCOPE)) return;
  const path = decodeURIComponent(new URL(request.url).pathname.slice(SCOPE_PATH.length));
  if (path === 'pages-lock-sw.js' || path === 'lock.json') return;
  event.respondWith(request.mode === 'navigate' ? navigate(request, path) : resource(request, path));
});

// The gate hands over a tab's session key; the next navigation (its reload) may then open the build.
self.addEventListener('message', (event) => {
  const data = event.data;
  const reply = (ok) => event.ports[0]?.postMessage(ok);
  if (data?.type === 'pages-lock:unlock' && typeof data.kek === 'string') {
    event.waitUntil(
      (async () => {
        const current = await loadLock(true);
        const k = current ? await unwrap(await importSessionKek(data.kek), current, false).catch(() => null) : null;
        if (k) {
          keys = k;
          passUntil = Date.now() + 10_000;
        }
        reply(Boolean(k));
      })(),
    );
  }
});
