// ABAVANDIMWE - Service Worker
// Version: 9.0 — Auto-updating with cold-start tolerance
const CACHE_VERSION = 'v9.0';  // ← BUMP THIS on every deploy
const CACHE_NAME = 'abavandimwe-' + CACHE_VERSION;

const STATIC_ASSETS = [
    '/manifest.json',
    '/offline.html',
    '/static/icons/icon-16x16.png',
    '/static/icons/icon-32x32.png',
    '/static/icons/icon-48x48.png',
    '/static/icons/icon-64x64.png',
    '/static/icons/icon-96x96.png',
    '/static/icons/icon-128x128.png',
    '/static/icons/icon-144x144.png',
    '/static/icons/icon-152x152.png',
    '/static/icons/icon-180x180.png',
    '/static/icons/icon-192x192.png',
    '/static/icons/icon-384x384.png',
    '/static/icons/icon-512x512.png'
];

// ===== INSTALL =====
self.addEventListener('install', (event) => {
    console.log('✅ SW install v9.0');
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_ASSETS).catch(() => {}))
            .then(() => self.skipWaiting())
    );
});

// ===== ACTIVATE: wipe ALL old caches =====
self.addEventListener('activate', (event) => {
    console.log('✅ SW activate v9.0');
    event.waitUntil(
        caches.keys()
            .then((names) => Promise.all(
                names.filter((n) => n !== CACHE_NAME).map((n) => {
                    console.log('🗑️ Deleting old cache:', n);
                    return caches.delete(n);
                })
            ))
            .then(() => self.clients.claim())
    );
});

// ===== MESSAGE =====
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});

// ===== PUSH =====
self.addEventListener('push', (event) => {
    let data = {};
    try { data = event.data.json(); }
    catch (e) {
        data = { title: 'ABAVANDIMWE', body: 'You have a new message!',
                 badge: '/static/icons/icon-192x192.png',
                 icon: '/static/icons/icon-192x192.png', data: { url: '/' } };
    }
    const options = {
        body: data.body || 'You have a new message on ABAVANDIMWE.',
        icon: data.icon || '/static/icons/icon-192x192.png',
        badge: data.badge || '/static/icons/icon-192x192.png',
        vibrate: [200, 100, 200],
        data: { url: (data.data && data.data.url) || '/' },
        tag: 'new-message', renotify: true, requireInteraction: true,
        actions: [{ action: 'open', title: 'Open App' }]
    };
    event.waitUntil(self.registration.showNotification(data.title || 'ABAVANDIMWE', options));
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const urlToOpen = (event.notification.data && event.notification.data.url) || '/';
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
            for (const c of list) if (c.url === urlToOpen && 'focus' in c) return c.focus();
            return clients.openWindow(urlToOpen);
        })
    );
});

// ===== FETCH =====
// Helper: fetch with timeout (so Render cold start doesn't blow up)
function fetchWithTimeout(request, ms) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timeout')), ms);
        fetch(request).then(
            (response) => { clearTimeout(timer); resolve(response); },
            (err) => { clearTimeout(timer); reject(err); }
        );
    });
}

self.addEventListener('fetch', (event) => {
    const request = event.request;
    const url = new URL(request.url);

    // 1) API — never cache, long timeout (60s) for Render cold start
    if (url.pathname.startsWith('/api/') ||
        url.pathname === '/login' ||
        url.pathname === '/gatekeeper' ||
        url.pathname === '/admin/data' ||
        url.pathname === '/save_display_name' ||
        url.pathname === '/logout' ||
        url.pathname === '/health' ||
        url.pathname.startsWith('/admin/')) {
        event.respondWith(
            fetchWithTimeout(request, 60000)
                .catch(() => new Response(JSON.stringify({ error: 'server waking up' }),
                                          { status: 503, headers: { 'Content-Type': 'application/json' } }))
        );
        return;
    }

    // 2) WebSockets — passthrough
    if (url.protocol === 'ws:' || url.protocol === 'wss:') return;

    // 3) HTML navigation — network FIRST with 60s timeout, then offline page
    if (request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html')) {
        event.respondWith(
            fetchWithTimeout(request, 60000)
                .then((response) => response)
                .catch(() => caches.match('/offline.html').then((c) => c || new Response(
                    '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Loading...</title></head>' +
                    '<body style="background:#0a0a0f;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;">' +
                    '<div style="text-align:center;padding:20px;max-width:400px;">' +
                    '<h1 style="color:#ffaa00;font-size:22px;">⏳ Server waking up</h1>' +
                    '<p style="color:#888;margin:16px 0;">Render is starting your server. This takes up to 60 seconds on first visit.</p>' +
                    '<button onclick="location.reload()" style="background:transparent;border:2px solid #0f0;color:#0f0;padding:14px 32px;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer;font-family:monospace;">↻ Retry</button>' +
                    '</div></body></html>', { headers: { 'Content-Type': 'text/html' } })))
        );
        return;
    }

    // 4) Static assets — cache first, network fallback
    event.respondWith(
        caches.match(request).then((cached) => {
            if (cached) return cached;
            return fetch(request).then((response) => {
                if (request.method === 'GET' && response.status === 200) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
                }
                return response;
            }).catch(() => new Response('', { status: 503 }));
        })
    );
});
