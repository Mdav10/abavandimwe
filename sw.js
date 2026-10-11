// ABAVANDIMWE - Service Worker
// Version: 10.0 (Auto-reconnect on network return, works on first click)
const CACHE_VERSION = 'v10.0';
const CACHE_NAME = 'abavandimwe-' + CACHE_VERSION;

const STATIC_ASSETS = [
    '/manifest.json',
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
    console.log('✅ SW install', CACHE_VERSION);
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_ASSETS).catch(() => {}))
            .then(() => self.skipWaiting())
    );
});

// ===== ACTIVATE =====
self.addEventListener('activate', (event) => {
    console.log('✅ SW activate', CACHE_VERSION);
    event.waitUntil(
        caches.keys().then((names) => Promise.all(
            names.filter((n) => n !== CACHE_NAME).map((n) => {
                console.log('🗑️ Deleting old cache:', n);
                return caches.delete(n);
            })
        )).then(() => self.clients.claim())
    );
});

// ===== MESSAGE =====
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();

    // When a page asks us to broadcast "reconnect", tell all pages
    if (event.data && event.data.type === 'BROADCAST_RECONNECT') {
        self.clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then(clients => clients.forEach(c => c.postMessage({ type: 'RECONNECT' })));
    }
});

// ===== PUSH NOTIFICATIONS =====
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

// ===== SYNC: reconnect check when browser fires background sync =====
self.addEventListener('sync', (event) => {
    if (event.tag === 'abavandimwe-reconnect') {
        event.waitUntil(
            self.clients.matchAll({ type: 'window', includeUncontrolled: true })
                .then(clients => clients.forEach(c => c.postMessage({ type: 'RECONNECT' })))
        );
    }
});

// ===== FETCH =====
self.addEventListener('fetch', (event) => {
    const request = event.request;
    const url = new URL(request.url);

    // WebSockets — passthrough
    if (url.protocol === 'ws:' || url.protocol === 'wss:') return;

    // API — always network, no cache
    if (url.pathname.startsWith('/api/') ||
        url.pathname === '/login' ||
        url.pathname === '/gatekeeper' ||
        url.pathname === '/admin/data' ||
        url.pathname === '/save_display_name' ||
        url.pathname === '/logout' ||
        url.pathname === '/health' ||
        url.pathname === '/api/version' ||
        url.pathname.startsWith('/admin/')) {
        return;
    }

    // ===== HTML NAVIGATION =====
    // Try network first. If offline, return a minimal page that:
    //   1. Shows the offline overlay
    //   2. Registers a "reconnect" listener that reloads the page when online
    // This works even on the FIRST click when the app is opened offline.
    if (request.mode === 'navigate' || url.pathname === '/') {
        event.respondWith(
            fetch(request).catch(() => {
                return new Response(`
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>ABAVANDIMWE</title>
                        <style>
                            body { margin:0; padding:0; background:#0a0a0f; color:#0f0; font-family:monospace; }
                            .container { display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh; text-align:center; }
                            h2 { color:#ff4444; font-size:24px; }
                            p { color:#888; font-size:14px; }
                            .retry-btn { background:transparent; border:2px solid #0f0; color:#0f0; padding:14px 40px; border-radius:12px; font-size:16px; font-weight:bold; cursor:pointer; margin-top:20px; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h2>📶 No Internet Connection</h2>
                            <p>Please check your network settings and try again.</p>
                            <button class="retry-btn" onclick="location.reload()">↻ Retry</button>
                        </div>
                        <script>
                            // ===== AUTO-RECONNECT on first click =====
                            // Whenever the browser comes back online, reload the page
                            // so the full app loads and connects the WebSocket.
                            window.addEventListener('online', function() {
                                location.reload();
                            });

                            // Also listen for the SW's RECONNECT message
                            if (navigator.serviceWorker) {
                                navigator.serviceWorker.addEventListener('message', function(e) {
                                    if (e.data && e.data.type === 'RECONNECT') {
                                        location.reload();
                                    }
                                });
                            }

                            // Also try to register a background sync
                            if ('serviceWorker' in navigator && 'SyncManager' in window) {
                                navigator.serviceWorker.ready.then(function(reg) {
                                    return reg.sync.register('abavandimwe-reconnect').catch(function() {});
                                });
                            }

                            // Poll every 3 seconds as a fallback for Android
                            setInterval(function() {
                                if (navigator.onLine) {
                                    location.reload();
                                }
                            }, 3000);
                        </script>
                    </body>
                    </html>
                `, { headers: { 'Content-Type': 'text/html' } });
            })
        );
        return;
    }

    // Static assets — cache first
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
