// ABAVANDIMWE - Service Worker
// Version: 9.2
const CACHE_VERSION = 'v9.2';
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

self.addEventListener('install', (event) => {
    console.log('✅ SW install', CACHE_VERSION);
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_ASSETS).catch(() => {}))
            .then(() => self.skipWaiting())
    );
});

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

self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

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

// ===== FETCH — no offline.html fallback for HTML =====
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

    // HTML navigation — browser goes straight to network
    if (request.mode === 'navigate' || url.pathname === '/') {
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
