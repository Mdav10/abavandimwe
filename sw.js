// ABAVANDIMWE - Service Worker
// Version: 8.1 — Auto-updating
const CACHE_VERSION = 'v8.1';  // ← CHANGE THIS on every deploy
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

// ===== INSTALL: cache assets, then activate immediately =====
self.addEventListener('install', (event) => {
    console.log('✅ SW install — version', CACHE_VERSION);
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_ASSETS).catch(() => {}))
            .then(() => self.skipWaiting())  // ← Activate immediately
    );
});

// ===== ACTIVATE: delete ALL old caches =====
self.addEventListener('activate', (event) => {
    console.log('✅ SW activate — version', CACHE_VERSION);
    event.waitUntil(
        caches.keys()
            .then((cacheNames) => Promise.all(
                cacheNames
                    .filter((name) => name !== CACHE_NAME)
                    .map((name) => {
                        console.log('🗑️ Deleting old cache:', name);
                        return caches.delete(name);
                    })
            ))
            .then(() => self.clients.claim())
    );
});

// ===== MESSAGE: allow client to force a skipWaiting =====
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});

// ===== PUSH NOTIFICATION =====
self.addEventListener('push', (event) => {
    let data = {};
    try {
        data = event.data.json();
    } catch (e) {
        data = {
            title: 'ABAVANDIMWE',
            body: 'You have a new message!',
            badge: '/static/icons/icon-192x192.png',
            icon: '/static/icons/icon-192x192.png',
            data: { url: '/' }
        };
    }
    const options = {
        body: data.body || 'You have a new message on ABAVANDIMWE.',
        icon: data.icon || '/static/icons/icon-192x192.png',
        badge: data.badge || '/static/icons/icon-192x192.png',
        vibrate: [200, 100, 200],
        data: { url: (data.data && data.data.url) || '/' },
        tag: 'new-message',
        renotify: true,
        requireInteraction: true,
        actions: [{ action: 'open', title: 'Open App' }]
    };
    event.waitUntil(self.registration.showNotification(data.title || 'ABAVANDIMWE', options));
});

// ===== NOTIFICATION CLICK =====
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const urlToOpen = (event.notification.data && event.notification.data.url) || '/';
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then((clientList) => {
                for (const client of clientList) {
                    if (client.url === urlToOpen && 'focus' in client) return client.focus();
                }
                return clients.openWindow(urlToOpen);
            })
    );
});

// ===== FETCH =====
self.addEventListener('fetch', (event) => {
    const request = event.request;
    const url = new URL(request.url);

    // 1) API endpoints — NETWORK ONLY
    if (url.pathname === '/login' || url.pathname === '/gatekeeper' ||
        url.pathname === '/admin/data' || url.pathname === '/save_display_name' ||
        url.pathname === '/logout' || url.pathname === '/health' ||
        url.pathname.startsWith('/admin/') ||
        url.pathname === '/api/push/subscribe' ||
        url.pathname === '/api/push/vapid_public_key' ||
        url.pathname === '/api/version' ||
        url.pathname.startsWith('/api/upload_') ||
        url.pathname.startsWith('/api/files/')) {
        event.respondWith(fetch(request).catch(() => new Response('API Error', { status: 503 })));
        return;
    }

    // 2) WebSockets — passthrough
    if (url.protocol === 'ws:' || url.protocol === 'wss:') {
        return;
    }

    // 3) HTML navigation — NETWORK FIRST, offline fallback
    if (request.mode === 'navigate' || url.pathname === '/' || url.pathname === '/offline.html') {
        event.respondWith(
            fetch(request)
                .then((response) => response)
                .catch(() => caches.match('/offline.html'))
        );
        return;
    }

    // 4) Static assets — CACHE FIRST with network fallback
    event.respondWith(
        caches.match(request).then((cached) => {
            if (cached) return cached;
            return fetch(request).then((response) => {
                const clone = response.clone();
                caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
                return response;
            }).catch(() => new Response('', { status: 503 }));
        })
    );
});
