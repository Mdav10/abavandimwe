// ABAVANDIMWE - Service Worker
// Version: 6.0 - With Push Notification Support
const CACHE_NAME = 'abavandimwe-v6.0.1';
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

// Install - cache static assets
self.addEventListener('install', (event) => {
    console.log('Service Worker installing...');
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('Caching static assets...');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => self.skipWaiting())
    );
});

// Activate - clean old caches and claim clients
self.addEventListener('activate', (event) => {
    console.log('Service Worker activating...');
    event.waitUntil(
        Promise.all([
            caches.keys().then((cacheNames) => {
                return Promise.all(
                    cacheNames.map((cacheName) => {
                        if (cacheName !== CACHE_NAME) {
                            console.log('Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            }),
            self.clients.claim()
        ])
    );
});

// ===== PUSH NOTIFICATION HANDLER =====
self.addEventListener('push', (event) => {
    console.log('🔔 Push notification received!');
    
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
        data: {
            url: data.data?.url || '/'
        },
        tag: 'new-message',
        renotify: true,
        requireInteraction: true,
        actions: [
            {
                action: 'open',
                title: 'Open App'
            }
        ]
    };

    event.waitUntil(
        self.registration.showNotification(
            data.title || 'ABAVANDIMWE',
            options
        )
    );
});

// ===== NOTIFICATION CLICK HANDLER =====
self.addEventListener('notificationclick', (event) => {
    console.log('🔔 Notification clicked!');
    event.notification.close();

    const urlToOpen = event.notification.data?.url || '/';

    event.waitUntil(
        clients.matchAll({
            type: 'window',
            includeUncontrolled: true
        }).then((clientList) => {
            // Check if there's already a window/tab open with the target URL
            for (const client of clientList) {
                if (client.url === urlToOpen && 'focus' in client) {
                    return client.focus();
                }
            }
            // If not, open a new window
            return clients.openWindow(urlToOpen);
        })
    );
});

// ===== MAIN FETCH HANDLER =====
self.addEventListener('fetch', (event) => {
    const request = event.request;
    const url = new URL(request.url);

    // ==== 1. ALWAYS NETWORK FIRST FOR ALL API REQUESTS ====
    if (url.pathname === '/login' ||
        url.pathname === '/gatekeeper' ||
        url.pathname === '/admin/data' ||
        url.pathname === '/admin/create_user' ||
        url.pathname === '/admin/delete_user' ||
        url.pathname === '/admin/delete_group' ||
        url.pathname === '/admin/delete_message' ||
        url.pathname === '/save_display_name' ||
        url.pathname === '/logout' ||
        url.pathname === '/health' ||
        url.pathname.startsWith('/admin/') ||
        url.pathname === '/api/push/subscribe' ||
        url.pathname === '/api/push/vapid_public_key') {
        event.respondWith(fetch(request).catch(() => new Response('API Error', { status: 503 })));
        return;
    }

    // ==== 2. IGNORE WEBSOCKETS ====
    if (url.protocol === 'ws:' || url.protocol === 'wss:') {
        return;
    }

    // ==== 3. FOR HTML PAGES - NEVER CACHE, ALWAYS FETCH ====
    if (request.mode === 'navigate' ||
        url.pathname === '/' ||
        url.pathname === '/chat' ||
        url.pathname === '/offline.html') {
        event.respondWith(
            fetch(request)
                .then((response) => {
                    return response;
                })
                .catch(() => {
                    return caches.match('/offline.html')
                        .then((cached) => {
                            if (cached) {
                                return cached;
                            }
                            // Emergency fallback
                            return new Response(`
                                <!DOCTYPE html>
                                <html>
                                <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Offline</title>
                                <style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:monospace;background:#0a0a0f;color:#0f0;height:100vh;display:flex;justify-content:center;align-items:center;text-align:center;padding:20px;}.container{max-width:400px;}h1{color:#ff4444;font-size:24px;margin-bottom:12px;}p{color:#888;font-size:14px;line-height:1.6;margin-bottom:24px;}button{background:transparent;border:2px solid #0f0;color:#0f0;padding:14px 40px;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer;}button:hover{background:#0f0;color:#000;}</style>
                                </head>
                                <body>
                                <div class="container">
                                <h1>📶 No Internet Connection</h1>
                                <p>Please check your network settings and try again.</p>
                                <button onclick="location.reload()">↻ Retry</button>
                                </div>
                                </body>
                                </html>
                            `, { headers: { 'Content-Type': 'text/html' } });
                        });
                })
        );
        return;
    }

    // ==== 4. FOR STATIC ASSETS (icons, manifest) - CACHE FIRST ====
    event.respondWith(
        caches.match(request)
            .then((cached) => {
                if (cached) {
                    return cached;
                }
                return fetch(request)
                    .then((response) => {
                        const clone = response.clone();
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(request, clone);
                        });
                        return response;
                    })
                    .catch(() => {
                        if (request.url.match(/\.(png|jpg|jpeg|svg|gif|ico)$/)) {
                            return new Response('', { status: 200 });
                        }
                        return new Response('Offline', { status: 503 });
                    });
            })
    );
});
