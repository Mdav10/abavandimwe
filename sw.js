// ABAVANDIMWE - Service Worker
// Version: 2.0
const CACHE_NAME = 'abavandimwe-v2';
const STATIC_ASSETS = [
    '/',
    '/manifest.json',
    '/offline.html',
    '/icons/icon-72x72.png',
    '/icons/icon-96x96.png',
    '/icons/icon-128x128.png',
    '/icons/icon-144x144.png',
    '/icons/icon-152x152.png',
    '/icons/icon-192x192.png',
    '/icons/icon-384x384.png',
    '/icons/icon-512x512.png'
];

// Install event - cache static assets only
self.addEventListener('install', (event) => {
    console.log('Service Worker installing...');
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => self.skipWaiting())
    );
});

// Activate event - clean old caches
self.addEventListener('activate', (event) => {
    console.log('Service Worker activating...');
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

// Fetch event - network first, then fallback to cache
self.addEventListener('fetch', (event) => {
    const request = event.request;
    const url = new URL(request.url);

    // Don't cache API requests (login, messages, admin, websocket)
    const isApiRequest = url.pathname === '/login' ||
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
                         url.pathname === '/ws' ||
                         url.protocol === 'ws:' ||
                         url.protocol === 'wss:';

    // Don't cache message requests
    const isMessageRequest = url.pathname.includes('/messages') ||
                             url.pathname.includes('/chat') ||
                             url.search.includes('message');

    // For API and WebSocket requests - try network, don't cache
    if (isApiRequest || isMessageRequest || url.protocol === 'ws:' || url.protocol === 'wss:') {
        event.respondWith(fetch(request));
        return;
    }

    // For static assets - network first, fallback to cache
    event.respondWith(
        fetch(request)
            .then((response) => {
                // Clone the response
                const responseClone = response.clone();
                // Cache the successful response
                caches.open(CACHE_NAME).then((cache) => {
                    cache.put(request, responseClone);
                });
                return response;
            })
            .catch(() => {
                // If network fails, try cache
                return caches.match(request)
                    .then((cachedResponse) => {
                        if (cachedResponse) {
                            return cachedResponse;
                        }
                        // If not in cache and it's a navigation request, show offline page
                        if (request.mode === 'navigate') {
                            return caches.match('/offline.html');
                        }
                        // For other assets, return a fallback
                        return new Response('Offline', {
                            status: 503,
                            statusText: 'Service Unavailable'
                        });
                    });
            })
    );
});

// Handle offline page specifically
self.addEventListener('fetch', (event) => {
    const request = event.request;
    const url = new URL(request.url);

    // If offline.html is requested, serve it
    if (url.pathname === '/offline.html') {
        event.respondWith(
            caches.match('/offline.html')
                .then((response) => response || fetch(request))
        );
        return;
    }

    // For the root page, always try network first, fallback to offline.html
    if (url.pathname === '/' && request.mode === 'navigate') {
        event.respondWith(
            fetch(request)
                .then((response) => {
                    // Cache the HTML response
                    const responseClone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(request, responseClone);
                    });
                    return response;
                })
                .catch(() => {
                    return caches.match('/offline.html')
                        .then((offlineResponse) => {
                            if (offlineResponse) {
                                return offlineResponse;
                            }
                            return new Response(`
                                <!DOCTYPE html>
                                <html>
                                <head><title>Offline</title>
                                <style>body{background:#0a0a0f;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center;padding:20px;}
                                .offline-icon{font-size:60px;margin-bottom:20px;}h1{color:#ff4444;}</style>
                                </head>
                                <body>
                                <div>
                                <div class="offline-icon">📶</div>
                                <h1>No Internet Connection</h1>
                                <p style="color:#888;">Please check your network settings and try again.</p>
                                <button onclick="location.reload()" style="margin-top:20px;padding:12px 30px;background:#0f0;color:#000;border:none;border-radius:8px;font-size:16px;cursor:pointer;">↻ Retry</button>
                                </div>
                                </body>
                                </html>
                            `, {
                                headers: { 'Content-Type': 'text/html' }
                            });
                        });
                })
        );
        return;
    }
});
