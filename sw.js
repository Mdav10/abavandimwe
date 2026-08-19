// ABAVANDIMWE - Service Worker
// Version: 4.0 - Force fresh page load
const CACHE_NAME = 'abavandimwe-v4';
const STATIC_ASSETS = [
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

// Install event - cache only static assets
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

// Activate event - clean old caches and claim clients
self.addEventListener('activate', (event) => {
    console.log('Service Worker activating...');
    event.waitUntil(
        Promise.all([
            // Delete old caches
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
            // Claim all clients immediately
            self.clients.claim()
        ])
    );
});

// Fetch event - network first, never cache HTML pages
self.addEventListener('fetch', (event) => {
    const request = event.request;
    const url = new URL(request.url);

    // ===== NEVER CACHE THESE =====
    // API requests
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
        url.pathname.startsWith('/admin/')) {
        event.respondWith(fetch(request).catch(() => new Response('API Error', { status: 503 })));
        return;
    }

    // WebSocket - ignore
    if (url.protocol === 'ws:' || url.protocol === 'wss:') {
        return;
    }

    // ===== FOR HTML PAGES - ALWAYS FETCH FRESH, NEVER CACHE =====
    if (request.mode === 'navigate' || 
        url.pathname === '/' || 
        url.pathname === '/chat' ||
        url.pathname === '/offline.html') {
        event.respondWith(
            fetch(request, {
                cache: 'no-store',
                headers: {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
            })
            .then((response) => {
                // Return fresh response - never cache
                return response;
            })
            .catch(() => {
                // When offline, show offline.html
                return caches.match('/offline.html')
                    .then((offlineResponse) => {
                        if (offlineResponse) {
                            return offlineResponse;
                        }
                        // Fallback inline offline page
                        return new Response(`
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Offline</title>
                                <style>
                                    *{margin:0;padding:0;box-sizing:border-box;}
                                    body{font-family:monospace;background:#0a0a0f;color:#0f0;height:100vh;display:flex;justify-content:center;align-items:center;text-align:center;padding:20px;}
                                    .offline-container{max-width:400px;}
                                    .offline-icon{font-size:80px;margin-bottom:20px;display:block;}
                                    h1{color:#ff4444;font-size:24px;margin-bottom:12px;}
                                    p{color:#888;font-size:14px;line-height:1.6;margin-bottom:24px;}
                                    .retry-btn{background:transparent;border:2px solid #0f0;color:#0f0;padding:14px 40px;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer;transition:all 0.3s;}
                                    .retry-btn:hover{background:#0f0;color:#000;}
                                    .retry-btn:active{transform:scale(0.95);}
                                    .sub-text{color:#333;font-size:10px;margin-top:20px;border-top:1px solid #1a1a2e;padding-top:16px;}
                                </style>
                            </head>
                            <body>
                                <div class="offline-container">
                                    <span class="offline-icon">📶</span>
                                    <h1>No Internet Connection</h1>
                                    <p>Please check your network settings and try again.</p>
                                    <button class="retry-btn" onclick="location.reload()">↻ Retry</button>
                                    <div class="sub-text">🔒 ABAVANDIMWE Secure Messaging</div>
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

    // ===== FOR STATIC ASSETS (icons, etc.) - CACHE FIRST =====
    event.respondWith(
        caches.match(request)
            .then((cachedResponse) => {
                if (cachedResponse) {
                    return cachedResponse;
                }
                return fetch(request)
                    .then((response) => {
                        // Cache for next time
                        const responseClone = response.clone();
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(request, responseClone);
                        });
                        return response;
                    })
                    .catch(() => {
                        // Fallback for images
                        if (request.url.includes('.png') || request.url.includes('.jpg') || request.url.includes('.svg')) {
                            return new Response('', { status: 200 });
                        }
                        return new Response('Offline', { status: 503 });
                    });
            })
    );
});
