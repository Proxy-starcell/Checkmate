let iframeSrc = '';

// List of paths that belong to your server
const serverPaths = new Set([
  '/',
  '/sw.js',
  '/newtab',
  '/xorcipher',
  '/static',
  '/signup',
  '/login',
  '/chat',
  '/profile',
  '/logout'
]);

// Additional check for dynamic chat paths
function isServerDynamicPath(path) {
  // Match /chat/{numeric_id} paths
  return /^\/chat\/\d+$/.test(path);
}

self.addEventListener('install', (event) => {
  console.log('[SW] Installed');
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  console.log('[SW] Activated');
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  if (event.data?.type === 'iframe-identity') {
    iframeSrc = event.data.iframeSrc;
    console.log(`[SW] Set iframe src to: ${iframeSrc}`);
  }
});

// Create a cache for static resources
const staticCache = new Map();

// Track pending requests to reduce duplicate fetches
const pendingRequests = new Map();

// Function to get a cache key from a URL
function getCacheKey(url) {
  return url.toString();
}

// Check if a URL is for a static resource that can be cached
function isStaticResource(url) {
  const path = url.pathname.toLowerCase();
  return /\.(js|css|jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|eot|mp4|webm|ogg|mp3|wav|pdf)$/.test(path);
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const reqUrl = new URL(req.url);

  // Skip verbose logging for static resources
  if (!isStaticResource(reqUrl)) {
    console.log(`[SW] Intercepted: ${reqUrl.href}`);
  }

  // 🔁 1. Handle navigation requests (optimize for speed)
  if (req.mode === 'navigate') {
    // Reset iframeSrc for root path and newtab
    if (reqUrl.pathname === '/newtab' || reqUrl.pathname === '/') {
      iframeSrc = '';
      return fetch(req);
    }
    
    // Special case for /xorcipher requests - these are already proxy requests
    // Pass them through directly for better performance
    if (reqUrl.pathname === '/xorcipher') {
      console.log(`[SW] Direct proxy request: ${reqUrl.href}`);
      return fetch(req);
    }
    
    // Handle chat routes and other server paths directly
    const isServerPath = Array.from(serverPaths).some(path => 
      reqUrl.pathname === path || reqUrl.pathname.startsWith(`${path}/`)
    );
    
    if (isServerPath || isServerDynamicPath(reqUrl.pathname)) {
      return fetch(req);
    }

    if (!iframeSrc) {
      console.warn(`[SW] iframeSrc not set, passing navigation through`);
      return;
    }

    const rewrittenUrl = `${iframeSrc.replace(/\/$/, '')}${reqUrl.pathname}`;
    const proxyUrl = `/xorcipher?url=${encodeURIComponent(rewrittenUrl)}&origin=${encodeURIComponent(iframeSrc)}`;

    console.log(`[SW] Proxying navigation: ${reqUrl.pathname} → ${proxyUrl}`);

    event.respondWith((async () => {
      // For POST/PUT requests, include the body
      const body = req.method !== 'GET' && req.method !== 'HEAD' ? await req.blob() : undefined;

      // Use a more efficient fetch request with minimal headers
      let response = await fetch(proxyUrl, {
        method: req.method,
        headers: req.headers,
        credentials: 'same-origin',
        redirect: 'follow',
        body: body,
      });

      // Create a streamlined response
      return response;
    })());
    return;
  }

  // 🔁 2. Handle all other requests with optimized processing
  event.respondWith((async () => {
    try {
      // If it's a static resource and we're using GET, check the cache first
      if (isStaticResource(reqUrl) && req.method === 'GET') {
        const cacheKey = getCacheKey(reqUrl);
        const cachedResponse = staticCache.get(cacheKey);
        
        if (cachedResponse) {
          // Use cached response for better performance
          return cachedResponse.clone();
        }
        
        // Check if this request is already in progress
        if (pendingRequests.has(cacheKey)) {
          // Wait for the existing request to complete
          return (await pendingRequests.get(cacheKey)).clone();
        }
      }
      
      // If it's a request to our domain
      if (reqUrl.origin === self.location.origin) {
        // Fast path check for server paths
        if (
          reqUrl.pathname === '/sw.js' || 
          reqUrl.pathname.startsWith('/static/') || 
          reqUrl.pathname.startsWith('/xorcipher') ||
          reqUrl.pathname === '/newtab'
        ) {
          return fetch(req);
        }

        // Check other server paths if needed
        const isServerPath = Array.from(serverPaths).some(path => 
          reqUrl.pathname === path || reqUrl.pathname.startsWith(`${path}/`)
        );
        
        // Also check for dynamic paths like /chat/123
        if (isServerPath || isServerDynamicPath(reqUrl.pathname)) {
          return fetch(req);
        }

        if (!iframeSrc) {
          // Fast path if iframeSrc isn't set
          return fetch(req);
        }

        // Rewrite internal requests to use the proxy
        const rewrittenUrl = `${iframeSrc.replace(/\/$/, '')}${reqUrl.pathname}${reqUrl.search}`;
        const proxyUrl = `/xorcipher?url=${encodeURIComponent(rewrittenUrl)}&origin=${encodeURIComponent(iframeSrc)}`;

        // For GET requests to static resources, track pending requests
        if (isStaticResource(reqUrl) && req.method === 'GET') {
          const cacheKey = getCacheKey(reqUrl);
          const responsePromise = fetch(proxyUrl, {
            method: req.method,
            // Only send essential headers for better performance
            headers: {
              'User-Agent': req.headers.get('User-Agent') || '',
              'Accept': req.headers.get('Accept') || '*/*',
              'Accept-Encoding': req.headers.get('Accept-Encoding') || ''
            },
            credentials: 'same-origin',
            redirect: 'follow'
          }).then(response => {
            // Cache the response for future use if it's successful
            if (response.ok) {
              const clonedResponse = response.clone();
              staticCache.set(cacheKey, clonedResponse);
              
              // Limit cache size to prevent memory issues
              if (staticCache.size > 200) {
                // Remove the oldest entries
                const keysToDelete = Array.from(staticCache.keys()).slice(0, 50);
                keysToDelete.forEach(key => staticCache.delete(key));
              }
            }
            
            // Remove from pending requests
            pendingRequests.delete(cacheKey);
            return response;
          });
          
          pendingRequests.set(cacheKey, responsePromise);
          return responsePromise;
        }
        
        // Non-cacheable requests
        return fetch(proxyUrl, {
          method: req.method,
          headers: req.headers,
          credentials: 'same-origin',
          redirect: 'follow',
          body: req.method !== 'GET' && req.method !== 'HEAD' ? await req.blob() : undefined
        });
      }

      // External origin — proxy normally with optimizations
      if (!iframeSrc) {
        return fetch(req);
      }

      const externalProxyUrl = `/xorcipher?url=${encodeURIComponent(reqUrl.href)}&origin=${encodeURIComponent(iframeSrc)}`;

      // For GET requests to static resources, use caching
      if (isStaticResource(reqUrl) && req.method === 'GET') {
        const cacheKey = getCacheKey(reqUrl);
        
        // Track pending requests to avoid duplicates
        if (pendingRequests.has(cacheKey)) {
          return (await pendingRequests.get(cacheKey)).clone();
        }
        
        const responsePromise = fetch(externalProxyUrl, {
          method: req.method,
          // Minimize headers for better performance
          headers: {
            'User-Agent': req.headers.get('User-Agent') || '',
            'Accept': req.headers.get('Accept') || '*/*',
            'Accept-Encoding': req.headers.get('Accept-Encoding') || ''
          },
          credentials: 'same-origin',
          redirect: 'follow'
        }).then(response => {
          // Cache successful responses
          if (response.ok) {
            const clonedResponse = response.clone();
            staticCache.set(cacheKey, clonedResponse);
            
            // Limit cache size
            if (staticCache.size > 200) {
              const keysToDelete = Array.from(staticCache.keys()).slice(0, 50);
              keysToDelete.forEach(key => staticCache.delete(key));
            }
          }
          
          pendingRequests.delete(cacheKey);
          return response;
        });
        
        pendingRequests.set(cacheKey, responsePromise);
        return responsePromise;
      }

      // Non-cacheable external requests
      return fetch(externalProxyUrl, {
        method: req.method,
        headers: req.headers,
        credentials: 'same-origin',
        redirect: 'follow',
        body: req.method !== 'GET' && req.method !== 'HEAD' ? await req.blob() : undefined
      });

    } catch (err) {
      console.error('[SW] Fetch error:', err);
      return fetch(req);
    }
  })());
});
