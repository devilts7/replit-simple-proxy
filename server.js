const express = require("express");
const proxy = require("express-http-proxy");
const cors = require("cors");
const path = require("path");
const { URL } = require("url");
const dns = require("dns").promises;
const net = require("net");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const compression = require("compression");

// Configuration from environment
const config = {
  PORT: process.env.PORT || 5000,
  NODE_ENV: process.env.NODE_ENV || "development",
  RATE_LIMIT_WINDOW_MS: parseInt(
    process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000,
  ),
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || 100),
  REQUEST_TIMEOUT_MS: parseInt(process.env.REQUEST_TIMEOUT_MS || 30000),
  MAX_RESPONSE_SIZE_MB: parseInt(process.env.MAX_RESPONSE_SIZE_MB || 50),
  DNS_LOOKUP_TIMEOUT_MS: parseInt(process.env.DNS_LOOKUP_TIMEOUT_MS || 5000),
  CACHE_ENABLED: process.env.CACHE_ENABLED === "true",
  CACHE_TTL_SECONDS: parseInt(process.env.CACHE_TTL_SECONDS || 300),
};

const app = express();

// Trust proxy
app.set("trust proxy", 1);

// ============================================================================
// MONITORING & METRICS
// ============================================================================
const metrics = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  blockedRequests: 0,
  rateLimitedRequests: 0,
  averageResponseTime: 0,
  startTime: Date.now(),
};

const recent = [];
const MAX_RECENT_LOGS = 100;

function recordMetric(type, data = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    type,
    ...data,
  };

  recent.unshift(entry);
  if (recent.length > MAX_RECENT_LOGS) {
    recent.pop();
  }

  metrics.totalRequests++;
  if (type === "success") metrics.successfulRequests++;
  if (type === "error") metrics.failedRequests++;
  if (type === "blocked") metrics.blockedRequests++;
  if (type === "rate_limited") metrics.rateLimitedRequests++;
}

// ============================================================================
// CACHING SYSTEM
// ============================================================================
class CacheManager {
  constructor(ttlSeconds = config.CACHE_TTL_SECONDS) {
    this.cache = new Map();
    this.ttlSeconds = ttlSeconds;
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    return entry.data;
  }

  set(key, data, ttlSeconds = this.ttlSeconds) {
    this.cache.set(key, {
      data,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  clear() {
    this.cache.clear();
  }

  getStats() {
    return {
      entries: this.cache.size,
      ttlSeconds: this.ttlSeconds,
    };
  }
}

const cacheManager = new CacheManager();

// ============================================================================
// SECURITY & MIDDLEWARE
// ============================================================================

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        frameAncestors: ["'self'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: false,
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  }),
);

app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Embedder-Policy", "credentialless");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  next();
});

app.use(compression());

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    methods: ["GET", "POST", "HEAD"],
    credentials: true,
  }),
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

const limiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX_REQUESTS,
  message: "Too many requests from this IP, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    recordMetric("rate_limited", {
      ip: req.ip,
      path: req.path,
    });
    res.status(429).json({
      error: "Too many requests",
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

const proxyLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX_REQUESTS / 2,
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    recordMetric("rate_limited", {
      ip: req.ip,
      path: "/proxy",
      targetUrl: req.query.url,
    });
    res.status(429).json({
      error: "Proxy rate limit exceeded",
      retryAfter: req.rateLimit.resetTime,
    });
  },
});

app.use(limiter);

// ============================================================================
// SSRF PROTECTION & VALIDATION
// ============================================================================

const PRIVATE_IP_RANGES = [
  /^127\./,
  /^10\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^:: 1$/,
  /^fe80:/,
  /^fc00:/,
  /^fd00:/,
];

const BLOCKED_HOSTNAMES = [
  "localhost",
  "loopback",
  "ip6-localhost",
  "metadata. google.internal",
  "metadata.azure.com",
  "instance-data",
  "169.254.169.254",
];

async function validateHost(hostname) {
  if (!hostname) {
    return { valid: false, reason: "Empty hostname" };
  }

  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.includes(lower)) {
    return { valid: false, reason: "Blocked hostname" };
  }

  if (PRIVATE_IP_RANGES.some((regex) => regex.test(hostname))) {
    return { valid: false, reason: "Private IP range" };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      config.DNS_LOOKUP_TIMEOUT_MS,
    );

    const addresses = await dns.resolve4(hostname);
    clearTimeout(timeoutId);

    if (!addresses || addresses.length === 0) {
      return { valid: false, reason: "DNS resolution failed" };
    }

    for (const ip of addresses) {
      if (PRIVATE_IP_RANGES.some((regex) => regex.test(ip))) {
        return { valid: false, reason: `Resolved to private IP: ${ip}` };
      }
    }

    return { valid: true, ips: addresses };
  } catch (err) {
    if (err.name === "AbortError") {
      return { valid: false, reason: "DNS lookup timeout" };
    }
    return { valid: false, reason: `DNS lookup failed: ${err.message}` };
  }
}

function sanitizeUrl(rawUrl) {
  try {
    rawUrl = rawUrl.trim();

    if (!rawUrl.match(/^https?:\/\//i)) {
      rawUrl = "https://" + rawUrl;
    }

    const parsed = new URL(rawUrl);

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return {
        valid: false,
        error: "Invalid protocol.  Only http and https are supported.",
      };
    }

    if (
      parsed.href.includes("\0") ||
      parsed.href.includes("\n") ||
      parsed.href.includes("\r")
    ) {
      return { valid: false, error: "Invalid characters in URL" };
    }

    if (parsed.href.length > 2048) {
      return { valid: false, error: "URL too long (max 2048 characters)" };
    }

    return { valid: true, url: parsed };
  } catch (err) {
    return { valid: false, error: `Invalid URL format: ${err.message}` };
  }
}

// ============================================================================
// ROUTES
// ============================================================================

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: Date.now() - metrics.startTime,
    timestamp: new Date().toISOString(),
  });
});

app.get("/metrics", (req, res) => {
  const uptime = Date.now() - metrics.startTime;
  const avgResponseTime =
    metrics.totalRequests > 0
      ? Math.round(metrics.averageResponseTime / metrics.totalRequests)
      : 0;

  res.json({
    uptime,
    totalRequests: metrics.totalRequests,
    successfulRequests: metrics.successfulRequests,
    failedRequests: metrics.failedRequests,
    blockedRequests: metrics.blockedRequests,
    rateLimitedRequests: metrics.rateLimitedRequests,
    averageResponseTime: avgResponseTime,
    successRate:
      metrics.totalRequests > 0
        ? ((metrics.successfulRequests / metrics.totalRequests) * 100).toFixed(
            2,
          ) + "%"
        : "N/A",
    cache: config.CACHE_ENABLED ? cacheManager.getStats() : "disabled",
  });
});

app.get("/debug/recent", (req, res) => {
  res.json({
    count: recent.length,
    maxStored: MAX_RECENT_LOGS,
    cacheEnabled: config.CACHE_ENABLED,
    config: {
      requestTimeoutMs: config.REQUEST_TIMEOUT_MS,
      maxResponseSizeMb: config.MAX_RESPONSE_SIZE_MB,
      rateLimitWindowMs: config.RATE_LIMIT_WINDOW_MS,
      rateLimitMaxRequests: config.RATE_LIMIT_MAX_REQUESTS,
    },
    requests: recent,
  });
});

app.post("/admin/cache/clear", (req, res) => {
  const authToken = req.headers["x-admin-token"];
  const expectedToken = process.env.ADMIN_TOKEN;

  if (
    config.NODE_ENV === "production" &&
    (!authToken || authToken !== expectedToken)
  ) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  cacheManager.clear();
  recordMetric("admin_action", { action: "cache_cleared" });
  res.json({ message: "Cache cleared successfully" });
});

app.use("/proxy", proxyLimiter);

app.use("/proxy", async (req, res, next) => {
  const urlParam = req.query.url;

  if (!urlParam) {
    recordMetric("blocked", {
      reason: "Missing URL parameter",
      ip: req.ip,
    });
    return res.status(400).json({
      error: "Missing 'url' query parameter",
      example: "/proxy?url=https%3A%2F%2Fgoogle.com",
    });
  }

  const sanitized = sanitizeUrl(decodeURIComponent(urlParam));
  if (!sanitized.valid) {
    recordMetric("blocked", {
      reason: "Invalid URL",
      details: sanitized.error,
      ip: req.ip,
    });
    return res.status(400).json({
      error: sanitized.error,
    });
  }

  const parsedUrl = sanitized.url;

  const validation = await validateHost(parsedUrl.hostname);
  if (!validation.valid) {
    recordMetric("blocked", {
      reason: validation.reason,
      hostname: parsedUrl.hostname,
      ip: req.ip,
    });
    return res.status(403).json({
      error: "Access to this host is forbidden",
      reason: validation.reason,
      hostname: parsedUrl.hostname,
    });
  }

  if (config.CACHE_ENABLED && req.method === "GET") {
    const cacheKey = parsedUrl.href;
    const cached = cacheManager.get(cacheKey);
    if (cached) {
      recordMetric("cache_hit", { url: parsedUrl.href });
      return res.json({
        ...cached,
        fromCache: true,
        cachedAt: cached.timestamp,
      });
    }
  }

  req.targetUrl = parsedUrl.href;
  req.proxyStartTime = Date.now();
  next();
});

// PROXY HANDLER - GOOGLE COMPLIANT
app.use(
  "/proxy",
  proxy((req) => req.targetUrl, {
    timeout: config.REQUEST_TIMEOUT_MS,
    proxyReqOptDecorator: (proxyReqOpts, srcReq) => {
      // Force IPv4 and handle self-signed certs for better compatibility
      proxyReqOpts.rejectUnauthorized = false;
      return proxyReqOpts;
    },
    proxyReqPathResolver: (req) => {
      try {
        const url = new URL(req.targetUrl);
        const pathAndQuery = url.pathname + (url.search || "");
        return pathAndQuery || "/";
      } catch (e) {
        return "/";
      }
    },

    proxyReqHeaderDecorator: (headers, srcReq) => {
      try {
        const url = new URL(srcReq.targetUrl);
        headers["Host"] = url.host;
      } catch (e) {
        console.error("Error setting Host header:", e);
      }

      // GOOGLE-COMPLIANT HEADERS
      const browserHeaders = {
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "identity",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
        "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
      };

      // Replace headers completely but preserve critical session/context headers
      const preservedHeaders = [
        "host",
        "content-length",
        "content-type",
        "cookie",
        "referer",
        "origin",
        "user-agent",
        "x-youtube-client-name",
        "x-youtube-client-version",
        "authorization",
        "range",
      ];

      const outgoingHeaders = {};
      Object.keys(headers).forEach((key) => {
        const lowerKey = key.toLowerCase();
        if (preservedHeaders.includes(lowerKey)) {
          outgoingHeaders[key] = headers[key];
        }
      });

      Object.assign(outgoingHeaders, browserHeaders);

      // Ensure Host header is correct for the target
      try {
        const url = new URL(srcReq.targetUrl);
        outgoingHeaders["Host"] = url.host;
      } catch (e) {}

      // Special handling for YouTube: remove any headers that might cause 400
      if (
        srcReq.targetUrl.includes("youtube.com") ||
        srcReq.targetUrl.includes("googlevideo.com")
      ) {
        const problematicPrefixes = [
          "sec-",
          "x-goog-",
          "x-youtube-",
          "x-client-data",
        ];
        const exactMatches = [
          "priority",
          "dnt",
          "save-data",
          "accept-language",
          "upgrade-insecure-requests",
          "purpose",
          "referer",
        ];

        Object.keys(outgoingHeaders).forEach((key) => {
          const lowerKey = key.toLowerCase();
          if (
            problematicPrefixes.some((prefix) => lowerKey.startsWith(prefix)) ||
            exactMatches.includes(lowerKey)
          ) {
            delete outgoingHeaders[key];
          }
        });

        // Crucial: YouTube 400s often happen due to cookie format or length via proxy
        // We strip cookies for media requests to ensure playback doesn't fail
        if (srcReq.targetUrl.includes("googlevideo.com")) {
          delete outgoingHeaders["cookie"];
        }

        // Force Host to be exactly what YouTube expects
        try {
          const url = new URL(srcReq.targetUrl);
          outgoingHeaders["Host"] = url.host;
        } catch (e) {}
      }

      return outgoingHeaders;
    },

    proxyResHeaderDecorator: (headers, srcRes, srcReq, destRes) => {
      const removeHeaders = [
        "x-frame-options",
        "content-security-policy",
        "content-security-policy-report-only",
        "strict-transport-security",
        "x-content-type-options",
        "x-xss-protection",
        "public-key-pins",
        "expect-ct",
        "x-permitted-cross-domain-policies",
      ];

      removeHeaders.forEach((header) => {
        delete headers[header];
      });

      // Handle gzip/br decompression by removing the header if we're rewriting
      if (srcRes.shouldRewrite) {
        delete headers["content-encoding"];
        delete headers["content-length"];
      }

      // Fix for broken CSS/JS/Images: Force Absolute URLs in Location header
      if (headers["location"]) {
        try {
          const targetUrlObj = new URL(srcReq.targetUrl);
          const redirectUrl = new URL(headers["location"], targetUrlObj.href)
            .href;
          headers["location"] = `/proxy?url=${encodeURIComponent(redirectUrl)}`;
        } catch (e) {
          // Fallback to original
        }
      }

      // GitHub security/integrity headers that cause CSRF/Session issues
      delete headers["set-cookie-secure"];
      delete headers["x-github-request-id"];

      headers["Access-Control-Allow-Origin"] = "*";
      headers["Access-Control-Allow-Methods"] =
        "GET, POST, PUT, DELETE, OPTIONS";
      headers["Access-Control-Allow-Headers"] = "*";
      headers["Access-Control-Expose-Headers"] = "*";

      return headers;
    },

    proxyErrorHandler: (err, res, next) => {
      const elapsed = Date.now() - res.req.proxyStartTime;

      console.error("❌ Proxy error:", err.message);
      console.error("Target URL:", res.req.targetUrl);
      console.error("Full error:", err);

      recordMetric("error", {
        error: err.message,
        code: err.code,
        url: res.req.targetUrl,
        elapsedMs: elapsed,
      });

      res.status(502).json({
        error: "Failed to reach upstream server",
        message: err.message,
        code: err.code,
        url: res.req.targetUrl,
        elapsedMs: elapsed,
      });
    },

    userResDecorator: (proxyRes, proxyResData, userReq, userRes) => {
      const elapsed = Date.now() - userReq.proxyStartTime;
      const contentLength =
        proxyRes.headers["content-length"] || proxyResData.length;

      console.log(`✓ Response received: ${userReq.targetUrl}`);
      console.log(`  Status: ${proxyRes.statusCode}`);
      console.log(`  Size: ${contentLength} bytes`);
      console.log(`  Time: ${elapsed}ms`);

      if (contentLength > config.MAX_RESPONSE_SIZE_MB * 1024 * 1024) {
        recordMetric("blocked", {
          reason: "Response too large",
          url: userReq.targetUrl,
          size: contentLength,
          maxSize: config.MAX_RESPONSE_SIZE_MB * 1024 * 1024,
        });
        userRes.status(413).json({
          error: "Response too large",
          maxSizeMb: config.MAX_RESPONSE_SIZE_MB,
        });
        return proxyResData;
      }

      metrics.averageResponseTime += elapsed;
      metrics.successfulRequests++;

      recordMetric("success", {
        url: userReq.targetUrl,
        statusCode: proxyRes.statusCode,
        contentLength: contentLength,
        elapsedMs: elapsed,
      });

      // REWRITE LINKS TO GO THROUGH PROXY
      const contentType = proxyRes.headers["content-type"] || "";
      if (contentType.includes("text/html")) {
        let body = proxyResData.toString();
        const targetUrlObj = new URL(userReq.targetUrl);
        const origin = targetUrlObj.origin;
        const baseUrl = targetUrlObj.href.substring(
          0,
          targetUrlObj.href.lastIndexOf("/") + 1,
        );

        // 1. Inject <base> tag at the very beginning of <head>
        // This is the most reliable way to handle relative assets without breaking the page structure
        const baseTag = `\n<base href="${baseUrl}">\n`;
        if (body.toLowerCase().includes("<head>")) {
          body = body.replace(/<head>/i, `<head>${baseTag}`);
        } else if (body.toLowerCase().includes("<html>")) {
          body = body.replace(/<html>/i, `<html><head>${baseTag}</head>`);
        } else {
          body = baseTag + body;
        }

        // 2. YouTube-specific URL transformations for embedding
        if (userReq.targetUrl.includes("youtube.com/watch?v=")) {
          const videoId = new URL(userReq.targetUrl).searchParams.get("v");
          if (videoId) {
            const embedUrl = `https://www.youtube.com/embed/${videoId}?autoplay=1&mute=1`;
            body = `<style>body,html{margin:0;padding:0;height:100%;overflow:hidden;}iframe{width:100%;height:100%;border:none;}</style><iframe src="${embedUrl}" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>`;
            return Buffer.from(body);
          }
        }

        // 3. Only rewrite absolute navigation links to keep the user in the proxy
        // We use a more cautious regex to avoid breaking scripts or complex attributes
        body = body.replace(
          /(?:href|action)=["']((?:https?:\/\/|\/)[^"']+)["']/gi,
          (match, url) => {
            // Skip common asset types that <base> handles better
            if (url.match(/\.(png|jpg|jpeg|gif|css|js|woff2|svg)$/i))
              return match;

            let fullUrl = url;
            if (url.startsWith("/")) {
              try {
                fullUrl = new URL(url, targetUrlObj.origin).href;
              } catch (e) {
                return match;
              }
            }

            // Use an attribute-aware prefix
            const attr = match.startsWith("href") ? "href" : "action";
            return `${attr}="/proxy?url=${encodeURIComponent(fullUrl)}"`;
          },
        );

        return Buffer.from(body);
      }

      if (
        config.CACHE_ENABLED &&
        userReq.method === "GET" &&
        proxyRes.statusCode === 200
      ) {
        const cacheKey = userReq.targetUrl;
        cacheManager.set(cacheKey, {
          statusCode: proxyRes.statusCode,
          contentType: proxyRes.headers["content-type"],
          data: proxyResData.toString(),
          timestamp: new Date().toISOString(),
          elapsedMs: elapsed,
        });
      }

      return proxyResData;
    },

    limit: config.MAX_RESPONSE_SIZE_MB + "mb",
  }),
);

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Serve static files AFTER the root route
app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
    path: req.originalUrl,
  });
});

app.use((err, req, res, next) => {
  console.error("Error:", err);
  recordMetric("error", {
    error: err.message,
    stack: config.NODE_ENV === "development" ? err.stack : undefined,
  });

  res.status(err.status || 500).json({
    error: "Internal server error",
    message: config.NODE_ENV === "development" ? err.message : undefined,
  });
});

// ============================================================================
// SERVER START
// ============================================================================

const server = app.listen(config.PORT, "0.0.0.0", () => {
  console.log("\n" + "=".repeat(60));
  console.log("✓ Replit Proxy Server Started");
  console.log("=".repeat(60));
  console.log(`✓ Port: ${config.PORT}`);
  console.log(`✓ Environment: ${config.NODE_ENV}`);
  console.log(`✓ URL: http://localhost:${config.PORT}`);
  console.log(`✓ Health:  http://localhost:${config.PORT}/health`);
  console.log(`✓ Metrics: http://localhost:${config.PORT}/metrics`);
  console.log(`✓ Debug: http://localhost:${config.PORT}/debug/recent`);
  console.log("=".repeat(60) + "\n");
});

server.setTimeout(config.REQUEST_TIMEOUT_MS + 5000);

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`✗ Port ${config.PORT} already in use`);
    process.exit(1);
  }
  console.error("Server error:", err);
  process.exit(1);
});

process.on("SIGTERM", () => {
  console.log("\n✓ SIGTERM received, shutting down gracefully.. .");
  server.close(() => {
    console.log("✓ Server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("\n✓ SIGINT received, shutting down gracefully.. .");
  server.close(() => {
    console.log("✓ Server closed");
    process.exit(0);
  });
});

module.exports = app;
