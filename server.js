"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const httpProxy = require("http-proxy");

const SESSION_COOKIE = "picd_theia_session";
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000;
const MAX_LOGIN_BODY_BYTES = 8192;
const LOGIN_WINDOW_MS = 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 10;

function safeEqual(left, right) {
  const leftDigest = crypto.createHash("sha256").update(left).digest();
  const rightDigest = crypto.createHash("sha256").update(right).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}

function signSession(secret, expiresAt) {
  const payload = Buffer.from(JSON.stringify({ exp: expiresAt, nonce: crypto.randomBytes(16).toString("hex") })).toString("base64url");
  const signature = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function hasValidSession(secret, token, now = Date.now()) {
  if (!token) return false;
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra) return false;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest();
  let actual;
  try {
    actual = Buffer.from(signature, "base64url");
  } catch {
    return false;
  }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return false;
  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return Number.isSafeInteger(session.exp) && session.exp > now;
  } catch {
    return false;
  }
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").flatMap(part => {
    const separator = part.indexOf("=");
    if (separator < 1) return [];
    return [[part.slice(0, separator).trim(), part.slice(separator + 1).trim()]];
  }));
}

function sendJson(response, status, value, headers = {}) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  response.end(JSON.stringify(value));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    let tooLarge = false;
    request.setEncoding("utf8");
    request.on("data", chunk => {
      if (tooLarge) return;
      body += chunk;
      if (Buffer.byteLength(body) > MAX_LOGIN_BODY_BYTES) {
        tooLarge = true;
      }
    });
    request.on("end", () => {
      if (tooLarge) {
        reject(Object.assign(new Error("Request body is too large."), { statusCode: 413 }));
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(Object.assign(new Error("Request must contain valid JSON."), { statusCode: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function setCorsHeaders(request, response, dashboardOrigins) {
  const origin = request.headers.origin;
  response.setHeader("Vary", "Origin");
  if (!dashboardOrigins.includes(origin)) return false;
  response.setHeader("Access-Control-Allow-Origin", origin);
  response.setHeader("Access-Control-Allow-Credentials", "true");
  return true;
}

function sessionCookie(value, expiresAt) {
  const expires = new Date(expiresAt).toUTCString();
  return `${SESSION_COOKIE}=${value}; Path=/; Expires=${expires}; Max-Age=${Math.max(0, Math.floor((expiresAt - Date.now()) / 1000))}; HttpOnly; Secure; SameSite=None; Partitioned`;
}

function addUpstreamAuthentication(proxyRequest, authorization, upstreamOrigin) {
  proxyRequest.setHeader("Authorization", authorization);
  // changeOrigin rewrites Host to the upstream, but Theia rejects requests whose
  // Origin does not match Host (403), so present the upstream's own origin.
  if (proxyRequest.getHeader("origin")) proxyRequest.setHeader("Origin", upstreamOrigin);
  const cookie = proxyRequest.getHeader("cookie");
  if (typeof cookie !== "string") return;
  const forwardedCookies = cookie.split(";").map(value => value.trim()).filter(value => !value.startsWith(`${SESSION_COOKIE}=`));
  if (forwardedCookies.length) proxyRequest.setHeader("Cookie", forwardedCookies.join("; "));
  else proxyRequest.removeHeader("Cookie");
}

function createGatewayServer(config) {
  const authorization = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
  const attempts = new Map();
  const proxy = httpProxy.createProxyServer({
    target: config.upstreamUrl,
    changeOrigin: true,
    ws: true,
    xfwd: true,
    proxyTimeout: 0,
    timeout: 0,
  });

  const upstreamOrigin = new URL(config.upstreamUrl).origin;
  proxy.on("proxyReq", proxyRequest => {
    addUpstreamAuthentication(proxyRequest, authorization, upstreamOrigin);
  });
  proxy.on("proxyReqWs", proxyRequest => {
    addUpstreamAuthentication(proxyRequest, authorization, upstreamOrigin);
  });
  proxy.on("proxyRes", (proxyResponse, request) => {
    if (proxyResponse.statusCode === 403) console.error(`Theia upstream returned 403 for ${request.method} ${request.url.split("?")[0]}`);
    delete proxyResponse.headers["www-authenticate"];
  });
  proxy.on("error", (error, request, response) => {
    console.error("Theia upstream proxy failed:", error.message);
    if (response && typeof response.writeHead === "function" && !response.headersSent) {
      sendJson(response, 502, { error: "The cloud IDE is temporarily unavailable." });
      return;
    }
    if (response && typeof response.destroy === "function") response.destroy();
    else if (request && typeof request.destroy === "function") request.destroy();
  });

  const server = http.createServer(async (request, response) => {
    const pathname = new URL(request.url, "http://gateway.local").pathname;
    if (pathname === "/healthz") {
      sendJson(response, 200, { ok: true });
      return;
    }

    if (pathname.startsWith("/auth/")) {
      const corsAllowed = setCorsHeaders(request, response, config.dashboardOrigins || [config.dashboardOrigin]);
      if (!corsAllowed) {
        sendJson(response, 403, { error: "Origin is not allowed." });
        return;
      }
      if (request.method === "OPTIONS") {
        response.writeHead(204, {
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "600",
        });
        response.end();
        return;
      }
      if (pathname === "/auth/session" && request.method === "GET") {
        const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
        sendJson(response, 200, { authenticated: hasValidSession(config.sessionSecret, token) });
        return;
      }
      if (pathname === "/auth/login" && request.method === "POST") {
        const forwardedAddresses = request.headers["x-forwarded-for"];
        const address = (typeof forwardedAddresses === "string" ? forwardedAddresses.split(",").at(-1)?.trim() : "") || request.socket.remoteAddress || "unknown";
        const now = Date.now();
        const previous = attempts.get(address);
        const attempt = previous && previous.startedAt + LOGIN_WINDOW_MS > now
          ? previous
          : { startedAt: now, count: 0 };
        if (attempts.size > 1000) {
          for (const [key, value] of attempts) {
            if (value.startedAt + LOGIN_WINDOW_MS <= now) attempts.delete(key);
          }
        }
        if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
          sendJson(response, 429, { error: "Too many sign-in attempts. Wait a minute and try again." });
          return;
        }
        try {
          const body = await readJson(request);
          const username = typeof body.username === "string" ? body.username : "";
          const password = typeof body.password === "string" ? body.password : "";
          if (!safeEqual(username, config.username) || !safeEqual(password, config.password)) {
            attempt.count++;
            attempts.set(address, attempt);
            sendJson(response, 401, { error: "Sign-in failed. Check your IDE username and password." });
            return;
          }
          attempts.delete(address);
          const expiresAt = Date.now() + SESSION_DURATION_MS;
          response.setHeader("Set-Cookie", sessionCookie(signSession(config.sessionSecret, expiresAt), expiresAt));
          sendJson(response, 200, { authenticated: true });
        } catch (error) {
          const status = Number.isInteger(error.statusCode) ? error.statusCode : 400;
          sendJson(response, status, { error: status === 413 ? error.message : "Request must contain valid JSON." });
        }
        return;
      }
      if (pathname === "/auth/logout" && request.method === "POST") {
        try {
          await readJson(request);
          response.setHeader("Set-Cookie", sessionCookie("", 0));
          sendJson(response, 200, { authenticated: false });
        } catch (error) {
          const status = Number.isInteger(error.statusCode) ? error.statusCode : 400;
          sendJson(response, status, { error: status === 413 ? error.message : "Request must contain valid JSON." });
        }
        return;
      }
      sendJson(response, 404, { error: "Not found." });
      return;
    }

    const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    if (!hasValidSession(config.sessionSecret, token)) {
      sendJson(response, 401, { error: "Sign in to Developer Studio to access the cloud IDE." });
      return;
    }
    proxy.web(request, response, { target: config.upstreamUrl });
  });

  server.on("upgrade", (request, socket, head) => {
    const token = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    const requestOrigin = request.headers.origin;
    const host = request.headers.host || "";
    const localHost = /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host);
    const protocol = request.headers["x-forwarded-proto"] === "http" || localHost
      ? "http"
      : "https";
    const expectedOrigin = `${protocol}://${host}`;
    if (!hasValidSession(config.sessionSecret, token) || requestOrigin !== expectedOrigin) {
      socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }
    proxy.ws(request, socket, head, { target: config.upstreamUrl });
  });

  return server;
}

function loadConfig(environment = process.env) {
  const upstreamUrl = environment.THEIA_UPSTREAM_URL;
  const username = environment.THEIA_BASIC_AUTH_USER;
  const password = environment.THEIA_BASIC_AUTH_PASSWORD;
  const dashboardOrigins = environment.DASHBOARD_ORIGIN?.split(",").map(origin => origin.trim()).filter(Boolean);
  const sessionSecret = environment.SESSION_SECRET;
  if (!upstreamUrl || !username || !password || !dashboardOrigins?.length || !sessionSecret) {
    throw new Error("Set THEIA_UPSTREAM_URL, THEIA_BASIC_AUTH_USER, THEIA_BASIC_AUTH_PASSWORD, DASHBOARD_ORIGIN, and SESSION_SECRET.");
  }
  let parsedUpstream;
  let parsedDashboards;
  try {
    parsedUpstream = new URL(upstreamUrl);
    parsedDashboards = dashboardOrigins.map(origin => new URL(origin));
  } catch {
    throw new Error("THEIA_UPSTREAM_URL and DASHBOARD_ORIGIN must be valid URLs.");
  }
  if (parsedUpstream.protocol !== "https:" && !(parsedUpstream.protocol === "http:" && ["localhost", "127.0.0.1"].includes(parsedUpstream.hostname))) {
    throw new Error("THEIA_UPSTREAM_URL must use HTTPS, except for localhost development.");
  }
  if (parsedUpstream.username || parsedUpstream.password || parsedUpstream.search || parsedUpstream.hash) {
    throw new Error("THEIA_UPSTREAM_URL must not include credentials, a query string, or a fragment.");
  }
  if (parsedDashboards.some((parsed, index) =>
    parsed.origin !== dashboardOrigins[index] ||
    (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && ["localhost", "127.0.0.1"].includes(parsed.hostname))) ||
    parsed.username || parsed.password || parsed.search || parsed.hash
  )) {
    throw new Error("Each DASHBOARD_ORIGIN must be an HTTPS origin (or localhost for development), with no path.");
  }
  if (Buffer.byteLength(sessionSecret) < 32) throw new Error("SESSION_SECRET must be at least 32 bytes.");
  return { upstreamUrl, username, password, dashboardOrigins, sessionSecret };
}

if (require.main === module) {
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    console.error("Theia login gateway configuration error:", error.message);
    process.exitCode = 1;
  }
  if (config) {
    const server = createGatewayServer(config);
    const port = Number(process.env.PORT || 10000);
    server.listen(port, "0.0.0.0", () => console.log(`Theia login gateway listening on port ${port}.`));
  }
}

module.exports = { createGatewayServer, hasValidSession, loadConfig, signSession };