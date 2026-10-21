"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const { once } = require("node:events");
const test = require("node:test");
const { createGatewayServer, hasValidSession, loadConfig, signSession } = require("../server");

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
}

test("gateway auth session, credential proxy, and logout", async t => {
  const username = "studio-user";
  const password = "test-password";
  const dashboardOrigin = "https://dashboard.example";
  const upstream = http.createServer((request, response) => {
    if (request.url === "/upstream-auth-error") {
      response.writeHead(401, { "WWW-Authenticate": 'Basic realm="Theia"' }).end("upstream credentials rejected");
      return;
    }
    if (request.headers.authorization !== `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`) {
      response.writeHead(401).end();
      return;
    }
    response.writeHead(200, { "Content-Type": "text/plain", "X-Upstream-Cookie": request.headers.cookie || "" }).end(`proxied ${request.url}`);
  });
  const upstreamPort = await listen(upstream);
  let gateway;
  t.after(() => {
    gateway?.close();
    upstream.close();
  });
  gateway = createGatewayServer({
    upstreamUrl: `http://127.0.0.1:${upstreamPort}`,
    username,
    password,
    dashboardOrigin,
    sessionSecret: "a".repeat(48),
  });
  const gatewayPort = await listen(gateway);
  const url = `http://127.0.0.1:${gatewayPort}`;
  const headers = { Origin: dashboardOrigin };

  const initialSession = await fetch(`${url}/auth/session`, { headers });
  assert.equal(initialSession.status, 200);
  assert.deepEqual(await initialSession.json(), { authenticated: false });
  assert.equal(initialSession.headers.get("access-control-allow-origin"), dashboardOrigin);

  const rejectedOrigin = await fetch(`${url}/auth/session`, { headers: { Origin: "https://untrusted.example" } });
  assert.equal(rejectedOrigin.status, 403);

  const deniedProxy = await fetch(`${url}/workspace`);
  assert.equal(deniedProxy.status, 401);
  assert.equal(deniedProxy.headers.get("www-authenticate"), null);

  const badLogin = await fetch(`${url}/auth/login`, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({ username, password: "incorrect" }),
  });
  assert.equal(badLogin.status, 401);

  const login = await fetch(`${url}/auth/login`, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  assert.equal(login.status, 200);
  const setCookie = login.headers.get("set-cookie");
  assert.ok(setCookie?.includes("HttpOnly"));
  assert.ok(setCookie?.includes("Secure"));
  assert.ok(setCookie?.includes("SameSite=None"));
  assert.ok(setCookie?.includes("Partitioned"));
  const cookie = setCookie.split(";")[0];

  const proxied = await fetch(`${url}/workspace`, { headers: { Cookie: `other=kept; ${cookie}` } });
  assert.equal(proxied.status, 200);
  assert.equal(await proxied.text(), "proxied /workspace");
  assert.equal(proxied.headers.get("x-upstream-cookie"), "other=kept");

  const upstreamAuthError = await fetch(`${url}/upstream-auth-error`, { headers: { Cookie: cookie } });
  assert.equal(upstreamAuthError.status, 401);
  assert.equal(upstreamAuthError.headers.get("www-authenticate"), null);

  const logout = await fetch(`${url}/auth/logout`, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: "{}",
  });
  assert.equal(logout.status, 200);
  const clearedCookie = logout.headers.get("set-cookie").split(";")[0];
  const afterLogout = await fetch(`${url}/auth/session`, { headers: { ...headers, Cookie: clearedCookie } });
  assert.deepEqual(await afterLogout.json(), { authenticated: false });
});

test("session tokens reject tampering and expiry", () => {
  const secret = "b".repeat(48);
  const token = signSession(secret, Date.now() + 1000);
  assert.equal(hasValidSession(secret, token), true);
  assert.equal(hasValidSession(secret, `${token}x`), false);
  assert.equal(hasValidSession(secret, signSession(secret, Date.now() - 1000)), false);
});

test("configuration rejects invalid origins and short session secrets", () => {
  const values = {
    THEIA_UPSTREAM_URL: "https://ide.example",
    THEIA_BASIC_AUTH_USER: "user",
    THEIA_BASIC_AUTH_PASSWORD: "password",
    DASHBOARD_ORIGIN: "https://dashboard.example",
    SESSION_SECRET: "short",
  };
  assert.throws(() => loadConfig(values), /at least 32 bytes/);
  assert.throws(() => loadConfig({ ...values, DASHBOARD_ORIGIN: "https://dashboard.example/path", SESSION_SECRET: "s".repeat(32) }), /with no path/);
});
