// Minimal test: simulate a Strapi instance via fetch monkeypatch and assert
// the auditor confirms a public-read leak + CORS reflection, and stays quiet
// on a locked instance.
import { audit } from "../scripts/audit.js";
import assert from "node:assert";

function mockFetch({ publicRead = false, cors = false, users = false } = {}) {
  return async (url, opts = {}) => {
    const u = String(url);
    const headers = new Map();
    const get = (k) => headers.get(k.toLowerCase()) ?? null;
    const wrap = (status, body) => ({ ok: status < 400, status, headers: { get }, text: async () => JSON.stringify(body), json: async () => body });

    if (u.includes("/api/users")) return users ? wrap(200, [{ id: 1, username: "admin", email: "a@b.c" }]) : wrap(403, {});
    if (u.includes("/graphql")) return wrap(404, {});
    if (u.includes("/admin/init")) return wrap(200, { data: { hasAdmin: true } });
    if (u.endsWith("/api") || u.includes("/api?")) {
      if (cors && opts.headers?.Origin) headers.set("access-control-allow-origin", opts.headers.Origin);
      return wrap(200, {});
    }
    if (u.includes("/api/")) {
      return publicRead ? wrap(200, { data: [{ id: 1, attributes: { title: "x", body: "y" } }], meta: { pagination: { total: 42 } } }) : wrap(403, {});
    }
    return wrap(404, {});
  };
}

let pass = 0;

globalThis.fetch = mockFetch({ publicRead: true, cors: true, users: true });
let r = await audit({ url: "https://demo.test", collections: ["articles"] });
assert.ok(r.findings.find((f) => f.check === "public_read"), "should flag public read");
assert.ok(r.findings.find((f) => f.check === "cors_reflection"), "should flag CORS reflection");
assert.ok(r.findings.find((f) => f.check === "user_enumeration"), "should flag user enumeration");
assert.ok(r.active_probe.confirmed >= 3, "should confirm >=3 leaks");
console.log("PASS: leaky instance flagged (public read + CORS + user enum)"); pass++;

globalThis.fetch = mockFetch({ publicRead: false, cors: false, users: false });
r = await audit({ url: "https://locked.test", collections: ["articles"] });
assert.strictEqual(r.findings.length, 0, "locked instance should be clean");
console.log("PASS: locked instance is clean"); pass++;

console.log(`\n${pass}/2 tests passed`);
