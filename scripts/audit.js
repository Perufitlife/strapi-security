#!/usr/bin/env node
// Strapi Security Auditor — pure Node.js, no deps.
//
// Detects, and PROVES with an anonymous probe, the most common Strapi
// production footguns:
//   - Public-role read enabled on content-types (anyone can GET your data)
//   - CORS misconfiguration (Origin reflected → credentialed cross-site reads)
//   - User enumeration via public /api/users
//   - GraphQL introspection left on in production
//   - Relational-filter oracle (populate createdBy/updatedBy leaks admin info)
//
// Keyless by design: point it at a URL (+ optionally your local repo to learn
// the collection names) and it confirms each leak by fetching it anonymously.
//
// Usage:
//   strapi-security --url https://cms.example.com [--discover ./my-strapi-app]
//   strapi-security --url https://cms.example.com --collections articles,authors
//   strapi-security --url https://cms.example.com --html report.html
//
// Your data and credentials never leave your machine — every request goes
// straight from this process to your Strapi instance.

import { readdirSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const UA = "strapi-security/0.1";
const EVIL_ORIGIN = "https://strapi-security-probe.example";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  public_read: {
    severity: "critical",
    title: "Content-type is publicly readable — anyone can GET your data",
    explain: "The Users & Permissions public role has `find`/`findOne` enabled for this collection. Any unauthenticated visitor can read every published entry. Disable the public action in Settings → Roles → Public unless the data is meant to be open.",
  },
  cors_reflection: {
    severity: "high",
    title: "CORS reflects arbitrary Origin — cross-site credentialed reads possible",
    explain: "The server echoes any Origin back in Access-Control-Allow-Origin. Combined with credentials this lets an attacker's site read API responses on behalf of a logged-in user. Pin `cors.origin` to an explicit allowlist in config/middlewares.js.",
  },
  user_enumeration: {
    severity: "high",
    title: "Public /api/users exposes the user list",
    explain: "The public role can read the Users collection, leaking usernames and emails (account enumeration + phishing fuel). Remove `find`/`findOne` on Users-permissions → User for the Public role.",
  },
  graphql_introspection: {
    severity: "medium",
    title: "GraphQL introspection enabled in production",
    explain: "The /graphql endpoint answers __schema introspection, handing attackers your full data model. Set `graphql.config.apolloServer.introspection = false` (and disable the playground) in production.",
  },
  relational_oracle: {
    severity: "high",
    title: "Public API leaks admin info via relational populate (CVE-2026-27886 class)",
    explain: "Populating createdBy/updatedBy through a public endpoint returns admin account fields. Restrict populate, upgrade Strapi, and never expose admin relations on public content types.",
  },
  admin_open_registration: {
    severity: "critical",
    title: "Admin panel has no registered super-admin (open first-admin registration)",
    explain: "/admin/init reports hasAdmin=false: anyone who reaches /admin can register the first super-admin and take over the CMS. Register the admin immediately or firewall /admin.",
  },
};

// --- Strapi REST helpers -----------------------------------------------------

async function getJson(url, headers = {}) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA, ...headers }, redirect: "follow" });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON */ }
    return { ok: r.ok, status: r.status, headers: r.headers, text, json };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  }
}

// Probe a content-type's public list endpoint anonymously.
async function probePublicRead(base, plural) {
  const url = `${base}/api/${encodeURIComponent(plural)}?pagination[pageSize]=1`;
  const r = await getJson(url);
  if (r.status === 200 && r.json && Array.isArray(r.json.data)) {
    const sample = r.json.data[0];
    const columns = sample && sample.attributes ? Object.keys(sample.attributes).slice(0, 8)
      : sample ? Object.keys(sample).slice(0, 8) : [];
    return {
      confirmed: true, status: 200,
      sample: { row_count: r.json.data.length, total: r.json.meta?.pagination?.total ?? null, columns },
    };
  }
  return { confirmed: false, status: r.status, reason: r.status === 403 || r.status === 401 ? "locked (good)" : `http ${r.status}` };
}

async function checkCors(base) {
  const r = await getJson(`${base}/api`, { Origin: EVIL_ORIGIN });
  const acao = r.headers?.get?.("access-control-allow-origin");
  if (acao && (acao === EVIL_ORIGIN || acao === "*")) {
    return { confirmed: true, reflected: acao, sentOrigin: EVIL_ORIGIN };
  }
  return { confirmed: false, reflected: acao || "(none)" };
}

async function checkUserEnum(base) {
  const r = await getJson(`${base}/api/users?pagination[pageSize]=1`);
  if (r.status === 200 && Array.isArray(r.json)) {
    return { confirmed: true, status: 200, sample_keys: r.json[0] ? Object.keys(r.json[0]).slice(0, 8) : [] };
  }
  return { confirmed: false, status: r.status };
}

async function checkGraphql(base) {
  try {
    const r = await fetch(`${base}/graphql`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": UA, Origin: EVIL_ORIGIN },
      body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
    });
    if (r.status === 404) return { present: false };
    const j = await r.json().catch(() => null);
    if (j?.data?.__schema) return { present: true, confirmed: true };
    return { present: true, confirmed: false };
  } catch { return { present: false }; }
}

async function checkRelationalOracle(base, plural) {
  const r = await getJson(`${base}/api/${encodeURIComponent(plural)}?populate=createdBy&pagination[pageSize]=1`);
  if (r.status === 200 && r.json?.data?.[0]) {
    const entry = r.json.data[0];
    const cb = entry.attributes?.createdBy?.data ?? entry.createdBy ?? null;
    if (cb && JSON.stringify(cb).match(/email|username|firstname/i)) {
      return { confirmed: true, status: 200 };
    }
  }
  return { confirmed: false, status: r.status };
}

async function checkAdminInit(base) {
  const r = await getJson(`${base}/admin/init`);
  if (r.status === 200 && r.json?.data && r.json.data.hasAdmin === false) {
    return { confirmed: true };
  }
  return { confirmed: false };
}

// --- collection discovery ----------------------------------------------------

// Parse a local Strapi repo for content-type schema.json files → plural api ids.
function discoverCollections(root) {
  const out = new Set();
  const apiDir = join(root, "src", "api");
  if (!existsSync(apiDir)) return [];
  for (const api of readdirSync(apiDir, { withFileTypes: true })) {
    if (!api.isDirectory()) continue;
    const ctDir = join(apiDir, api.name, "content-types");
    if (!existsSync(ctDir)) continue;
    for (const ct of readdirSync(ctDir, { withFileTypes: true })) {
      if (!ct.isDirectory()) continue;
      const schemaPath = join(ctDir, ct.name, "schema.json");
      if (!existsSync(schemaPath)) continue;
      try {
        const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
        const plural = schema.info?.pluralName || schema.collectionName || ct.name;
        if (plural) out.add(plural);
      } catch { /* skip */ }
    }
  }
  return [...out];
}

// Reasonable default guesses when no repo and no --collections given.
const COMMON_COLLECTIONS = ["articles", "posts", "pages", "categories", "authors", "products", "comments", "tags"];

// --- main audit --------------------------------------------------------------

export async function audit({ url, collections = [], discoverRoot = null, activeProbe = true }) {
  if (!url) throw new Error("audit() requires { url }");
  const base = url.replace(/\/+$/, "");
  const findings = [];

  let names = [...collections];
  if (discoverRoot) names.push(...discoverCollections(discoverRoot));
  if (names.length === 0) names = [...COMMON_COLLECTIONS];
  names = [...new Set(names)];

  let probed = 0, confirmed = 0;

  // Per-collection: public read + relational oracle (only when probing is on).
  for (const plural of names) {
    if (!activeProbe) continue;
    const probe = await probePublicRead(base, plural);
    probed++;
    if (probe.confirmed) {
      confirmed++;
      findings.push({
        check: "public_read", ...CHECKS.public_read,
        target: `/api/${plural}`,
        details: { collection: plural, total_rows: probe.sample.total, columns: probe.sample.columns },
        probe,
        fix: `Settings → Users & Permissions → Roles → Public → uncheck find/findOne for "${plural}".`,
      });
      // Only worth the oracle check on collections that are already public.
      const oracle = await probeRelational(base, plural, findings);
      if (oracle) confirmed++;
    }
  }

  // Site-wide checks.
  if (activeProbe) {
    const cors = await checkCors(base); probed++;
    if (cors.confirmed) {
      confirmed++;
      findings.push({ check: "cors_reflection", ...CHECKS.cors_reflection, target: base, details: cors,
        fix: "config/middlewares.js → strapi::cors → set origin: ['https://your-frontend.com']." });
    }

    const users = await checkUserEnum(base); probed++;
    if (users.confirmed) {
      confirmed++;
      findings.push({ check: "user_enumeration", ...CHECKS.user_enumeration, target: "/api/users", details: users,
        fix: "Roles → Public → uncheck Users-permissions → User → find/findOne." });
    }

    const gql = await checkGraphql(base); probed++;
    if (gql.present && gql.confirmed) {
      confirmed++;
      findings.push({ check: "graphql_introspection", ...CHECKS.graphql_introspection, target: "/graphql", details: gql,
        fix: "config/plugins.js → graphql.config: introspection:false, playgroundAlways:false in production." });
    }

    const init = await checkAdminInit(base); probed++;
    if (init.confirmed) {
      confirmed++;
      findings.push({ check: "admin_open_registration", ...CHECKS.admin_open_registration, target: "/admin", details: init,
        fix: "Register the super-admin now, or block /admin at the firewall/reverse-proxy." });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    strapi_url: base,
    scanned_by: "strapi-security v0.1",
    active_probe: { enabled: activeProbe, probed, confirmed },
    collections_checked: names,
    summary,
    findings,
  };
}

// helper kept out of the main loop for readability
async function probeRelational(base, plural, findings) {
  const oracle = await checkRelationalOracle(base, plural);
  if (oracle.confirmed) {
    findings.push({
      check: "relational_oracle", ...CHECKS.relational_oracle,
      target: `/api/${plural}?populate=createdBy`, details: { collection: plural }, probe: oracle,
      fix: "Upgrade Strapi (>=5.45) and strip admin relations from public populate.",
    });
    return true;
  }
  return false;
}

// --- CLI ---------------------------------------------------------------------

function parseArgs(argv) {
  const a = argv.slice(2);
  const flag = (k) => { const i = a.indexOf(k); return i !== -1 ? a[i + 1] : null; };
  return {
    help: a.includes("--help") || a.includes("-h"),
    url: flag("--url") || process.env.STRAPI_URL,
    collections: (flag("--collections") || "").split(",").map((s) => s.trim()).filter(Boolean),
    discoverRoot: a.includes("--discover") ? (flag("--discover") && !flag("--discover").startsWith("--") ? flag("--discover") : process.cwd()) : null,
    activeProbe: !a.includes("--no-probe"),
    html: a.includes("--html") ? (flag("--html") || "strapi-report.html") : null,
  };
}

export async function run() {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.url) {
    console.error(`strapi-security — audit a Strapi CMS, prove each leak with an anonymous probe.

Usage:
  strapi-security --url https://cms.example.com
  strapi-security --url https://cms.example.com --discover ./my-strapi-app
  strapi-security --url https://cms.example.com --collections articles,authors
  strapi-security --url https://cms.example.com --html report.html

Flags:
  --url <url>            Strapi base URL (or STRAPI_URL env)
  --discover [path]      Learn collection names from a local Strapi repo (default: cwd)
  --collections a,b,c    Explicit collection plural names to probe
  --no-probe             List checks without sending any request
  --html <file>          Write an HTML report

Detects: public-role read exposure, CORS reflection, user enumeration,
GraphQL introspection, relational-populate admin leak, open admin registration.`);
    process.exit(opts.url ? 0 : 1);
  }

  const result = await audit(opts);

  if (opts.html) {
    const { renderHtml } = await import("./report.js");
    writeFileSync(opts.html, renderHtml(result));
    console.error(`HTML report written to ${opts.html}`);
  }
  console.log(JSON.stringify(result, null, 2));
  const s = result.summary;
  console.error(`\n${s.critical} critical, ${s.high} high, ${s.medium} medium` +
    (result.active_probe.enabled ? ` — ${result.active_probe.confirmed} CONFIRMED via anonymous probe` : ""));
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) run().catch((e) => { console.error(e.message); process.exit(1); });
