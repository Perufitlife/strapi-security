# strapi-security

> Audit any **Strapi** CMS for the misconfigurations that actually leak data — public-role read exposure, CORS reflection, user enumeration, GraphQL introspection, and the relational-populate admin oracle — and **prove each one live with an anonymous probe**. Other checklists tell you what *might* be wrong; this fetches the bytes and shows you what *is*.

> ⚡ **Run it in one line, no admin token, no install:**
> ```bash
> npx strapi-security --url https://your-strapi.example.com
> ```

> 🤝 **Want it done for you?** [Fixed-scope audit — $99 / 24h](https://buy.stripe.com/3cIeVdgikfj47yx9LkcAo0m): I verify each finding live and send a written report with the exact config fixes.

[![npm](https://img.shields.io/npm/v/strapi-security?color=red)](https://www.npmjs.com/package/strapi-security) [![downloads](https://img.shields.io/npm/dw/strapi-security)](https://www.npmjs.com/package/strapi-security) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

```
$ npx strapi-security --url https://cms.example.com
1 critical, 2 high, 0 medium — 3 CONFIRMED via anonymous probe
  CRITICAL  /api/articles   public-role read enabled — 1,204 rows reachable
  HIGH      CORS            Origin reflected → cross-site credentialed reads
  HIGH      /api/users      user list exposed (username + email)
```

## Why this exists

Strapi powers a huge share of headless-CMS deployments, and the default
Users & Permissions model makes one mistake very easy: leaving `find`/`findOne`
enabled for the **Public** role. The result is an API anyone can read. 2026
alone brought a cluster of data-exposure CVEs around public endpoints
([CVE-2026-27886](https://strapi.io/blog/headless-cms-security) relational
filtering oracle, CORS reflection, lookup-operator private-field leaks).

`strapi-security` checks for these and **confirms the real ones** by issuing the
exact anonymous request an attacker would — so you triage facts, not maybes.

## What it checks

| Check | Severity | How it's confirmed |
|---|---|---|
| Public-role read on a content-type | critical | anonymous `GET /api/{collection}` returns rows |
| CORS reflects arbitrary Origin | high | sends a foreign `Origin`, sees it echoed in `Access-Control-Allow-Origin` |
| `/api/users` user enumeration | high | anonymous `GET /api/users` returns the user list |
| Relational-populate admin oracle | high | `?populate=createdBy` leaks admin fields |
| GraphQL introspection in prod | medium | `__schema` query answered on `/graphql` |
| Open first-admin registration | critical | `/admin/init` reports `hasAdmin:false` |

## Usage

```bash
# Probe a live instance (guesses common collection names)
npx strapi-security --url https://cms.example.com

# Learn your exact collection names from your local repo, then probe
npx strapi-security --url https://cms.example.com --discover ./my-strapi-app

# Probe specific collections
npx strapi-security --url https://cms.example.com --collections articles,authors

# Write a shareable HTML report
npx strapi-security --url https://cms.example.com --html report.html

# Static only (no requests sent)
npx strapi-security --url https://cms.example.com --no-probe
```

Output is JSON on stdout (pipe it into CI) and a one-line summary on stderr.
Exit is non-zero only on usage errors — gate your pipeline on the JSON `summary`.

## Install (optional)

```bash
npm i -g strapi-security
strapi-security --url https://cms.example.com
```

Zero dependencies. Your data and credentials never leave your machine — every
request goes straight from the tool to your Strapi instance.

## Sister tools

Same active-probe philosophy for the rest of the backend stack, all MIT:

[supabase-security](https://github.com/Perufitlife/supabase-security-skill) ·
[pocketbase-security](https://github.com/Perufitlife/pocketbase-security-skill) ·
[firebase-security](https://github.com/Perufitlife/firebase-security-skill) ·
[appwrite-security](https://github.com/Perufitlife/appwrite-security-skill) ·
[nhost-security](https://github.com/Perufitlife/nhost-security-skill) ·
[directus-security](https://github.com/Perufitlife/directus-security)

## License

MIT © [Renzo Madueno](https://github.com/Perufitlife)
