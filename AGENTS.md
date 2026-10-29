# AGENTS.md — WhoisDNS Web Tools

Project instructions for AI coding agents working in this repository.

## Project context

A Node.js/Express web tool for domain WHOIS lookup, DNS record inspection, and DNS propagation checks. No build step: the frontend is plain HTML/CSS/JS served from `public/`.

| Path | Purpose |
|---|---|
| `server.js` | Express app: routing, middleware, error handling |
| `lib/domain.js` | Input validation, eTLD+1, punycode, IP detection |
| `lib/whois.js` | Port 43 socket WHOIS with RDAP fallback |
| `lib/doh.js`, `lib/dns.js` | DNS-over-HTTPS client and record resolution |
| `lib/propagation.js` | Multi-resolver propagation checks |
| `lib/ip.js`, `lib/cache.js`, `lib/ratelimit.js`, `lib/antispam.js` | Supporting services |
| `public/` | Frontend assets (no bundler) |
| `test/` | `node:test` suites (unit, API, SEO, anti-spam) |
| `scripts/backup.js` | Timestamped snapshot with SHA-256 manifest |

Design decisions and the color/typography system live in `DESIGN.md`. Read it before changing UI.

## Required verification

Run both before claiming a task is done:

```bash
npm run lint
npm test
```

Node 18, 20, and 22 are supported (see `.github/workflows/ci.yml`). Do not use `node --test` glob patterns: they only expand on Node 22+, which previously broke CI on 18 and 20.

## Browser verification (chrome-devtools MCP)

Project config enables `chrome-devtools-mcp` (see `opencode.example.json`; the real `opencode.json` holds credentials and is gitignored).

Requires Node 22+ and a local Chrome install. Start the dev server first, then use the MCP tools to verify UI work instead of guessing:

| Tool | Use |
|---|---|
| `chrome-devtools_navigate_page` | Open `http://localhost:3000/` |
| `chrome-devtools_resize_page` | Check 390x844, 768x1024, 1440x900 |
| `chrome-devtools_evaluate_script` | Read computed styles, assert computed colours/font sizes |
| `chrome-devtools_take_screenshot` | Capture desktop/mobile frames |
| `chrome-devtools_list_console_messages` | Catch runtime errors |
| `chrome-devtools_lighthouse_audit` | Accessibility, SEO, best-practices scores |
| `chrome-devtools_get_css_styles` | Inspect the real cascade for a selector |

Use `evaluate_script` and `lighthouse_audit` for claims about the UI: a screenshot cannot be read by a text-only model, computed values can.

Note: `lighthouse_audit` with `mode: "navigation"` must run after navigating to an http(s) URL; on `about:blank` it errors.

## Quality gate (Anti-Slop)

Skills: `antislop` (core) plus `antislop-ui`, `antislop-human`, `antislop-layoutmobile`, `antislop-copywriting`, `antislop-code` under `.opencode/skills/`.

Apply them as a review gate on UI, copy, and code, not as a style rewrite. Concretely:

- No generic AI-slop UI: no gratuitous gradients, glassmorphism, or "modern" decoration without purpose.
- Reuse the existing design tokens in `public/css/style.css`; do not invent a parallel palette.
- No abstraction layers, helper modules, or config indirection unless the current task needs them.
- No new dependencies when the standard library or an installed package already solves it.
- Preserve existing architecture: routes in `server.js`, logic in `lib/`, no framework migrations.
- Do not change public API shapes (`/api/*` response fields) unless the task requires it.
- Keep diffs minimal; do not reformat files you were not asked to touch.

## Communication (Caveman)

Global `AGENTS.md` in the opencode config directory already defines the caveman voice rules. Do not repeat them here.

Project-specific note: this is a technical tool for engineers. Keep error messages, CLI output, and API field names verbatim. Long explanations belong in `README.md`, not in chat replies.

## Workflow (Superpowers)

Skills: `brainstorming`, `writing-plans`, `executing-plans`, `test-driven-development`, `systematic-debugging`, `requesting-code-review`, `receiving-code-review`, `verification-before-completion`, `using-git-worktrees`, `dispatching-parallel-agents`, `subagent-driven-development`, `finishing-a-development-branch`.

Use them when the task is non-trivial:

- Ambiguous requirement or design choice → `brainstorming`, then `writing-plans`.
- Bug with unclear cause → `systematic-debugging` before editing code.
- New behavior → `test-driven-development`.
- Multi-file change → `writing-plans`, then `executing-plans`.
- Before declaring done → `verification-before-completion`.

Skip them for single-line fixes and pure questions. Loading every skill on every task wastes context.

## Division of responsibility

The three systems must not duplicate each other:

| System | Answers | Does not |
|---|---|---|
| Anti-Slop | "Is this generic, redundant, or over-engineered?" | Decide workflow order or wording length |
| Caveman | "How terse should the reply be?" | Judge code quality or plan the work |
| Superpowers | "In what order do I plan, debug, test, review?" | Rewrite UI taste or compress prose |

If two rules appear to conflict, prefer: correctness and security > existing project conventions > Anti-Slop > Superpowers process > Caveman brevity.

## Boundaries

- Never commit secrets, API keys, or `.env` files.
- Never modify `node_modules/`, `.git/`, or run `git clean -fd`.
- Never rewrite `README.md`, `DESIGN.md`, or this file without a stated reason.
- Back up configuration before changing it.
