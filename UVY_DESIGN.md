# UVY Design adoption

This application follows the [UVY Design guidance](https://github.com/UnitVectorY-Labs/uvy-design/tree/5f8bd54) at commit `5f8bd54`. The guidance is unversioned and each application owns its implementation.

## Local files and provenance

- `assets/uvy-tokens.css`, `assets/uvy-elements.css`, and `assets/uvy-theme.js` are originally copied from the former v0.1.0 asset package and are maintained locally; checksums are recorded below.
- `assets/style.css` contains the app adapter after its existing style rules. It maps the existing explorer, summaries, records, provider tables and mobile drawer to the current guidance on color, type, spacing, navigation and panels.
- `assets/vendor/htmx-4.0.0.min.js` retains the existing HTMX version but is served locally. Its SHA-384 matches the original CDN SRI.
- `templates/icons.html` embeds official Tabler outline SVG paths. Source commit/URLs/SHA-256 hashes are in `assets/licenses/ICON-SOURCES.json`; copied paths have only decorative semantics/class attributes added. UI emoji are replaced with labeled inline icons.
- MIT design/icon and Zero-Clause BSD HTMX notices ship under `assets/licenses/` and are copied to static output.

No runtime script, font, CSS or icon CDN is required. External RFC, source and provider links remain ordinary hyperlinks.

## Behavior and layout

The existing left navigation/right content pane, home summary order, domain record order, raw responses, provider/domain cross-links and mobile drawer remain. Full pages and existing fragment routes remain. Record checkboxes keep AND semantics and the hide-missing-CAA default. A shared delegated filter handler also applies those same controls consistently on direct provider-page entry. Normal data is not put behind new tabs or disclosures.

The theme controller runs before CSS, follows OS appearance without an override, and stores explicit light/dark in a host-only `uvy-theme` cookie. Its button is at the top right. The project/license footer remains in the normal flex shell outside independently scrolling content, never positioned over content. No-JavaScript pages expose a canonical browse-all-domain fallback; filtering remains a JavaScript enhancement.

Mobile summary cards retain their values/order in compact two-column grids. Existing compact labeled domain records and provider tables wrap their fields without page-wide horizontal scrolling. Semantic success/error/absence colors remain separate from interface blue/orange.

## Verification and review

Generate with `go run . -generate`; build, `go test ./...` (including a fixture-based full/domain/provider page and local-asset generation integration test), and `go vet ./...`. Browser verification covers source-content/summary parity, search and combined record filters, provider/domain HTMX cross-links/history/title/focus, cookie persistence, no-JS browse/theme, 320/390px fit and zero external runtime requests.

Source summary rankings with equal counts may reorder between builds because their existing sort has no tie-breaker; this change leaves that computation unchanged, and parity compares the complete linked data set rather than incidental tie order.

Before/after evidence uses the same complete committed10,000-domain crawl dataset at base commit `704ed00c66584cba5293b2d4d891e2f345b59d50`. A clearly identified timeout fixture supplies the error-page case because the actual dataset contains no error entries. The baseline has no dark theme; both OS preferences faithfully produce the original light appearance. Playwright Chromium library is used; no Playwright MCP is available. Evidence is stored on the design repository's dedicated evidence branch and embedded in the PR, never committed here.

For updates: review the current design guidance, maintain the application-owned implementation, regenerate, test and review representative screenshots. Do not fetch shared assets at runtime or replace application navigation/data semantics.

## Canonical file SHA-256

- `assets/uvy-tokens.css`: `0e97baaece886e0015c4238eaf7dbed9ea68f330c0f50729311c43b4a5a98533`

- `assets/uvy-elements.css`: `b2f92292dd9317bb770be1a4c745c9a00b81b6cef39cbcac54d2fe192135b092`

- `assets/uvy-theme.js`: `b105c0ddec8c19b6a380a33ffa5f9f558ca49baa477921a1dee9596d77bc61ed`

- `assets/vendor/htmx-4.0.0.min.js`: `e484d9171a9db30a39c8f16e3d709d4137f3211c659f8e6125816635033d593f`
