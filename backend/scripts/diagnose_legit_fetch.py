"""
Diagnostic — path_length root-cause check (Phase 3.5 follow-up)

Runs a PATCHED, INSTRUMENTED version of the legit-URL resolution logic
against a small sample (default 200) of Tranco domains, without touching
build_training_dataset.py yet. Reports a breakdown of outcomes so we know
which fix actually matters before doing a full dataset rebuild.

Patches applied vs. the current _resolve_real_url:
  1. Sends a real User-Agent header (current code sends none — likely
     causing bot-block responses that look like "success" but aren't).
  2. Checks resp.status — treats 4xx/5xx as failure (falls back), instead
     of silently accepting a blocked/error page as a "genuine bare URL".
  3. Weighted template choice for the fallback — empty-string template
     downweighted to 5% instead of a flat 1-in-11 (~9%).

Outcome categories counted:
  - live_success_with_path : real fetch succeeded, landed on a non-bare URL
  - live_success_bare       : real fetch succeeded (status 200), genuinely
                               bare domain (no redirect to a deeper path)
  - blocked_or_error_status : fetch "succeeded" at the connection level but
                               returned 4xx/5xx (bot-block, dead page, etc.)
                               -> now correctly falls back instead of being
                               counted as legit-bare
  - exception_fallback      : real network/timeout/DNS failure -> fallback
  - fallback_used_empty_tpl : of the fallback cases, how many still landed
                               on the empty-string template

Run:
    docker compose exec api python scripts/diagnose_legit_fetch.py
"""

import asyncio
import random
import importlib.util

import aiohttp

SAMPLE_SIZE = 200
CONCURRENCY = 12
TIMEOUT_SECONDS = 10

_PATH_TEMPLATES = ['', '/login', '/about', '/products', '/blog/{slug}',
                    '/en-us/home', '/account/settings', '/search?q={slug}',
                    '/support/contact', '/{slug}/index.html', '/api/v1/status']
_TEMPLATE_WEIGHTS = [5 if t == '' else 9.5 for t in _PATH_TEMPLATES]  # empty ~5%, rest split ~95%

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

exception_types = {}
counts = {
    "live_success_with_path": 0,
    "live_success_bare": 0,
    "blocked_or_error_status": 0,
    "exception_fallback": 0,
    "fallback_used_empty_tpl": 0,
}


def _synthesize_path_weighted(domain: str) -> str:
    template = random.choices(_PATH_TEMPLATES, weights=_TEMPLATE_WEIGHTS, k=1)[0]
    if template == '':
        counts["fallback_used_empty_tpl"] += 1
    if "{slug}" in template:
        slug_words = ["update", "guide", "help", "news", "info"]
        template = template.replace("{slug}", random.choice(slug_words))
    return f"https://{domain}{template}"


async def _resolve_patched(session, domain, sem, retries=1):
    async with sem:
        candidates = [domain]
        for attempt_domain in candidates:
            for attempt in range(retries + 1):
                try:
                    async with session.get(
                        f"https://{attempt_domain}",
                        timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
                        allow_redirects=True,
                        max_redirects=5,
                        headers={"User-Agent": USER_AGENT},
                    ) as resp:
                        if resp.status >= 400:
                            counts["blocked_or_error_status"] += 1
                            return _synthesize_path_weighted(domain)
                        final_url = str(resp.url)
                        path = final_url.split("://", 1)[-1].split("/", 1)
                        has_path = len(path) > 1 and path[1] != ""
                        if has_path:
                            counts["live_success_with_path"] += 1
                        else:
                            counts["live_success_bare"] += 1
                        if attempt_domain != domain:
                            counts["www_fallback_worked"] = counts.get("www_fallback_worked", 0) + 1
                        return final_url
                except aiohttp.ClientConnectorError as e:
                    if not attempt_domain.startswith("www.") and "www." + attempt_domain not in candidates:
                        candidates.append("www." + attempt_domain)
                    if attempt < retries:
                        await asyncio.sleep(0.5)
                        continue
                    break  # try next candidate (www.) if any, else fall through to fallback below
                except Exception as e:
                    if attempt < retries:
                        await asyncio.sleep(0.5)
                        continue
                    counts["exception_fallback"] += 1
                    etype = type(e).__name__
                    exception_types[etype] = exception_types.get(etype, 0) + 1
                    return _synthesize_path_weighted(domain)
        # exhausted apex + www. candidates, all via ClientConnectorError
        counts["exception_fallback"] += 1
        exception_types["ClientConnectorError"] = exception_types.get("ClientConnectorError", 0) + 1
        return _synthesize_path_weighted(domain)


async def main():
    spec = importlib.util.spec_from_file_location(
        "build_training_dataset", "scripts/build_training_dataset.py"
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    print(f"Downloading Tranco list and sampling {SAMPLE_SIZE} domains...")
    with __import__("urllib.request", fromlist=["urlopen"]).urlopen(m.TRANCO_URL, timeout=60) as resp:
        raw = resp.read()
    import zipfile, io, csv
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        csv_name = next(n for n in zf.namelist() if n.endswith(".csv"))
        with zf.open(csv_name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            domains = [row[1] for row in reader if len(row) >= 2][:50_000]
    sample = random.sample(domains, min(SAMPLE_SIZE, len(domains)))

    sem = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_resolve_patched(session, d, sem) for d in sample]
        for i, coro in enumerate(asyncio.as_completed(tasks)):
            await coro
            if (i + 1) % 50 == 0:
                print(f"  resolved {i + 1}/{len(sample)}")

    total = sum(v for k, v in counts.items() if k != "fallback_used_empty_tpl")
    print("\n=== Outcome breakdown (patched logic) ===")
    for k in ["live_success_with_path", "live_success_bare",
              "blocked_or_error_status", "exception_fallback"]:
        pct = counts[k] / total * 100 if total else 0
        print(f"  {k:28s} {counts[k]:4d}  ({pct:5.1f}%)")
    fallback_total = counts["blocked_or_error_status"] + counts["exception_fallback"]
    print(f"\n  fallback triggered (either reason): {fallback_total} "
          f"({fallback_total/total*100:.1f}%)")
    print(f"  of those, landed on empty template: {counts['fallback_used_empty_tpl']} "
          f"({counts['fallback_used_empty_tpl']/fallback_total*100 if fallback_total else 0:.1f}% of fallbacks)")
    print(f"\n  effective bare-path rate (live_success_bare + empty-template fallbacks): "
          f"{counts['live_success_bare'] + counts['fallback_used_empty_tpl']} "
          f"({(counts['live_success_bare'] + counts['fallback_used_empty_tpl'])/total*100:.1f}%)")
    print(f"  www. retry rescued a connection: {counts.get('www_fallback_worked', 0)}")

    print("\n=== Exception type breakdown ===")
    for etype, cnt in sorted(exception_types.items(), key=lambda x: -x[1]):
        print(f"  {etype:30s} {cnt:4d}")


if __name__ == "__main__":
    asyncio.run(main())