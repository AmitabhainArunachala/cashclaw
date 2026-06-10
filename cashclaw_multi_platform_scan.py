#!/usr/bin/env python3
"""Multi-platform bounty scanner.

Scans GitHub, Polar.sh, Algora, IssueHunt, Superteam, and many org
repos for paid bounties. Outputs a unified leaderboard with dollar values.
Adds competition detection and 'likely_claimed' marking.
"""

import subprocess
import json
import re
import sys
import os
import urllib.request
import urllib.error
import urllib.parse
import ssl
from datetime import datetime, timezone


def eprint(*args, **kwargs):
    """Print to stderr for diagnostics."""
    print(*args, file=sys.stderr, **kwargs)


def fetch_url(url, timeout=15, headers=None):
    """Fetch a URL and return parsed JSON, or None on failure."""
    req_headers = {"User-Agent": "CashClaw/1.0"}
    if headers:
        req_headers.update(headers)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=req_headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)
    except Exception as exc:
        eprint(f"  [WARN] fetch failed for {url}: {exc}")
        return None


def gh_api(path, jq=None):
    """Call gh CLI API, return parsed JSON dict/list, or None on failure.
    When jq is used, returns str or None.
    """
    cmd = ["gh", "api", path]
    if jq:
        cmd += ["--jq", jq]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        eprint("  [WARN] gh CLI not found - skipping GitHub queries")
        return None
    except subprocess.TimeoutExpired:
        eprint("  [WARN] gh API timed out")
        return None
    if r.returncode != 0:
        stderr = r.stderr.strip()
        if "rate limit" in stderr.lower():
            eprint("  [WARN] GitHub API rate limited")
        elif "not found" in stderr.lower():
            pass  # many paths 404, that's normal
        else:
            eprint(f"  [WARN] gh API error: {stderr[:120]}")
        return None
    if jq:
        return r.stdout.strip()
    if not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def extract_value(text):
    """Extract dollar value from title/body text."""
    if not text:
        return 0
    patterns = [
        r"\$\s*([\d,]+(?:\.\d+)?)",
        r"(\d+)\s*USD",
        r"(\d+)\s*USDC?",
        r"(\d+)\s*USDT",
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            try:
                val = int(float(m.group(1).replace(",", "")))
                # Sanity cap at $1M to avoid parsing errors
                return min(val, 1_000_000)
            except (ValueError, IndexError):
                pass
    return 0


def check_linked_prs(owner, name, issue_number):
    """Check if an issue has linked PRs using GitHub issue timeline API.
    Returns (pr_count, likely_claimed).
    """
    if not owner or not name or not issue_number:
        return 0, False
    try:
        data = gh_api(
            f"repos/{owner}/{name}/issues/{issue_number}/timeline"
            "?per_page=5"
        )
        if not data:
            return 0, False
        pr_count = 0
        for ev in data:
            if isinstance(ev, dict) and ev.get("event") == "cross-referenced":
                source = ev.get("source", {})
                if source.get("type") == "issue":
                    pr_count += 1
        return pr_count, pr_count > 0
    except Exception:
        return 0, False


def check_linked_prs_batch(bounties):
    """Check linked PRs for all GitHub issues using one GraphQL call per owner/name pair."""
    # Group by owner/name
    groups = {}
    for b in bounties:
        src = b.get("source", "")
        if src.startswith("gh-") and b["owner"] and b["name"] and b.get("issue_number"):
            key = f"{b['owner']}/{b['name']}"
            groups.setdefault(key, []).append(b)

    total = sum(len(v) for v in groups.values())
    eprint(f"  Checking competition for {total} issues across {len(groups)} repos...")

    done = 0
    for repo, issues in groups.items():
        owner, name = repo.split("/")
        numbers = [b["issue_number"] for b in issues]

        # Try GraphQL batch query for up to 50 issues at once
        aliases = []
        for n in numbers:
            alias = f"r{n}"
            aliases.append(
                f'{alias}: repository(owner: "{owner}", name: "{name}")'
                f' {{ issue(number: {n}) {{ timelineItems(first: 5, itemTypes: CROSS_REFERENCED_EVENT)'
                f" {{ nodes {{ ... on CrossReferencedEvent {{ "
                f"source {{ ... on PullRequest {{ id }} }} }} }} }} }} }}"
            )
        query = "{" + " ".join(aliases) + "}"

        # Split into batches of 10 (GraphQL complexity limits)
        batch_size = 10
        for i in range(0, len(issues), batch_size):
            batch = issues[i : i + batch_size]
            batch_numbers = [b["issue_number"] for b in batch]
            batch_aliases = []
            for n in batch_numbers:
                alias = f"r{n}"
                batch_aliases.append(
                    f'{alias}: repository(owner: "{owner}", name: "{name}")'
                    f' {{ issue(number: {n}) {{ timelineItems(first: 5, itemTypes: CROSS_REFERENCED_EVENT)'
                    f" {{ nodes {{ ... on CrossReferencedEvent {{ "
                    f"source {{ ... on PullRequest {{ id }} }} }} }} }} }} }}"
                )
            chunk_query = "{" + " ".join(batch_aliases) + "}"

            result = gh_api("graphql", f"-f query='{chunk_query}'")

            if result and isinstance(result, str):
                try:
                    result = json.loads(result)
                except json.JSONDecodeError:
                    pass

            if isinstance(result, dict) and "data" in result:
                data = result["data"]
                for b in batch:
                    n = b["issue_number"]
                    alias = f"r{n}"
                    issue_data = data.get(alias, {}).get("issue", {})
                    if issue_data:
                        nodes = (
                            issue_data.get("timelineItems", {})
                            .get("nodes", [])
                        )
                        pr_count = sum(1 for nd in nodes if nd is not None)
                        b["pr_count"] = pr_count
                        b["likely_claimed"] = pr_count > 0
            else:
                # Fallback: individual calls
                for b in batch:
                    pr_count, claimed = check_linked_prs(owner, name, b["issue_number"])
                    b["pr_count"] = pr_count
                    b["likely_claimed"] = claimed

            done += len(batch)
            if done % 50 == 0:
                eprint(f"    ... checked {done}/{total} issues for linked PRs")

    eprint(f"    Checked {total} total issues for competition")
    return bounties


def process_gh_item(item, source):
    """Convert a GitHub API issue item to our unified format."""
    title = item.get("title", "")
    body = item.get("body") or ""
    url = item.get("html_url", "")
    repo_url = item.get("repository_url", "")
    parts = repo_url.rstrip("/").split("/")
    owner = parts[-2] if len(parts) >= 2 else ""
    name = parts[-1] if len(parts) >= 1 else ""
    value = extract_value(title)
    if value == 0:
        value = extract_value(body[:1000])
    labels = [l.get("name", "") for l in item.get("labels", [])]
    issue_number = item.get("number")
    return {
        "url": url,
        "title": title[:200],
        "value_usd": value,
        "owner": owner,
        "name": name,
        "source": source,
        "labels": labels,
        "created": item.get("created_at", ""),
        "updated": item.get("updated_at", ""),
        "issue_number": issue_number,
        "pr_count": 0,
        "likely_claimed": False,
    }


# ─── SOURCE SCANNERS ───────────────────────────────────────────────


def scan_github_wide():
    """Wide GitHub search via gh CLI - many queries for bounty issues."""
    results = []
    queries = [
        # Existing queries (label-based)
        ("label:bounty state:open sort:updated", "gh-label-bounty"),
        ("bounty $ state:open sort:updated", "gh-text-bounty-dollar"),
        ("label:algora state:open", "gh-algora"),
        ("label:polar-sh state:open label:bounty", "gh-polar"),
        ('"bounty" "pull request" state:open sort:updated', "gh-bounty-pr"),
        # New wide queries
        ("label:paid state:open sort:updated", "gh-label-paid"),
        ("label:reward state:open sort:updated", "gh-label-reward"),
        ('"$1000 bounty" state:open sort:updated', "gh-1000-bounty"),
        ('"$500 bounty" state:open sort:updated', "gh-500-bounty"),
        ('"security bounty" state:open sort:updated', "gh-security-bounty"),
        ('"bounty program" state:open sort:updated', "gh-bounty-program"),
        ('"bug bounty" state:open sort:updated', "gh-bug-bounty"),
        ('"paid issue" state:open sort:updated', "gh-paid-issue"),
        ('"reward" state:open label:bounty sort:updated', "gh-reward-bounty"),
        ("label:sponsor state:open sort:updated", "gh-sponsor"),
        ("label:funded state:open sort:updated", "gh-funded"),
        ("label:grant state:open sort:updated", "gh-grant"),
        ("label:💰 state:open sort:updated", "gh-emoji-money"),
        ("label:prize state:open sort:updated", "gh-prize"),
        ("label:open-task state:open sort:updated", "gh-open-task"),
    ]
    for q, source in queries:
        encoded = urllib.parse.quote(q, safe="+")
        path = f"search/issues?q={encoded}&per_page=30"
        data = gh_api(path)
        if not data or "items" not in data:
            continue
        items = data.get("items", [])
        eprint(f"    {source}: {len(items)} results")
        for item in items:
            results.append(process_gh_item(item, source))
    return results


def scan_github_orgs():
    """Scan specific org repos for bounty labels."""
    results = []
    orgs = [
        "tenstorrent",
        "nvidia",
        "langchain-ai",
        "vercel",
        "supabase",
        "netlify",
        "cloudflare",
        "denoland",
        "astral-sh",
    ]
    labels_to_check = ["bounty", "paid", "reward", "funded", "sponsor"]
    for org in orgs:
        for lbl in labels_to_check:
            source = f"gh-org-{org}-{lbl}"
            path = (
                f"search/issues?q=is:issue+is:open+label:{lbl}"
                f"+org:{org}&per_page=30"
            )
            data = gh_api(path)
            if not data or "items" not in data:
                continue
            items = data.get("items", [])
            if items:
                eprint(f"    {source}: {len(items)} results")
            for item in items:
                results.append(process_gh_item(item, source))
    return results


def scan_polar_sh():
    """Scan Polar.sh API for funded issues."""
    results = []
    # Polar.sh API v1 - try multiple known endpoint patterns
    urls = [
        "https://api.polar.sh/v1/issues/search?sort=funding&limit=30",
        "https://api.polar.sh/v1/issues?sort=-funding&limit=30",
        "https://api.polar.sh/v1/pledges?limit=30",
    ]
    for url in urls:
        data = fetch_url(url)
        if not data:
            continue
        # Try different response shapes
        items = None
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("items") or data.get("data") or data.get("results")
        if not items or not isinstance(items, list):
            continue
        eprint(f"    polar.sh: {len(items)} results from {url.split('?')[0]}")
        for item in items:
            title = item.get("title") or ""
            body = item.get("body") or item.get("description") or ""
            url_str = (
                item.get("html_url")
                or item.get("url")
                or item.get("platform_url")
                or ""
            )
            value = extract_value(title)
            if value == 0:
                value = extract_value(str(item.get("funding", {})))
            if value == 0:
                value = extract_value(body[:1000])
            labels = item.get("labels") or []
            if isinstance(labels, list) and labels and isinstance(labels[0], dict):
                labels = [l.get("name", "") for l in labels]
            owner = item.get("organization", {}).get("name", "") if isinstance(
                item.get("organization"), dict
            ) else ""
            repo_name = item.get("repository", {}).get("name", "") if isinstance(
                item.get("repository"), dict
            ) else ""
            results.append(
                {
                    "url": url_str,
                    "title": title[:200],
                    "value_usd": value,
                    "owner": owner,
                    "name": repo_name,
                    "source": "polar-api",
                    "labels": labels,
                    "created": item.get("created_at", ""),
                    "updated": item.get("updated_at", ""),
                    "issue_number": item.get("number"),
                    "pr_count": 0,
                    "likely_claimed": False,
                }
            )
        # Only try first working URL
        break
    return results


def scan_algora():
    """Scan Algora.io for bounties."""
    results = []
    # Algora is a Phoenix LiveView app - try their API endpoint
    url = "https://algora.io/api/bounties"
    data = fetch_url(url)
    if data:
        eprint(f"    algora: got response via API")
    else:
        # Try scraping with /orgs page or use the gh label approach
        eprint("    algora: API not available (skipping)")
    # Also try via GitHub label search through the normal gh pipeline
    return results


def scan_issuehunt():
    """Scan IssueHunt for bounty issues."""
    results = []
    url = "https://issuehunt.io/api/v1/issues"
    data = fetch_url(url)
    if data:
        eprint(f"    issuehunt: got response")
    else:
        eprint("    issuehunt: API not available (skipping)")
    return results


def scan_superteam():
    """Scan Superteam/Solana earn for bounties."""
    results = []
    urls = [
        "https://earn.superteam.fun/api/bounties",
        "https://earn.superteam.fun/api/listings?type=bounty",
    ]
    for url in urls:
        data = fetch_url(url)
        if not data:
            continue
        items = None
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("bounties") or data.get("listings") or data.get("data") or data.get("results")
        if not items or not isinstance(items, list):
            continue
        eprint(f"    superteam: {len(items)} results")
        for item in items:
            title = item.get("title") or item.get("name") or ""
            body = item.get("description") or item.get("body") or ""
            url_str = item.get("url") or item.get("link") or item.get("slug", "")
            if url_str and not url_str.startswith("http"):
                url_str = f"https://earn.superteam.fun{url_str}"
            value = extract_value(title)
            if value == 0:
                value = extract_value(str(item.get("reward", {})))
            if value == 0:
                value = extract_value(str(item.get("amount", "")))
            if value == 0:
                value = extract_value(body[:1000])
            labels = item.get("tags") or item.get("labels") or []
            if isinstance(labels, list) and labels and isinstance(labels[0], dict):
                labels = [l.get("name", "") for l in labels]
            owner = item.get("org", "") or item.get("organization", "")
            results.append(
                {
                    "url": url_str,
                    "title": title[:200],
                    "value_usd": value,
                    "owner": owner if isinstance(owner, str) else "",
                    "name": "",
                    "source": "superteam",
                    "labels": labels if isinstance(labels, list) else [],
                    "created": item.get("created_at", "") or item.get("created", ""),
                    "updated": item.get("updated_at", "") or item.get("updated", ""),
                    "issue_number": None,
                    "pr_count": 0,
                    "likely_claimed": False,
                }
            )
        break
    return results


# ─── COMPETITION DETECTION ─────────────────────────────────────────


def detect_competition(bounties):
    """For each GitHub issue, check linked PRs to mark competition.
    Uses batched GraphQL queries when possible.
    """
    return check_linked_prs_batch(bounties)


# ─── MAIN ──────────────────────────────────────────────────────────


def main():
    eprint("CashClaw Multi-Platform Bounty Scanner v2.0")
    eprint("===========================================")
    eprint()

    all_bounties = []

    # 1. Wide GitHub search
    eprint("[1/5] Scanning GitHub (wide search)...")
    try:
        gh_bounties = scan_github_wide()
        all_bounties.extend(gh_bounties)
        eprint(f"  -> {len(gh_bounties)} results")
    except Exception as e:
        eprint(f"  [ERROR] GitHub wide scan failed: {e}")

    # 2. GitHub Org scans
    eprint("[2/5] Scanning GitHub org repos...")
    try:
        org_bounties = scan_github_orgs()
        all_bounties.extend(org_bounties)
        eprint(f"  -> {len(org_bounties)} results")
    except Exception as e:
        eprint(f"  [ERROR] GitHub org scan failed: {e}")

    # 3. Polar.sh
    eprint("[3/5] Scanning Polar.sh...")
    try:
        polar_bounties = scan_polar_sh()
        all_bounties.extend(polar_bounties)
        eprint(f"  -> {len(polar_bounties)} results")
    except Exception as e:
        eprint(f"  [ERROR] Polar.sh scan failed: {e}")

    # 4. Superteam
    eprint("[4/5] Scanning Superteam/Solana...")
    try:
        super_bounties = scan_superteam()
        all_bounties.extend(super_bounties)
        eprint(f"  -> {len(super_bounties)} results")
    except Exception as e:
        eprint(f"  [ERROR] Superteam scan failed: {e}")

    # 5. Algora + IssueHunt (graceful skips)
    eprint("[5/5] Scanning Algora + IssueHunt...")
    try:
        algora_bounties = scan_algora()
        all_bounties.extend(algora_bounties)
    except Exception as e:
        eprint(f"  [ERROR] Algora scan failed: {e}")
    try:
        ih_bounties = scan_issuehunt()
        all_bounties.extend(ih_bounties)
    except Exception as e:
        eprint(f"  [ERROR] IssueHunt scan failed: {e}")

    # Deduplicate by URL
    eprint("\nDeduplicating...")
    seen = set()
    unique = []
    for b in all_bounties:
        key = b.get("url", "")
        if key and key not in seen:
            seen.add(key)
            unique.append(b)
    eprint(f"  {len(unique)} unique bounties (from {len(all_bounties)} raw)")

    # Competition detection
    unique = detect_competition(unique)

    # Split into valued / unvalued
    with_value = [b for b in unique if b.get("value_usd", 0) > 0]
    without_value = [b for b in unique if b.get("value_usd", 0) == 0]
    with_value.sort(key=lambda x: x["value_usd"], reverse=True)

    # ── REPORT ──
    sep = "─" * 70
    print(f"\n{sep}")
    print(f"  CASHCLAW BOUNTY SCAN REPORT  —  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{sep}")

    # Unclaimed bounties with values
    unclaimed_valued = [b for b in with_value if not b.get("likely_claimed")]
    claimed_valued = [b for b in with_value if b.get("likely_claimed")]

    print(f"\n  UNCLAIMED BOUNTIES WITH KNOWN VALUE ({len(unclaimed_valued)}):")
    print(f"{sep}")
    for b in unclaimed_valued[:40]:
        pr_tag = f"  [{b['pr_count']} PR(s)]" if b["pr_count"] > 0 else ""
        print(f"  ${b['value_usd']:>7,}  {b['title'][:65]}{pr_tag}")
        print(f"           {b['url']}")
        print(f"           Source: {b['source']:24s}  Labels: {', '.join(b['labels'][:4])}")
        print()

    if claimed_valued:
        print(f"\n  CLAIMED/COMPETED BOUNTIES ({len(claimed_valued)}):")
        print(f"{sep}")
        for b in claimed_valued[:15]:
            print(f"  ${b['value_usd']:>7,}  {b['title'][:65]}  [{b['pr_count']} PR]")
            print(f"           {b['url']}")
            print()

    print(f"\n  UNVALUED BOUNTIES ({len(without_value)}):")
    print(f"{sep}")
    for b in without_value[:10]:
        print(f"  $       ?  {b['title'][:70]}")
        print(f"           {b['url']}")
        print()

    # Summary
    total_value = sum(b["value_usd"] for b in unclaimed_valued)
    total_all_value = sum(b["value_usd"] for b in with_value)
    print(f"\n  {'=' * 50}")
    print(f"  SUMMARY")
    print(f"  {'=' * 50}")
    print(f"  Total bounties found:            {len(unique)}")
    print(f"  With known value:                {len(with_value)}")
    print(f"    Unclaimed:                     {len(unclaimed_valued)} (${total_value:,})")
    print(f"    Claimed/competed:              {len(claimed_valued)}")
    print(f"  Value unknown:                   {len(without_value)}")
    if unclaimed_valued:
        top = unclaimed_valued[0]
        print(f"  Top unclaimed bounty:            ${top['value_usd']:,} — {top['title'][:50]}")
        print(f"                                 {top['url']}")
    print(f"  Total potential (unclaimed):     ${total_value:,}")
    print(f"  Total scanned value (all):       ${total_all_value:,}")

    # Source breakdown
    print(f"\n  SOURCE BREAKDOWN:")
    sources = {}
    for b in unique:
        s = b.get("source", "unknown")
        sources[s] = sources.get(s, 0) + 1
    for s, c in sorted(sources.items(), key=lambda x: -x[1]):
        print(f"    {s:30s}: {c:4d}")

    # Write output
    out_dir = os.path.expanduser("~/.cashclaw")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "latest_scan.json")

    # Remove issue_number from output (internal detail)
    output_bounties = []
    for b in unique:
        ob = {k: v for k, v in b.items() if k != "issue_number"}
        output_bounties.append(ob)

    with open(out_path, "w") as f:
        json.dump(
            {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "total": len(unique),
                "valued": len(with_value),
                "unclaimed_valued": len(unclaimed_valued),
                "total_unclaimed_value": total_value,
                "total_value": total_all_value,
                "source_breakdown": sources,
                "bounties": output_bounties,
            },
            f,
            indent=2,
        )
    print(f"\n  Full results saved to {out_path}")
    print(f"{sep}\n")


if __name__ == "__main__":
    main()
