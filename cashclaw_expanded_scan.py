#!/usr/bin/env python3
"""Expanded multi-platform bounty scanner.
Covers: GitHub (wide), Algora, Polar.sh, direct org scans, IssueHunt.
Adds competition detection (linked PRs).
"""
import subprocess, json, re, sys, os, time
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError

def gh_api(path, jq=None):
    try:
        cmd = ["gh", "api", path]
        if jq:
            cmd += ["--jq", jq]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return None
        if jq:
            return r.stdout.strip()
        return json.loads(r.stdout)
    except:
        return None

def http_get_json(url, headers=None, timeout=15):
    try:
        req = Request(url)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        req.add_header("User-Agent", "CashClaw/2.0")
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except:
        return None

def extract_value(text):
    if not text:
        return 0
    patterns = [
        r'\$\s*([\d,]+(?:\.\d+)?)',
        r'(\d+)\s*USD',
        r'(\d+)\s*USDC?',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return int(float(m.group(1).replace(',', '')))
    return 0

def count_linked_prs(owner, repo, issue_number):
    try:
        data = gh_api(f"repos/{owner}/{repo}/issues/{issue_number}/timeline",
                      jq="[.[] | select(.source != null) | .source.issue.pull_request] | length")
        if data:
            return int(data)
    except:
        pass
    return 0

def make_bounty(item, source, value_override=None):
    title = item.get('title', '')
    body = item.get('body', '') or ''
    url = item.get('html_url', '')
    repo_url = item.get('repository_url', '')
    parts = repo_url.rstrip('/').split('/')
    owner = parts[-2] if len(parts) >= 2 else ''
    name = parts[-1] if len(parts) >= 1 else ''
    value = value_override or extract_value(title)
    if value == 0:
        value = extract_value(body[:800])
    labels = [l.get('name', '') if isinstance(l, dict) else str(l)
              for l in item.get('labels', [])]
    issue_num = item.get('number', 0)
    competition = 0
    if owner and name and issue_num:
        competition = count_linked_prs(owner, name, issue_num)
    return {
        'url': url,
        'title': title[:120],
        'value_usd': value,
        'owner': owner,
        'name': name,
        'source': source,
        'labels': labels[:5],
        'created': item.get('created_at', ''),
        'updated': item.get('updated_at', ''),
        'competition': competition,
        'status': 'likely_claimed' if competition > 0 else 'open',
    }

def scan_github_wide():
    print("  [1/6] GitHub wide search...", file=sys.stderr)
    results = []
    queries = [
        ("label:bounty state:open sort:updated", "gh-bounty-label"),
        ("bounty $ state:open sort:updated", "gh-bounty-dollar"),
        ("label:algora state:open", "gh-algora"),
        ("label:polar-sh state:open label:bounty", "gh-polar"),
        ("label:paid state:open sort:updated", "gh-paid"),
        ("label:reward state:open sort:updated", "gh-reward"),
        ("\"bounty program\" state:open sort:updated", "gh-bounty-program"),
        ("$1000 bounty state:open sort:updated", "gh-1k"),
        ("$500 bounty state:open sort:updated", "gh-500"),
        ("\"security bounty\" state:open sort:updated", "gh-security"),
        ("label:\"bounty: \" state:open sort:updated", "gh-bounty-colon"),
        ("\"paid bounty\" state:open sort:updated", "gh-paid-bounty"),
        ("\"bug bounty\" state:open sort:updated", "gh-bug-bounty"),
        ("label:hacktoberfest-accepted state:open sort:updated", "gh-hacktober"),
        ("label:\"good first issue\" bounty state:open", "gh-good-first-bounty"),
    ]
    for q, source in queries:
        encoded = q.replace(" ", "+")
        data = gh_api(f"search/issues?q={encoded}&per_page=30")
        if not data or 'items' not in data:
            continue
        for item in data['items']:
            results.append(make_bounty(item, source))
        time.sleep(0.5)
    print(f"    Found {len(results)} from GitHub wide", file=sys.stderr)
    return results

def scan_org_bounties():
    print("  [2/6] Org-specific bounty scans...", file=sys.stderr)
    results = []
    orgs = [
        "tenstorrent", "nvidia", "langchain-ai", "vercel", "supabase",
        "netlify", "cloudflare", "denoland", "astral-sh", "zerodha",
        "tensorflow", "pytorch", "huggingface", "ollama", "mistralai",
        "vllm-project", "modal-labs", "replit", "posthog", "calcom",
    ]
    for org in orgs:
        data = gh_api(f"search/issues?q=org:{org}+label:bounty+state:open&per_page=20")
        if not data or 'items' not in data:
            continue
        for item in data['items']:
            results.append(make_bounty(item, f"org:{org}"))
        time.sleep(0.3)
    print(f"    Found {len(results)} from org scans", file=sys.stderr)
    return results

def scan_algora():
    print("  [3/6] Algora bounties...", file=sys.stderr)
    results = []
    urls_to_try = [
        "https://algora.io/api/bounties",
        "https://algora.io/bounties.json",
    ]
    for url in urls_to_try:
        data = http_get_json(url)
        if data and isinstance(data, list):
            for item in data:
                value = item.get('amount', 0) or item.get('reward', 0)
                if isinstance(value, str):
                    value = extract_value(value)
                results.append({
                    'url': item.get('url', item.get('issue_url', '')),
                    'title': item.get('title', '')[:120],
                    'value_usd': int(value) if value else 0,
                    'owner': item.get('owner', item.get('org', '')),
                    'name': item.get('repo', ''),
                    'source': 'algora',
                    'labels': [],
                    'created': item.get('created_at', ''),
                    'updated': item.get('updated_at', ''),
                    'competition': 0,
                    'status': 'open',
                })
            break
    if not results:
        fallback = gh_api("search/issues?q=label:algora+state:open&per_page=50")
        if fallback and 'items' in fallback:
            for item in fallback['items']:
                results.append(make_bounty(item, 'algora-gh'))
    print(f"    Found {len(results)} from Algora", file=sys.stderr)
    return results

def scan_polar():
    print("  [4/6] Polar.sh bounties...", file=sys.stderr)
    results = []
    data = http_get_json(
        "https://api.polar.sh/api/v1/issues?sort=amount_threshold&limit=50"
    )
    if data and isinstance(data, list):
        for item in data:
            value = item.get('amount_threshold', 0) or 0
            results.append({
                'url': item.get('issue_url', item.get('url', '')),
                'title': item.get('title', '')[:120],
                'value_usd': int(value / 100) if value > 100 else int(value),
                'owner': item.get('organization', {}).get('name', '') if isinstance(item.get('organization'), dict) else '',
                'name': item.get('repository', {}).get('name', '') if isinstance(item.get('repository'), dict) else '',
                'source': 'polar',
                'labels': [],
                'created': item.get('issue_created_at', ''),
                'updated': item.get('issue_updated_at', ''),
                'competition': 0,
                'status': 'open',
            })
    if not results:
        fallback = gh_api("search/issues?q=label:polar-sh+label:bounty+state:open&per_page=30")
        if fallback and 'items' in fallback:
            for item in fallback['items']:
                results.append(make_bounty(item, 'polar-gh'))
    print(f"    Found {len(results)} from Polar", file=sys.stderr)
    return results

def scan_issuehunt():
    print("  [5/6] IssueHunt...", file=sys.stderr)
    results = []
    data = http_get_json("https://issuehunt.io/api/v1/issues?status=open&sort=amount&limit=30")
    if data:
        items = data if isinstance(data, list) else data.get('issues', data.get('data', []))
        for item in items:
            value = item.get('amount', item.get('fundedAmount', 0))
            if isinstance(value, str):
                value = extract_value(value)
            results.append({
                'url': item.get('url', item.get('githubIssueURL', '')),
                'title': item.get('title', '')[:120],
                'value_usd': int(value) if value else 0,
                'owner': item.get('owner', item.get('repository', {}).get('owner', '') if isinstance(item.get('repository'), dict) else ''),
                'name': item.get('repo', item.get('repository', {}).get('name', '') if isinstance(item.get('repository'), dict) else ''),
                'source': 'issuehunt',
                'labels': [],
                'created': item.get('createdAt', ''),
                'updated': '',
                'competition': 0,
                'status': 'open',
            })
    if not results:
        fallback = gh_api("search/issues?q=label:issuehunt+state:open&per_page=20")
        if fallback and 'items' in fallback:
            for item in fallback['items']:
                results.append(make_bounty(item, 'issuehunt-gh'))
    print(f"    Found {len(results)} from IssueHunt", file=sys.stderr)
    return results

def scan_superteam():
    print("  [6/6] Superteam/Solana bounties...", file=sys.stderr)
    results = []
    data = http_get_json("https://superteam.xyz/api/bounties")
    if not data:
        fallback = gh_api("search/issues?q=org:solana-labs+label:bounty+state:open&per_page=20")
        if not fallback:
            fallback = gh_api("search/issues?q=\"solana bounty\"+state:open&per_page=20")
        if fallback and 'items' in fallback:
            for item in fallback['items']:
                results.append(make_bounty(item, 'superteam-gh'))
    elif isinstance(data, list):
        for item in data:
            value = item.get('reward', item.get('amount', 0))
            if isinstance(value, str):
                value = extract_value(value)
            results.append({
                'url': item.get('link', item.get('url', '')),
                'title': item.get('title', '')[:120],
                'value_usd': int(value) if value else 0,
                'owner': 'superteam',
                'name': '',
                'source': 'superteam',
                'labels': [],
                'created': '',
                'updated': '',
                'competition': 0,
                'status': 'open',
            })
    print(f"    Found {len(results)} from Superteam", file=sys.stderr)
    return results

def main():
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  CASHCLAW EXPANDED SCAN — {datetime.utcnow().isoformat()}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    all_bounties = []
    all_bounties.extend(scan_github_wide())
    all_bounties.extend(scan_org_bounties())
    all_bounties.extend(scan_algora())
    all_bounties.extend(scan_polar())
    all_bounties.extend(scan_issuehunt())
    all_bounties.extend(scan_superteam())

    seen = set()
    unique = []
    for b in all_bounties:
        if b['url'] and b['url'] not in seen:
            seen.add(b['url'])
            unique.append(b)

    valued = [b for b in unique if b['value_usd'] > 0]
    unvalued = [b for b in unique if b['value_usd'] == 0]
    valued.sort(key=lambda x: x['value_usd'], reverse=True)
    open_valued = [b for b in valued if b['status'] == 'open']
    claimed_valued = [b for b in valued if b['status'] == 'likely_claimed']

    print(f"\n{'='*60}")
    print(f"  UNCLAIMED BOUNTIES WITH VALUE ({len(open_valued)})")
    print(f"{'='*60}\n")
    for b in open_valued[:20]:
        print(f"  ${b['value_usd']:>6,}  [{b['status']}] {b['title'][:65]}")
        print(f"          {b['url']}")
        print(f"          Source: {b['source']}  PRs: {b['competition']}")
        print()

    print(f"\n{'='*60}")
    print(f"  LIKELY CLAIMED ({len(claimed_valued)})")
    print(f"{'='*60}\n")
    for b in claimed_valued[:10]:
        print(f"  ${b['value_usd']:>6,}  [CLAIMED x{b['competition']}] {b['title'][:55]}")
        print(f"          {b['url']}")
        print()

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Total unique:    {len(unique)}")
    print(f"  Valued (total):  {len(valued)} (${sum(b['value_usd'] for b in valued):,})")
    print(f"  UNCLAIMED+valued:{len(open_valued)} (${sum(b['value_usd'] for b in open_valued):,})")
    print(f"  Claimed+valued:  {len(claimed_valued)}")
    print(f"  Value unknown:   {len(unvalued)}")

    out_dir = os.path.expanduser('~/.cashclaw')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'latest_scan.json')
    with open(out_path, 'w') as f:
        json.dump({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'total': len(unique),
            'valued': len(valued),
            'open_valued': len(open_valued),
            'total_value': sum(b['value_usd'] for b in valued),
            'open_value': sum(b['value_usd'] for b in open_valued),
            'bounties': valued + unvalued,
        }, f, indent=2)
    print(f"\n  Saved to {out_path}")

if __name__ == '__main__':
    main()
