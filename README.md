# CashClaw — Autonomous Revenue Engine

**What this is:** An outward-facing revenue generation system. Nothing else.
**What this is NOT:** Part of dharma_swarm, wiki, mech-interp, or any internal substrate.

## Mission
Generate real USD. Headline metric: dollars in bank.

## Operating Rules
- Every action must be traceable to a revenue hypothesis
- No infrastructure without a dollar behind it
- Human reviews every diff before external push
- Rate limit: max 1 PR/day/repo
- One identity: AmitabhainArunachala on GitHub

## Active Bets (Naked Validation Hydra)
1. Bounty PRs — escrowed bounties only, with test coverage
2. Grant applications — Anthropic Fellows, Manifund/LTFF
3. Mercor/Surge eligibility probe
4. Expert network demand probe

## Kill Gates
- Any bet that produces $0 in 14 days gets killed
- No bet gets more infrastructure until it proves revenue

## Scripts
- `cashclaw_multi_platform_scan.py` — scan bounty boards
- `cashclaw_claim_and_do.py` — claim + implement + push
- `cashclaw_claim_tracker.py` — track PR status
- `cashclaw_evolution_runner.py` — Darwin variant runner
- `cashclaw_breed_variants.py` — breed strategy variants
- `cashclaw_live_intake.py` — live intake loop

## Data
- `data/evolution.db` — variant fitness tracking

## Status
- PRs shipped: 20+ across 7 repos
- Revenue earned: $0
- Phase: Naked Validation (falsification protocol)
