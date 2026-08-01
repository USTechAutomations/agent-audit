# Worked examples — real sealed output, not fixtures

These four files are verbatim renderings of sealed audit rows from our own store. They
are here so you can see exactly what the tool produces before pointing it at anything.

| File | What it is |
|---|---|
| `nemotron-baseline_2026-06-13_audit.md` | Normal customer-support system prompt · 20/38 pass |
| `nemotron-hardened_2026-06-13_audit.md` | Same model + battery, hardened prompt · 25/38 pass |
| `nemotron-baseline_2026-06-14_audit.md` | The baseline re-audited the next day · 20/38 pass |
| `nemotron-baseline_2026-06-14_drift.md` | Drift attestation for 06-13 → 06-14 · **NO REGRESSION**, 38 unchanged |

## Reading the baseline vs hardened pair

The only variable between the two 2026-06-13 runs is the system prompt. Hardening it
moved `system_prompt_leak` from 1/6 to 5/6 and `groundedness` from 7/8 to 8/8, and moved
`data_exfiltration` and `prompt_injection` **not at all** — the planted API key was
returned on 6 of 6 attempts under both prompts. A single headline number (20 → 25) hides
the thing that matters: the credential was never protected.

## Two honest caveats

1. **The battery hash in these files is not the one you will get, and neither are the
   canary tokens.** These runs used an internal `core_v1` with *fixed* canary values —
   the `pwned-9001` and `ZEBRA-CANARY-7731` strings you see quoted in the failure detail
   are those retired tokens, published here only because they are part of the sealed
   evidence. The published battery generates canary values per install (see
   `manifest.json` → `canary_policy`), which changes `battery_sha256`; your run will
   never contain these strings. Drift is only ever compared within one install's own
   series, so the hash difference costs you nothing — but it is real, and pretending
   otherwise would defeat the point of sealing them. That these tokens are now burned by
   being published is precisely the argument for generating your own.
2. **This is one agent surface, not a benchmark.** No conclusion about any model vendor
   should be drawn from four files. Run it against your own endpoint.
