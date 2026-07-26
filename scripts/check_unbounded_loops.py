#!/usr/bin/env python3
"""Static analysis: flag loops over persistent/instance collections that also
make a cross-contract call inside the loop body.

Soroban meters CPU instructions per invocation. A loop whose iteration count
is driven by on-chain state (e.g. every investor position recorded against a
pool) has no compile-time bound, so a contract call inside that loop body
(a token transfer, another contract's client, etc.) means the transaction's
cost scales with how much state has accumulated — with no CI or compiler
warning today. financing_pool::distribute_yield is the known instance this
check was written for (see contracts/financing_pool/src/lib.rs).

This script does a best-effort structural scan, not a full parse of Rust. It
looks for:
  1. A `for` loop whose iterated expression is `.iter()`/`.values()`/`.keys()`
     on a variable that was populated from `env.storage()...get(...)`
     (i.e. sourced from persistent/instance/temporary ledger state) without
     any visible bound (`.take(`, an index/`MAX` cap, or a `break` guarded by
     a counter) between the load and the loop.
  2. A cross-contract call inside that loop's body: construction of a
     generated `*Client::new(` (any contract's client) or a direct
     `token::Client`/`token::StellarAssetClient` call, OR a method call on a
     variable that was bound to such a client earlier in the function (the
     common case — the client is built once before the loop and reused).

Usage:
    scripts/check_unbounded_loops.py [--update-baseline]

Findings are compared against scripts/unbounded_loop_baseline.txt, one
`path:function` per line. A finding whose enclosing function is in the
baseline is reported as already-known (does not fail CI); everything else
is a new finding and fails the check. Pass --update-baseline to rewrite the
baseline file with the current findings (used when deliberately accepting a
new instance, or after fixing one and wanting to shrink the baseline).
"""
import argparse
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "scripts" / "unbounded_loop_baseline.txt"
CONTRACTS_GLOB = "contracts/*/src/**/*.rs"

STORAGE_GET_RE = re.compile(r"\.storage\(\)\s*\.\w+\(\)\s*\.get(?:::<[^>]*>)?\s*\(")
ITER_CALL_RE = re.compile(r"\b(\w+)\.(iter|values|keys)\(\)")
FOR_LOOP_RE = re.compile(r"^\s*for\s+.+\s+in\s+(.+?)\s*\{\s*$")
FN_DEF_RE = re.compile(r"^\s*(?:pub\s+)?fn\s+(\w+)\s*[<(]")
# Matches a client construction, either a generated `FooContractClient::new(`
# or the SDK's own `token::Client::new(` / `token::StellarAssetClient::new(`.
CLIENT_CTOR_RE = re.compile(r"\b\w*Client::new\s*\(")
# Direct construct-and-call in one expression (rare, but catches it without
# needing the variable-tracking path below).
INLINE_CROSS_CONTRACT_CALL_RE = re.compile(r"\b\w*Client::new\s*\([^;]*\)\s*\.\s*\w+\s*\(")
BOUND_HINT_RE = re.compile(r"\.take\(|\bMAX\w*\b|\.min\(\s*\d|break\b")


def strip_test_module(text):
    """Cut the file off at `mod tests` / `mod proptests` so fixtures don't
    trigger false positives — those never run on-chain."""
    marker = re.search(r"^\s*(?:#\[cfg\(test\)\]\s*\n)?\s*mod\s+(?:tests|proptests)\s*\{", text, re.M)
    return text[: marker.start()] if marker else text


def find_enclosing_function(lines, loop_line_idx):
    for i in range(loop_line_idx, -1, -1):
        m = FN_DEF_RE.match(lines[i])
        if m:
            return m.group(1), i + 1
    return "<module-level>", 1


def matching_brace_end(lines, start_idx):
    """start_idx is the line containing the opening `{` of the loop body."""
    depth = 0
    for i in range(start_idx, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i > start_idx:
            return i
        if depth <= 0 and i == start_idx and lines[i].count("}") > 0:
            return i
    return len(lines) - 1


def scan_file(path):
    raw = path.read_text()
    text = strip_test_module(raw)
    lines = text.splitlines()

    # Track variables whose value came from a storage .get() call, so a later
    # `.iter()` on that variable is treated as iterating ledger-sourced state.
    # `.storage().persistent().get(...)`-style chains are frequently split
    # across lines, so match against a joined window rather than one line.
    storage_sourced_vars = set()
    # Track variables bound to a contract client (`let x = FooClient::new(...)`),
    # so a later `x.some_method(...)` inside a loop body is recognized as a
    # cross-contract call even though the construction itself isn't in the loop.
    client_vars = set()
    findings = []
    window_size = 6

    for idx, line in enumerate(lines):
        window = "\n".join(lines[idx : idx + window_size])
        if STORAGE_GET_RE.search(window):
            # crude: grab the `let <name>` on this line or the next couple of
            # lines up (multi-line `let x: T = env.storage()...get(...)`).
            for back in range(idx, max(-1, idx - 4), -1):
                m = re.search(r"let\s+(?:mut\s+)?(\w+)", lines[back])
                if m:
                    storage_sourced_vars.add(m.group(1))
                    break

        if CLIENT_CTOR_RE.search(line):
            m = re.search(r"let\s+(?:mut\s+)?(\w+)", line)
            if m:
                client_vars.add(m.group(1))

        for_match = FOR_LOOP_RE.match(line)
        if not for_match:
            continue
        iter_expr = for_match.group(1)
        iter_match = ITER_CALL_RE.search(iter_expr)
        if not iter_match:
            continue
        base_var = iter_match.group(1)
        if base_var not in storage_sourced_vars:
            continue

        body_end = matching_brace_end(lines, idx)
        body = "\n".join(lines[idx : body_end + 1])

        client_call_re = re.compile(
            r"\b(?:" + "|".join(re.escape(v) for v in client_vars) + r")\s*\.\s*\w+\s*\("
        ) if client_vars else None

        has_cross_contract_call = bool(
            INLINE_CROSS_CONTRACT_CALL_RE.search(body)
            or (client_call_re and client_call_re.search(body))
        )
        if not has_cross_contract_call:
            continue
        if BOUND_HINT_RE.search(body):
            continue

        fn_name, fn_line = find_enclosing_function(lines, idx)
        rel_path = path.relative_to(REPO_ROOT).as_posix()
        findings.append(
            {
                "file": rel_path,
                "function": fn_name,
                "loop_line": idx + 1,
                "key": f"{rel_path}:{fn_name}",
            }
        )

    return findings


def load_baseline():
    if not BASELINE_PATH.exists():
        return set()
    keys = set()
    for line in BASELINE_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        keys.add(line)
    return keys


def write_baseline(keys):
    lines = [
        "# Known unbounded-loop-with-cross-contract-call findings.",
        "# One `path:function` per line. New findings not listed here fail CI —",
        "# see scripts/check_unbounded_loops.py for what's being detected.",
        "#",
        "# Remove an entry once the underlying loop is bounded (or the",
        "# cross-contract call is moved out of it) so it can't silently regress.",
        "",
    ]
    lines.extend(sorted(keys))
    BASELINE_PATH.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--update-baseline", action="store_true")
    args = parser.parse_args()

    all_findings = []
    for path in sorted(REPO_ROOT.glob(CONTRACTS_GLOB)):
        all_findings.extend(scan_file(path))

    if args.update_baseline:
        write_baseline({f["key"] for f in all_findings})
        print(f"Wrote {len(all_findings)} finding(s) to {BASELINE_PATH.relative_to(REPO_ROOT)}")
        return 0

    baseline = load_baseline()
    known = [f for f in all_findings if f["key"] in baseline]
    new = [f for f in all_findings if f["key"] not in baseline]

    if known:
        print("Known (baselined) unbounded-loop findings:")
        for f in known:
            print(f"  {f['file']}:{f['loop_line']} in {f['function']}()")
        print()

    if new:
        print("NEW unbounded-loop-with-cross-contract-call findings:")
        for f in new:
            print(f"  {f['file']}:{f['loop_line']} in {f['function']}()")
        print()
        print(
            "A loop here iterates a collection loaded from ledger storage and "
            "makes a cross-contract call per iteration, with no visible bound "
            "(.take(), a MAX cap, or a counter-guarded break). Its cost scales "
            "with on-chain state size and can exceed Soroban's CPU instruction "
            "limit at scale."
        )
        print(
            "Either bound the loop (paginate, cap, or move the call out of the "
            "loop), or if this is an accepted, already-tracked risk, add it to "
            f"{BASELINE_PATH.relative_to(REPO_ROOT)} via --update-baseline."
        )
        return 1

    print(f"No new unbounded-loop findings ({len(known)} known, baselined).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
