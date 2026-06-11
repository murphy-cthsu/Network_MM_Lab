"""Build verifier/allowlist.json from a clean-boot evidence bundle.

Run on the laptop against a bundle captured on the Pi in a known-good
state (agent.py --out clean_bundle.json). Every measured (path, hash) of
that clean boot becomes allowed; later attestations are compared against
it. There is deliberately no "golden PCR value" — PCR 10 differs every
boot and grows continuously, so trust comes from quote+replay+allowlist
(see verifier/verify.py).

--watch marks demo-critical binaries: they get a dedicated status in every
verdict, and a measurement violation on them is treated as compromising.

--exclude-prefix keeps VOLATILE trees out of the allowlist (user caches,
desktop session files, ...): such files legitimately change, so if they are
allowlisted and a root process ever re-reads one, the new hash flips the
verdict — a false positive. Excluded they fall into the unknown-paths
bucket: reported on every verdict, never compromising. --keep-prefix
re-includes subtrees of an excluded prefix (e.g. this repo inside /home,
so the attester's own code stays integrity-checked); watched paths are
always kept.

Usage:
  python3 verifier/make_allowlist.py --bundle clean_bundle.json \
      --watch /path/to/gated_prelude.sh [--out verifier/allowlist.json] \
      [--exclude-prefix /home/user/] [--keep-prefix /home/user/repo/]
  python3 verifier/make_allowlist.py --ima-log dev/sample_ima_log/clean.log ...
"""

import argparse
import json
import os

from verify import DEFAULT_ALLOWLIST, replay_ima_log


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--bundle", help="evidence bundle JSON (agent.py --out)")
    src.add_argument("--ima-log", help="raw IMA ascii log file")
    parser.add_argument("--watch", action="append", default=[],
                        metavar="PATH", help="watched binary (repeatable)")
    parser.add_argument("--exclude-prefix", action="append", default=[],
                        metavar="PREFIX",
                        help="leave paths under PREFIX out of the allowlist "
                             "(volatile trees; repeatable)")
    parser.add_argument("--keep-prefix", action="append", default=[],
                        metavar="PREFIX",
                        help="re-include subtrees of an excluded prefix "
                             "(repeatable; watched paths are always kept)")
    parser.add_argument("--out", default=DEFAULT_ALLOWLIST)
    args = parser.parse_args()

    if args.bundle:
        with open(args.bundle) as f:
            text = json.load(f)["ima_log"]
        source = args.bundle
    else:
        with open(args.ima_log) as f:
            text = f.read()
        source = args.ima_log

    def included(path):
        if path in args.watch or any(path.startswith(k) for k in args.keep_prefix):
            return True
        return not any(path.startswith(x) for x in args.exclude_prefix)

    _, entries = replay_ima_log(text)  # also validates every line
    paths = {}
    violations = 0
    excluded = 0
    for e in entries:
        if e["violation"]:
            violations += 1
            continue
        if not included(e["path"]):
            excluded += 1
            continue
        digest = e["file_hash"].partition(":")[2]
        paths.setdefault(e["path"], [])
        if digest not in paths[e["path"]]:
            paths[e["path"]].append(digest)

    missing = [w for w in args.watch if w not in paths]
    if missing:
        raise SystemExit(
            f"watched path(s) not measured in this log: {missing}\n"
            f"execute them once on the Pi, recapture the bundle, and retry"
        )

    allowlist = {
        "comment": f"generated from clean boot: {os.path.basename(source)}",
        "watched": sorted(args.watch),
        "paths": {p: paths[p] for p in sorted(paths)},
    }
    with open(args.out, "w") as f:
        json.dump(allowlist, f, indent=2)
        f.write("\n")
    print(f"{args.out}: {len(paths)} path(s), "
          f"{sum(len(v) for v in paths.values())} hash(es), "
          f"{len(args.watch)} watched, {violations} violation entr(y/ies) "
          f"skipped, {excluded} entr(y/ies) excluded by prefix")
    if violations:
        print("note: violation entries cannot be allowlisted; they only "
              "compromise the verdict when they involve a watched path")


if __name__ == "__main__":
    main()
