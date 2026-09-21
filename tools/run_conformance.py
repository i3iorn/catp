#!/usr/bin/env python3
"""Drive an implementation-under-test (IUT) against docs/test-vectors.json.

Speaks the IUT contract in docs/CONFORMANCE_RUNNER.md (issue #35): feeds
each vector to the IUT's stdin as one JSON line, reads one PASS/FAIL line
back per vector, and reports the result. Standard-library only -- no
package to install, no Rust toolchain required, so a contributor testing a
second-language implementation only needs Python 3 and that implementation.

Usage:
    python3 tools/run_conformance.py -- <iut-command> [args...]
    python3 tools/run_conformance.py --vectors docs/test-vectors.json \\
        --report report.json -- ./my-iut

Exit status: 0 if every vector passed and the IUT's output lined up 1:1
with the input; 1 otherwise.
"""

import argparse
import json
import subprocess
import sys


def load_vectors(path):
    with open(path, "r", encoding="utf-8") as f:
        vectors = json.load(f)
    if not isinstance(vectors, list):
        raise SystemExit(f"error: {path} is not a JSON array")
    return vectors


def vector_label(index, vector):
    name = vector.get("name")
    kind = vector.get("kind", "?")
    if name:
        return f"#{index} ({kind}) {name!r}"
    return f"#{index} ({kind})"


def run(vectors, command):
    """Feed `vectors` to `command`'s stdin as JSON Lines, one per line, and
    read back one verdict line per vector. Returns (results, error), where
    `results` is a list of (ok: bool, reason: str | None) aligned with
    `vectors`, and `error` is a fatal driver-level problem (line-count
    mismatch, IUT crash before completion), or None.
    """
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,  # inherited: IUT diagnostics go straight to our stderr
        text=True,
    )

    stdin_payload = "".join(json.dumps(v, separators=(",", ":")) + "\n" for v in vectors)
    try:
        stdout_data, _ = proc.communicate(input=stdin_payload)
    except BrokenPipeError:
        return [], "IUT closed stdin before all vectors were sent (likely crashed)"

    lines = [line for line in stdout_data.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()  # trailing newline

    if len(lines) != len(vectors):
        return [], (
            f"IUT wrote {len(lines)} output line(s) for {len(vectors)} vector(s) "
            f"(exit code {proc.returncode}); output and input must be 1:1"
        )

    results = []
    for line in lines:
        if line == "PASS":
            results.append((True, None))
        elif line.startswith("FAIL"):
            reason = line[len("FAIL"):].strip() or "(no reason given)"
            results.append((False, reason))
        else:
            results.append((False, f"unrecognized output line: {line!r}"))
    return results, None


def main(argv):
    parser = argparse.ArgumentParser(
        description="Run docs/test-vectors.json through an IUT via the conformance runner contract.",
    )
    parser.add_argument(
        "--vectors", default="docs/test-vectors.json", help="path to the vector file (default: %(default)s)"
    )
    parser.add_argument("--report", help="also write a JSON summary to this path")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- <iut-command> [args...]")
    args = parser.parse_args(argv)

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("no IUT command given; usage: run_conformance.py [options] -- <iut-command> [args...]")

    vectors = load_vectors(args.vectors)
    if not vectors:
        raise SystemExit(f"error: {args.vectors} has no vectors")

    results, error = run(vectors, command)
    if error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)

    failures = [
        {"index": i, "label": vector_label(i, vectors[i]), "reason": reason}
        for i, (ok, reason) in enumerate(results)
        if not ok
    ]
    passed = len(results) - len(failures)

    print(f"{passed}/{len(results)} vectors passed")
    for f in failures:
        print(f"  FAIL {f['label']}: {f['reason']}")

    if args.report:
        report = {
            "vectors_file": args.vectors,
            "total": len(results),
            "passed": passed,
            "failed": len(failures),
            "failures": failures,
        }
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")

    sys.exit(0 if not failures else 1)


if __name__ == "__main__":
    main(sys.argv[1:])
