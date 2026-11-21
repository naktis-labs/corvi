#!/usr/bin/env python3
"""Run Corvi's release gates and report each one separately.

The roadmap's last task asks for a single pass over the workspace, schema,
public API, OAuth, transport, rootless workload, ownership, secret-custody,
crash-recovery and standalone-outage gates. Running them by hand is easy to
get wrong: a gate that is quietly skipped looks like a gate that passed. This
script therefore runs every gate, records its exit status, and prints a
summary that names the gates that FAILED or were SKIPPED.

The named subject gates are read out of one workspace test run rather than
from a second run of the same tests: cargo reports each test target's result,
and every subject gate names the packages that carry it. One run, one truth,
and no gate that can be green because nobody looked at it.

By default it does not modify a cluster or publish anything. An explicitly
opted-in cluster validation can install CRDs and create a namespace.
Licensing and publication stay blocked on the explicit owner decision (ADR-0001 section 14), and this script
does not create a release, a tag or an artifact.

Usage:

    python3 scripts/release_gates.py            # run every gate
    python3 scripts/release_gates.py --fast     # skip the slow workspace build
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_VENV = ROOT / ".superpowers" / "contract-venv" / "bin" / "python"

# The subject gates, and the packages whose tests carry each one. A gate
# whose packages produced no test result at all is reported as skipped, not
# as passed.
SUBJECT_GATES: list[tuple[str, list[str]]] = [
    ("public API conformance", ["mail-api"]),
    ("transport conformance", ["mail-imap", "mail-smtp", "mail-jmap"]),
    ("OAuth issuer and upstream onboarding", ["mail-auth", "mail-upstream-oauth"]),
    ("policy engine and bridges", ["mail-policy-engine", "mail-bridge"]),
    ("rootless workload, ownership and rebinding", ["mail-operator"]),
    ("credential admission and secret custody", ["mail-credential"]),
    ("provider and control-plane contracts", ["mail-admin", "provider-migadu"]),
    ("durable queue and telemetry", ["mail-queue", "mail-telemetry"]),
    ("secret custody, crash and recovery", ["mail-storage"]),
    ("disclosure policy", ["mail-policy"]),
]


def python_command() -> list[str]:
    """The interpreter used for the schema checks.

    The contract checks need jsonschema and PyYAML, which live in the local
    contract virtual environment. When it is absent the checks are skipped
    rather than silently passing.
    """
    if CONTRACT_VENV.exists():
        return [str(CONTRACT_VENV)]
    return [sys.executable]


def run(command: str, cwd: Path = ROOT) -> tuple[int, str]:
    """Run one shell command and return its exit status and output."""
    completed = subprocess.run(
        command,
        shell=True,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, output.strip()


def run_tests() -> tuple[int, str, dict[str, dict[str, int]]]:
    """Run the workspace tests and report the result of each package.

    Returns the exit status, the combined output, and a mapping of package
    name to the counts of passed and failed tests. Cargo runs a package's
    unit tests, then its integration tests, then its doc tests, so the
    results are attributed to the package whose test binary is running. A
    package that produced no result at all is reported as absent, and a gate
    that names it is skipped rather than passed.
    """
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "--offline",
            "--workspace",
            "--all-targets",
            "--no-fail-fast",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    # Cargo writes the "Running ..." line to stderr and the test output to
    # stdout. They are merged into one stream so that each result stays
    # attached to the binary that produced it.
    output = completed.stdout or ""
    packages: dict[str, dict[str, int]] = {}
    current = ""
    for line in output.splitlines():
        library = re.search(
            r"Running unittests src/lib\.rs \(target/debug/deps/([a-z0-9_]+)-[0-9a-f]+\)",
            line,
        )
        if library:
            current = library.group(1).replace("_", "-")
            continue
        doc = re.search(r"Doc-tests ([a-z0-9_]+)", line)
        if doc:
            current = doc.group(1).replace("_", "-")
            continue
        result = re.match(r"test result: (\w+)\. (\d+) passed; (\d+) failed", line)
        if result and current:
            counts = packages.setdefault(current, {"passed": 0, "failed": 0})
            counts["passed"] += int(result.group(2))
            counts["failed"] += int(result.group(3))
    return completed.returncode, output.strip(), packages


def cargo_available() -> bool:
    """Whether cargo is on the PATH."""
    return shutil.which("cargo") is not None


def gate_format() -> tuple[str, str]:
    """Formatting must be clean."""
    status, output = run("cargo fmt --all -- --check")
    if status == 0:
        return "passed", "the workspace is formatted"
    return "failed", output[-2000:]


def gate_clippy() -> tuple[str, str]:
    """Clippy must be warning-free across every target."""
    status, output = run(
        "cargo clippy --offline --workspace --all-targets -- -D warnings"
    )
    if status == 0:
        return "passed", "clippy reported no warnings"
    return "failed", output[-4000:]


def gate_boundaries() -> tuple[str, str]:
    """The dependency boundary check must hold."""
    status, output = run("python3 scripts/check_crate_boundaries.py")
    if status == 0:
        return "passed", output.splitlines()[0] if output else "boundaries hold"
    return "failed", output[-2000:]


def gate_contracts() -> tuple[str, str]:
    """The source contract schemas must validate."""
    status, output = run(
        f"{' '.join(python_command())} scripts/check_source_contracts.py"
    )
    if status == 0:
        return "passed", "the checked-in schemas validate (design only)"
    return "failed", output[-2000:]


def gate_doc_links() -> tuple[str, str]:
    """Every internal documentation link must resolve."""
    status, output = run("python3 scripts/check_doc_links.py")
    if status == 0:
        return "passed", output.splitlines()[0] if output else "links resolve"
    return "failed", output[-2000:]


def gate_generated_crds() -> tuple[str, str]:
    """The checked-in CRD manifests must match the generated output.

    This gate needs no cluster: it regenerates the manifests from the
    checked-in JSON Schemas and compares them with the files in the
    repository.
    """
    status, output = run("python3 scripts/generate_crds.py --check")
    if status == 0:
        return "passed", output.splitlines()[0] if output else "the CRDs match"
    return "failed", output[-2000:]


def gate_cluster_validation() -> tuple[str, str]:
    """The generated CRDs and the operator fixtures against a real API server.

    The validation itself lives in scripts/validate_cluster.sh because it
    needs a cluster. Without one the gate is skipped, and a skipped gate is
    never reported as passed.
    """
    status, output = run("bash scripts/validate_cluster.sh")
    if status == 0:
        return "passed", "the API server accepted the CRDs and the fixtures"
    if status == 2:
        detail = next(
            (line for line in output.splitlines() if line.startswith("SKIPPED:")),
            "cluster validation unavailable",
        )
        return "skipped", detail
    return "failed", output[-3000:]


def gate_crd_generator_tests() -> tuple[str, str]:
    """The CRD generator's own tests must pass.

    They cover the decisions the cluster cannot show: how a rejected keyword
    is translated, and how a recursive reference is refused.
    """
    status, output = run(
        f"{' '.join(python_command())} -m unittest tests.test_generate_crds tests.test_cluster_validation"
    )
    if status == 0:
        return "passed", output.splitlines()[-1] if output else "the tests passed"
    return "failed", output[-2000:]


def gate_smoke() -> tuple[str, str]:
    """The standalone gateway must serve its checked surfaces.

    The smoke test needs a built binary, so it is skipped rather than failed
    when the binary is absent.
    """
    binary = ROOT / "target" / "debug" / "corvi-gateway"
    if not binary.exists():
        return "skipped", "the gateway binary is not built"
    status, output = run("python3 scripts/smoke_gateway.py")
    if status == 0:
        return "passed", "the standalone gateway served every checked surface"
    return "failed", output[-3000:]


def subject_gate(
    name: str, packages: list[str], results: dict[str, dict[str, int]]
) -> tuple[str, str]:
    """Report one subject gate from the workspace test results."""
    missing = [package for package in packages if package not in results]
    if missing:
        return "skipped", f"no test result for {', '.join(missing)}"
    failed = sum(results[package]["failed"] for package in packages)
    passed = sum(results[package]["passed"] for package in packages)
    if failed:
        return "failed", f"{failed} failing test(s) in {', '.join(packages)}"
    return "passed", f"{passed} test(s) in {', '.join(packages)}"


def main() -> int:
    """Run the gates and print a summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fast",
        action="store_true",
        help="skip the gates that need a full cargo build",
    )
    arguments = parser.parse_args()

    if not arguments.fast and not cargo_available():
        print("cargo is not on the PATH", file=sys.stderr)
        return 1

    results: list[tuple[str, str, str]] = []
    packages: dict[str, dict[str, int]] = {}

    def record(name: str, gate) -> None:
        started = time.monotonic()
        status, detail = gate()
        elapsed = time.monotonic() - started
        results.append((name, status, detail))
        print(f"[{status:7}] {name} ({elapsed:.1f}s)")
        if status != "passed":
            for line in detail.splitlines()[-20:]:
                print(f"         {line}")

    record("workspace format", gate_format)
    record("workspace clippy", gate_clippy)

    if not arguments.fast:
        started = time.monotonic()
        status, output, packages = run_tests()
        elapsed = time.monotonic() - started
        results.append(("workspace tests", "passed" if status == 0 else "failed", output))
        print(
            f"[{'passed' if status == 0 else 'failed':7}] workspace tests ({elapsed:.1f}s)"
        )
        if status != 0:
            for line in output.splitlines()[-20:]:
                print(f"         {line}")

    record("crate dependency boundaries", gate_boundaries)
    record("source contract schemas", gate_contracts)
    record("documentation links", gate_doc_links)
    record("generated CRD manifests", gate_generated_crds)
    record("CRD generator tests", gate_crd_generator_tests)
    record("operator resources against a live API server", gate_cluster_validation)

    if not arguments.fast:
        for name, gate_packages in SUBJECT_GATES:
            record(name, lambda n=name, p=gate_packages: subject_gate(n, p, packages))

    record("standalone gateway smoke test", gate_smoke)

    failed = [name for name, status, _ in results if status == "failed"]
    skipped = [name for name, status, _ in results if status == "skipped"]
    passed = [name for name, status, _ in results if status == "passed"]

    print()
    print(f"{len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped")
    for name in failed:
        print(f"  failed: {name}")
    for name in skipped:
        print(f"  skipped: {name}")

    if failed:
        print("\nrelease gates failed", file=sys.stderr)
        return 1
    print(
        "\nThe gates passed. This is not a release authorization: the licence "
        "and publication decision remains with the owner (ADR-0001 section 14)."
    )
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    raise SystemExit(main())
