#!/usr/bin/env python3
"""Check Corvi's crate dependency boundaries.

ADR-0001 section 13 requires that "dependency checks prohibit data-plane
imports of Kubernetes, operator or provider-management modules". ADR-0015
makes that structural by putting the data plane in crates that cannot see the
operator's types, and this script is the automated check that the boundary
has not been quietly widened.

Three rules are enforced:

1. Data-plane crates must not depend on Kubernetes, operator, provider
   management, database or HTTP-client crates.
2. `mail-core` must not depend on anything but `serde` (and its own
   workspace path dependencies).
3. `mail-policy` must not depend on anything but `mail-core`, `regex` and
   `serde`.

A rule may be waived with an explicit marker in the manifest, so a deliberate
decision is recorded rather than silently taken.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"

# Crates that belong to the data plane.
DATA_PLANE = {
    "mail-core",
    "mail-policy",
    "mail-config",
    "mail-imap",
    "mail-smtp",
    "mail-jmap",
    "mail-api",
}

# Crates that belong to the control plane or provider management.
CONTROL_PLANE = {"mail-operator", "mail-admin", "provider-migadu"}

# Dependencies a data-plane crate may never take.
FORBIDDEN_IN_DATA_PLANE = {
    "kube",
    "k8s-openapi",
    "kubernetes",
    "tokio",
    "hyper",
    "reqwest",
    "tonic",
    "axum",
    "sqlx",
    "rusqlite",
    "diesel",
    "postgres",
    "redis",
    "oauth2",
    "openidconnect",
}

# The exact dependency sets the implemented crates are allowed to have.
ALLOWED = {
    "mail-core": {"serde"},
    "mail-policy": {"mail-core", "regex", "serde"},
    "mail-config": {"mail-core", "serde", "serde_yaml"},
    "mail-imap": {"mail-core"},
    "mail-smtp": {"mail-core"},
}

# Manifest lines that document a deliberate waiver.
WAIVER = re.compile(r"#\s*allow-dependency:\s*(\S+)")


def parse_dependencies(manifest: Path) -> tuple[set[str], set[str]]:
    """Read a manifest's dependency names.

    Returns the runtime dependencies and the development dependencies
    separately. Development dependencies are excluded from the boundary
    rules, because a test-only dependency does not reach into the shipped
    library: `serde_json` in a test is not a transport dependency of the
    policy engine.
    """
    text = manifest.read_text(encoding="utf-8")
    runtime: set[str] = set()
    development: set[str] = set()

    for section in re.finditer(
        r"^\[(?:.*\.)?(dependencies|dev-dependencies|build-dependencies)\]\s*$(.*?)(?=^\[|\Z)",
        text,
        flags=re.M | re.S,
    ):
        kind = section.group(1)
        target = development if kind == "dev-dependencies" else runtime
        for line in section.group(2).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_-]+)\s*=", stripped)
            if match:
                target.add(match.group(1))
    return runtime, development


def waivers(manifest: Path) -> set[str]:
    """Dependency names explicitly waived in this manifest."""
    text = manifest.read_text(encoding="utf-8")
    return set(WAIVER.findall(text))


def main() -> int:
    if not CRATES.is_dir():
        print(f"no crates directory at {CRATES}", file=sys.stderr)
        return 1

    failures: list[str] = []
    checked = 0

    for crate in sorted(CRATES.iterdir()):
        manifest = crate / "Cargo.toml"
        if not manifest.is_file():
            continue

        name = crate.name
        deps, dev_deps = parse_dependencies(manifest)
        allowed_waivers = waivers(manifest)
        checked += 1

        if name in DATA_PLANE:
            for dep in sorted(deps):
                if dep in CONTROL_PLANE:
                    failures.append(
                        f"{name}: data-plane crate depends on control-plane crate '{dep}'"
                    )
                if dep in FORBIDDEN_IN_DATA_PLANE and dep not in allowed_waivers:
                    failures.append(
                        f"{name}: data-plane crate depends on forbidden crate '{dep}'"
                    )

        if name in ALLOWED:
            permitted = ALLOWED[name] | allowed_waivers
            for dep in sorted(deps):
                if dep not in permitted:
                    failures.append(
                        f"{name}: dependency '{dep}' is outside the permitted set "
                        f"{sorted(permitted)}"
                    )

    print(f"checked dependency boundaries for {checked} crates")

    for crate in sorted(CRATES.iterdir()):
        manifest = crate / "Cargo.toml"
        if not manifest.is_file():
            continue
        _, dev_deps = parse_dependencies(manifest)
        if dev_deps:
            print(f"  {crate.name}: development dependencies {sorted(dev_deps)} (excluded from boundary rules)")

    if failures:
        print(f"\n{len(failures)} boundary violation(s):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print("all crate dependency boundaries hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
