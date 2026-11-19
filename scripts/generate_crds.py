#!/usr/bin/env python3
"""Derive structural Kubernetes CRD manifests from Corvi's checked-in JSON Schemas.

The JSON Schemas under ``api/`` are the single source of truth for the
operator resources. This script converts them into structural OpenAPI v3 CRD
manifests under ``api/operator/crds/``, so the CRDs are *derived* and never
hand-duplicated. It uses the Python standard library only.

Usage::

    python3 scripts/generate_crds.py          # write the manifests
    python3 scripts/generate_crds.py --check  # fail when the checked-in files drift

Both modes are deterministic: the same inputs always produce byte-identical
output, so ``--check`` is usable as a release gate.

Where the CRD metadata comes from
---------------------------------

The generator never hard-codes a group, version, scope, plural or singular.
Each CRD is described by the schema it is derived from:

* ``api/corvi-gateway.schema.json`` declares ``x-corvi-kubernetes-crd`` with
  ``group``, ``version``, ``scope``, ``plural``, ``singular``, ``kind``,
  ``statusSubresource`` and ``scaleSubresource``. Those fields are copied.
* ``api/mail-resource-ownership.schema.json`` has no CRD block: its ``oneOf``
  branches are the resources. Each branch declares its own identity in its
  body, ``properties.apiVersion.const`` (``corvi.naktis.eu/v1alpha1``) and
  ``properties.kind.const`` (``MailProvider``/``Mailbox``/``MailIdentity``).
  The group and the version are parsed from that ``apiVersion`` const, and the
  kind is read from the ``kind`` const.

Two fields are not declared anywhere in the ownership schema, and both are
derived rather than invented:

* **scope** is read from the branch's own ``metadata`` definition: it
  requires ``namespace``, so the resource is ``Namespaced``. A branch that did
  not require ``namespace`` would be ``Cluster``. The Kubernetes default,
  ``Namespaced``, is used when a branch declares no ``metadata`` at all.
* **plural** and **singular** follow the Kubernetes naming convention:
  ``singular`` is the lower-cased kind, ``plural`` is the lower-cased kind
  with the English plural rule applied (``s``/``x``/``z``/``ch``/``sh`` take
  ``es``, a consonant plus ``y`` takes ``ies``, everything else takes ``s``).
  The rule is checked against ``corvigateways``, the one plural the schema
  declares, so a drift in the rule is an error rather than a surprise.

Structural schema decisions
---------------------------

* ``$ref``/``$defs`` are inlined. A CRD has no reference syntax, so every
  reference is substituted by its target. A reference that reaches itself is a
  cycle that a structural schema cannot express: the generator fails with the
  reference and its location instead of recursing forever.
* ``const`` becomes ``enum`` with a single member. The two keywords express
  the same constraint, and the API server evaluates ``enum``; it rejects
  ``const`` as an unknown field of the CRD schema.
* ``additionalProperties: false`` is dropped. The API server prunes unknown
  fields by default, but pruning is not identical to JSON Schema rejection:
  unknown fields are removed rather than rejected. A structural schema may
  not carry ``additionalProperties`` next to ``properties``.
* ``additionalProperties: true`` becomes ``x-kubernetes-preserve-unknown-fields:
  true``. That is the structural spelling of "unknown fields are allowed".
* ``additionalProperties: <schema>`` is kept as it is when the object has no
  ``properties`` of its own. Together with ``properties`` it has no faithful
  structural spelling, so the generator fails and names the location.
* ``apiVersion``, ``kind`` and ``metadata`` are dropped from the root schema.
  The API machinery owns them: a request whose ``apiVersion`` or ``kind`` does
  not match the CRD is rejected before the schema is consulted, and metadata
  is validated by Kubernetes itself. The ownership schema's ``metadata``
  definition only asserts ``name`` and ``namespace``, both of which the API
  server requires anyway.
* The root ``title`` and ``description`` are not copied. They describe the
  *schema file* (they say the schema is a design contract and not a CRD
  manifest), which would be misleading in ``kubectl explain``. The generator
  writes a provenance description instead. Every per-field description is
  copied verbatim.
* Inside ``allOf``/``anyOf``/``oneOf`` branches the API server requires
  ``type`` to be empty at every level: a branch inherits the type of the
  schema that contains it. The generator strips ``type`` inside branches.
* ``default`` is copied. The API server applies it before the CEL rules run.

Rejected keywords
-----------------

These keywords are not part of the CRD schema vocabulary. The API server
rejects them outright (strict decoding of the CRD object reports them as
unknown fields), so the generator never emits them. For each one:

``not``
    Translated into a CEL rule under ``x-kubernetes-validations``. The inner
    schema is compiled into a CEL expression and negated, so
    ``not: {properties: {x: {const: true}}}`` becomes
    ``!(!has(self.x) || self.x == true)``.

``if`` / ``then`` / ``else``
    Translated into one CEL rule per construct:
    ``(<if>) ? (<then>) : (<else>)``. A missing ``then`` or ``else`` compiles
    to ``true``, which is the JSON Schema semantics of an absent branch. The
    condition is compiled faithfully, so ``if: {properties: {backend:
    {const: "sqlite"}}, required: ["backend"]}`` becomes
    ``has(self.backend) && self.backend == "sqlite"``.

``dependentRequired``
    Translated into CEL: ``{"a": ["b"]}`` becomes
    ``!has(self.a) || has(self.b)``. The dependency is a presence relation
    between two fields, which CEL expresses exactly.

``propertyNames``
    **No faithful translation exists.** A CEL rule cannot enumerate the keys
    of an object, so a constraint on the *names* of the properties cannot be
    expressed. The generator fails with the keyword and its location and lets
    a human decide.

``unevaluatedProperties``
    **No faithful translation exists.** The keyword constrains the properties
    that no other keyword evaluated, which CEL cannot compute. The generator
    fails with the keyword and its location and lets a human decide.

Any other keyword is refused as well: the generator never drops a constraint
it does not understand.

What CEL can and cannot express
--------------------------------

The CEL compiler supports ``type``, ``const``, ``enum``, ``required``,
``properties``, ``not``, ``anyOf``, ``allOf``, ``oneOf``, ``minimum``,
``maximum``, ``minLength``, ``maxLength``, ``minItems``, ``maxItems`` and
``items``. ``pattern`` has no CEL equivalent (CEL has no regular expression
function), so a pattern inside a translated construct fails the generator with
its location instead of being silently lost.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

OWNERSHIP_SCHEMA = ROOT / "api" / "mail-resource-ownership.schema.json"
GATEWAY_SCHEMA = ROOT / "api" / "corvi-gateway.schema.json"
OUTPUT_DIR = ROOT / "api" / "operator" / "crds"

CRD_API_VERSION = "apiextensions.k8s.io/v1"


class ConversionError(Exception):
    """A schema construct that has no faithful CRD representation."""


# --------------------------------------------------------------------------
# YAML emission
# --------------------------------------------------------------------------

# A plain (unquoted) scalar may not start with an indicator character, may
# not contain a colon, a space or a hash, and may not be read as a boolean,
# a null or a number by YAML 1.1 (which is what Kubernetes uses).
_PLAIN_SCALAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_./-]*$")
_YAML_KEYWORDS = {
    "y",
    "n",
    "yes",
    "no",
    "true",
    "false",
    "on",
    "off",
    "null",
    "~",
    "",
}


def _scalar(value: Any) -> str:
    """Render one scalar as YAML."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        if _PLAIN_SCALAR.match(value) and value.lower() not in _YAML_KEYWORDS:
            try:
                int(value)
            except ValueError:
                pass
            else:
                return _quote(value)
            try:
                float(value)
            except ValueError:
                pass
            else:
                return _quote(value)
            return value
        return _quote(value)
    raise ConversionError(f"cannot render {type(value).__name__} as YAML")


def _quote(text: str) -> str:
    """Render a string as a double-quoted YAML scalar."""
    out = ['"']
    for character in text:
        if character == '"':
            out.append('\\"')
        elif character == "\\":
            out.append("\\\\")
        elif character == "\n":
            out.append("\\n")
        elif character == "\t":
            out.append("\\t")
        elif character == "\r":
            out.append("\\r")
        elif ord(character) < 0x20 or ord(character) == 0x7F:
            out.append("\\x%02x" % ord(character))
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _emit_entry(label: str, value: Any, indent: int, lines: list[str]) -> None:
    """Emit one mapping entry whose label is already rendered."""
    if isinstance(value, dict):
        if not value:
            lines.append(f"{label} {{}}")
            return
        lines.append(label)
        _emit(value, indent, lines)
        return
    if isinstance(value, list):
        if not value:
            lines.append(f"{label} []")
            return
        lines.append(label)
        _emit(value, indent, lines)
        return
    lines.append(f"{label} {_scalar(value)}")


def _emit(value: Any, indent: int, lines: list[str]) -> None:
    """Emit a mapping or a sequence at the given indentation."""
    pad = " " * indent
    if isinstance(value, dict):
        if not value:
            lines.append(f"{pad}{{}}")
            return
        for key, item in value.items():
            _emit_entry(f"{pad}{_scalar(key)}:", item, indent + 2, lines)
        return
    if isinstance(value, list):
        if not value:
            lines.append(f"{pad}[]")
            return
        for item in value:
            if isinstance(item, dict):
                if not item:
                    lines.append(f"{pad}- {{}}")
                    continue
                nested: list[str] = []
                _emit(item, indent + 2, nested)
                lines.append(f"{pad}- {nested[0].lstrip()}")
                lines.extend(nested[1:])
                continue
            if isinstance(item, list):
                if not item:
                    lines.append(f"{pad}- []")
                    continue
                nested = []
                _emit(item, indent + 2, nested)
                lines.append(f"{pad}- {nested[0].lstrip()}")
                lines.extend(nested[1:])
                continue
            lines.append(f"{pad}- {_scalar(item)}")
        return
    lines.append(f"{pad}{_scalar(value)}")


def dump_yaml(value: Any) -> str:
    """Render a value as a YAML document."""
    lines: list[str] = []
    _emit(value, 0, lines)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Schema conversion
# --------------------------------------------------------------------------

# Keywords that map one-to-one onto an OpenAPI v3 structural schema.
DIRECT_KEYWORDS = {
    "description",
    "type",
    "format",
    "enum",
    "pattern",
    "default",
    "nullable",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "minProperties",
    "maxProperties",
    "required",
}

# Keywords that carry a constraint the CRD schema cannot express but that CEL
# can, and the keywords that have no faithful translation at all.
TRANSLATED_KEYWORDS = {"not", "if", "then", "else", "dependentRequired"}
UNTRANSLATABLE_KEYWORDS = {
    "propertyNames": "CEL cannot enumerate the keys of an object",
    "unevaluatedProperties": "CEL cannot compute the properties left unevaluated",
}


class Converter:
    """Convert one JSON Schema document into structural CRD schemas."""

    def __init__(self, document: dict, source: str) -> None:
        self.document = document
        self.source = source

    # -- references -------------------------------------------------------

    def resolve(self, ref: str, location: str) -> dict:
        """Return the target of a local ``#/$defs`` reference."""
        prefix = "#/$defs/"
        if not ref.startswith(prefix):
            raise ConversionError(
                f"{self.source}{location}: only local {prefix} references are "
                f"supported, got {ref!r}"
            )
        name = ref[len(prefix) :]
        definitions = self.document.get("$defs", {})
        if name not in definitions:
            raise ConversionError(
                f"{self.source}{location}: unresolved reference {ref!r}"
            )
        return definitions[name]

    def dereference(self, node: dict, location: str, stack: tuple[str, ...]) -> dict:
        """Substitute a ``$ref`` by its target, guarding against cycles."""
        if "$ref" not in node:
            return node
        ref = node["$ref"]
        if ref in stack:
            raise ConversionError(
                f"{self.source}{location}: reference {ref!r} reaches itself; a "
                "structural CRD schema cannot express a recursive reference"
            )
        merged = dict(self.resolve(ref, location))
        for key, value in node.items():
            if key != "$ref":
                merged[key] = value
        return merged

    # -- CEL compilation --------------------------------------------------

    def compile(
        self,
        node: dict,
        location: str,
        stack: tuple[str, ...] = (),
        path: str = "self",
    ) -> str:
        """Compile a schema into a CEL expression that is true when it holds."""
        if not isinstance(node, dict):
            raise ConversionError(
                f"{self.source}{location}: expected a schema object, got "
                f"{type(node).__name__}"
            )
        node = self.dereference(node, location, stack)
        if "$ref" in node:
            return self.compile(node, location, stack + (node["$ref"],), path)

        parts: list[str] = []
        required = set(node.get("required", []))
        for key, value in node.items():
            if key in ("$schema", "$id", "$defs", "title", "description", "default"):
                continue
            if key.startswith("x-corvi-"):
                continue
            if key == "required":
                for name in value:
                    if name not in node.get("properties", {}):
                        parts.append(f"has({path}.{name})")
            elif key == "properties":
                for name, sub in value.items():
                    inner = self.compile(
                        sub,
                        f"{location}/properties/{name}",
                        stack,
                        f"{path}.{name}",
                    )
                    if name in required:
                        parts.append(f"has({path}.{name}) && ({inner})")
                    else:
                        parts.append(f"(!has({path}.{name}) || ({inner}))")
            elif key == "const":
                parts.append(f"{path} == {_cel_literal(value)}")
            elif key == "enum":
                members = ", ".join(_cel_literal(member) for member in value)
                parts.append(f"{path} in [{members}]")
            elif key == "type":
                parts.append(_cel_type(value, path))
            elif key == "minimum":
                parts.append(f"{path} >= {value}")
            elif key == "maximum":
                parts.append(f"{path} <= {value}")
            elif key == "minLength":
                parts.append(f"size({path}) >= {value}")
            elif key == "maxLength":
                parts.append(f"size({path}) <= {value}")
            elif key == "minItems":
                parts.append(f"size({path}) >= {value}")
            elif key == "maxItems":
                parts.append(f"size({path}) <= {value}")
            elif key == "items":
                inner = self.compile(value, f"{location}/items", stack, "item")
                parts.append(f"{path}.all(item, ({inner}))")
            elif key == "not":
                inner = self.compile(value, f"{location}/not", stack, path)
                parts.append(f"!({inner})")
            elif key == "anyOf":
                branches = [
                    self.compile(sub, f"{location}/anyOf/{index}", stack, path)
                    for index, sub in enumerate(value)
                ]
                parts.append("(" + " || ".join(branches) + ")")
            elif key == "allOf":
                branches = [
                    self.compile(sub, f"{location}/allOf/{index}", stack, path)
                    for index, sub in enumerate(value)
                ]
                parts.append("(" + " && ".join(branches) + ")")
            elif key == "oneOf":
                parts.append(self._compile_one_of(value, location, stack, path))
            elif key in ("if", "then", "else", "dependentRequired"):
                continue
            elif key == "pattern":
                raise ConversionError(
                    f"{self.source}{location}: 'pattern' has no CEL equivalent, "
                    "so it cannot be translated into a validation rule"
                )
            else:
                raise ConversionError(
                    f"{self.source}{location}: keyword {key!r} cannot be "
                    "compiled into a CEL rule"
                )

        if any(key in node for key in ("if", "then", "else")):
            parts.append(self._compile_conditional(node, location, stack, path))
        if "dependentRequired" in node:
            parts.append(self._compile_dependent_required(node, path))

        if not parts:
            return "true"
        return "(" + " && ".join(parts) + ")"

    def _compile_conditional(
        self, node: dict, location: str, stack: tuple[str, ...], path: str
    ) -> str:
        """Compile an ``if``/``then``/``else`` construct into a CEL rule."""
        condition = (
            self.compile(node["if"], f"{location}/if", stack, path)
            if "if" in node
            else "true"
        )
        consequence = (
            self.compile(node["then"], f"{location}/then", stack, path)
            if "then" in node
            else "true"
        )
        alternative = (
            self.compile(node["else"], f"{location}/else", stack, path)
            if "else" in node
            else "true"
        )
        return f"({condition}) ? ({consequence}) : ({alternative})"

    def _compile_one_of(
        self, value: list, location: str, stack: tuple[str, ...], path: str
    ) -> str:
        """Compile ``oneOf`` into "exactly one branch holds"."""
        branches = [
            self.compile(sub, f"{location}/oneOf/{index}", stack, path)
            for index, sub in enumerate(value)
        ]
        if not branches:
            return "true"
        at_least_one = "(" + " || ".join(branches) + ")"
        pairs = [
            f"(({left}) && ({right}))"
            for index, left in enumerate(branches)
            for right in branches[index + 1 :]
        ]
        if not pairs:
            return at_least_one
        return f"({at_least_one} && !(" + " || ".join(pairs) + "))"

    def _compile_dependent_required(self, node: dict, path: str) -> str:
        """Compile ``dependentRequired`` into a CEL rule."""
        parts = []
        for key in sorted(node["dependentRequired"]):
            dependencies = node["dependentRequired"][key]
            present = " && ".join(f"has({path}.{name})" for name in dependencies)
            parts.append(f"(!has({path}.{key}) || ({present}))")
        return "(" + " && ".join(parts) + ")"

    # -- structural conversion -------------------------------------------

    def _validate_cel_fields(
        self, constraint: dict, base: dict, location: str
    ) -> None:
        """Ensure CEL-translated constraints only address declared fields."""
        constraint = self.dereference(constraint, location, ())
        base = self.dereference(base, location, ())
        declared = base.get("properties", {})
        dependencies = constraint.get("dependentRequired", {})
        for name in set(dependencies).union(*(set(names) for names in dependencies.values())):
            if name not in declared:
                raise ConversionError(
                    f"{self.source}{location}: CEL constraint references "
                    f"undeclared property {name!r}"
                )
        for name in constraint.get("required", []):
            if name not in declared:
                raise ConversionError(
                    f"{self.source}{location}: CEL constraint references "
                    f"undeclared property {name!r}"
                )
        for name, sub in constraint.get("properties", {}).items():
            if name not in declared:
                raise ConversionError(
                    f"{self.source}{location}: CEL constraint references "
                    f"undeclared property {name!r}"
                )
            self._validate_cel_fields(
                sub, declared[name], f"{location}/properties/{name}"
            )
        if "items" in constraint and "items" in base:
            self._validate_cel_fields(
                constraint["items"], base["items"], f"{location}/items"
            )
        for keyword in ("not", "if", "then", "else"):
            if keyword in constraint:
                self._validate_cel_fields(
                    constraint[keyword], base, f"{location}/{keyword}"
                )
        for keyword in ("oneOf", "anyOf", "allOf"):
            for index, sub in enumerate(constraint.get(keyword, [])):
                self._validate_cel_fields(
                    sub, base, f"{location}/{keyword}/{index}"
                )

    def _validate_branch_properties(
        self,
        branch: dict,
        base: dict,
        location: str,
        stack: tuple[str, ...] = (),
    ) -> None:
        """Reject branch constraints that refer outside the declared schema."""
        if not isinstance(branch, dict) or not isinstance(base, dict):
            raise ConversionError(f"{self.source}{location}: branch and base must be schema objects")
        if "$ref" in branch:
            ref = branch["$ref"]
            if ref in stack:
                raise ConversionError(
                    f"{self.source}{location}: reference {ref!r} reaches itself; "
                    "a structural CRD schema cannot express a recursive reference"
                )
            branch = self.dereference(branch, location, stack)
            stack = stack + (ref,)
        if "$ref" in base:
            ref = base["$ref"]
            if ref in stack:
                raise ConversionError(
                    f"{self.source}{location}: reference {ref!r} reaches itself; "
                    "a structural CRD schema cannot express a recursive reference"
                )
            base = self.dereference(base, location, stack)
            stack = stack + (ref,)
        branch_properties = branch.get("properties", {})
        if "metadata" in branch_properties:
            raise ConversionError(f"{self.source}{location}: metadata is forbidden in a branch")
        base_properties = base.get("properties", {})
        extra = sorted(set(branch_properties) - set(base_properties))
        if extra:
            raise ConversionError(
                f"{self.source}{location}: branch-only properties {extra!r} "
                "cannot be represented faithfully in a structural CRD schema"
            )
        for name, sub in branch_properties.items():
            self._validate_branch_properties(
                sub,
                base_properties[name],
                f"{location}/properties/{name}",
                stack,
            )
        if "items" in branch:
            base_items = base.get("items")
            if base_items is None:
                raise ConversionError(
                    f"{self.source}{location}/items: branch-only items cannot "
                    "be represented faithfully in a structural CRD schema"
                )
            else:
                self._validate_branch_properties(
                    branch["items"], base_items, f"{location}/items", stack
                )
        for keyword in ("oneOf", "anyOf", "allOf"):
            for index, sub in enumerate(branch.get(keyword, [])):
                self._validate_branch_properties(
                    sub, base, f"{location}/{keyword}/{index}", stack
                )

    def convert(
        self,
        node: dict,
        location: str,
        stack: tuple[str, ...] = (),
        in_branch: bool = False,
        cel_base: dict | None = None,
    ) -> tuple[dict, list[dict]]:
        """Convert a schema node into (structural schema, CEL rules)."""
        if not isinstance(node, dict):
            raise ConversionError(
                f"{self.source}{location}: expected a schema object, got "
                f"{type(node).__name__}"
            )
        if "$ref" in node:
            ref = node["$ref"]
            if ref in stack:
                raise ConversionError(
                    f"{self.source}{location}: reference {ref!r} reaches itself; "
                    "a structural CRD schema cannot express a recursive reference"
                )
            target = self.dereference(node, location, stack)
            merged = dict(target)
            for key, value in node.items():
                if key != "$ref":
                    merged[key] = value
            return self.convert(
                merged, location, stack + (ref,), in_branch, cel_base
            )

        if cel_base is None:
            cel_base = node

        for exclusive, inclusive in (
            ("exclusiveMinimum", "minimum"),
            ("exclusiveMaximum", "maximum"),
        ):
            if exclusive in node and inclusive in node:
                raise ConversionError(
                    f"{self.source}{location}: {exclusive!r} conflicts with "
                    f"{inclusive!r}; both bounds cannot be represented faithfully"
                )

        if "dependentRequired" in node:
            self._validate_cel_fields(
                {"dependentRequired": node["dependentRequired"]}, cel_base, location
            )
        for key in ("if", "then", "else", "not"):
            if key in node:
                self._validate_cel_fields(
                    node[key], cel_base, f"{location}/{key}"
                )

        schema: dict[str, Any] = {}
        rules: list[dict] = []

        for key, value in node.items():
            if key in ("$schema", "$id", "$defs", "title"):
                continue
            if key.startswith("x-corvi-"):
                continue
            if in_branch and key in ("description", "default", "nullable", "additionalProperties"):
                raise ConversionError(
                    f"{self.source}{location}: keyword {key!r} is not supported inside a structural schema branch"
                )
            if key == "description":
                schema["description"] = value
            elif key == "type":
                if in_branch:
                    # A branch inherits the type of the schema that holds it.
                    continue
                schema["type"] = value
            elif key == "properties":
                properties: dict[str, Any] = {}
                for name, sub in value.items():
                    # The nested schema carries its own rules; they belong to
                    # the nested object, not to this one.
                    converted, _sub_rules = self.convert(
                        sub,
                        f"{location}/properties/{name}",
                        stack,
                        in_branch,
                        (self.dereference(cel_base, location, ()).get("properties", {}).get(name, sub)
                         if in_branch else sub),
                    )
                    if in_branch and "x-kubernetes-validations" in converted:
                        raise ConversionError(
                            f"{self.source}{location}/properties/{name}: nested branch CEL rules are unsupported"
                        )
                    properties[name] = converted
                schema["properties"] = properties
            elif key in ("oneOf", "anyOf", "allOf"):
                branches = []
                for index, sub in enumerate(value):
                    branch_base = cel_base if in_branch else node
                    self._validate_branch_properties(
                        sub, branch_base, f"{location}/{key}/{index}"
                    )
                    converted, sub_rules = self.convert(
                        sub, f"{location}/{key}/{index}", stack,
                        in_branch=True, cel_base=branch_base,
                    )
                    # A branch constrains the object that holds it, so a rule
                    # translated from the branch belongs to that object and
                    # not to the branch.
                    converted.pop("x-kubernetes-validations", None)
                    branches.append(converted)
                    rules.extend(sub_rules)
                schema[key] = branches
            elif key == "items":
                if isinstance(value, list):
                    raise ConversionError(
                        f"{self.source}{location}: tuple-form 'items' has no "
                        "structural CRD equivalent"
                    )
                converted, _sub_rules = self.convert(
                    value, f"{location}/items", stack, in_branch
                )
                if in_branch and "x-kubernetes-validations" in converted:
                    raise ConversionError(
                        f"{self.source}{location}/items: nested branch CEL rules are unsupported"
                    )
                schema["items"] = converted
            elif key == "additionalProperties":
                has_properties = "properties" in node
                if value is False:
                    # The API server prunes unknown fields by default, which
                    # is what additionalProperties: false asks for, and a
                    # structural schema may not carry both.
                    continue
                if value is True:
                    schema["x-kubernetes-preserve-unknown-fields"] = True
                    continue
                if has_properties:
                    raise ConversionError(
                        f"{self.source}{location}: 'additionalProperties' with a "
                        "schema has no structural CRD equivalent next to "
                        "'properties'; a human must decide"
                    )
                converted, _sub_rules = self.convert(
                    value, f"{location}/additionalProperties", stack, in_branch
                )
                schema["additionalProperties"] = converted
            elif key == "const":
                if "enum" in schema:
                    raise ConversionError(
                        f"{self.source}{location}: 'const' and 'enum' together "
                        "have no single structural equivalent"
                    )
                schema["enum"] = [value]
            elif key in ("exclusiveMinimum", "exclusiveMaximum"):
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ConversionError(
                        f"{self.source}{location}: {key!r} must be numeric in the "
                        "JSON Schema input"
                    )
                bound = "minimum" if key == "exclusiveMinimum" else "maximum"
                flag = key
                if bound in schema or flag in schema:
                    raise ConversionError(
                        f"{self.source}{location}: {key!r} conflicts with "
                        f"{bound!r} or {flag!r}"
                    )
                schema[bound] = value
                schema[flag] = True
            elif key in DIRECT_KEYWORDS:
                schema[key] = value
            elif key in TRANSLATED_KEYWORDS:
                continue
            elif key in UNTRANSLATABLE_KEYWORDS:
                raise ConversionError(
                    f"{self.source}{location}: keyword {key!r} is not part of the "
                    f"CRD schema vocabulary and {UNTRANSLATABLE_KEYWORDS[key]}; "
                    "a human must decide"
                )
            else:
                raise ConversionError(
                    f"{self.source}{location}: keyword {key!r} has no CRD "
                    "mapping; a human must decide"
                )

        for rule in self._rules_for(node, location, stack):
            rules.append(rule)

        if rules:
            validations = schema.get("x-kubernetes-validations", [])
            validations.extend(rules)
            schema["x-kubernetes-validations"] = validations

        return schema, rules

    def _rules_for(
        self, node: dict, location: str, stack: tuple[str, ...]
    ) -> list[dict]:
        """Build the CEL rules for the translated keywords of one schema node."""
        rules: list[dict] = []
        if "if" in node or "then" in node or "else" in node:
            if "then" in node or "else" in node:
                condition = (
                    self.compile(node["if"], f"{location}/if", stack)
                    if "if" in node
                    else "true"
                )
                consequence = (
                    self.compile(node["then"], f"{location}/then", stack)
                    if "then" in node
                    else "true"
                )
                alternative = (
                    self.compile(node["else"], f"{location}/else", stack)
                    if "else" in node
                    else "true"
                )
                rules.append(
                    {
                        "rule": f"({condition}) ? ({consequence}) : ({alternative})",
                        "message": (
                            f"{self.source}{location}: if/then/else translated to "
                            f"CEL: ({condition}) implies ({consequence}), "
                            f"otherwise ({alternative})"
                        ),
                    }
                )
        if "not" in node:
            inner = self.compile(node["not"], f"{location}/not", stack)
            rules.append(
                {
                    "rule": f"!({inner})",
                    "message": (
                        f"{self.source}{location}: 'not' translated to CEL: "
                        f"!({inner})"
                    ),
                }
            )
        if "dependentRequired" in node:
            expression = self._compile_dependent_required(node, "self")
            rules.append(
                {
                    "rule": expression,
                    "message": (
                        f"{self.source}{location}: 'dependentRequired' translated "
                        f"to CEL: {expression}"
                    ),
                }
            )
        return rules


def _cel_literal(value: Any) -> str:
    """Render a JSON value as a CEL literal."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        return f"'{escaped}'"
    raise ConversionError(f"cannot render {type(value).__name__} as a CEL literal")


def _cel_type(value: Any, path: str) -> str:
    """Render a JSON Schema type as a CEL type test."""
    names = {
        "string": f"{path} is string",
        "integer": f"{path} is int",
        "number": f"({path} is int || {path} is double)",
        "boolean": f"{path} is bool",
        "object": f"{path} is map",
        "array": f"{path} is list",
    }
    if isinstance(value, list):
        return "(" + " || ".join(_cel_type(item, path) for item in value) + ")"
    if value not in names:
        raise ConversionError(f"type {value!r} has no CEL equivalent")
    return names[value]


# --------------------------------------------------------------------------
# CRD assembly
# --------------------------------------------------------------------------


def derive_plural(kind: str) -> str:
    """Derive a resource plural from its kind, by the Kubernetes convention."""
    lower = kind.lower()
    if lower.endswith(("s", "x", "z", "ch", "sh")):
        return f"{lower}es"
    if lower.endswith("y") and len(lower) > 1 and lower[-2] not in "aeiou":
        return f"{lower[:-1]}ies"
    return f"{lower}s"


def derive_scope(kind_schema: dict, converter: Converter, location: str) -> str:
    """Derive the resource scope from the schema's own metadata definition."""
    metadata = kind_schema.get("properties", {}).get("metadata")
    if metadata is None:
        return "Namespaced"
    resolved = converter.dereference(metadata, f"{location}/properties/metadata", ())
    required = resolved.get("required", [])
    return "Namespaced" if "namespace" in required else "Cluster"


def build_crd(
    *,
    kind: str,
    group: str,
    version: str,
    scope: str,
    plural: str,
    singular: str,
    schema: dict,
    status_subresource: bool,
    scale_subresource: dict | None,
    source: str,
    source_reference: str,
) -> dict:
    """Assemble one CustomResourceDefinition manifest."""
    version_entry: dict[str, Any] = {
        "name": version,
        "served": True,
        "storage": True,
    }
    subresources: dict[str, Any] = {}
    if status_subresource:
        subresources["status"] = {}
    if scale_subresource:
        subresources["scale"] = {
            "specReplicasPath": scale_subresource["specReplicasPath"],
            "statusReplicasPath": scale_subresource["statusReplicasPath"],
        }
        if scale_subresource.get("labelSelectorPath"):
            subresources["scale"]["labelSelectorPath"] = scale_subresource[
                "labelSelectorPath"
            ]
    if subresources:
        version_entry["subresources"] = subresources
    version_entry["schema"] = {"openAPIV3Schema": schema}

    return {
        "apiVersion": CRD_API_VERSION,
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": f"{plural}.{group}",
            "annotations": {
                "corvi.naktis.eu/generated-by": "scripts/generate_crds.py",
                "corvi.naktis.eu/schema-source": source_reference,
            },
        },
        "spec": {
            "group": group,
            "scope": scope,
            "names": {
                "plural": plural,
                "singular": singular,
                "kind": kind,
                "listKind": f"{kind}List",
            },
            "versions": [version_entry],
        },
    }


def ownership_crds(document: dict, source: str) -> list[tuple[str, dict]]:
    """Build one CRD per branch of the ownership schema's ``oneOf``."""
    converter = Converter(document, source)
    branches = document.get("oneOf")
    if not branches:
        raise ConversionError(
            f"{source}: the ownership schema has no 'oneOf' branches to convert"
        )
    results: list[tuple[str, dict]] = []
    for index, branch in enumerate(branches):
        location = f"/oneOf/{index}"
        target = branch.get("$ref") if isinstance(branch, dict) else None
        kind_schema = converter.dereference(branch, location, ())
        properties = kind_schema.get("properties", {})
        api_version = properties.get("apiVersion", {}).get("const")
        kind = properties.get("kind", {}).get("const")
        if not api_version or not kind:
            raise ConversionError(
                f"{source}{location}: the branch does not declare its "
                "apiVersion and kind; the CRD metadata cannot be derived"
            )
        group, _, version = api_version.rpartition("/")
        if not group or not version:
            raise ConversionError(
                f"{source}{location}: apiVersion {api_version!r} is not a "
                "group/version pair"
            )
        pointer = f"/oneOf/{index}"
        if target:
            pointer = target.replace("#", "")
        reference = f"{source}#{pointer}"
        schema, _rules = converter.convert(kind_schema, location)
        schema = {
            "type": "object",
            "description": (
                f"{kind}, derived from {reference}. The checked-in JSON "
                "Schema is the source of truth; this manifest is generated by "
                "scripts/generate_crds.py and must not be edited by hand."
            ),
            "required": ["spec"],
            "properties": {"spec": schema["properties"]["spec"]},
        }
        scope = derive_scope(kind_schema, converter, location)
        plural = derive_plural(kind)
        singular = kind.lower()
        results.append(
            (
                f"corvi-{kind.lower()}.yaml",
                build_crd(
                    kind=kind,
                    group=group,
                    version=version,
                    scope=scope,
                    plural=plural,
                    singular=singular,
                    schema=schema,
                    status_subresource=False,
                    scale_subresource=None,
                    source=source,
                    source_reference=reference,
                ),
            )
        )
    return results


def gateway_crd(document: dict, source: str) -> tuple[str, dict]:
    """Build the CorviGateway CRD from its schema."""
    converter = Converter(document, source)
    declared = document.get("x-corvi-kubernetes-crd")
    if not declared:
        raise ConversionError(
            f"{source}: the schema declares no 'x-corvi-kubernetes-crd' metadata"
        )
    for key in ("group", "version", "scope", "plural", "singular", "kind"):
        if key not in declared:
            raise ConversionError(
                f"{source}: 'x-corvi-kubernetes-crd' does not declare {key!r}"
            )
    kind = declared["kind"]
    plural = declared["plural"]
    singular = declared["singular"]
    derived = derive_plural(kind)
    if derived != plural:
        raise ConversionError(
            f"{source}: the declared plural {plural!r} does not match the "
            f"plural derived from the kind {kind!r} ({derived!r})"
        )
    if singular != kind.lower():
        raise ConversionError(
            f"{source}: the declared singular {singular!r} does not match the "
            f"kind {kind!r}"
        )
    schema, _rules = converter.convert(document, "")
    schema = {
        "type": "object",
        "description": (
            f"{kind}, derived from {source}. The checked-in JSON Schema is the "
            "source of truth; this manifest is generated by "
            "scripts/generate_crds.py and must not be edited by hand."
        ),
        "required": ["spec"],
        "properties": {
            "spec": schema["properties"]["spec"],
            "status": schema["properties"]["status"],
        },
    }
    scale = declared.get("scaleSubresource")
    return (
        f"corvi-{kind.lower()}.yaml",
        build_crd(
            kind=kind,
            group=declared["group"],
            version=declared["version"],
            scope=declared["scope"],
            plural=plural,
            singular=singular,
            schema=schema,
            status_subresource=bool(declared.get("statusSubresource")),
            scale_subresource=scale,
            source=source,
            source_reference=f"{source}#/",
        ),
    )


def generate() -> dict[str, str]:
    """Return the generated manifests, keyed by their path under the root."""
    ownership = json.loads(OWNERSHIP_SCHEMA.read_text(encoding="utf-8"))
    gateway = json.loads(GATEWAY_SCHEMA.read_text(encoding="utf-8"))
    manifests: list[tuple[str, dict]] = []
    manifests.extend(
        ownership_crds(
            ownership, str(OWNERSHIP_SCHEMA.relative_to(ROOT)).replace("\\", "/")
        )
    )
    manifests.append(
        gateway_crd(gateway, str(GATEWAY_SCHEMA.relative_to(ROOT)).replace("\\", "/"))
    )
    generated: dict[str, str] = {}
    for name, manifest in manifests:
        path = f"api/operator/crds/{name}"
        if path in generated:
            raise ConversionError(f"{path}: two schemas produce the same CRD")
        generated[path] = dump_yaml(manifest)
    return generated


def write(generated: dict[str, str]) -> None:
    """Write the generated manifests to the repository."""
    for path, content in generated.items():
        target = ROOT / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        print(f"wrote {path}")


def check(generated: dict[str, str]) -> list[str]:
    """Return the differences between the checked-in manifests and the output."""
    problems: list[str] = []
    for path, content in sorted(generated.items()):
        target = ROOT / path
        if not target.exists():
            problems.append(f"{path}: missing; run scripts/generate_crds.py")
            continue
        existing = target.read_text(encoding="utf-8")
        if existing != content:
            problems.append(
                f"{path}: differs from the generated output; run "
                "scripts/generate_crds.py"
            )
    directory = ROOT / "api" / "operator" / "crds"
    if directory.exists():
        for existing in sorted(directory.glob("*.yaml")):
            relative = str(existing.relative_to(ROOT)).replace("\\", "/")
            if relative not in generated:
                problems.append(
                    f"{relative}: not produced by the generator; remove it or "
                    "teach the generator about it"
                )
    return problems


def main() -> int:
    """Generate or check the CRD manifests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare the checked-in manifests with the generated output",
    )
    arguments = parser.parse_args()

    try:
        generated = generate()
    except ConversionError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if arguments.check:
        problems = check(generated)
        if problems:
            print("the generated CRDs are out of date:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            return 1
        print(
            f"the {len(generated)} generated CRDs match the checked-in manifests"
        )
        return 0

    write(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
