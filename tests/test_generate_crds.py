import json
import unittest
from pathlib import Path

from scripts import generate_crds

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML lives in the contract venv
    yaml = None

ROOT = Path(__file__).resolve().parents[1]


class GeneratedManifestTest(unittest.TestCase):
    def test_every_kind_has_a_manifest(self):
        generated = generate_crds.generate()
        self.assertEqual(
            sorted(generated),
            [
                "api/operator/crds/corvi-corvigateway.yaml",
                "api/operator/crds/corvi-mailbox.yaml",
                "api/operator/crds/corvi-mailidentity.yaml",
                "api/operator/crds/corvi-mailprovider.yaml",
            ],
        )

    def test_checked_in_manifests_match_the_generator(self):
        for path, content in generate_crds.generate().items():
            self.assertEqual(
                (ROOT / path).read_text(encoding="utf-8"),
                content,
                f"{path} differs from the generated output",
            )

    def test_generation_is_deterministic(self):
        self.assertEqual(generate_crds.generate(), generate_crds.generate())

    @unittest.skipIf(yaml is None, "PyYAML is not installed")
    def test_manifests_are_valid_yaml(self):
        for path in generate_crds.generate():
            document = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
            self.assertEqual(document["kind"], "CustomResourceDefinition")
            self.assertEqual(document["apiVersion"], "apiextensions.k8s.io/v1")
            version = document["spec"]["versions"][0]
            self.assertEqual(version["name"], "v1alpha1")
            self.assertIn("openAPIV3Schema", version["schema"])
            self.assertEqual(
                document["metadata"]["name"],
                f"{document['spec']['names']['plural']}.{document['spec']['group']}",
            )


class MetadataTest(unittest.TestCase):
    def test_plural_follows_the_kubernetes_convention(self):
        self.assertEqual(generate_crds.derive_plural("MailProvider"), "mailproviders")
        self.assertEqual(generate_crds.derive_plural("Mailbox"), "mailboxes")
        self.assertEqual(generate_crds.derive_plural("MailIdentity"), "mailidentities")
        self.assertEqual(generate_crds.derive_plural("CorviGateway"), "corvigateways")

    def test_the_declared_plural_matches_the_derived_one(self):
        document = json.loads(
            (ROOT / "api" / "corvi-gateway.schema.json").read_text(encoding="utf-8")
        )
        declared = document["x-corvi-kubernetes-crd"]
        self.assertEqual(
            generate_crds.derive_plural(declared["kind"]), declared["plural"]
        )

    def test_the_group_and_version_come_from_the_schema(self):
        document = json.loads(
            (ROOT / "api" / "mail-resource-ownership.schema.json").read_text(
                encoding="utf-8"
            )
        )
        converter = generate_crds.Converter(document, "ownership")
        branch = converter.dereference(document["oneOf"][0], "/oneOf/0", ())
        const = branch["properties"]["apiVersion"]["const"]
        self.assertEqual(const, "corvi.naktis.eu/v1alpha1")
        self.assertEqual(const.rpartition("/")[0], "corvi.naktis.eu")
        self.assertEqual(const.rpartition("/")[2], "v1alpha1")
        self.assertEqual(
            branch["properties"]["kind"]["const"], "MailProvider"
        )


class ConversionTest(unittest.TestCase):
    def setUp(self):
        self.converter = generate_crds.Converter(
            {"$defs": {}}, "test"
        )

    def convert(self, node):
        schema, rules = self.converter.convert(node, "/test")
        return schema, rules

    def test_const_becomes_a_single_member_enum(self):
        schema, _rules = self.convert({"type": "string", "const": "sqlite"})
        self.assertEqual(schema["enum"], ["sqlite"])
        self.assertNotIn("const", schema)

    def test_additional_properties_false_is_dropped(self):
        schema, _rules = self.convert(
            {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": False}
        )
        self.assertNotIn("additionalProperties", schema)
        self.assertIn("properties", schema)

    def test_additional_properties_true_preserves_unknown_fields(self):
        schema, _rules = self.convert(
            {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": True}
        )
        self.assertTrue(schema["x-kubernetes-preserve-unknown-fields"])

    def test_additional_properties_with_a_schema_next_to_properties_fails(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert(
                {
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                    "additionalProperties": {"type": "string"},
                }
            )
        self.assertIn("additionalProperties", str(raised.exception))

    def test_if_then_becomes_a_cel_rule(self):
        schema, rules = self.convert(
            {
                "type": "object",
                "properties": {"backend": {"type": "string"}, "claim": {"type": "string"}},
                "if": {
                    "properties": {"backend": {"const": "sqlite"}},
                    "required": ["backend"],
                },
                "then": {"required": ["claim"]},
            }
        )
        self.assertEqual(len(rules), 1)
        self.assertIn("has(self.backend)", rules[0]["rule"])
        self.assertIn("has(self.claim)", rules[0]["rule"])
        self.assertEqual(
            schema["x-kubernetes-validations"][0]["rule"], rules[0]["rule"]
        )

    def test_not_becomes_a_negated_cel_rule(self):
        schema, rules = self.convert(
            {
                "type": "object",
                "properties": {"x": {"type": "boolean"}},
                "not": {"properties": {"x": {"const": True}}, "required": ["x"]},
            }
        )
        self.assertEqual(len(rules), 1)
        self.assertTrue(rules[0]["rule"].startswith("!("))
        self.assertIn("self.x == true", rules[0]["rule"])
        self.assertIn("x-kubernetes-validations", schema)

    def test_dependent_required_becomes_a_cel_rule(self):
        _schema, rules = self.convert(
            {
                "type": "object",
                "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
                "dependentRequired": {"a": ["b"]},
            }
        )
        self.assertEqual(len(rules), 1)
        self.assertIn("has(self.a)", rules[0]["rule"])
        self.assertIn("has(self.b)", rules[0]["rule"])

    def test_property_names_is_refused(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert({"type": "object", "propertyNames": {"pattern": "^x$"}})
        self.assertIn("propertyNames", str(raised.exception))

    def test_unevaluated_properties_is_refused(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert({"type": "object", "unevaluatedProperties": False})
        self.assertIn("unevaluatedProperties", str(raised.exception))

    def test_an_unknown_keyword_is_refused(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert({"type": "object", "contains": {"type": "string"}})
        self.assertIn("contains", str(raised.exception))

    def test_branch_only_properties_are_refused(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert(
                {
                    "type": "object",
                    "oneOf": [
                        {"properties": {"branchOnly": {"type": "string"}}}
                    ],
                }
            )
        self.assertIn("branchOnly", str(raised.exception))
        self.assertIn("oneOf", str(raised.exception))

    def test_nested_branch_only_properties_are_refused(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert(
                {
                    "type": "object",
                    "properties": {"nested": {"type": "object"}},
                    "oneOf": [
                        {
                            "properties": {
                                "nested": {
                                    "properties": {
                                        "branchOnly": {"type": "string"}
                                    }
                                }
                            }
                        }
                    ],
                }
            )
        self.assertIn("branchOnly", str(raised.exception))

    def test_unique_items_true_is_refused(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert({"type": "array", "uniqueItems": True})
        self.assertIn("uniqueItems", str(raised.exception))

    def test_numeric_exclusive_minimum_maps_to_openapi_bound(self):
        schema, _rules = self.convert(
            {"type": "integer", "exclusiveMinimum": 3}
        )
        self.assertEqual(schema["minimum"], 3)
        self.assertIs(schema["exclusiveMinimum"], True)

    def test_numeric_exclusive_maximum_maps_to_openapi_bound(self):
        schema, _rules = self.convert(
            {"type": "integer", "exclusiveMaximum": 7}
        )
        self.assertEqual(schema["maximum"], 7)
        self.assertIs(schema["exclusiveMaximum"], True)

    def test_exclusive_minimum_conflicts_regardless_of_keyword_order(self):
        schemas = [
            {"exclusiveMinimum": 3, "minimum": 2},
            {"minimum": 2, "exclusiveMinimum": 3},
        ]
        for node in schemas:
            with self.subTest(node=node):
                with self.assertRaises(generate_crds.ConversionError) as raised:
                    self.convert(node)
                self.assertIn("minimum", str(raised.exception))

    def test_exclusive_maximum_conflicts_regardless_of_keyword_order(self):
        schemas = [
            {"exclusiveMaximum": 7, "maximum": 8},
            {"maximum": 8, "exclusiveMaximum": 7},
        ]
        for node in schemas:
            with self.subTest(node=node):
                with self.assertRaises(generate_crds.ConversionError) as raised:
                    self.convert(node)
                self.assertIn("maximum", str(raised.exception))

    def test_branch_properties_under_items_are_refused(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert(
                {
                    "type": "array",
                    "items": {"type": "object"},
                    "oneOf": [
                        {
                            "items": {
                                "properties": {
                                    "branchOnly": {"type": "string"}
                                }
                            }
                        }
                    ],
                }
            )
        self.assertIn("branchOnly", str(raised.exception))

    def test_translated_conditional_cannot_reference_undeclared_field(self):
        with self.assertRaises(generate_crds.ConversionError) as raised:
            self.convert(
                {
                    "type": "object",
                    "properties": {"known": {"type": "boolean"}},
                    "if": {
                        "properties": {"unknown": {"const": True}},
                        "required": ["unknown"],
                    },
                    "then": {"required": ["known"]},
                }
            )
        self.assertIn("unknown", str(raised.exception))

    def test_branch_conditional_uses_enclosing_declarations(self):
        self.convert({"type": "object", "properties": {"backend": {"type": "string"}},
                      "allOf": [{"if": {"required": ["backend"]},
                                 "then": {"properties": {"backend": {"const": "sqlite"}}}}]})

    def test_conditional_required_field_must_be_declared(self):
        with self.assertRaisesRegex(generate_crds.ConversionError, "missing"):
            self.convert({"type": "object", "properties": {},
                          "allOf": [{"if": {"required": ["missing"]}}]})

    def test_dependent_required_rejects_undeclared_fields(self):
        for dependency in ({"a": ["missing"]}, {"missing": ["a"]}):
            with self.subTest(dependency=dependency):
                with self.assertRaisesRegex(generate_crds.ConversionError, "missing"):
                    self.convert({"type": "object", "properties": {"a": {"type": "string"}},
                                  "dependentRequired": dependency})

    def test_branch_items_require_parent_items(self):
        with self.assertRaises(generate_crds.ConversionError):
            self.convert({"type": "object", "properties": {"a": {"type": "array"}},
                          "oneOf": [{"properties": {"a": {"items": {"type": "string"}}}}]})

    def test_forbidden_branch_keywords_are_refused(self):
        for key, value in (("description", "text"), ("default", 1),
                           ("nullable", True), ("additionalProperties", True)):
            with self.subTest(key=key):
                with self.assertRaises(generate_crds.ConversionError):
                    self.convert({"type": "object", "oneOf": [{key: value}]})

    def test_branch_nested_cel_rules_are_refused(self):
        node = {"type": "object", "properties": {"a": {"type": "object", "properties": {"x": {"type": "string"}}}},
                "oneOf": [{"properties": {"a": {"dependentRequired": {"x": ["x"]}}}}]}
        with self.assertRaises(generate_crds.ConversionError):
            self.convert(node)

    def test_branch_tuple_items_fail_cleanly(self):
        node = {"oneOf": [{"items": [{"type": "string"}]}], "type": "array", "items": [{"type": "string"}]}
        with self.assertRaises(generate_crds.ConversionError):
            self.convert(node)

    def test_branch_metadata_property_is_refused(self):
        node = {"type": "object", "properties": {"metadata": {"type": "object"}},
                "oneOf": [{"properties": {"metadata": {"type": "object"}}}]}
        with self.assertRaises(generate_crds.ConversionError):
            self.convert(node)

    def test_a_self_referential_reference_is_refused(self):
        converter = generate_crds.Converter(
            {"$defs": {"node": {"type": "object", "properties": {"child": {"$ref": "#/$defs/node"}}}}},
            "test",
        )
        with self.assertRaises(generate_crds.ConversionError) as raised:
            converter.convert({"$ref": "#/$defs/node"}, "/test")
        self.assertIn("reaches itself", str(raised.exception))

    def test_recursive_reference_in_a_branch_guard_fails_cleanly(self):
        converter = generate_crds.Converter(
            {
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {"child": {"$ref": "#/$defs/node"}},
                        "oneOf": [{"required": ["child"]}],
                    }
                }
            },
            "test",
        )
        with self.assertRaises(generate_crds.ConversionError) as raised:
            converter.convert({"$ref": "#/$defs/node"}, "/test")
        self.assertIn("reaches itself", str(raised.exception))

    def test_a_reference_is_inlined(self):
        converter = generate_crds.Converter(
            {"$defs": {"name": {"type": "string", "minLength": 1}}}, "test"
        )
        schema, _rules = converter.convert(
            {"type": "object", "properties": {"name": {"$ref": "#/$defs/name"}}},
            "/test",
        )
        self.assertEqual(
            schema["properties"]["name"], {"type": "string", "minLength": 1}
        )

    def test_a_type_inside_a_branch_is_dropped(self):
        schema, _rules = self.convert(
            {
                "type": "object",
                "properties": {"a": {"type": "object"}},
                "anyOf": [{"properties": {"a": {"type": "object"}}}],
            }
        )
        self.assertNotIn("type", schema["anyOf"][0]["properties"]["a"])


class YamlTest(unittest.TestCase):
    def test_nested_structures_are_indented(self):
        text = generate_crds.dump_yaml(
            {
                "a": {"b": {"c": "d"}},
                "list": [{"x": 1}, {"z": [2, 3]}],
                "empty": {},
            }
        )
        self.assertEqual(
            text,
            "a:\n"
            "  b:\n"
            "    c: d\n"
            "list:\n"
            "  - x: 1\n"
            "  - z:\n"
            "      - 2\n"
            "      - 3\n"
            "empty: {}\n",
        )

    def test_ambiguous_scalars_are_quoted(self):
        text = generate_crds.dump_yaml({"a": "yes", "b": "1", "c": "true", "d": "x"})
        self.assertEqual(text, 'a: "yes"\nb: "1"\nc: "true"\nd: x\n')

    def test_yaml_boolean_words_are_quoted_as_keys(self):
        text = generate_crds.dump_yaml({"y": "on", "n": 1})
        self.assertEqual(text, '"y": "on"\n"n": 1\n')


if __name__ == "__main__":
    unittest.main()
