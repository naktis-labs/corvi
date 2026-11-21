import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.check_source_contracts import check_contracts


class SourceContractsTest(unittest.TestCase):
    def test_checked_in_contracts_validate(self):
        self.assertEqual(check_contracts(Path(__file__).resolve().parents[1]), [])

    def test_invalid_openapi_is_reported(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            shutil.copytree(root / 'api', temp / 'api')
            (temp / 'api/openapi.yaml').write_text('openapi: [invalid\n')
            self.assertTrue(check_contracts(temp))

    def test_invalid_connection_example_is_reported(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            shutil.copytree(root / 'api', temp / 'api')
            (temp / 'api/examples/gateway-connection.example.json').write_text('{}')
            self.assertTrue(check_contracts(temp))

class ContractFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        shutil.copytree(Path(__file__).resolve().parents[1] / 'api', self.root / 'api')
        self.addCleanup(self.tmp.cleanup)

    def test_non_mapping_openapi_reports_error(self):
        (self.root / 'api/openapi.yaml').write_text('[]')
        self.assertTrue(check_contracts(self.root))

    def test_missing_schema_reference_reports_error(self):
        path = self.root / 'api/corvi-gateway.schema.json'
        import json
        data = json.loads(path.read_text())
        data['$ref'] = '#/$defs/nonexistent'
        path.write_text(json.dumps(data))
        self.assertTrue(check_contracts(self.root))

    def test_failures_are_accumulated(self):
        (self.root / 'api/openapi.yaml').write_text('[')
        (self.root / 'api/examples/gateway-connection.example.json').write_text('{}')
        self.assertGreaterEqual(len(check_contracts(self.root)), 2)

    def test_invalid_email_format_is_reported(self):
        import json
        path = self.root / 'api/examples/provider-direct-connection.example.json'
        data = json.loads(path.read_text())
        data['SMTP_FROM_ADDRESS'] = 'not-an-email'
        path.write_text(json.dumps(data))
        self.assertTrue(check_contracts(self.root))

    def test_missing_mcp_tool_is_reported(self):
        import json
        path = self.root / 'api/mcp-tools.json'
        data = json.loads(path.read_text())
        data['tools'].pop()
        path.write_text(json.dumps(data))
        self.assertTrue(check_contracts(self.root))

    def test_unresolved_mcp_schema_reference_is_reported(self):
        import json
        path = self.root / 'api/mcp-tools.json'
        data = json.loads(path.read_text())
        data['tools'][0]['outputSchema']['$ref'] = '#/$defs/missing'
        path.write_text(json.dumps(data))
        self.assertTrue(check_contracts(self.root))


if __name__ == "__main__":
    unittest.main()
