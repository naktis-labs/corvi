import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/validate_cluster.sh'


class ClusterValidationTest(unittest.TestCase):
    def run_script(self, opted_in, bad_rejection=False, missing_namespace=False, create_fails=False):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            log = directory / 'calls'
            kubectl = directory / 'kubectl'
            kubectl.write_text('''#!/bin/bash
printf '%s\\n' "$*" >> "$LOG"
if [[ "$*" == "get namespace corvi-system" && "$MISSING" == 1 && ! -f "$STATE" ]]; then exit 1; fi
if [[ "$*" == "create namespace corvi-system" ]]; then
  if [[ "$CREATE_FAILS" == 1 ]]; then exit 1; fi
  touch "$STATE"
fi
if [[ "$*" == *"invalid-"* && "$*" != *"invalid-dangling"* && "$*" != *"invalid-management"* && "$*" != *"invalid-owner"* && "$*" != *"invalid-suspended"* ]]; then
  if [[ "$BAD" == 1 ]]; then echo 'Error from server (Forbidden): access denied' >&2; else
    case "$*" in
      *invalid-cross-namespace*) echo 'strict decoding error: unknown field "spec.gatewayRef.namespace"' >&2 ;;
      *invalid-podspec*) echo 'strict decoding error: unknown field "spec.template"' >&2 ;;
      *invalid-missing-mailbox*) echo 'spec.mailboxRef: Required value' >&2 ;;
      *invalid-missing-provider*) echo 'spec.providerRef: Required value' >&2 ;;
      *invalid-ephemeral*) echo 'spec: Invalid value: api/corvi-gateway.schema.json/properties/spec/allOf/1' >&2 ;;
      *invalid-sqlite*) echo 'spec: Invalid value: api/corvi-gateway.schema.json/properties/spec/allOf/0' >&2 ;;
    esac
  fi
  exit 1
fi
exit 0
''')
            kubectl.chmod(0o755)
            env = dict(os.environ, PATH=f'{directory}:' + os.environ['PATH'], LOG=str(log), BAD='1' if bad_rejection else '0', MISSING='1' if missing_namespace else '0', CREATE_FAILS='1' if create_fails else '0', STATE=str(directory / 'namespace'))
            env.pop('CORVI_CLUSTER_VALIDATION', None)
            if opted_in:
                env['CORVI_CLUSTER_VALIDATION'] = '1'
            result = subprocess.run(['bash', str(SCRIPT)], env=env, text=True, capture_output=True)
            return result, log.read_text() if log.exists() else ''

    def test_no_opt_in_never_calls_kubectl(self):
        result, calls = self.run_script(False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, '')

    def test_creates_namespace_and_rejects_unrelated_errors(self):
        result, calls = self.run_script(True, bad_rejection=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('namespace corvi-system', calls)
        self.assertIn('access denied', result.stderr + result.stdout)

    def test_missing_namespace_is_created(self):
        result, calls = self.run_script(True, missing_namespace=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('create namespace corvi-system', calls)
        self.assertIn('wait --for=condition=Established', calls)

    def test_namespace_creation_failure_stops_validation(self):
        result, calls = self.run_script(True, missing_namespace=True, create_fails=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('--dry-run=server', calls)

    def test_accepts_validation_errors(self):
        result, calls = self.run_script(True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('namespace corvi-system', calls)


if __name__ == '__main__':
    unittest.main()
