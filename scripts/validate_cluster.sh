#!/usr/bin/env bash
# Validate the generated CRDs and the operator fixtures against a real
# Kubernetes API server.
#
# This script is deliberately separate from scripts/release_gates.py's
# cluster-independent gates: it needs a reachable API server, and it must
# never be reported as passed when there is none.
#
# Exit codes:
#   0  every check that could run passed
#   1  a check failed
#   2  skipped: no Kubernetes API server is reachable
#
# What it checks:
#   1. the generated CRDs install into the API server without a warning
#   2. every valid fixture is accepted by the API server
#   3. every invalid fixture reaches the outcome its semantics call for:
#      either the API server rejects it (the invalidity is schema-level) or
#      it accepts it (the invalidity is semantic, and only the operator's
#      reconciler can reject it).
#
# The expectations come from api/operator/README.md, which records why each
# fixture is invalid. A fixture that is in neither list is an error: the
# table must not fall behind the fixtures.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRD_DIR="${ROOT}/api/operator/crds"
FIXTURE_DIR="${ROOT}/api/operator/fixtures"

# Fixtures the API server itself must reject: the invalidity is expressed by
# the CRD schema (a required field, an unknown field or a CEL rule).
SCHEMA_REJECTED="invalid-cross-namespace-ref invalid-ephemeral-embedded-issuer invalid-missing-mailbox-ref invalid-missing-provider-ref invalid-podspec-injection invalid-sqlite-two-replicas"

# Fixtures the API server must accept: their invalidity is semantic (a
# dangling reference, a suspended provider, a management-only provider owning
# a mailbox, a user-supplied owner reference) and only the operator's
# reconciler refuses them.
SEMANTIC_ONLY="invalid-dangling-gateway-ref invalid-management-only-mailbox invalid-owner-reference-injection invalid-suspended-provider"

failures=0
skipped=0

skip() {
  echo "SKIPPED: $*"
  exit 2
}

fail() {
  echo "FAILED: $*" >&2
  failures=$((failures + 1))
}

if [[ "${CORVI_CLUSTER_VALIDATION:-}" != "1" ]]; then
  skip "set CORVI_CLUSTER_VALIDATION=1 to permit CRD and namespace changes on the current cluster"
fi

if ! command -v kubectl >/dev/null 2>&1; then
  skip "kubectl is not on the PATH; no API server can be reached"
fi

if ! kubectl version --request-timeout=10s >/dev/null 2>&1; then
  skip "no Kubernetes API server is reachable with this kubeconfig"
fi

server_version="$(kubectl version -o json 2>/dev/null | tr -d ' \n' | sed 's/.*"serverVersion":{[^}]*"gitVersion":"\([^"]*\)".*/\1/')"
echo "API server: ${server_version:-unknown}"

echo
echo "== installing the generated CRDs =="
crd_output="$(kubectl apply -f "${CRD_DIR}/" 2>&1)"
crd_status=$?
echo "${crd_output}" | sed 's/^/   /'
if [ ${crd_status} -ne 0 ]; then
  fail "the API server rejected the generated CRDs"
  exit 1
fi
if grep -qi 'warning' <<< "${crd_output}"; then
  fail "the API server reported a warning while installing the CRDs"
fi

if ! kubectl wait --for=condition=Established --timeout=60s -f "${CRD_DIR}/"; then
  fail "the generated CRDs did not become Established"
  exit 1
fi

echo
echo "== ensuring fixture namespace =="
if ! kubectl get namespace corvi-system >/dev/null 2>&1; then
  if ! kubectl create namespace corvi-system; then
    fail "could not create fixture namespace corvi-system"
    exit 1
  fi
fi
if ! kubectl get namespace corvi-system >/dev/null 2>&1; then
  fail "fixture namespace corvi-system is not accessible"
  exit 1
fi

echo
echo "== valid fixtures (the API server must accept these) =="
for fixture in "${FIXTURE_DIR}"/*.yaml; do
  name="$(basename "${fixture}")"
  case "${name}" in
    invalid-*) continue ;;
  esac
  output="$(kubectl apply --dry-run=server -f "${fixture}" 2>&1)"
  if [ $? -eq 0 ]; then
    echo "   accepted: ${name}"
  else
    fail "${name} was rejected by the API server:"
    echo "${output}" | sed 's/^/      /'
  fi
done

echo
echo "== invalid fixtures =="
for fixture in "${FIXTURE_DIR}"/invalid-*.yaml; do
  name="$(basename "${fixture}" .yaml)"
  output="$(kubectl apply --dry-run=server -f "${fixture}" 2>&1)"
  status=$?
  if [[ " ${SCHEMA_REJECTED} " == *" ${name} "* ]]; then
    if [ ${status} -eq 0 ]; then
      fail "${name} should have been rejected by the API server (schema-level invalidity) but was accepted"
    else
      case "${name}" in
        invalid-cross-namespace-ref) expected='strict decoding error: unknown field "spec.gatewayRef.namespace"' ;;
        invalid-podspec-injection) expected='strict decoding error: unknown field "spec.template"' ;;
        invalid-missing-mailbox-ref) expected='spec.mailboxRef: Required value' ;;
        invalid-missing-provider-ref) expected='spec.providerRef: Required value' ;;
        invalid-ephemeral-embedded-issuer) expected='api/corvi-gateway.schema.json/properties/spec/allOf/1' ;;
        invalid-sqlite-two-replicas) expected='api/corvi-gateway.schema.json/properties/spec/allOf/0' ;;
        *) fail "${name} has no expected schema error configured"; continue ;;
      esac
      if [[ "${output}" == *"${expected}"* ]]; then
        echo "   rejected by the API server (schema-level): ${name}"
      else
        fail "${name} failed without its expected schema validation error:"
        echo "${output}" | sed 's/^/      /'
      fi
    fi
  elif [[ " ${SEMANTIC_ONLY} " == *" ${name} "* ]]; then
    if [ ${status} -ne 0 ]; then
      fail "${name} should be schema-level valid (only the operator's semantic validation rejects it) but the API server rejected it:"
      echo "${output}" | sed 's/^/      /'
    else
      echo "   schema-level valid, rejected by the operator's semantic validation: ${name}"
    fi
  else
    fail "${name} is not classified as schema-rejected or semantic-only; update the table in ${BASH_SOURCE[0]}"
  fi
done

echo
if [ ${failures} -eq 0 ]; then
  echo "cluster validation passed"
  exit 0
fi
echo "cluster validation failed: ${failures} check(s)" >&2
exit 1
