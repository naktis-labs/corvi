#!/usr/bin/env python3
"""Check source design contracts, not runtime implementation conformance."""
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker, exceptions


def local_refs(document, value, label, errors):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == '$ref' and isinstance(child, str) and child.startswith('#/'):
                target = document
                try:
                    for part in child[2:].split('/'):
                        target = target[part.replace('~1', '/').replace('~0', '~')]
                except (KeyError, TypeError, IndexError):
                    errors.append(f'{label}: unresolved reference {child}')
            local_refs(document, child, label, errors)
    elif isinstance(value, list):
        for child in value:
            local_refs(document, child, label, errors)


def check_contracts(root: Path) -> list[str]:
    errors = []
    api = root / 'api'
    schemas = sorted(api.glob('*.schema.json'))
    if not schemas:
        errors.append('no JSON Schema files found')
    loaded = {}
    for path in schemas:
        try:
            schema = json.loads(path.read_text())
            Draft202012Validator.check_schema(schema)
            local_refs(schema, schema, path, errors)
            loaded[path.name] = schema
        except (ValueError, OSError, exceptions.SchemaError) as exc:
            errors.append(f'{path}: {exc}')
    path = api / 'openapi.yaml'
    try:
        spec = yaml.safe_load(path.read_text())
        if not isinstance(spec, dict) or spec.get('openapi') != '3.1.0' or not isinstance(spec.get('paths'), dict) or not spec['paths']:
            errors.append(f'{path}: expected OpenAPI 3.1.0 and nonempty paths')
        else:
            local_refs(spec, spec, path, errors)
    except (ValueError, OSError, yaml.YAMLError) as exc:
        errors.append(f'{path}: {exc}')
    schema = loaded.get('generated-connection-secret.schema.json')
    if schema is not None:
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for path in sorted((api / 'examples').glob('*.json')):
            try:
                for error in validator.iter_errors(json.loads(path.read_text())):
                    errors.append(f'{path}: {error.message}')
            except (ValueError, OSError, exceptions._RefResolutionError) as exc:
                errors.append(f'{path}: {exc}')
    for name in ('mcp-tools.json', 'mcp-resources.json'):
        path = api / name
        try:
            data = json.loads(path.read_text())
            if name == 'mcp-resources.json':
                local_refs(data, data, path, errors)
            if name == 'mcp-tools.json':
                expected = {'mail_list_identities', 'mail_list', 'mail_search', 'mail_get', 'mail_get_attachment', 'mail_send', 'mail_get_send_status'}
                if {tool['name'] for tool in data['tools']} != expected or len(data['tools']) != 7:
                    errors.append(f'{path}: expected seven specified tools')
                for tool in data['tools']:
                    for field in ('inputSchema', 'outputSchema'):
                        Draft202012Validator.check_schema(tool[field])
                        local_refs(tool[field], tool[field], path, errors)
        except (ValueError, OSError, KeyError, TypeError, exceptions.SchemaError) as exc:
            errors.append(f'{path}: {exc}')
    return errors


if __name__ == '__main__':
    problems = check_contracts(Path(__file__).resolve().parents[1])
    for problem in problems:
        print(problem)
    if problems:
        raise SystemExit(1)
    print('source contracts validate (design only)')
