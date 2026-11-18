//! A small JSON Schema checker for the checked-in contracts.
//!
//! The gateway validates what a client sends against the schema the
//! contract declares, and validates what it returns against the schema the
//! contract declares. The subset implemented here is the one the checked-in
//! contracts use: objects with closed property sets, arrays, strings with
//! length bounds, numbers with bounds, enums, constants and local `$ref`s.
//!
//! This is not a general JSON Schema implementation. It refuses what it
//! cannot check rather than passing it, because a schema check that silently
//! accepts everything would be worse than none.

use serde_json::Value;

/// Check a value against a schema.
///
/// The errors name the offending path and what was wrong, and are meant for
/// a developer reading a test failure; a protocol adapter turns them into a
/// generic invalid-input answer.
pub fn validate(value: &Value, schema: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    check(value, schema, schema, "", &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Check a value against a schema whose `$ref`s resolve in `root`.
pub fn validate_in(value: &Value, schema: &Value, root: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    check(value, schema, root, "", &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// The recursive check.
fn check(value: &Value, schema: &Value, root: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(schema) = schema.as_object() else {
        return;
    };

    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        match resolve(reference, root) {
            Some(target) => check(value, target, root, path, errors),
            None => errors.push(format!("{path}: unresolved schema reference '{reference}'")),
        }
        return;
    }

    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        if !type_matches(expected, value) {
            errors.push(format!(
                "{path}: expected type '{expected}', found '{}'",
                type_name(value)
            ));
            return;
        }
    }

    if let Some(constant) = schema.get("const") {
        if value != constant {
            errors.push(format!("{path}: value is not the required constant"));
        }
    }

    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.iter().any(|candidate| candidate == value) {
            errors.push(format!("{path}: value is not one of the allowed values"));
        }
    }

    match value {
        Value::Object(object) => {
            let properties = schema.get("properties").and_then(Value::as_object);
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for name in required {
                    if let Some(name) = name.as_str() {
                        if !object.contains_key(name) {
                            errors.push(format!("{path}: missing required property '{name}'"));
                        }
                    }
                }
            }
            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                for name in object.keys() {
                    let known = properties.is_some_and(|known| known.contains_key(name));
                    if !known {
                        errors.push(format!("{path}: unknown property '{name}'"));
                    }
                }
            }
            if let Some(properties) = properties {
                for (name, child) in object {
                    if let Some(child_schema) = properties.get(name) {
                        let child_path = if path.is_empty() {
                            name.clone()
                        } else {
                            format!("{path}.{name}")
                        };
                        check(child, child_schema, root, &child_path, errors);
                    }
                }
            }
        }
        Value::Array(items) => {
            if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64) {
                if (items.len() as u64) < minimum {
                    errors.push(format!("{path}: expected at least {minimum} items"));
                }
            }
            if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64) {
                if (items.len() as u64) > maximum {
                    errors.push(format!("{path}: expected at most {maximum} items"));
                }
            }
            if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
                for (index, item) in items.iter().enumerate() {
                    if items[..index].contains(item) {
                        errors.push(format!("{path}: items must be unique"));
                        break;
                    }
                }
            }
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    check(item, item_schema, root, &format!("{path}[{index}]"), errors);
                }
            }
        }
        Value::String(text) => {
            let length = text.chars().count() as u64;
            if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
                if length < minimum {
                    errors.push(format!("{path}: expected at least {minimum} characters"));
                }
            }
            if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64) {
                if length > maximum {
                    errors.push(format!("{path}: expected at most {maximum} characters"));
                }
            }
        }
        Value::Number(number) => {
            let value = number.as_f64().unwrap_or_default();
            if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
                if value < minimum {
                    errors.push(format!("{path}: expected at least {minimum}"));
                }
            }
            if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
                if value > maximum {
                    errors.push(format!("{path}: expected at most {maximum}"));
                }
            }
        }
        _ => {}
    }
}

/// Resolve a local reference.
fn resolve<'a>(reference: &str, root: &'a Value) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    let mut current = root;
    for segment in pointer.trim_start_matches('/').split('/') {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        current = current.get(&segment)?;
    }
    Some(current)
}

/// Whether a value has the named type.
fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        _ => true,
    }
}

/// The name of a value's type, for an error message.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_a_valid_object() {
        let schema = json!({
            "type": "object",
            "properties": {"id": {"type": "string", "minLength": 1}},
            "required": ["id"],
            "additionalProperties": false
        });
        assert!(validate(&json!({"id": "x"}), &schema).is_ok());
    }

    #[test]
    fn rejects_an_unknown_property() {
        let schema = json!({
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "additionalProperties": false
        });
        assert!(validate(&json!({"id": "x", "extra": 1}), &schema).is_err());
    }

    #[test]
    fn rejects_a_missing_required_property() {
        let schema = json!({
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"]
        });
        assert!(validate(&json!({}), &schema).is_err());
    }

    #[test]
    fn rejects_a_value_outside_an_enum() {
        let schema = json!({"type": "string", "enum": ["a", "b"]});
        assert!(validate(&json!("c"), &schema).is_err());
        assert!(validate(&json!("a"), &schema).is_ok());
    }

    #[test]
    fn resolves_a_local_reference() {
        let root = json!({
            "$defs": {"name": {"type": "string", "maxLength": 3}},
            "type": "object",
            "properties": {"n": {"$ref": "#/$defs/name"}}
        });
        assert!(validate_in(&json!({"n": "ab"}), &root, &root).is_ok());
        assert!(validate_in(&json!({"n": "abcd"}), &root, &root).is_err());
    }

    #[test]
    fn checks_array_bounds() {
        let schema = json!({
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 2
        });
        assert!(validate(&json!([]), &schema).is_err());
        assert!(validate(&json!(["a"]), &schema).is_ok());
        assert!(validate(&json!(["a", "b", "c"]), &schema).is_err());
    }
}
