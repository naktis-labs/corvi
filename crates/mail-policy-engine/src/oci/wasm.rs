//! Policy module inspection.
//!
//! ADR-0004 section 4.4 requires the actual WebAssembly binary to be
//! validated: media-type metadata alone is never proof of trust. This module
//! parses a module with `wasmparser`, reports what it imports and exports, and
//! checks it against the local import allowlist.
//!
//! The allowlist is the *only* way a module obtains a host capability. An
//! annotation, a media type or a registry name grants nothing.

use std::fmt;

use wasmparser::{Imports, Parser, Payload, TypeRef, Validator};

/// One import the module declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedImport {
    /// The module the import comes from, for example `corvi:policy/host@0.1.0`.
    pub module: String,
    /// The imported name.
    pub name: String,
}

/// The host capabilities a module may import.
///
/// The default is an empty allowlist: a module that imports nothing is
/// accepted, and every import needs an explicit local decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityAllowlist {
    allowed: Vec<AllowedImport>,
}

impl CapabilityAllowlist {
    /// An allowlist that permits no import at all.
    pub fn deny_all() -> Self {
        Self {
            allowed: Vec::new(),
        }
    }

    /// An allowlist with the given imports.
    pub fn with(allowed: Vec<AllowedImport>) -> Self {
        Self { allowed }
    }

    /// Whether an import is permitted.
    pub fn permits(&self, module: &str, name: &str) -> bool {
        self.allowed
            .iter()
            .any(|entry| entry.module == module && entry.name == name)
    }

    /// Whether the allowlist is empty.
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

/// The exports a policy module must provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiExpectation {
    entry_point_exports: Vec<String>,
}

impl AbiExpectation {
    /// The expectations of the `corvi-policy-v1` ABI.
    ///
    /// The entry point is accepted under its plain core module name and under
    /// the canonical component export name.
    pub fn corvi_policy_v1() -> Self {
        Self {
            entry_point_exports: vec![
                "evaluate".to_string(),
                "corvi:policy/decisions@0.1.0#evaluate".to_string(),
            ],
        }
    }

    /// Expectations with an explicit list of acceptable entry point exports.
    pub fn with_entry_point_exports(entry_point_exports: Vec<String>) -> Self {
        Self {
            entry_point_exports,
        }
    }

    /// The acceptable entry point exports.
    pub fn entry_point_exports(&self) -> &[String] {
        &self.entry_point_exports
    }
}

/// The kind of an imported entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    /// An imported function: a host capability.
    Function,
    /// An imported table: shared host state.
    Table,
    /// An imported memory: shared host state.
    Memory,
    /// An imported global: shared host state.
    Global,
    /// An imported tag.
    Tag,
}

/// One import the module declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFact {
    /// The module the import comes from.
    pub module: String,
    /// The imported name.
    pub name: String,
    /// The kind of the imported entity.
    pub kind: ImportKind,
}

/// What a module declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleFacts {
    /// The imports of the module.
    pub imports: Vec<ImportFact>,
    /// The exported names of the module.
    pub exports: Vec<String>,
}

/// Why a module could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmError {
    /// The bytes are not a readable WebAssembly module.
    Parse(String),
    /// The module is readable but not structurally valid.
    Invalid(String),
}

impl fmt::Display for WasmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmError::Parse(reason) => write!(formatter, "the module does not parse: {reason}"),
            WasmError::Invalid(reason) => {
                write!(formatter, "the module is not valid: {reason}")
            }
        }
    }
}

impl std::error::Error for WasmError {}

/// The kind of an imported entity.
fn import_kind(ty: TypeRef) -> ImportKind {
    match ty {
        TypeRef::Func(_) | TypeRef::FuncExact(_) => ImportKind::Function,
        TypeRef::Table(_) => ImportKind::Table,
        TypeRef::Memory(_) => ImportKind::Memory,
        TypeRef::Global(_) => ImportKind::Global,
        TypeRef::Tag(_) => ImportKind::Tag,
    }
}

/// Parse a module and report its imports and exports.
pub fn inspect(bytes: &[u8]) -> Result<ModuleFacts, WasmError> {
    let mut facts = ModuleFacts::default();

    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|error| WasmError::Parse(error.to_string()))? {
            Payload::ImportSection(reader) => {
                for group in reader {
                    let group = group.map_err(|error| WasmError::Parse(error.to_string()))?;
                    match group {
                        Imports::Single(_, import) => facts.imports.push(ImportFact {
                            module: import.module.to_string(),
                            name: import.name.to_string(),
                            kind: import_kind(import.ty),
                        }),
                        Imports::Compact1 { module, items } => {
                            for item in items {
                                let item =
                                    item.map_err(|error| WasmError::Parse(error.to_string()))?;
                                facts.imports.push(ImportFact {
                                    module: module.to_string(),
                                    name: item.name.to_string(),
                                    kind: import_kind(item.ty),
                                });
                            }
                        }
                        Imports::Compact2 { module, ty, names } => {
                            for name in names {
                                let name =
                                    name.map_err(|error| WasmError::Parse(error.to_string()))?;
                                facts.imports.push(ImportFact {
                                    module: module.to_string(),
                                    name: name.to_string(),
                                    kind: import_kind(ty),
                                });
                            }
                        }
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|error| WasmError::Parse(error.to_string()))?;
                    facts.exports.push(export.name.to_string());
                }
            }
            _ => {}
        }
    }

    Ok(facts)
}

/// Validate that a module is structurally valid WebAssembly.
pub fn validate_module(bytes: &[u8]) -> Result<(), WasmError> {
    Validator::new()
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|error| WasmError::Invalid(error.to_string()))
}
