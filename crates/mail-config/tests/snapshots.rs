use mail_config::{
    ActivationError, AuthzError, Reloader, Snapshot, SnapshotStore, ValidationError,
};
use mail_core::{Action, IdentityId};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VALID: &str = "generation: 1\nlisten: 127.0.0.1:8080\nallow_loopback_plaintext: true\nidentities:\n  - id: alice\n    mailbox: account-a\n    address: alice@example.test\n    isolation: dedicated\n";

const CREDENTIALS: &str = "generation: 1\nlisten: 127.0.0.1:8080\nallow_loopback_plaintext: true\nidentities:\n  - id: alice\n    mailbox: account-a\n    address: alice@example.test\n    isolation: dedicated\ncredentials:\n  - id: client-a\n    token:\n      secret: file:///run/secrets/client-a\n    expires_at: 4102444800\n    grants:\n      - identity: alice\n        actions: [mail:messages:list, mail:messages:read]\n";

/// Two identities in two different mailboxes, one credential that may act on
/// both of them for reading only.
const TWO_MAILBOXES: &str = "generation: 1\nlisten: 127.0.0.1:8080\nallow_loopback_plaintext: true\nidentities:\n  - id: alice\n    mailbox: account-a\n    address: alice@example.test\n    isolation: dedicated\n  - id: bob\n    mailbox: account-b\n    address: bob@example.test\n    isolation: dedicated\ncredentials:\n  - id: client-a\n    token:\n      secret: file:///run/secrets/client-a\n    grants:\n      - identity: alice\n        actions: [mail:messages:read]\n      - identity: bob\n        actions: [mail:messages:read]\n";

fn temp_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "corvi-mail-config-{}-{}",
        std::process::id(),
        unique
    ));
    fs::create_dir_all(&path).expect("temporary directory");
    path
}

fn write_secret(path: &Path, value: &str, mode: u32) {
    fs::write(path, value).expect("secret written");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("secret permissions");
}

/// The secret a credential in [`CREDENTIALS`] and [`TWO_MAILBOXES`] refers to.
const TOKEN: &str = "s3cret-token";

/// Build a store whose credential points at a real, protected secret file.
fn store_with_secret(yaml: &str) -> (SnapshotStore, PathBuf) {
    let directory = temp_dir();
    let secret_path = directory.join("client-a");
    write_secret(&secret_path, TOKEN, 0o600);
    let yaml = yaml.replace(
        "file:///run/secrets/client-a",
        &format!("file://{}", secret_path.display()),
    );
    let store = SnapshotStore::new(Snapshot::from_yaml(&yaml).unwrap()).unwrap();
    (store, secret_path)
}

#[test]
fn rejected_replacement_keeps_last_known_good_snapshot() {
    let store = SnapshotStore::new(Snapshot::from_yaml(VALID).unwrap()).unwrap();
    let invalid = Snapshot::from_yaml(&VALID.replace("127.0.0.1", "0.0.0.0")).unwrap();
    assert_eq!(
        store.activate(invalid),
        Err(ActivationError::Invalid(ValidationError::InsecureListener))
    );
    assert_eq!(store.active().generation(), 1);
}

#[test]
fn stale_generations_cannot_replace_current_snapshot() {
    let store = SnapshotStore::new(Snapshot::from_yaml(VALID).unwrap()).unwrap();
    assert_eq!(
        store.activate(Snapshot::from_yaml(VALID).unwrap()),
        Err(ActivationError::StaleGeneration)
    );
    assert_eq!(store.active().generation(), 1);
}

#[test]
fn a_zero_generation_is_refused() {
    let candidate = Snapshot::from_yaml(&VALID.replace("generation: 1", "generation: 0")).unwrap();
    assert_eq!(
        SnapshotStore::new(candidate).err(),
        Some(ActivationError::Invalid(ValidationError::ZeroGeneration))
    );
}

#[test]
fn unknown_fields_and_invalid_ids_are_rejected() {
    assert!(Snapshot::from_yaml(&(VALID.to_owned() + "password: plaintext\n")).is_err());
    let invalid = Snapshot::from_yaml(&VALID.replace("id: alice", "id: 'bad id' ")).unwrap();
    assert_eq!(
        SnapshotStore::new(invalid).err(),
        Some(ActivationError::Invalid(
            ValidationError::InvalidIdentityBinding
        ))
    );
}

#[test]
fn unknown_fields_nested_under_an_identity_are_rejected() {
    // A nested secret-looking field must not be silently ignored.
    let nested = VALID.replace(
        "    isolation: dedicated\n",
        "    isolation: dedicated\n    password: hunter2\n",
    );
    assert!(Snapshot::from_yaml(&nested).is_err());

    // A typo in an alias key is refused rather than silently dropped.
    let typo = VALID.replace(
        "    isolation: dedicated\n",
        "    isolation: dedicated\n    alises: [x@example.test]\n",
    );
    assert!(Snapshot::from_yaml(&typo).is_err());
}

#[test]
fn inline_secret_values_are_rejected() {
    let inline = CREDENTIALS.replace(
        "      secret: file:///run/secrets/client-a",
        "      secret: hunter2",
    );
    assert!(Snapshot::from_yaml(&inline).is_err());
}

#[test]
fn a_credential_selects_exactly_one_identity_grant() {
    let store = SnapshotStore::new(Snapshot::from_yaml(CREDENTIALS).unwrap()).unwrap();
    let active = store.active();
    let credential = active.credential("client-a").expect("credential present");
    assert!(
        credential
            .grants()
            .permits(&IdentityId::new("alice"), Action::Read)
    );
    assert!(
        !credential
            .grants()
            .permits(&IdentityId::new("alice"), Action::Send)
    );
    assert!(
        !credential
            .grants()
            .permits(&IdentityId::new("bob"), Action::Read)
    );
}

#[test]
fn expired_credentials_are_not_usable() {
    let expired = CREDENTIALS.replace("expires_at: 4102444800", "expires_at: 1");
    let store = SnapshotStore::new(Snapshot::from_yaml(&expired).unwrap()).unwrap();
    let active = store.active();
    let credential = active.credential("client-a").expect("credential present");
    assert!(credential.is_expired(2));
    assert!(!credential.is_expired(0));
    // The expiry is exclusive: a credential expires at the instant it reaches
    // its expiry second.
    assert!(credential.is_expired(1));
    assert!(!credential.is_expired(0));
    assert_eq!(
        store.authorize(
            "client-a",
            TOKEN,
            &IdentityId::new("alice"),
            Action::Read,
            2
        ),
        Err(AuthzError::Expired)
    );
}

#[test]
fn revoking_a_credential_by_generation_removes_it() {
    let store = SnapshotStore::new(Snapshot::from_yaml(CREDENTIALS).unwrap()).unwrap();
    let active = store.active();
    assert!(active.credential("client-a").is_some());
    let without = CREDENTIALS
        .replace(
            "credentials:\n  - id: client-a\n    token:\n      secret: file:///run/secrets/client-a\n    expires_at: 4102444800\n    grants:\n      - identity: alice\n        actions: [mail:messages:list, mail:messages:read]\n",
            "",
        )
        .replace("generation: 1", "generation: 2");
    store
        .activate(Snapshot::from_yaml(&without).unwrap())
        .unwrap();
    let active = store.active();
    assert!(active.credential("client-a").is_none());
    assert_eq!(
        store.authorize(
            "client-a",
            TOKEN,
            &IdentityId::new("alice"),
            Action::Read,
            0
        ),
        Err(AuthzError::UnknownCredential)
    );
}

#[test]
fn a_non_loopback_plaintext_listener_is_refused() {
    let candidate = Snapshot::from_yaml(&VALID.replace("127.0.0.1", "0.0.0.0")).unwrap();
    assert_eq!(
        SnapshotStore::new(candidate).err(),
        Some(ActivationError::Invalid(ValidationError::InsecureListener))
    );
}

#[test]
fn a_loopback_listener_without_explicit_plaintext_opt_in_is_refused() {
    let candidate = Snapshot::from_yaml(&VALID.replace(
        "allow_loopback_plaintext: true",
        "allow_loopback_plaintext: false",
    ))
    .unwrap();
    assert_eq!(
        SnapshotStore::new(candidate).err(),
        Some(ActivationError::Invalid(ValidationError::InsecureListener))
    );
}

#[test]
fn grants_do_not_union_across_identities_or_mailboxes() {
    let (store, _) = store_with_secret(TWO_MAILBOXES);
    let alice = IdentityId::new("alice");
    let bob = IdentityId::new("bob");
    assert!(
        store
            .authorize("client-a", TOKEN, &alice, Action::Read, 0)
            .is_ok()
    );
    assert!(
        store
            .authorize("client-a", TOKEN, &bob, Action::Read, 0)
            .is_ok()
    );
    // Reading one mailbox does not grant sending, and reading one identity
    // does not grant an action that only the other identity would carry.
    assert_eq!(
        store.authorize("client-a", TOKEN, &alice, Action::Send, 0),
        Err(AuthzError::NotGranted)
    );
    assert_eq!(
        store.authorize("client-a", TOKEN, &bob, Action::Send, 0),
        Err(AuthzError::NotGranted)
    );
    assert_eq!(
        store.authorize(
            "client-a",
            TOKEN,
            &IdentityId::new("carol"),
            Action::Read,
            0
        ),
        Err(AuthzError::UnknownIdentity)
    );
}

/// Authorization requires a credential that was actually authenticated.
#[test]
fn authorization_requires_a_valid_presented_secret() {
    let (store, _) = store_with_secret(CREDENTIALS);
    let alice = IdentityId::new("alice");

    assert!(
        store
            .authorize("client-a", TOKEN, &alice, Action::Read, 0)
            .is_ok()
    );
    assert_eq!(
        store.authorize("client-a", "wrong-token", &alice, Action::Read, 0),
        Err(AuthzError::InvalidCredential)
    );
}

/// A credential whose secret file cannot be read denies access.
#[test]
fn an_unreadable_secret_file_denies_access() {
    let directory = temp_dir();
    let yaml = CREDENTIALS.replace(
        "file:///run/secrets/client-a",
        &format!("file://{}", directory.join("absent").display()),
    );
    let store = SnapshotStore::new(Snapshot::from_yaml(&yaml).unwrap()).unwrap();
    assert_eq!(
        store.authorize(
            "client-a",
            TOKEN,
            &IdentityId::new("alice"),
            Action::Read,
            0
        ),
        Err(AuthzError::InvalidCredential)
    );
}

#[test]
fn a_world_readable_secret_file_is_refused() {
    let directory = temp_dir();
    let secret_path = directory.join("client-a");
    write_secret(&secret_path, "s3cret-token", 0o644);

    let yaml = CREDENTIALS.replace(
        "file:///run/secrets/client-a",
        &format!("file://{}", secret_path.display()),
    );
    let store = SnapshotStore::new(Snapshot::from_yaml(&yaml).unwrap()).unwrap();
    let active = store.active();
    let credential = active.credential("client-a").expect("credential present");
    assert!(credential.authenticate("s3cret-token").is_err());
}

/// Two identities claiming one address make ownership undefined.
#[test]
fn two_identities_claiming_one_address_are_refused() {
    let collision =
        TWO_MAILBOXES.replace("address: bob@example.test", "address: ALICE@example.test");
    assert_eq!(
        SnapshotStore::new(Snapshot::from_yaml(&collision).unwrap()).err(),
        Some(ActivationError::Invalid(ValidationError::DuplicateAddress))
    );

    // An alias of one identity that is the address of another is the same
    // ambiguity.
    let alias_collision = TWO_MAILBOXES.replace(
        "    address: alice@example.test\n",
        "    address: alice@example.test\n    aliases: [bob@example.test]\n",
    );
    assert_eq!(
        SnapshotStore::new(Snapshot::from_yaml(&alias_collision).unwrap()).err(),
        Some(ActivationError::Invalid(ValidationError::DuplicateAddress))
    );
}

/// A control character in an address or mailbox is an injection vector.
#[test]
fn control_characters_in_an_identity_are_refused() {
    let address = VALID.replace(
        "address: alice@example.test",
        "address: \"a@b.test\\r\\nX-Injected: yes\"",
    );
    assert_eq!(
        SnapshotStore::new(Snapshot::from_yaml(&address).unwrap()).err(),
        Some(ActivationError::Invalid(
            ValidationError::InvalidIdentityBinding
        ))
    );

    let mailbox = VALID.replace("mailbox: account-a", "mailbox: \"acct\\na\"");
    assert_eq!(
        SnapshotStore::new(Snapshot::from_yaml(&mailbox).unwrap()).err(),
        Some(ActivationError::Invalid(
            ValidationError::InvalidIdentityBinding
        ))
    );
}

#[test]
fn a_grant_for_an_undefined_identity_is_refused() {
    let candidate =
        Snapshot::from_yaml(&TWO_MAILBOXES.replace("identity: bob", "identity: carol")).unwrap();
    assert_eq!(
        SnapshotStore::new(candidate).err(),
        Some(ActivationError::Invalid(ValidationError::UnknownIdentity))
    );
}

#[test]
fn a_grant_naming_an_unknown_action_is_refused() {
    let candidate =
        Snapshot::from_yaml(&TWO_MAILBOXES.replace("mail:messages:read", "mail:everything"))
            .unwrap();
    assert_eq!(
        SnapshotStore::new(candidate).err(),
        Some(ActivationError::Invalid(ValidationError::UnknownAction))
    );
}

#[test]
fn reload_activates_a_newer_generation_and_keeps_the_old_one_on_failure() {
    let directory = temp_dir();
    let path = directory.join("snapshot.yaml");
    fs::write(&path, VALID).expect("snapshot written");

    let store = SnapshotStore::new(Snapshot::from_file(&path).unwrap()).unwrap();
    assert_eq!(store.active().generation(), 1);

    fs::write(&path, VALID.replace("generation: 1", "generation: 2")).expect("snapshot written");
    assert!(store.reload_from_path(&path).unwrap());
    assert_eq!(store.active().generation(), 2);

    fs::write(&path, "generation: 3\nlisten: 0.0.0.0:8080\n").expect("snapshot written");
    assert!(store.reload_from_path(&path).is_err());
    assert_eq!(store.active().generation(), 2);
}

/// An unchanged file is a no-op, not an error: both reload paths agree.
#[test]
fn a_reload_of_an_unchanged_file_activates_nothing() {
    let directory = temp_dir();
    let path = directory.join("snapshot.yaml");
    fs::write(&path, VALID).expect("snapshot written");
    let store = SnapshotStore::new(Snapshot::from_file(&path).unwrap()).unwrap();
    assert!(!store.reload_from_path(&path).unwrap());
    assert_eq!(store.active().generation(), 1);

    let reloader = Reloader::new(&path);
    assert!(!reloader.reload(&store).unwrap());
    assert_eq!(store.active().generation(), 1);
}

/// The reloader reads the file again on every call.
#[test]
fn the_reloader_picks_up_a_newer_generation() {
    let directory = temp_dir();
    let path = directory.join("snapshot.yaml");
    fs::write(&path, VALID).expect("snapshot written");
    let store = SnapshotStore::new(Snapshot::from_file(&path).unwrap()).unwrap();
    let reloader = Reloader::new(&path);

    fs::write(&path, VALID.replace("generation: 1", "generation: 2")).expect("snapshot written");
    assert!(reloader.reload(&store).unwrap());
    assert_eq!(store.active().generation(), 2);
}

#[test]
fn a_credential_is_authenticated_by_its_protected_secret_file() {
    let (store, _) = store_with_secret(CREDENTIALS);
    let active = store.active();
    let credential = active.credential("client-a").expect("credential present");
    assert!(credential.authenticate(TOKEN).unwrap());
    assert!(!credential.authenticate("wrong-token").unwrap());
}

/// Only one trailing newline is stripped from a secret file.
#[test]
fn a_secret_value_keeps_its_own_trailing_newline() {
    let directory = temp_dir();
    let secret_path = directory.join("client-a");
    write_secret(&secret_path, "value\n\n", 0o600);

    let yaml = CREDENTIALS.replace(
        "file:///run/secrets/client-a",
        &format!("file://{}", secret_path.display()),
    );
    let store = SnapshotStore::new(Snapshot::from_yaml(&yaml).unwrap()).unwrap();
    let active = store.active();
    let credential = active.credential("client-a").expect("credential present");
    assert!(credential.authenticate("value\n").unwrap());
    assert!(!credential.authenticate("value").unwrap());
}
