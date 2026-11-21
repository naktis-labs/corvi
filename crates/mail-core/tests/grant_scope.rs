use mail_core::{Action, IdentityGrant, IdentityId, ScopedGrants};

#[test]
fn grants_are_checked_per_identity_without_union() {
    let a = IdentityId::new("identity-a");
    let b = IdentityId::new("identity-b");
    let grants = ScopedGrants::new(vec![
        IdentityGrant::new(a.clone(), [Action::Read]),
        IdentityGrant::new(b.clone(), [Action::Send]),
    ]);
    assert!(grants.permits(&a, Action::Read));
    assert!(!grants.permits(&a, Action::Send));
    assert!(grants.permits(&b, Action::Send));
    assert!(!grants.permits(&b, Action::Read));
    assert!(!grants.permits(&IdentityId::new("other"), Action::Read));
}
