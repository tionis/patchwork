use patchwork::{
    auth::{Action, Grant, Selector, permits, permits_delegation},
    model::{StreamId, StreamName},
};
fn grant(action: Action, selector: Selector) -> Grant {
    Grant {
        actions: vec![action],
        selector,
    }
}
#[test]
fn current_policy_and_issuance_ceiling_intersect_per_resource() {
    let id: StreamId = "str_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".parse().unwrap();
    let name: StreamName = "foo/bar".parse().unwrap();
    let read = grant(Action::RecordRead, Selector::Stream(id.as_str().into()));
    let broad = Grant {
        actions: Action::ALL.to_vec(),
        selector: Selector::Prefix(String::new()),
    };
    assert!(permits(
        std::slice::from_ref(&broad),
        std::slice::from_ref(&read),
        Action::RecordRead,
        Some(&id),
        &name
    ));
    assert!(!permits(
        std::slice::from_ref(&broad),
        std::slice::from_ref(&read),
        Action::RecordAppend,
        Some(&id),
        &name
    ));
    assert!(!permits(
        &[],
        std::slice::from_ref(&read),
        Action::RecordRead,
        Some(&id),
        &name
    ));
    assert!(!permits(
        &[read],
        &[broad],
        Action::StreamCreate,
        None,
        &name
    ));
}
#[test]
fn prefix_boundaries_and_delegation_are_universal() {
    let parent = grant(Action::RecordRead, Selector::Prefix("foo/".into()));
    for (name, allowed) in [
        ("foo/bar", true),
        ("foo/bar/baz", true),
        ("foobar/x", false),
        ("foo", false),
    ] {
        assert_eq!(
            permits(
                std::slice::from_ref(&parent),
                std::slice::from_ref(&parent),
                Action::RecordRead,
                None,
                &name.parse().unwrap()
            ),
            allowed
        );
    }
    let child = grant(Action::RecordRead, Selector::Prefix("foo/bar/".into()));
    assert!(permits_delegation(
        std::slice::from_ref(&parent),
        std::slice::from_ref(&parent),
        &[child]
    ));
    for prefix in ["", "foobar/", "foo"] {
        let child = grant(Action::RecordRead, Selector::Prefix(prefix.into()));
        assert!(!permits_delegation(
            std::slice::from_ref(&parent),
            std::slice::from_ref(&parent),
            &[child]
        ));
    }
    assert!(Selector::Prefix("foo//".into()).validate().is_err());
    assert!(Selector::Stream("not-an-id".into()).validate().is_err());
}
#[test]
fn exhaustive_single_action_matrix_matches_reference_intersection() {
    let name = "events/test".parse().unwrap();
    for current in Action::ALL {
        for issued in Action::ALL {
            for requested in Action::ALL {
                let a = grant(current, Selector::Prefix(String::new()));
                let b = grant(issued, Selector::Prefix("events/".into()));
                assert_eq!(
                    permits(&[a], &[b], requested, None, &name),
                    current == requested && issued == requested
                );
            }
        }
    }
}
