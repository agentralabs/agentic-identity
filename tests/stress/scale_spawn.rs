//! Scale test: spawn tree with many descendants.
//!
//! Validates authority bounding and lineage across large spawn trees.

use agentic_identity::identity::IdentityAnchor;
use agentic_identity::spawn::{self, SpawnConstraints, SpawnLifetime, SpawnType};
use agentic_identity::trust::capability::Capability;

#[test]
fn stress_spawn_100_children() {
    let parent = IdentityAnchor::new(Some("scale-parent".to_string()));
    let authority = vec![Capability::new("*")];
    let ceiling = vec![Capability::new("*")];

    let mut children = Vec::new();
    for i in 0..100 {
        let (child, record, _receipt) = spawn::spawn_child(
            &parent,
            SpawnType::Worker,
            &format!("child-{i}"),
            authority.clone(),
            ceiling.clone(),
            SpawnLifetime::Indefinite,
            SpawnConstraints::default(),
            None,
            &[],
        )
        .unwrap();
        children.push((child, record));
    }

    assert_eq!(children.len(), 100);
    // All children should have unique IDs
    let ids: std::collections::HashSet<_> = children.iter().map(|(c, _)| c.id()).collect();
    assert_eq!(ids.len(), 100);
}

#[test]
fn stress_spawn_tree_depth_5() {
    let root = IdentityAnchor::new(Some("tree-root".to_string()));
    let authority = vec![Capability::new("*")];
    let ceiling = vec![Capability::new("*")];

    let mut current = root;
    let mut records = Vec::new();

    for depth in 0..5 {
        let constraints = SpawnConstraints {
            max_spawn_depth: Some(10),
            max_children: None,
            max_descendants: None,
            can_spawn: true,
            authority_decay: None,
        };

        let (child, record, _receipt) = spawn::spawn_child(
            &current,
            SpawnType::Delegate,
            &format!("depth-{depth}"),
            authority.clone(),
            ceiling.clone(),
            SpawnLifetime::Indefinite,
            constraints,
            None,
            &records,
        )
        .unwrap();
        records.push(record);
        current = child;
    }

    assert_eq!(records.len(), 5);

    // Verify lineage using get_ancestors
    let ancestors = spawn::get_ancestors(&current.id(), &records).unwrap();
    assert!(!ancestors.is_empty(), "Should have ancestors in lineage");
}

#[test]
fn stress_spawn_authority_narrowing() {
    let root = IdentityAnchor::new(Some("narrowing-root".to_string()));

    let all_caps = vec![
        Capability::new("calendar:*"),
        Capability::new("email:*"),
        Capability::new("deploy:*"),
    ];

    let (child1, rec1, _) = spawn::spawn_child(
        &root,
        SpawnType::Delegate,
        "child-with-2",
        vec![Capability::new("calendar:*"), Capability::new("email:*")],
        all_caps.clone(),
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        None,
        &[],
    )
    .unwrap();

    let (_child2, rec2, _) = spawn::spawn_child(
        &child1,
        SpawnType::Worker,
        "grandchild-with-1",
        vec![Capability::new("calendar:events:read")],
        vec![Capability::new("calendar:*"), Capability::new("email:*")],
        SpawnLifetime::Indefinite,
        SpawnConstraints::default(),
        None,
        std::slice::from_ref(&rec1),
    )
    .unwrap();

    assert_eq!(rec2.authority_granted.len(), 1);
    assert_eq!(rec2.authority_granted[0].uri, "calendar:events:read");
}

#[test]
fn stress_spawn_all_types() {
    let parent = IdentityAnchor::new(Some("all-types".to_string()));
    let authority = vec![Capability::new("*")];
    let ceiling = vec![Capability::new("*")];

    let types = vec![
        SpawnType::Worker,
        SpawnType::Delegate,
        SpawnType::Clone,
        SpawnType::Specialist,
        SpawnType::Custom("custom_type".into()),
    ];

    for spawn_type in types {
        let tag = spawn_type.as_tag().to_string();
        let (_child, record, _receipt) = spawn::spawn_child(
            &parent,
            spawn_type,
            &format!("child-{tag}"),
            authority.clone(),
            ceiling.clone(),
            SpawnLifetime::Indefinite,
            SpawnConstraints::default(),
            None,
            &[],
        )
        .unwrap();
        assert_eq!(record.spawn_type.as_tag(), tag);
    }
}
