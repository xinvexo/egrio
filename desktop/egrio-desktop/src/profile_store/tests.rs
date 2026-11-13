use super::*;

const SOURCE: &str =
    "# original\nmixed-port: 7890\nipv6: true\nmode: direct\nrules: ['MATCH,DIRECT']\n";

struct Fixture {
    path: PathBuf,
    store: ProfileStore,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("egrio-profile-store-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        let store = ProfileStore::open_at(&path).unwrap();
        Self { path, store }
    }
    fn profile(&self) -> SavedProfileSummary {
        self.store
            .create_profile("Profile".into(), SOURCE.into())
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
#[test]
fn network_switches_write_the_source_and_name_its_revision() {
    let fixture = Fixture::new();
    let saved = fixture.profile();
    let preview = fixture
        .store
        .preview_profile_setting(&saved.id, &saved.source_revision, "ipv6", "false")
        .unwrap();
    assert!(!preview.network.ipv6);
    assert_eq!(
        fixture.store.get_profile_source(&saved.id).unwrap().yaml,
        SOURCE
    );
    fixture
        .store
        .set_profile_setting(&saved.id, &saved.source_revision, "ipv6", "false")
        .unwrap();
    let written = fixture.store.get_profile_source(&saved.id).unwrap();
    assert_eq!(written.yaml, SOURCE.replace("ipv6: true", "ipv6: false"));
    assert!(
        !fixture
            .store
            .profile_configuration_snapshot(&saved.id)
            .unwrap()
            .network
            .ipv6
    );
    assert!(matches!(
        fixture
            .store
            .set_profile_setting(&saved.id, &saved.source_revision, "allow-lan", "true"),
        Err(ProfileStoreError::RevisionConflict)
    ));
    fixture
        .store
        .set_profile_setting(&saved.id, &written.source_revision, "allow-lan", "true")
        .unwrap();
    assert_eq!(
        fixture.store.get_profile_source(&saved.id).unwrap().yaml,
        "# original\nallow-lan: true\nmixed-port: 7890\nipv6: false\nmode: direct\nrules: ['MATCH,DIRECT']\n"
    );
}

#[test]
fn manual_save_rejects_stale_or_invalid_source_without_changing_metadata() {
    let fixture = Fixture::new();
    let saved = fixture.profile();
    let before = fs::read(fixture.store.manifest_path()).unwrap();
    assert!(matches!(
        fixture
            .store
            .save_profile_source(&saved.id, SOURCE.into(), "stale-source-hash"),
        Err(ProfileStoreError::RevisionConflict)
    ));
    assert_eq!(fs::read(fixture.store.manifest_path()).unwrap(), before);
    assert!(fixture
        .store
        .save_profile_source(&saved.id, "mixed-port: 0\n".into(), &saved.source_revision)
        .is_err());
    assert_eq!(fs::read(fixture.store.manifest_path()).unwrap(), before);
    assert_eq!(
        fixture.store.get_profile_source(&saved.id).unwrap().yaml,
        SOURCE
    );
}

#[test]
fn a_picked_mode_belongs_to_its_profile_until_the_file_writes_another() {
    let fixture = Fixture::new();
    let a = fixture.profile();
    fixture
        .store
        .set_profile_traffic_policy(&a.id, TrafficPolicyMode::Global, None)
        .unwrap();
    let b = fixture
        .store
        .create_profile("B".into(), "mixed-port: 9876\nmode: direct\n".into())
        .unwrap();
    fixture.store.set_active_profile(&b.id).unwrap();
    let mode = || {
        fixture
            .store
            .active_configuration_snapshot()
            .unwrap()
            .unwrap()
            .profile
            .traffic_policy_mode
    };
    assert_eq!(mode(), TrafficPolicyMode::Direct);
    fixture.store.set_active_profile(&a.id).unwrap();
    assert_eq!(mode(), TrafficPolicyMode::Global);
    // Saving the file with the same mode keeps the pick ...
    let saved = fixture
        .store
        .save_profile_source(&a.id, SOURCE.replace("7890", "7891"), &a.source_revision)
        .unwrap();
    assert_eq!(mode(), TrafficPolicyMode::Global);
    // ... and writing another mode replaces it.
    let source = fixture.store.get_profile_source(&a.id).unwrap().yaml;
    fixture
        .store
        .save_profile_source(
            &a.id,
            source.replace("mode: direct", "mode: rule"),
            &saved.source_revision,
        )
        .unwrap();
    assert_eq!(mode(), TrafficPolicyMode::Rule);
}

/// A document from elsewhere does not open the proxy to the network; one
/// written here, or the switch in the settings, does.
#[test]
fn an_imported_document_keeps_the_listener_local() {
    let fixture = Fixture::new();
    // The head of the template most subscription converters start from.
    let converted = "port: 7890\nsocks-port: 7891\nallow-lan: true  # shared\nmode: Rule\nproxies: ~\nrules: ['MATCH,DIRECT']\n";
    let listens = |id: &str| {
        fixture.store.set_active_profile(id).unwrap();
        let snapshot = fixture.store.active_settings_snapshot().unwrap().unwrap();
        (
            snapshot.network.allow_lan,
            snapshot.network.listen_addr().unwrap(),
        )
    };

    let imported = fixture
        .store
        .import_profile("Imported".into(), converted.into())
        .unwrap();
    assert_eq!(
        fixture.store.get_profile_source(&imported.id).unwrap().yaml,
        converted.replace("allow-lan: true", "allow-lan: false"),
        "only that key changes, and its comment stays"
    );
    assert_eq!(
        listens(&imported.id),
        (false, "127.0.0.1:7890".parse().unwrap())
    );

    // What it says otherwise is kept as it came.
    let local = fixture
        .store
        .import_profile("Local".into(), SOURCE.into())
        .unwrap();
    assert_eq!(
        fixture.store.get_profile_source(&local.id).unwrap().yaml,
        SOURCE
    );

    // The user's own switch and the user's own document open it.
    fixture
        .store
        .set_profile_setting(
            &imported.id,
            &fixture
                .store
                .get_profile_source(&imported.id)
                .unwrap()
                .source_revision,
            "allow-lan",
            "true",
        )
        .unwrap();
    assert_eq!(
        listens(&imported.id),
        (true, "0.0.0.0:7890".parse().unwrap())
    );
    let authored = fixture
        .store
        .create_profile("Authored".into(), converted.into())
        .unwrap();
    assert!(listens(&authored.id).0);

    // A document the key cannot be rewritten in is refused, not kept open.
    let error = fixture
        .store
        .import_profile("Flow".into(), "{allow-lan: true, mixed-port: 7890}".into())
        .unwrap_err();
    assert!(error.to_string().contains("allow-lan"), "{error}");
}

#[test]
fn shared_source_is_collected_only_after_the_last_profile_releases_it() {
    let fixture = Fixture::new();
    let a = fixture
        .store
        .create_profile("A".into(), SOURCE.into())
        .unwrap();
    let b = fixture
        .store
        .create_profile("B".into(), SOURCE.into())
        .unwrap();
    let path = fixture.store.source_path(&a.source_revision);
    let owned = fixture.store.profile_configuration_snapshot(&a.id).unwrap();
    fixture.store.delete_profile(&a.id).unwrap();
    assert!(path.is_file());
    fixture.store.delete_profile(&b.id).unwrap();
    assert!(!path.exists());
    assert_eq!(owned.profile.traffic_policy_mode, TrafficPolicyMode::Direct);
}

#[test]
fn provider_cache_is_bound_to_its_source_descriptor() {
    let fixture = Fixture::new();
    let source="rule-providers:\n  Block:\n    type: http\n    behavior: domain\n    url: https://example.com/first\nrules: ['RULE-SET,Block,REJECT','MATCH,DIRECT']\n";
    let local = fixture
        .store
        .create_profile("Rules".into(), source.into())
        .unwrap();
    let target = fixture
        .store
        .rule_provider_fetch_target(&local.id, "Block")
        .unwrap();
    fixture
        .store
        .save_rule_provider_content(&local.id, &target, "payload: [example.org]\n", 1)
        .unwrap();
    assert_eq!(
        fixture
            .store
            .active_configuration_snapshot()
            .unwrap()
            .unwrap()
            .profile
            .rule_sets
            .len(),
        1
    );
    let changed = source.replace("/first", "/second");
    fixture
        .store
        .save_profile_source(&local.id, changed, &local.source_revision)
        .unwrap();
    assert!(fixture.store.active_configuration_snapshot().is_err());
    assert_eq!(
        fixture
            .store
            .missing_rule_provider_fetch_targets(&local.id)
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        fixture
            .store
            .save_rule_provider_content(&local.id, &target, "payload: [old]\n", 1),
        Err(ProfileStoreError::StaleRefresh)
    ));
}

#[test]
fn unchanged_provider_content_updates_fetch_metadata_without_changing_effective_revision() {
    let fixture = Fixture::new();
    let source = "rule-providers: {Block: {type: http, behavior: domain, url: 'https://example.com/rules'}}\nrules: ['RULE-SET,Block,REJECT','MATCH,DIRECT']\n";
    let profile = fixture
        .store
        .create_profile("Rules".into(), source.into())
        .unwrap();
    let target = fixture
        .store
        .rule_provider_fetch_target(&profile.id, "Block")
        .unwrap();
    assert!(fixture
        .store
        .save_rule_provider_content(&profile.id, &target, "payload: [first.example]\n", 1)
        .unwrap());
    let revision = || {
        fixture
            .store
            .profile_summary_by_id(&profile.id)
            .unwrap()
            .revision
    };
    let before = revision();
    fixture
        .store
        .write(|doc| {
            let record = ProfileStore::record_mut(doc, &profile.id)?;
            record.provider_cache[0].fetched_at_unix = 1;
            Ok(())
        })
        .unwrap();
    assert!(!fixture
        .store
        .save_rule_provider_content(&profile.id, &target, "payload: [first.example]\n", 1)
        .unwrap());
    assert_eq!(revision(), before);
    assert!(
        fixture
            .store
            .rule_provider_fetch_target(&profile.id, "Block")
            .unwrap()
            .fetched_at_unix
            .unwrap()
            > 1
    );
    assert!(fixture
        .store
        .save_rule_provider_content(&profile.id, &target, "payload: [second.example]\n", 1)
        .unwrap());
    assert_ne!(revision(), before);
    assert_eq!(
        fixture
            .store
            .active_configuration_snapshot()
            .unwrap()
            .unwrap()
            .profile
            .rule_sets[0]
            .entries
            .iter()
            .collect::<Vec<_>>(),
        ["second.example"]
    );
}

#[test]
fn runtime_requires_only_referenced_providers_and_reuses_matching_content() {
    let fixture = Fixture::new();
    let source = "rule-providers:\n  Used:\n    type: http\n    behavior: domain\n    url: https://example.com/used\n  Unused:\n    type: file\n    behavior: unsupported\nrules: ['RULE-SET,Used,REJECT','MATCH,DIRECT']\n";
    let saved = fixture
        .store
        .create_profile("Dependencies".into(), source.into())
        .unwrap();
    let missing = fixture
        .store
        .missing_rule_provider_fetch_targets(&saved.id)
        .unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].name, "Used");
    assert!(fixture.store.active_configuration_snapshot().is_err());
    assert!(fixture.store.active_settings_snapshot().unwrap().is_some());
    fixture
        .store
        .save_rule_provider_content(&saved.id, &missing[0], "payload: [example.org]\n", 1)
        .unwrap();
    assert!(fixture
        .store
        .missing_rule_provider_fetch_targets(&saved.id)
        .unwrap()
        .is_empty());
    let runtime = fixture
        .store
        .active_configuration_snapshot()
        .unwrap()
        .unwrap();
    assert_eq!(runtime.profile.rule_sets.len(), 1);
    assert_eq!(runtime.profile.rule_sets[0].name, "Used");
    let record = ProfileStore::record(&fixture.store.load().unwrap(), &saved.id)
        .unwrap()
        .clone();
    let cache = &record.provider_cache[0];
    fs::remove_file(
        fixture
            .store
            .provider_path(&cache.descriptor_hash, &cache.content_hash),
    )
    .unwrap();
    assert_eq!(
        fixture
            .store
            .missing_rule_provider_fetch_targets(&saved.id)
            .unwrap()
            .len(),
        1
    );
    assert!(fixture.store.active_configuration_snapshot().is_err());
}

#[test]
fn rule_edits_determine_the_provider_dependencies() {
    let fixture = Fixture::new();
    let source = "rule-providers:\n  Optional:\n    type: http\n    behavior: domain\n    url: https://example.com/optional\nrules: ['MATCH,DIRECT']\n";
    let saved = fixture
        .store
        .create_profile("Rules".into(), source.into())
        .unwrap();
    assert!(fixture
        .store
        .missing_rule_provider_fetch_targets(&saved.id)
        .unwrap()
        .is_empty());
    assert!(fixture.store.active_configuration_snapshot().is_ok());
    fixture
        .store
        .add_profile_rule(
            &saved.id,
            "RULE-SET,Optional,REJECT",
            &saved.source_revision,
        )
        .unwrap();
    assert_eq!(
        fixture
            .store
            .missing_rule_provider_fetch_targets(&saved.id)
            .unwrap()
            .len(),
        1
    );
    let rules = fixture.store.profile_rules(&saved.id).unwrap();
    assert_eq!(rules.kind(0).as_deref(), Some("RULE-SET"));
    fixture
        .store
        .delete_profile_rules(
            &saved.id,
            &[ProfileRuleList::rule_id(0)],
            &rules.source_revision,
        )
        .unwrap();
    assert!(fixture
        .store
        .missing_rule_provider_fetch_targets(&saved.id)
        .unwrap()
        .is_empty());
    assert!(fixture
        .store
        .active_configuration_snapshot()
        .unwrap()
        .unwrap()
        .profile
        .rule_sets
        .is_empty());
}

#[test]
fn a_rule_the_app_writes_names_only_what_the_profile_declares() {
    let fixture = Fixture::new();
    let saved = fixture.profile();
    let before = fs::read(fixture.store.manifest_path()).unwrap();
    for line in ["DOMAIN,example.org,Missing", "RULE-SET,Missing,DIRECT"] {
        assert!(fixture
            .store
            .add_profile_rule(&saved.id, line, &saved.source_revision)
            .is_err());
    }
    // An alias shares the list with another key; editing it is refused.
    let aliased = fixture
        .store
        .create_profile(
            "Aliased".into(),
            "rules: &shared\n  - MATCH,DIRECT\ncopy: *shared\n".into(),
        )
        .unwrap();
    let before_aliased = fs::read(fixture.store.manifest_path()).unwrap();
    assert!(fixture
        .store
        .delete_profile_rules(&aliased.id, &["rule-0".into()], &aliased.source_revision)
        .is_err());
    assert_eq!(
        fs::read(fixture.store.manifest_path()).unwrap(),
        before_aliased
    );
    assert_ne!(before, before_aliased);
}

#[test]
fn an_undeclared_or_unsupported_required_provider_cannot_silently_fall_through() {
    let fixture = Fixture::new();
    for source in [
        "rules: ['RULE-SET,Missing,DIRECT']",
        "rule-providers: {Missing: {type: http, behavior: unsupported, url: 'https://example.com/rules'}}\nrules: ['RULE-SET,Missing,DIRECT']",
    ] {
        let saved = fixture.store.create_profile("Invalid dependency".into(), source.into()).unwrap();
        fixture.store.set_active_profile(&saved.id).unwrap();
        assert!(fixture.store.profile_configuration_snapshot(&saved.id).is_ok());
        assert!(fixture.store.missing_rule_provider_fetch_targets(&saved.id).is_err());
        assert!(fixture.store.active_configuration_snapshot().is_err());
    }
}

#[test]
fn profile_deletion_preserves_host_preferences() {
    let fixture = Fixture::new();
    let profile = fixture.profile();
    fixture.store.set_app_setting("ui_theme", "dark").unwrap();
    fixture.store.set_app_setting("log_level", "debug").unwrap();
    fixture.store.delete_profile(&profile.id).unwrap();
    assert_eq!(
        fixture.store.app_setting("ui_theme").unwrap().as_deref(),
        Some("dark")
    );
    assert_eq!(
        fixture.store.app_setting("log_level").unwrap().as_deref(),
        Some("debug")
    );
}

#[test]
fn only_source_changes_move_the_update_time() {
    let fixture = Fixture::new();
    let saved = fixture.profile();
    // Backdated, so a move shows within the same second.
    fixture
        .store
        .write(|document| {
            ProfileStore::record_mut(document, &saved.id)?.updated_at_unix = 0;
            Ok(())
        })
        .unwrap();
    let updated = || fixture.store.list_profiles().unwrap()[0].updated_at_unix;
    fixture.store.rename_profile(&saved.id, "Renamed").unwrap();
    fixture
        .store
        .set_profile_traffic_policy(&saved.id, TrafficPolicyMode::Rule, None)
        .unwrap();
    assert_eq!(updated(), 0);
    fixture
        .store
        .set_profile_setting(&saved.id, &saved.source_revision, "ipv6", "false")
        .unwrap();
    assert!(updated() > 0);
}

#[test]
fn transaction_error_after_preparing_source_does_not_publish_its_pointer() {
    let fixture = Fixture::new();
    let saved = fixture.profile();
    let before = fs::read(fixture.store.manifest_path()).unwrap();
    let raw = SOURCE.replace("7890", "9876");
    let result: Result<(), ProfileStoreError> = fixture.store.write(|document| {
        let record = ProfileStore::record_mut(document, &saved.id)?;
        record.source_content_hash = fixture.store.put_source(&raw)?;
        Err(ProfileStoreError::Configuration(
            "injected pre-commit failure".into(),
        ))
    });
    assert!(result.is_err());
    assert_eq!(fs::read(fixture.store.manifest_path()).unwrap(), before);
    assert_eq!(
        fixture.store.get_profile_source(&saved.id).unwrap().yaml,
        SOURCE
    );
}

#[test]
fn editing_a_rule_rewrites_its_line_in_place() {
    let fixture = Fixture::new();
    let source = "rules: ['DOMAIN,example.org,DIRECT', 'MATCH,DIRECT']\n";
    let profile = fixture
        .store
        .create_profile("Rules".into(), source.into())
        .unwrap();
    let listed = fixture.store.profile_rules(&profile.id).unwrap();
    fixture
        .store
        .update_profile_rule(
            &profile.id,
            &ProfileRuleList::rule_id(1),
            "MATCH,REJECT",
            &listed.source_revision,
        )
        .unwrap();
    assert_eq!(
        fixture.store.get_profile_source(&profile.id).unwrap().yaml,
        "rules:\n  - DOMAIN,example.org,DIRECT\n  - MATCH,REJECT\n"
    );
    // The ids were listed for the old source.
    assert!(matches!(
        fixture.store.delete_profile_rules(
            &profile.id,
            &[ProfileRuleList::rule_id(1)],
            &listed.source_revision
        ),
        Err(ProfileStoreError::RevisionConflict)
    ));
    let edited = fixture.store.profile_rules(&profile.id).unwrap();
    fixture
        .store
        .delete_profile_rules(
            &profile.id,
            &[ProfileRuleList::rule_id(1)],
            &edited.source_revision,
        )
        .unwrap();
    let after = fixture
        .store
        .profile_configuration_snapshot(&profile.id)
        .unwrap();
    assert_eq!(after.profile.rules.len(), 1);
    assert_eq!(
        after.profile.rules.get(0).map(|rule| rule.kind),
        Some(RuleKind::Domain)
    );
}

/// A rule of a type the Core does not know is listed by the type its source
/// writes, which is the type an edit of it writes back.
#[test]
fn a_rule_of_an_unknown_type_is_listed_by_the_type_it_is_written_with() {
    let fixture = Fixture::new();
    let source = "rules: ['IP-ASN,13335,DIRECT', 'in-port,7890,DIRECT', 'MATCH,DIRECT']\n";
    let profile = fixture
        .store
        .create_profile("Rules".into(), source.into())
        .unwrap();
    let listed = fixture.store.profile_rules(&profile.id).unwrap();
    let kinds: Vec<_> = (0..4).map(|place| listed.kind(place)).collect();
    assert_eq!(
        kinds,
        [
            Some("IP-ASN".to_string()),
            Some("IN-PORT".to_string()),
            Some("MATCH".to_string()),
            None
        ]
    );
    // The Core leaves both out, and the list says so.
    let mut unsupported: Vec<_> = listed.unsupported.keys().copied().collect();
    unsupported.sort_unstable();
    assert_eq!(unsupported, [0, 1]);
    // A rule's id names its place, and only a place the list has.
    assert_eq!(listed.place(&ProfileRuleList::rule_id(2)), Some(2));
    assert_eq!(listed.place(&ProfileRuleList::rule_id(3)), None);
    assert_eq!(listed.place("2"), None);
    // The dialog writes the type it was given, in capitals.
    let edited = listed.rules.get(0).unwrap();
    let line = crate::profile_source::rule_line(
        &listed.kind(0).unwrap(),
        edited.payload,
        "REJECT",
        edited.no_resolve,
    );
    fixture
        .store
        .update_profile_rule(
            &profile.id,
            &ProfileRuleList::rule_id(0),
            &line,
            &listed.source_revision,
        )
        .unwrap();
    assert_eq!(
        fixture.store.get_profile_source(&profile.id).unwrap().yaml,
        "rules:\n  - IP-ASN,13335,REJECT\n  - in-port,7890,DIRECT\n  - MATCH,DIRECT\n"
    );
}

#[test]
fn reordering_moves_lines_and_a_new_rule_starts_at_the_front() {
    let fixture = Fixture::new();
    let profile = fixture
        .store
        .create_profile(
            "Rules".into(),
            "rules:\n  # mine\n  - DOMAIN,source.example,DIRECT\n  - MATCH,DIRECT\n".into(),
        )
        .unwrap();
    fixture
        .store
        .add_profile_rule(
            &profile.id,
            "DOMAIN,first.example,REJECT",
            &profile.source_revision,
        )
        .unwrap();
    let listed = fixture.store.profile_rules(&profile.id).unwrap();
    let payloads = |list: &ProfileRuleList| {
        list.rules
            .iter()
            .map(|rule| rule.payload.unwrap_or_default().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(payloads(&listed), ["first.example", "source.example", ""]);
    let ordered = [1, 0, 2].map(ProfileRuleList::rule_id);
    fixture
        .store
        .reorder_profile_rules(&profile.id, &ordered, &listed.source_revision)
        .unwrap();
    assert_eq!(
        fixture.store.get_profile_source(&profile.id).unwrap().yaml,
        "rules:\n  # mine\n  - DOMAIN,source.example,DIRECT\n  - DOMAIN,first.example,REJECT\n  - MATCH,DIRECT\n"
    );
    let after = fixture.store.profile_rules(&profile.id).unwrap();
    fixture
        .store
        .add_profile_rule(
            &profile.id,
            "DOMAIN,second.example,REJECT",
            &after.source_revision,
        )
        .unwrap();
    assert_eq!(
        payloads(&fixture.store.profile_rules(&profile.id).unwrap()),
        ["second.example", "source.example", "first.example", ""]
    );
}

#[test]
fn directory_sync_failure_reports_published_content_instead_of_a_rejected_write() {
    let fixture = Fixture::new();
    let path = fixture.path.join("published.json");
    fs::write(&path, "old").unwrap();
    let result = write_text_file_with_directory_sync(&path, "new", |_, _| {
        Err(std::io::Error::other("injected directory sync failure"))
    });
    match result {
        Err(ProfileStoreError::PublishedButNotSynced {
            path: published,
            source,
        }) => {
            assert_eq!(published, path.display().to_string());
            assert!(source.to_string().contains("directory sync"));
        }
        other => panic!("wrong publication result: {other:?}"),
    }
    assert_eq!(fs::read_to_string(&path).unwrap(), "new");
}

#[test]
fn publication_failure_is_an_io_error_and_never_reaches_directory_sync() {
    let fixture = Fixture::new();
    let path = fixture.path.join("blocked.json");
    fs::create_dir(&path).unwrap();
    let result = write_text_file_with_directory_sync(&path, "new", |_, _| {
        panic!("failed rename cannot synchronize a published file")
    });
    assert!(matches!(result, Err(ProfileStoreError::Io(_))));
    assert!(path.is_dir());
    assert_eq!(fs::read_dir(&fixture.path).unwrap().count(), 1);
}

#[test]
fn reads_and_node_choices_compose_from_one_parse_of_the_source() {
    let fixture = Fixture::new();
    let source = "proxies:\n  - { name: a, type: socks5, server: 192.0.2.1, port: 1080 }\n  - { name: b, type: socks5, server: 192.0.2.2, port: 1080 }\nproxy-groups:\n  - { name: Proxy, type: select, proxies: [a, b] }\nrules: ['DOMAIN,a.test,Proxy', 'DOMAIN,b.test,DIRECT', 'MATCH,DIRECT']\n";
    let profile = fixture
        .store
        .create_profile("Parsed".into(), source.into())
        .unwrap();
    let parses = || {
        fixture
            .store
            .parsed
            .parses
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    assert_eq!(parses(), 1);

    let inventory = fixture.store.profile_inventory(&profile.id).unwrap();
    let group = &inventory.groups[0];
    for member in ["a", "b", "a"] {
        fixture
            .store
            .set_group_selection(&profile.id, &group.id, member)
            .unwrap();
    }
    assert!(fixture
        .store
        .set_group_selection(&profile.id, &group.id, "DIRECT")
        .is_err());
    // A choice leaves the source, and the rule ids listed for it, as they were.
    let rules = fixture.store.profile_rules(&profile.id).unwrap();
    assert_eq!(rules.source_revision, profile.source_revision);
    let summary = fixture.store.list_profiles().unwrap().remove(0);
    let effective = fixture
        .store
        .active_configuration_snapshot()
        .unwrap()
        .unwrap();
    assert_eq!(parses(), 1, "every read composed from the first parse");

    assert_eq!(effective.profile.groups[0].selected.as_deref(), Some("a"));
    assert_eq!(summary.rules, effective.profile.rules.len());
    assert_eq!((summary.proxies, summary.groups, summary.rules), (2, 1, 3));
}

/// With more profiles than parsed sources are kept, a listing parses none of
/// them again, and the profile in use is read without a parse after it.
#[test]
fn a_listing_of_many_profiles_parses_none_again() {
    let fixture = Fixture::new();
    let source = |index: usize| {
        format!(
            "proxies:\n  - {{ name: n{index}, type: socks5, server: 192.0.2.1, port: 1080 }}\nrules: ['MATCH,DIRECT']\n"
        )
    };
    let profiles: Vec<_> = (0..6)
        .map(|index| {
            fixture
                .store
                .create_profile(format!("P{index}"), source(index))
                .unwrap()
        })
        .collect();
    // A store opened by another command shares the parsed sources; a new
    // process has none.
    let cold = ProfileStore::open_at(&fixture.path).unwrap();
    let parses = |store: &ProfileStore| {
        store
            .parsed
            .parses
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let active = cold.active_profile().unwrap().unwrap();
    assert_eq!(active.id, profiles[0].id);
    assert_eq!(parses(&cold), 1);
    for _ in 0..3 {
        let listed = cold.list_profiles().unwrap();
        assert_eq!(listed.len(), 6);
        assert!(listed
            .iter()
            .all(|profile| profile.proxies == 1 && profile.rules == 1));
        assert_eq!(parses(&cold), 6, "each of the other five once");
        // The profile in use is still parsed: its nodes are read from it.
        assert_eq!(cold.profile_inventory(&active.id).unwrap().proxies.len(), 1);
        assert_eq!(parses(&cold), 6);
    }
}
