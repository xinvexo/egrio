//! The profiles page: the saved profiles, the active one first, each with
//! its counts and when its file last changed; choosing one applies it, its
//! name renames in place, its file opens in the editor, and deleting asks
//! first where the delete button was, without moving anything else. The add
//! dialog imports a profile from a link or a file, each a local copy that
//! never updates itself, or starts a blank one in the editor.

use egrio_desktop::models::SavedProfileSummary;

use crate::msg::{EditorMsg, Msg, ProfilesMsg};
use crate::node::{
    button, caption, card, column, editable_text, heading, icon_button, list_card, paragraph,
    placeholder, placeholder_with_action, radio, row, scroll, spacer, stack, text, text_field,
    Axis, ButtonKey, ButtonStyle, CrossAlign, Icon, Node, TextStyle, Tone,
};
use crate::state::{ProfileAction, Remote, State};

/// The add dialog's draft.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AddProfile {
    pub name: String,
    pub url: String,
    /// An import it started is running.
    pub pending: bool,
    /// Why its last import failed, which the dialog shows in place of its
    /// explanation until the next one.
    pub error: Option<String>,
}

/// The profiles in the page's order: the active one, then the most recently
/// changed.
fn ordered<'a>(
    profiles: &'a [SavedProfileSummary],
    active: Option<&str>,
) -> Vec<&'a SavedProfileSummary> {
    let mut ordered: Vec<&SavedProfileSummary> = profiles.iter().collect();
    ordered.sort_by(|a, b| {
        let a_active = Some(a.id.as_str()) == active;
        let b_active = Some(b.id.as_str()) == active;
        b_active
            .cmp(&a_active)
            .then_with(|| b.updated_at_unix.cmp(&a.updated_at_unix))
    });
    ordered
}

/// The name an import from `url` gets when the user gave none: its host.
pub fn name_from_url(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host.starts_with('[') {
        host.split_once(']').map(|(host, _)| &host[1..])?
    } else {
        host.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_string())
}

pub fn view(state: &State) -> Node {
    let text = state.text();
    let add = button(text.add_profile(), ButtonStyle::Plain)
        .icon(Icon::Add)
        .on_press(Msg::Profiles(ProfilesMsg::OpenAdd));
    let profiles = match &state.profiles {
        Remote::Ready(profiles) => profiles,
        Remote::Failed(_) => return card(vec![placeholder(text.fetch_failed(), None)]).grow(),
        Remote::Loading => return card(vec![placeholder(text.loading(), None)]).grow(),
    };
    if profiles.is_empty() {
        return card(vec![placeholder_with_action(
            text.profiles_empty(),
            text.add_profile(),
            Some(Icon::Add),
            Msg::Profiles(ProfilesMsg::OpenAdd),
        )
        .grow()])
        .grow();
    }
    let active = state
        .active_profile
        .ready()
        .and_then(Option::as_ref)
        .map(|profile| profile.id.as_str());
    let cards = ordered(profiles, active)
        .into_iter()
        .map(|profile| profile_card(state, profile, Some(profile.id.as_str()) == active))
        .collect();
    scroll(
        column(
            10.0,
            vec![
                row(
                    8.0,
                    vec![caption(text.profile_count(profiles.len())), spacer(), add],
                ),
                column(8.0, cards),
            ],
        )
        .key("profiles"),
    )
    .grow()
}

fn profile_card(state: &State, profile: &SavedProfileSummary, active: bool) -> Node {
    let text = state.text();
    let id = profile.id.clone();
    let action = state
        .profile_action
        .as_ref()
        .filter(|(target, _)| *target == profile.id)
        .map(|(_, action)| *action);
    // A configuration change that runs long makes the actions wait.
    let idle = state.profile_action.is_none() && !state.transition_slow();
    let confirming = state.confirm_delete.as_deref() == Some(profile.id.as_str());
    let editing = state
        .editor
        .as_ref()
        .and_then(|editor| editor.profile.as_deref())
        == Some(profile.id.as_str());

    let mut title = vec![
        editable_text(
            profile.name.clone(),
            TextStyle::Heading,
            action.is_none(),
            {
                let id = id.clone();
                move |name| Msg::Profiles(ProfilesMsg::Rename(id.clone(), name))
            },
        )
        .tooltip(Some(text.rename().into())),
        spacer(),
    ];
    if confirming {
        // The confirmation takes the delete button's place, so the card keeps
        // its shape.
        title.push(
            button(
                if active {
                    text.stop_and_delete()
                } else {
                    text.delete()
                },
                ButtonStyle::Destructive,
            )
            .busy(action == Some(ProfileAction::Delete))
            .on_press(Msg::Profiles(ProfilesMsg::Delete {
                id: id.clone(),
                stop_if_active: active,
            }))
            .tooltip(Some(
                if active {
                    text.confirm_stop_delete()
                } else {
                    text.confirm_delete()
                }
                .into(),
            )),
        );
        title.push(
            button(text.cancel(), ButtonStyle::Plain)
                .enabled(action.is_none())
                .on_press(Msg::Profiles(ProfilesMsg::CancelDelete)),
        );
    } else {
        title.push(
            icon_button(Icon::Edit)
                .enabled(action.is_none())
                .on_press(Msg::Editor(EditorMsg::Edit {
                    id: id.clone(),
                    name: profile.name.clone(),
                }))
                .tooltip(Some(text.edit_profile().into())),
        );
        if active {
            title.push(
                icon_button(Icon::Reapply)
                    .enabled(idle)
                    .busy(action == Some(ProfileAction::Reapply))
                    .on_press(Msg::Profiles(ProfilesMsg::Reapply(id.clone())))
                    .tooltip(Some(text.reapply().into())),
            );
        }
        title.push(
            icon_button(Icon::Delete)
                .enabled(action.is_none() && !editing)
                .on_press(Msg::Profiles(ProfilesMsg::AskDelete(id.clone())))
                .tooltip(Some(
                    if editing {
                        text.delete_while_editing()
                    } else {
                        text.delete()
                    }
                    .into(),
                )),
        );
    }
    let details = vec![
        row(8.0, title),
        row(
            16.0,
            vec![
                caption(text.profile_stats(profile.proxies, profile.groups, profile.rules)),
                spacer(),
                text_node(
                    text.updated_at(profile.updated_at_unix, crate::format::now_unix())
                        .unwrap_or_default(),
                ),
            ],
        ),
    ];
    list_card(
        active,
        vec![stack(
            Axis::Horizontal,
            12.0,
            CrossAlign::Start,
            vec![
                radio(active, idle, Msg::Profiles(ProfilesMsg::Apply(id.clone()))).tooltip(Some(
                    if active { text.in_use() } else { text.apply() }.into(),
                )),
                column(6.0, details).grow(),
            ],
        )],
    )
    .key(profile.id.clone())
}

fn text_node(value: String) -> Node {
    text(value, TextStyle::Caption, Tone::Faint)
}

/// The add dialog: an optional name, a link to download, or a file.
pub fn add_dialog(state: &State, draft: &AddProfile) -> Node {
    let text = state.text();
    let open = !draft.pending;
    column(
        14.0,
        vec![
            heading(text.add_profile()),
            text_field(draft.name.clone(), text.name_placeholder(), open, |name| {
                Msg::Profiles(ProfilesMsg::AddName(name))
            }),
            row(
                8.0,
                vec![
                    text_field(draft.url.clone(), text.url_placeholder(), open, |url| {
                        Msg::Profiles(ProfilesMsg::AddUrl(url))
                    })
                    .grow(),
                    button(text.download(), ButtonStyle::Primary)
                        .icon(Icon::Download)
                        .key(ButtonKey::Return)
                        .busy(draft.pending)
                        .enabled(!draft.url.trim().is_empty())
                        .on_press(Msg::Profiles(ProfilesMsg::Download)),
                ],
            ),
            row(
                8.0,
                vec![
                    button(text.import_file(), ButtonStyle::Secondary)
                        .enabled(open)
                        .on_press(Msg::Profiles(ProfilesMsg::ChooseFile)),
                    button(text.new_blank(), ButtonStyle::Secondary)
                        .enabled(open)
                        .on_press(Msg::Profiles(ProfilesMsg::NewBlank)),
                    spacer(),
                ],
            ),
            row(
                8.0,
                vec![
                    // A failure says why where the cancel button has room.
                    match &draft.error {
                        Some(error) => paragraph(error.clone(), Tone::Danger).grow(),
                        None => spacer(),
                    },
                    button(text.cancel(), ButtonStyle::Plain)
                        .key(ButtonKey::Escape)
                        .enabled(open)
                        .on_press(Msg::CloseDialog),
                ],
            ),
        ],
    )
    .width(460.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_import_without_a_name_is_named_after_its_host() {
        assert_eq!(
            name_from_url("https://example.com/clash.yaml").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            name_from_url("https://user:pw@sub.example.org:8443/a?b").as_deref(),
            Some("sub.example.org")
        );
        assert_eq!(
            name_from_url("http://[2001:db8::1]:80/x").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(name_from_url("https:///nothing"), None);
    }

    fn profile(id: &str, updated: i64) -> SavedProfileSummary {
        SavedProfileSummary {
            id: id.into(),
            name: id.into(),
            revision: String::new(),
            source_revision: String::new(),
            traffic_policy_mode: egrio_core::TrafficPolicyMode::Rule,
            global_outbound: None,
            proxies: 0,
            groups: 0,
            rules: 0,
            updated_at_unix: updated,
        }
    }

    #[test]
    fn a_failed_import_says_why_beside_the_cancel_button() {
        use crate::node::Kind;
        let state = State::new(crate::text::Lang::En);
        let mut draft = AddProfile::default();
        let rows = add_dialog(&state, &draft).children.len();
        draft.error = Some("Couldn't download the profile: 404".into());
        let tree = add_dialog(&state, &draft);
        assert_eq!(
            tree.children.len(),
            rows,
            "the failure takes no row of its own"
        );
        let last = tree.children.last().unwrap();
        assert!(matches!(
            &last.children[0].kind,
            Kind::Text(text) if text.tone == Tone::Danger && text.text.ends_with("404")
        ));
    }

    #[test]
    fn the_active_profile_leads_then_the_most_recently_changed() {
        let profiles = [profile("a", 1), profile("b", 3), profile("c", 2)];
        let ids: Vec<&str> = ordered(&profiles, Some("a"))
            .iter()
            .map(|profile| profile.id.as_str())
            .collect();
        assert_eq!(ids, ["a", "b", "c"]);
    }
}
