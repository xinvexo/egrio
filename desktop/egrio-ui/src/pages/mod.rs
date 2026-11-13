//! The pages of the main window, one module each.

pub mod activity;
pub mod connections;
pub mod logs;
pub mod nodes;
pub mod profiles;
pub mod rules;
pub mod settings;

use crate::node::Node;
use crate::state::{Section, State};

/// The content of the shown section.
pub fn view(state: &State) -> Node {
    match state.section {
        Section::Activity => activity::view(state),
        Section::Nodes => nodes::view(state),
        Section::Connections => connections::view(state),
        Section::Logs => logs::view(state),
        Section::Settings => settings::view(state),
        Section::Profiles => profiles::view(state),
        Section::Rules => rules::view(state),
    }
}
