//! The reconciler: the tree a backend has realized, with an id per node, and
//! the patches that turn it into a new view's tree. Siblings match by key, or
//! by position when unkeyed; a node of another component is replaced, a node
//! of the same component keeps its native control and receives new
//! properties only when they changed.

use crate::node::{Attrs, Kind, Node};

pub type NodeId = u64;

/// A node the backend has realized, with its last properties and handlers.
#[derive(Debug, Clone)]
pub struct Mounted {
    pub id: NodeId,
    pub key: Option<String>,
    pub attrs: Attrs,
    pub kind: Kind,
    pub children: Vec<Mounted>,
}

/// One change for the backend, applied in order.
#[derive(Debug, Clone)]
pub enum Patch {
    /// The node keeps its control; these are its new properties.
    Update {
        id: NodeId,
        attrs: Attrs,
        kind: Kind,
    },
    /// Realize `node` and put it at `index` among `parent`'s children.
    Insert {
        parent: NodeId,
        index: usize,
        node: Mounted,
    },
    /// Remove the node and everything under it.
    Remove { parent: NodeId, id: NodeId },
    /// Move an existing child to `index` among `parent`'s children.
    Move {
        parent: NodeId,
        id: NodeId,
        index: usize,
    },
    /// Swap the node for a newly realized one of another component.
    Replace { old: NodeId, node: Mounted },
}

#[derive(Debug, Default)]
pub struct Ids(NodeId);

impl Ids {
    fn next(&mut self) -> NodeId {
        self.0 += 1;
        self.0
    }
}

/// Assigns ids to a new tree.
pub fn mount(node: &Node, ids: &mut Ids) -> Mounted {
    Mounted {
        id: ids.next(),
        key: node.key.clone(),
        attrs: node.attrs.clone(),
        kind: node.kind.clone(),
        children: node
            .children
            .iter()
            .map(|child| mount(child, ids))
            .collect(),
    }
}

/// Patches that turn `old` into `new`, updating `old` to match.
pub fn reconcile(old: &mut Mounted, new: &Node, ids: &mut Ids) -> Vec<Patch> {
    let mut patches = Vec::new();
    diff(old, new, ids, &mut patches);
    patches
}

fn diff(old: &mut Mounted, new: &Node, ids: &mut Ids, patches: &mut Vec<Patch>) {
    if !old.kind.same_component(&new.kind) {
        let node = mount(new, ids);
        patches.push(Patch::Replace {
            old: old.id,
            node: node.clone(),
        });
        *old = node;
        return;
    }
    if old.attrs != new.attrs || old.kind != new.kind {
        patches.push(Patch::Update {
            id: old.id,
            attrs: new.attrs.clone(),
            kind: new.kind.clone(),
        });
    }
    // Handlers never compare unequal: keep the newest ones for events.
    old.attrs = new.attrs.clone();
    old.kind = new.kind.clone();
    diff_children(old.id, &mut old.children, &new.children, ids, patches);
}

fn identity(key: &Option<String>, unkeyed_position: usize) -> Identity<'_> {
    match key {
        Some(key) => Identity::Key(key),
        None => Identity::Position(unkeyed_position),
    }
}

#[derive(PartialEq, Eq)]
enum Identity<'a> {
    Key(&'a str),
    Position(usize),
}

fn identities(keys: impl Iterator<Item = Option<String>>) -> Vec<(Option<String>, usize)> {
    let mut unkeyed = 0;
    keys.map(|key| {
        let position = unkeyed;
        if key.is_none() {
            unkeyed += 1;
        }
        (key, position)
    })
    .collect()
}

fn diff_children(
    parent: NodeId,
    old: &mut Vec<Mounted>,
    new: &[Node],
    ids: &mut Ids,
    patches: &mut Vec<Patch>,
) {
    let old_identities = identities(old.iter().map(|child| child.key.clone()));
    let new_identities = identities(new.iter().map(|child| child.key.clone()));

    // Which old child each new child keeps, if any.
    let mut taken = vec![false; old.len()];
    // A kept child of another component is replaced in place.
    let reused: Vec<Option<usize>> =
        new_identities
            .iter()
            .map(|(key, position)| {
                let wanted = identity(key, *position);
                let found = old_identities.iter().enumerate().position(
                    |(index, (old_key, old_position))| {
                        !taken[index] && identity(old_key, *old_position) == wanted
                    },
                );
                if let Some(index) = found {
                    taken[index] = true;
                }
                found
            })
            .collect();

    // Remove the old children nothing keeps, last first.
    for index in (0..old.len()).rev() {
        if !taken[index] {
            patches.push(Patch::Remove {
                parent,
                id: old[index].id,
            });
        }
    }
    let mut remaining: Vec<Option<Mounted>> = old
        .drain(..)
        .zip(taken)
        .map(|(child, kept)| kept.then_some(child))
        .collect();
    // The order the backend holds after the removals.
    let mut order: Vec<NodeId> = remaining.iter().flatten().map(|child| child.id).collect();

    let mut result = Vec::with_capacity(new.len());
    for (index, (child, kept)) in new.iter().zip(reused).enumerate() {
        match kept.and_then(|old_index| remaining[old_index].take()) {
            Some(mut existing) => {
                if order.get(index) != Some(&existing.id) {
                    patches.push(Patch::Move {
                        parent,
                        id: existing.id,
                        index,
                    });
                    order.retain(|id| *id != existing.id);
                    order.insert(index, existing.id);
                }
                diff(&mut existing, child, ids, patches);
                result.push(existing);
            }
            None => {
                let node = mount(child, ids);
                patches.push(Patch::Insert {
                    parent,
                    index,
                    node: node.clone(),
                });
                order.insert(index, node.id);
                result.push(node);
            }
        }
    }
    *old = result;
}

/// The realized node with `id`, searching depth first.
pub fn find(root: &Mounted, id: NodeId) -> Option<&Mounted> {
    if root.id == id {
        return Some(root);
    }
    root.children.iter().find_map(|child| find(child, id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{badge, column, row, text, TextStyle, Tone};

    fn label(key: &str, value: &str) -> Node {
        text(value, TextStyle::Body, Tone::Default).key(key)
    }

    /// Applies patches to a model of the backend: each node is (id, label).
    fn apply(model: &mut Vec<(NodeId, String)>, patches: &[Patch]) {
        for patch in patches {
            match patch {
                Patch::Remove { id, .. } => model.retain(|(existing, _)| existing != id),
                Patch::Insert { index, node, .. } => {
                    model.insert(*index, (node.id, describe(&node.kind)))
                }
                Patch::Move { id, index, .. } => {
                    let position = model
                        .iter()
                        .position(|(existing, _)| existing == id)
                        .unwrap();
                    let entry = model.remove(position);
                    model.insert(*index, entry);
                }
                Patch::Update { id, kind, .. } => {
                    let entry = model
                        .iter_mut()
                        .find(|(existing, _)| existing == id)
                        .unwrap();
                    entry.1 = describe(kind);
                }
                Patch::Replace { old, node } => {
                    let entry = model
                        .iter_mut()
                        .find(|(existing, _)| existing == old)
                        .unwrap();
                    *entry = (node.id, describe(&node.kind));
                }
            }
        }
    }

    fn describe(kind: &Kind) -> String {
        match kind {
            Kind::Text(text) => text.text.clone(),
            Kind::Badge(badge) => format!("badge:{}", badge.text),
            _ => "?".into(),
        }
    }

    fn model_of(mounted: &Mounted) -> Vec<(NodeId, String)> {
        mounted
            .children
            .iter()
            .map(|child| (child.id, describe(&child.kind)))
            .collect()
    }

    #[test]
    fn an_unchanged_tree_needs_no_patch() {
        let mut ids = Ids::default();
        let view = column(8.0, vec![label("a", "A"), label("b", "B")]);
        let mut mounted = mount(&view, &mut ids);
        assert!(reconcile(&mut mounted, &view, &mut ids).is_empty());
    }

    #[test]
    fn keyed_children_move_insert_and_leave_in_order() {
        let mut ids = Ids::default();
        let mut mounted = mount(
            &column(8.0, vec![label("a", "A"), label("b", "B"), label("c", "C")]),
            &mut ids,
        );
        let mut model = model_of(&mounted);
        let kept_c = mounted.children[2].id;
        let next = column(
            8.0,
            vec![label("c", "C"), label("d", "D"), label("a", "A2")],
        );
        let patches = reconcile(&mut mounted, &next, &mut ids);
        apply(&mut model, &patches);
        assert_eq!(
            model
                .iter()
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            ["C", "D", "A2"]
        );
        assert_eq!(model, model_of(&mounted));
        assert_eq!(
            mounted.children[0].id, kept_c,
            "a moved child keeps its control"
        );
    }

    #[test]
    fn another_component_at_the_same_place_is_replaced() {
        let mut ids = Ids::default();
        let mut mounted = mount(&row(4.0, vec![label("x", "X")]), &mut ids);
        let mut model = model_of(&mounted);
        let patches = reconcile(
            &mut mounted,
            &row(4.0, vec![badge("X", Tone::Accent).key("x")]),
            &mut ids,
        );
        assert!(matches!(patches.as_slice(), [Patch::Replace { .. }]));
        apply(&mut model, &patches);
        assert_eq!(model, vec![(mounted.children[0].id, "badge:X".into())]);
    }

    #[test]
    fn a_stack_that_turns_or_aligns_otherwise_is_replaced() {
        use crate::node::{caption, stack, Axis, CrossAlign};
        let mut ids = Ids::default();
        let mut old = mount(&column(8.0, vec![caption("a")]), &mut ids);
        let turned = stack(Axis::Horizontal, 8.0, CrossAlign::Fill, vec![caption("a")]);
        let patches = reconcile(&mut old, &turned, &mut ids);
        assert!(matches!(patches.as_slice(), [Patch::Replace { .. }]));
        let realigned = stack(
            Axis::Horizontal,
            8.0,
            CrossAlign::Center,
            vec![caption("a")],
        );
        let patches = reconcile(&mut old, &realigned, &mut ids);
        assert!(matches!(patches.as_slice(), [Patch::Replace { .. }]));
        // Only its spacing changing keeps it.
        let spaced = stack(
            Axis::Horizontal,
            12.0,
            CrossAlign::Center,
            vec![caption("a")],
        );
        let patches = reconcile(&mut old, &spaced, &mut ids);
        assert!(matches!(patches.as_slice(), [Patch::Update { .. }]));
    }

    #[test]
    fn unkeyed_children_match_by_position() {
        let mut ids = Ids::default();
        let plain = |value: &str| text(value, TextStyle::Body, Tone::Default);
        let mut mounted = mount(&column(8.0, vec![plain("A"), plain("B")]), &mut ids);
        let first = mounted.children[0].id;
        let patches = reconcile(
            &mut mounted,
            &column(8.0, vec![plain("A"), plain("B2"), plain("C")]),
            &mut ids,
        );
        assert_eq!(mounted.children[0].id, first);
        assert!(matches!(patches[0], Patch::Update { .. }));
        assert!(matches!(patches[1], Patch::Insert { index: 2, .. }));
    }
}
