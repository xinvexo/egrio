//! What a rule set matches a name by without holding the name: keywords,
//! regular expressions and names with wildcard labels.

use aho_corasick::AhoCorasick;
use regex::{RegexSet, RegexSetBuilder};

/// A rule set's keywords and expressions over a normalized name, any of
/// which matching is a match. Each kind is one automaton, so a name is run
/// through them once however many they are.
#[derive(Debug, Clone, Default)]
pub(super) struct Patterns {
    /// Texts found anywhere in a name.
    keywords: Option<AhoCorasick>,
    /// Regular expressions, in as few automata as build: one, unless it
    /// would pass the size the builder allows.
    expressions: Vec<RegexSet>,
}

/// Collects a rule set's patterns as its entries are read.
#[derive(Debug, Default)]
pub(super) struct PatternsBuilder {
    keywords: Vec<String>,
    expressions: Vec<String>,
    skipped: usize,
}

impl PatternsBuilder {
    /// A normalized text a name matches by holding it anywhere. An empty
    /// one says nothing and is left out.
    pub(super) fn keyword(&mut self, keyword: &str) {
        if keyword.is_empty() {
            self.skipped += 1;
        } else {
            self.keywords.push(keyword.to_owned());
        }
    }

    /// A regular expression, matching case-insensitively as names do.
    pub(super) fn expression(&mut self, expression: &str) {
        self.expressions.push(expression.to_owned());
    }

    /// A domain entry with `*` labels: `*` stands for exactly one whole
    /// label; a `*` mixed into a label is literal.
    pub(super) fn wildcard_name(&mut self, entry: &str) {
        let labels = entry
            .split('.')
            .map(|label| {
                if label == "*" {
                    "[^.]+".to_string()
                } else {
                    regex::escape(label)
                }
            })
            .collect::<Vec<_>>()
            .join("\\.");
        self.expressions.push(format!("^{labels}$"));
    }

    /// The patterns, and how many of those given were left out: empty
    /// keywords and expressions that do not compile.
    pub(super) fn build(mut self) -> (Patterns, usize) {
        let mut patterns = Patterns::default();
        if !self.keywords.is_empty() {
            match AhoCorasick::new(&self.keywords) {
                Ok(keywords) => patterns.keywords = Some(keywords),
                // More keywords than its automaton addresses: they are
                // expressions of their own text.
                Err(_) => self
                    .expressions
                    .extend(self.keywords.iter().map(|keyword| regex::escape(keyword))),
            }
        }
        let skipped = self.skipped + patterns.add_expressions(&self.expressions);
        (patterns, skipped)
    }
}

impl Patterns {
    /// One automaton for all of `expressions` where that builds. An
    /// expression that does not compile fails it, as does an automaton past
    /// the size the builder allows: each half is then built on its own, down
    /// to the expression that is left out. Returns how many were.
    fn add_expressions(&mut self, expressions: &[String]) -> usize {
        if expressions.is_empty() {
            return 0;
        }
        match RegexSetBuilder::new(expressions)
            .case_insensitive(true)
            .build()
        {
            Ok(set) => {
                self.expressions.push(set);
                0
            }
            Err(_) if expressions.len() == 1 => 1,
            Err(_) => {
                let (head, tail) = expressions.split_at(expressions.len() / 2);
                self.add_expressions(head) + self.add_expressions(tail)
            }
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.keywords.is_none() && self.expressions.is_empty()
    }

    pub(super) fn is_match(&self, name: &str) -> bool {
        self.keywords
            .as_ref()
            .is_some_and(|keywords| keywords.is_match(name))
            || self.expressions.iter().any(|set| set.is_match(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_pattern_matching_is_a_match() {
        let mut builder = PatternsBuilder::default();
        builder.keyword("a.b");
        builder.keyword("word");
        builder.wildcard_name("img.*.example");
        builder.expression(r"^cdn\d+\.example$");
        builder.expression("UPPER");
        let (patterns, skipped) = builder.build();
        assert_eq!(skipped, 0);
        assert_eq!(patterns.expressions.len(), 1);
        for name in [
            "xa.by.test",
            "keyword.test",
            "img.eu.example",
            "cdn42.example",
            "has-upper-inside.test",
        ] {
            assert!(patterns.is_match(name), "{name}");
        }
        // A keyword is its text, not an expression; a `*` is one label.
        for name in ["axb.test", "img.x.y.example", "img.example", "cdn.example"] {
            assert!(!patterns.is_match(name), "{name}");
        }
    }

    #[test]
    fn no_pattern_matches_nothing() {
        let (patterns, skipped) = PatternsBuilder::default().build();
        assert_eq!(skipped, 0);
        assert!(patterns.is_empty());
        assert!(!patterns.is_match("example.test"));

        // An empty keyword would be held by every name.
        let mut builder = PatternsBuilder::default();
        builder.keyword("");
        let (patterns, skipped) = builder.build();
        assert_eq!(skipped, 1);
        assert!(patterns.is_empty());
    }

    /// One expression that does not compile leaves the others matching.
    #[test]
    fn an_expression_that_does_not_compile_is_left_out_alone() {
        let mut builder = PatternsBuilder::default();
        for expression in ["^one$", "^two$", "([", "^three$", "^four$", "(?<", "^five$"] {
            builder.expression(expression);
        }
        let (patterns, skipped) = builder.build();
        assert_eq!(skipped, 2);
        for name in ["one", "two", "three", "four", "five"] {
            assert!(patterns.is_match(name), "{name}");
        }
        assert!(!patterns.is_match("six"));

        let mut builder = PatternsBuilder::default();
        builder.expression("([");
        let (patterns, skipped) = builder.build();
        assert_eq!(skipped, 1);
        assert!(patterns.is_empty());
    }
}
