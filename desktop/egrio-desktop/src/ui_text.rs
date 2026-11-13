//! The interface language the stored preference resolves to; the
//! interface's text is in `egrio-ui`'s `text` module.

use crate::desktop_behavior::{load_language_preference, LanguagePreference};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiLang {
    ZhCn,
    EnUs,
}

/// Resolves the stored preference; storage read failures fall back to the
/// default preference (`System`), never to an error — language must not be
/// able to break a session operation.
pub fn current_lang() -> UiLang {
    resolve(load_language_preference().unwrap_or_default())
}

pub fn resolve(pref: LanguagePreference) -> UiLang {
    match pref {
        LanguagePreference::ZhCn => UiLang::ZhCn,
        LanguagePreference::EnUs => UiLang::EnUs,
        LanguagePreference::System => system_lang(),
    }
}

/// OS locale → language: "zh*" is Chinese, anything else English, and an
/// undecidable locale Chinese.
fn system_lang() -> UiLang {
    match sys_locale::get_locale() {
        Some(locale) if !locale.to_ascii_lowercase().starts_with("zh") => UiLang::EnUs,
        _ => UiLang::ZhCn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_preferences_resolve_without_consulting_the_os() {
        assert_eq!(resolve(LanguagePreference::ZhCn), UiLang::ZhCn);
        assert_eq!(resolve(LanguagePreference::EnUs), UiLang::EnUs);
    }
}
