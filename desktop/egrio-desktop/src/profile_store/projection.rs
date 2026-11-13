use super::*;

pub(super) fn inventory(profile_id: &str, content: &RuntimeProfile) -> ProfileInventory {
    ProfileInventory {
        profile_id: profile_id.to_string(),
        proxies: content
            .proxies
            .iter()
            .enumerate()
            .map(|(index, proxy)| SavedProxyNode {
                id: proxy.id.clone(),
                name: proxy.name.clone(),
                protocol: proxy.protocol.as_str().into(),
                server: proxy.server.clone(),
                port: proxy.port,
                sort_order: index as i64,
                unsupported: egrio_core::proxy_support_issue(content, proxy),
                hidden: proxy.hidden(),
                test_url: proxy.test_url().map(str::to_owned),
                dialer_proxy: proxy.dialer_proxy().map(str::to_owned),
            })
            .collect(),
        groups: content
            .groups
            .iter()
            .enumerate()
            .map(|(index, group)| SavedPolicyGroup {
                id: group.id.clone(),
                name: group.name.clone(),
                kind: group.kind.as_str().into(),
                members: group.members.clone(),
                sort_order: index as i64,
            })
            .collect(),
    }
}
