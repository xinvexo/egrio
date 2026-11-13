//! Every string the interface shows, in Chinese and English. Each string is a
//! method: a missing translation or a wrong argument fails to compile.
//! Chinese uses full-width punctuation; English plurals are decided here.

/// The interface language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Zh,
    En,
}

impl Lang {
    /// The stored preference resolved against the system language.
    pub fn current() -> Self {
        match egrio_desktop::ui_text::current_lang() {
            egrio_desktop::ui_text::UiLang::ZhCn => Lang::Zh,
            egrio_desktop::ui_text::UiLang::EnUs => Lang::En,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Text(pub Lang);

macro_rules! strings {
    ($($name:ident => $zh:literal, $en:literal;)*) => {
        impl Text {
            $(pub fn $name(&self) -> &'static str {
                match self.0 {
                    Lang::Zh => $zh,
                    Lang::En => $en,
                }
            })*
        }
    };
}

strings! {
    nav_activity => "活动", "Activity";
    nav_nodes => "节点", "Nodes";
    nav_profiles => "配置", "Profiles";
    nav_rules => "规则", "Rules";
    nav_connections => "连接", "Connections";
    nav_logs => "日志", "Logs";
    nav_settings => "设置", "Settings";

    system_proxy => "系统代理", "System Proxy";
    tun => "TUN 模式", "TUN Mode";
    mode_rule => "规则", "Rule";
    mode_global => "全局", "Global";
    mode_direct => "直连", "Direct";
    needs_profile => "没有配置", "No profile";

    system_proxy_on_failed => "开启系统代理失败", "Couldn't turn on System Proxy";
    system_proxy_off_failed => "关闭系统代理失败", "Couldn't turn off System Proxy";
    tun_on_failed => "开启 TUN 模式失败", "Couldn't turn on TUN Mode";
    tun_off_failed => "关闭 TUN 模式失败", "Couldn't turn off TUN Mode";
    tun_approval => "TUN 模式需要批准", "TUN Mode needs approval";
    tun_not_restored => "TUN 环境未就绪，TUN 模式没有开启", "TUN Mode stayed off: its environment isn't ready";
    mode_failed => "切换代理模式失败", "Couldn't switch the mode";

    guard_reasserted => "系统代理被其他程序修改，已恢复", "Another program changed the system proxy; restored";
    guard_yielded => "系统代理被其他程序接管，Egrio 已关闭系统代理", "Another program took over the system proxy; Egrio turned System Proxy off";
    tun_interrupted => "TUN 模式中断，正在恢复", "TUN Mode was interrupted; restoring";
    tun_recovered => "TUN 模式已恢复", "TUN Mode restored";
    tun_recovery_failed => "TUN 模式未能恢复", "TUN Mode could not be restored";

    configuration_pending => "配置等待应用", "Configuration is pending";
    configuration_cleanup_pending => "配置已应用，旧连接仍在清理", "Configuration applied; connection cleanup pending";
    configuration_rejected => "配置变更被拒绝", "Configuration change rejected";
    configuration_degraded => "配置应用未完成", "Configuration update incomplete";

    loading => "加载中…", "Loading…";

    logs_all => "全部", "All";
    logs_info => "信息", "Info";
    logs_warn => "警告", "Warnings";
    logs_error => "错误", "Errors";
    logs_clear => "清空", "Clear";
    logs_empty => "暂无日志", "No logs yet";
    logs_empty_filtered => "该级别暂无日志", "No logs at this level";
    fetch_failed => "获取失败", "Unavailable";

    traffic_title => "实时流量", "Live Traffic";
    download => "下载", "Download";
    upload => "上传", "Upload";
    local_proxy => "本机代理地址", "Local Proxy Address";
    not_listening => "未监听", "Not listening";
    active_connections => "活跃连接", "Active Connections";
    process_count => "进程数量", "Processes";
    egress_title => "出口", "Egress";
    egress_ip => "出口 IP", "Egress IP";
    egress_no_address => "没有取得出口地址", "No egress address yet";
    egress_provider => "服务商", "Provider";
    egress_location => "位置", "Location";
    egress_idle => "系统代理与 TUN 模式都没有开启", "System Proxy and TUN Mode are off";
    egress_direct => "直连模式", "Direct mode";

    unknown_process => "未知程序", "Unknown Process";
    upload_total => "上传流量", "Upload";
    download_total => "下载流量", "Download";
    connections_active => "活跃连接", "Active";
    clear => "清理", "Clear";
    clear_tooltip => "清理已结束的连接", "Clear finished connections";
    clear_failed => "清理连接记录失败", "Couldn't clear the connection records";
    flat => "平铺", "Flat";
    by_host => "域名", "Host";
    by_process => "程序", "Process";
    col_protocol => "协议", "Protocol";
    col_process => "进程", "Process";
    col_target => "目标", "Target";
    col_outbound => "出站", "Outbound";
    col_state => "状态", "State";
    col_download => "下载", "Download";
    connections_empty => "暂无连接记录", "No connection records";
    connections_no_match => "没有匹配的连接", "No matching connections";
    search_connections => "搜索连接", "Search connections";
    state_active => "活跃", "Active";
    state_completed => "已完成", "Completed";
    state_cancelled => "已取消", "Cancelled";
    state_rejected => "已拒绝", "Rejected";
    state_failed => "失败", "Failed";
    state_unknown => "结果未知", "Unknown";
    field_target => "目标", "Target";
    field_address => "地址", "Address";
    field_source => "源地址", "Source";
    field_rule => "规则", "Rule";
    field_inbound => "入站", "Inbound";
    field_outbound => "出站", "Outbound";
    field_egress_interface => "出接口", "Egress Interface";
    field_opened_at => "开始时间", "Opened";
    field_duration => "时长", "Duration";
    field_termination => "结束原因", "End Reason";
    close_detail => "关闭连接详情", "Close connection details";
    termination_completed => "正常结束", "Ended normally";
    termination_cancelled => "连接已取消", "Connection cancelled";
    termination_client_closed => "客户端已关闭连接", "Client closed the connection";
    termination_route_rejected => "被路由规则拒绝", "Rejected by a routing rule";
    termination_scoped_requires_direct => "本地接口地址需要 DIRECT 出站", "Interface-scoped address requires DIRECT";
    termination_scope_unresolved => "IPv6 接口作用域未解析", "IPv6 interface scope is unresolved";
    termination_unknown => "未收到连接结束结果", "No connection end result was received";
    outbound_config => "节点配置不可用", "Node configuration unusable";
    outbound_local => "本机拒绝", "Refused on this device";
    outbound_hop_resolve => "节点地址解析失败", "Node address did not resolve";
    outbound_hop_connect => "节点不可达", "Node unreachable";
    outbound_hop_auth => "节点拒绝认证", "Node rejected the credentials";
    outbound_hop_protocol => "节点协议错误", "Node protocol error";
    outbound_target_resolve => "目标地址解析失败", "Destination did not resolve";
    outbound_target => "目标拒绝或不可达", "Destination refused or unreachable";
    stage_admission => "接收连接", "Connection admission";
    stage_enrich => "识别目标", "Target resolution";
    stage_route => "选择路由", "Routing";
    stage_dial => "建立连接", "Connection setup";
    stage_reply => "回复客户端", "Client reply";
    stage_relay => "转发数据", "Data relay";
    side_client => "客户端", "Client";
    side_upstream => "上游", "Upstream";
    action_read => "读取", "read";
    action_write => "写入", "write";
    action_flush => "刷新缓冲区", "flush";
    action_shutdown => "关闭连接", "shutdown";

    messages => "消息", "Messages";
    messages_empty => "没有消息", "No messages";
    messages_clear => "清空", "Clear";
    source_tun => "TUN 模式", "TUN Mode";
    source_system_proxy => "系统代理", "System Proxy";
    source_configuration => "配置", "Configuration";
    source_connections => "连接", "Connections";
    source_listener => "本机代理", "Local Proxy";

    global_outbound => "全局出站", "Global Outbound";
    global_outbound_failed => "切换全局出站失败", "Couldn't switch the global outbound";
    nodes_no_profile => "还没有使用中的配置", "No profile in use";
    nodes_empty => "当前配置没有节点", "This profile has no nodes";
    group_empty => "这个策略组没有成员", "This group has no members";
    not_chosen => "未选择", "None chosen";
    builtin_outbound => "内置", "Built-in";
    latency_timeout => "超时", "Timeout";
    unsupported_badge => "不支持", "Unsupported";
    press_to_test => "测速", "Test latency";


    rules_filter => "筛选类型、内容或出站", "Filter by type, content or outbound";
    rules_empty => "当前配置没有规则", "This profile has no rules";
    rules_no_match => "没有匹配的规则", "No matching rules";
    col_kind => "类型", "Type";
    col_payload => "内容", "Content";
    col_hits => "命中", "Hits";
    local_rule_set => "本地规则集", "Local rule set";
    not_fetched => "未下载", "Not downloaded";
    test_route => "测试路由", "Test Route";
    run_test => "测试", "Test";
    route_target_placeholder => "域名或 IP", "Domain or IP";
    route_test_saved => "Core 未运行", "The Core isn't running";
    refresh_providers => "更新联网规则集", "Update online rule sets";
    no_remote_providers => "没有联网规则集", "No online rule sets";
    reset_hits => "重置命中统计", "Reset hit counts";
    add_rule => "新增规则", "Add Rule";
    edit_rule => "编辑规则", "Edit Rule";
    field_kind => "类型", "Type";
    field_payload => "内容", "Content";
    field_country => "国家或地区", "Country or region";
    field_network => "传输协议", "Transport";
    field_rule_set => "规则集", "Rule set";
    no_rule_sets => "没有规则集", "No rule sets";
    pick_executable => "选择…", "Choose…";
    rule_add_failed => "添加规则失败", "Couldn't add the rule";
    rule_update_failed => "更新规则失败", "Couldn't update the rule";
    rules_delete_failed => "删除规则失败", "Couldn't delete the rules";
    rules_reorder_failed => "调整规则顺序失败", "Couldn't reorder the rules";
    providers_refresh_failed => "更新规则集失败", "Couldn't update the rule sets";
    provider_fetch_failed => "下载规则集失败", "Couldn't download the rule set";
    route_test_error => "测试路由失败", "Couldn't test the route";
    source_rules => "规则", "Rules";

    tray_show => "显示主界面", "Show Main Window";
    tray_quit => "退出", "Quit";
    tray_outbound_mode => "出站模式", "Outbound Mode";
    tray_latency_test => "延迟测试", "Test Latency";
    tray_latency_testing => "延迟测试中…", "Testing Latency…";
    select_failed => "切换节点失败", "Couldn't switch the node";

    menu_hide => "隐藏 Egrio", "Hide Egrio";
    menu_quit => "退出 Egrio", "Quit Egrio";
    menu_edit => "编辑", "Edit";
    menu_undo => "撤销", "Undo";
    menu_redo => "重做", "Redo";
    menu_cut => "剪切", "Cut";
    menu_copy => "拷贝", "Copy";
    menu_paste => "粘贴", "Paste";
    menu_select_all => "全选", "Select All";
    menu_window => "窗口", "Window";
    menu_minimize => "最小化", "Minimize";
    menu_close => "关闭", "Close";

    settings_network => "网络", "Network";
    settings_general => "通用", "General";
    settings_appearance => "外观", "Appearance";
    settings_about => "关于", "About";
    environment_ready => "环境已安装", "Environment installed";
    environment_install => "安装环境", "Install environment";
    environment_install_failed => "环境安装失败", "Environment installation failed";
    ipv6 => "IPv6 解析", "IPv6 DNS";
    allow_lan => "允许局域网访问", "Allow LAN Access";
    listener_port => "监听端口", "Listener port";
    autostart => "开机自启", "Launch at Login";
    silent_start => "静默启动", "Silent Start";
    log_level => "日志级别", "Log level";
    log_level_off => "关闭", "Off";
    log_level_error => "错误", "Error";
    log_level_warn => "警告", "Warning";
    log_level_info => "信息", "Info";
    log_level_debug => "调试", "Debug";
    log_level_trace => "跟踪", "Trace";
    geodata => "GEODATA", "GEODATA";
    geodata_missing => "尚未下载", "Not downloaded";
    geodata_updating => "正在下载…", "Downloading…";
    geodata_update => "更新", "Update";
    geodata_updated => "GEODATA 已更新", "GEODATA updated";
    geodata_current => "GEODATA 已是最新", "GEODATA is up to date";
    geodata_update_failed => "更新 GEODATA 失败", "Couldn't update GEODATA";
    theme => "主题", "Theme";
    theme_system => "跟随系统", "System";
    theme_light => "浅色", "Light";
    theme_dark => "深色", "Dark";
    language => "语言", "Language";
    language_system => "跟随系统", "System";
    language_zh => "中文", "中文";
    language_en => "English", "English";
    version => "版本", "Version";
    check_updates_at_launch => "启动时检查更新", "Check for Updates at Launch";
    updates => "更新", "Updates";
    check_for_updates => "检查更新", "Check for Updates";
    checking_updates => "正在检查…", "Checking…";
    up_to_date => "已是最新版本", "Egrio is up to date";
    upgrade => "升级", "Upgrade";
    downloading_update => "正在下载新版本…", "Downloading the new version…";
    update_check_failed => "检查更新失败", "Couldn't check for updates";
    upgrade_failed => "升级失败", "Couldn't upgrade";
    source_update => "更新", "Updates";
    save_failed => "保存设置失败", "Couldn't save the setting";
    log_level_failed => "保存日志级别失败", "Couldn't save the log level";
    theme_failed => "保存外观失败", "Couldn't save the appearance";
    language_failed => "保存语言失败", "Couldn't save the language";
    source_settings => "设置", "Settings";
    source_geodata => "GEODATA", "GEODATA";
    updated_just_now => "刚刚更新", "Updated just now";

    add_profile => "添加配置", "Add Profile";
    profiles_empty => "还没有配置", "No profiles yet";
    rename => "重命名", "Rename";
    reapply => "重新应用", "Reapply";
    delete => "删除", "Delete";
    cancel => "取消", "Cancel";
    confirm_delete => "删除此配置？", "Delete this profile?";
    confirm_stop_delete => "停止代理连接并删除此配置？", "Stop proxy connections and delete this profile?";
    stop_and_delete => "停止并删除", "Stop and delete";
    in_use => "使用中", "Active";
    apply => "应用", "Apply";
    name_placeholder => "名称（可选）", "Name (optional)";
    url_placeholder => "https://example.com/clash.yaml", "https://example.com/clash.yaml";
    import_file => "从文件导入", "Import from File";
    default_profile_name => "导入的配置", "Imported profile";
    new_profile_name => "新配置", "New profile";
    new_blank => "新建空白配置", "New Blank Profile";
    edit_profile => "编辑", "Edit";
    delete_while_editing => "正在编辑", "Being edited";
    sample_node_name => "示例节点", "Sample Node";
    revert => "还原", "Revert";
    save => "保存", "Save";
    saving => "正在保存…", "Saving…";
    profile_save_failed => "保存配置失败", "Couldn't save the profile";
    editor_read_failed => "未能读取配置", "Couldn't read the profile";
    no_yaml_problems => "无语法错误", "No syntax errors";
    show_problem => "定位", "Show";
    menu_file => "文件", "File";
    local_profile_name => "本地配置", "Local profile";
    download_failed => "下载配置失败", "Couldn't download the profile";
    import_failed => "导入配置失败", "Couldn't import the profile";
    apply_failed => "切换配置失败", "Couldn't switch to the profile";
    delete_failed => "删除配置失败", "Couldn't delete the profile";
    rename_failed => "重命名配置失败", "Couldn't rename the profile";
    reapply_failed => "重新应用配置失败", "Couldn't reapply the profile";
    file_read_failed => "读取文件失败", "Couldn't read the file";
}

impl Text {
    /// A message on one line: its title, then its detail.
    pub fn message_line(&self, title: &str, detail: &str) -> String {
        match self.0 {
            Lang::Zh => format!("{title}：{detail}"),
            Lang::En => format!("{title}: {detail}"),
        }
    }

    /// The outbound a node dials its server through.
    pub fn via(&self, name: &str) -> String {
        match self.0 {
            Lang::Zh => format!("经 {name}"),
            Lang::En => format!("via {name}"),
        }
    }

    pub fn custom_test_url(&self, url: &str) -> String {
        match self.0 {
            Lang::Zh => format!("测速地址：{url}"),
            Lang::En => format!("Test URL: {url}"),
        }
    }

    pub fn latency_failed(&self, error: &str) -> String {
        match self.0 {
            Lang::Zh => format!("测速失败：{error}"),
            Lang::En => format!("Test failed: {error}"),
        }
    }

    pub fn unsupported_hint(&self, reason: &str) -> String {
        match self.0 {
            Lang::Zh => format!("Egrio 暂不能连接此节点：{reason}"),
            Lang::En => format!("Egrio can't connect through this node yet: {reason}"),
        }
    }

    /// The caption over the nodes page's tiles: its title, then how many.
    pub fn nodes_caption(&self, count: usize) -> String {
        match self.0 {
            Lang::Zh => format!("节点 {count}"),
            Lang::En => format!("Nodes {count}"),
        }
    }

    /// The caption over the nodes page's rail: its title, then how many
    /// groups.
    pub fn groups_caption(&self, count: usize) -> String {
        match self.0 {
            Lang::Zh => format!("策略组 {count}"),
            Lang::En => format!("Groups {count}"),
        }
    }

    /// A newer version is out, as a message title.
    pub fn new_version(&self, version: &str) -> String {
        match self.0 {
            Lang::Zh => format!("发现新版本 {version}"),
            Lang::En => format!("Egrio {version} is available"),
        }
    }

    pub fn update_available(&self, version: &str) -> String {
        match self.0 {
            Lang::Zh => format!("新版本 {version} 可用"),
            Lang::En => format!("Version {version} is available"),
        }
    }

    pub fn rule_count(&self, count: usize) -> String {
        match (self.0, count) {
            (Lang::Zh, _) => format!("{count} 条规则"),
            (Lang::En, 1) => "1 rule".into(),
            (Lang::En, _) => format!("{count} rules"),
        }
    }

    pub fn rules_selected(&self, selected: usize, total: usize) -> String {
        match self.0 {
            Lang::Zh => format!("已选 {selected} / {total}"),
            Lang::En => format!("{selected} of {total} selected"),
        }
    }

    pub fn delete_rules(&self, count: usize) -> String {
        match (self.0, count) {
            (Lang::Zh, _) => format!("删除选中的 {count} 条规则"),
            (Lang::En, 1) => "Delete the selected rule".into(),
            (Lang::En, _) => format!("Delete the {count} selected rules"),
        }
    }

    /// How many entries a downloaded rule set has.
    pub fn entry_count(&self, count: i64) -> String {
        match (self.0, count) {
            (Lang::Zh, _) => format!("{count} 条"),
            (Lang::En, 1) => "1 entry".into(),
            (Lang::En, _) => format!("{count} entries"),
        }
    }

    pub fn route_test_failed(&self, error: &str) -> String {
        match self.0 {
            Lang::Zh => format!("测试失败：{error}"),
            Lang::En => format!("Test failed: {error}"),
        }
    }

    /// The content field's example for a rule type.
    pub fn payload_placeholder(&self, kind: &str) -> &'static str {
        match (self.0, kind) {
            (_, "DOMAIN") => "www.google.com",
            (_, "DOMAIN-SUFFIX") => "google.com",
            (_, "DOMAIN-KEYWORD") => "google",
            (_, "DOMAIN-REGEX") => r"^(api|cdn)\.",
            (_, "IP-CIDR") => "192.168.0.0/16",
            (_, "IP-CIDR6") => "2001:db8::/32",
            (_, "SRC-IP-CIDR") => "192.168.1.0/24",
            (_, "PROCESS-NAME") => "Telegram",
            (Lang::Zh, "PROCESS-PATH") => "完整路径",
            (Lang::En, "PROCESS-PATH") => "Full path",
            (_, "DST-PORT") => "443/8000-9000",
            (_, "SRC-PORT") => "8080",
            (_, "AND") => "((DOMAIN-SUFFIX,example.com),(NETWORK,udp))",
            (_, "OR") => "((NETWORK,udp),(DST-PORT,443))",
            (_, "NOT") => "((DOMAIN-KEYWORD,ads))",
            (_, "GEOSITE") => "cn",
            _ => "",
        }
    }

    /// One update of every online rule set: how many changed, were already
    /// current and failed.
    pub fn providers_refreshed(&self, updated: usize, unchanged: usize, failed: usize) -> String {
        let succeeded = updated + unchanged;
        match (self.0, failed, updated, unchanged) {
            (Lang::Zh, 0, 0, _) => format!("{unchanged} 个规则集已是最新"),
            (Lang::En, 0, 0, 1) => "1 rule set is up to date".into(),
            (Lang::En, 0, 0, _) => format!("{unchanged} rule sets are up to date"),
            (Lang::Zh, 0, _, 0) => format!("已更新 {updated} 个规则集"),
            (Lang::En, 0, 1, 0) => "Updated 1 rule set".into(),
            (Lang::En, 0, _, 0) => format!("Updated {updated} rule sets"),
            (Lang::Zh, 0, _, _) => {
                format!("规则集检查完成：{updated} 个更新，{unchanged} 个未变化")
            }
            (Lang::En, 0, _, _) => {
                format!("Rule sets checked: {updated} updated, {unchanged} unchanged")
            }
            (Lang::Zh, _, 0, 0) => format!("规则集更新失败：{failed} 个失败"),
            (Lang::En, _, 0, 0) => format!("Rule sets failed to update: {failed} failed"),
            (Lang::Zh, _, _, _) => {
                format!("规则集未全部更新：{succeeded} 个成功，{failed} 个失败")
            }
            (Lang::En, _, _, _) => {
                format!("Rule sets partly updated: {succeeded} succeeded, {failed} failed")
            }
        }
    }

    pub fn message_count(&self, count: usize) -> String {
        match (self.0, count) {
            (Lang::Zh, _) => format!("{count} 条消息"),
            (Lang::En, 1) => "1 message".into(),
            (Lang::En, _) => format!("{count} messages"),
        }
    }

    pub fn profile_count(&self, count: usize) -> String {
        match (self.0, count) {
            (Lang::Zh, _) => format!("{count} 个配置"),
            (Lang::En, 1) => "1 profile".into(),
            (Lang::En, _) => format!("{count} profiles"),
        }
    }

    pub fn save_failed_detail(&self, error: &str) -> String {
        match self.0 {
            Lang::Zh => format!("保存失败：{error}"),
            Lang::En => format!("Couldn't save: {error}"),
        }
    }

    /// A YAML error, with its place when the parser names one.
    pub fn yaml_problem(&self, problem: &egrio_desktop::profile_source::YamlProblem) -> String {
        let message = &problem.message;
        match (self.0, problem.location) {
            (Lang::Zh, Some(at)) => format!("第 {} 行第 {} 列：{message}", at.line, at.column),
            (Lang::En, Some(at)) => format!("Line {}, column {}: {message}", at.line, at.column),
            (_, None) => message.clone(),
        }
    }

    pub fn profile_stats(&self, proxies: usize, groups: usize, rules: usize) -> String {
        match self.0 {
            Lang::Zh => format!("{proxies} 节点 · {groups} 组 · {rules} 规则"),
            Lang::En => format!("{proxies} nodes · {groups} groups · {rules} rules"),
        }
    }

    /// When something last changed: relative within a week ("3 小时前更新",
    /// "Updated yesterday"), then the date; `None` when the time is unknown.
    pub fn updated_at(&self, updated_unix: i64, now_unix: i64) -> Option<String> {
        use chrono::{Datelike, TimeZone};
        const MINUTE: i64 = 60;
        const HOUR: i64 = 60 * MINUTE;
        const DAY: i64 = 24 * HOUR;
        if updated_unix <= 0 {
            return None;
        }
        let elapsed = (now_unix - updated_unix).max(0);
        if elapsed < MINUTE {
            return Some(self.updated_just_now().into());
        }
        let plural = |count: i64, unit: &str| {
            if count == 1 {
                format!("1 {unit} ago")
            } else {
                format!("{count} {unit}s ago")
            }
        };
        let time = match (self.0, elapsed) {
            (Lang::Zh, elapsed) if elapsed < HOUR => format!("{}分钟前", elapsed / MINUTE),
            (Lang::En, elapsed) if elapsed < HOUR => plural(elapsed / MINUTE, "minute"),
            (Lang::Zh, elapsed) if elapsed < DAY => format!("{}小时前", elapsed / HOUR),
            (Lang::En, elapsed) if elapsed < DAY => plural(elapsed / HOUR, "hour"),
            (Lang::Zh, elapsed) if elapsed < 2 * DAY => "昨天".into(),
            (Lang::En, elapsed) if elapsed < 2 * DAY => "yesterday".into(),
            (Lang::Zh, elapsed) if elapsed < 3 * DAY => "前天".into(),
            (Lang::Zh, elapsed) if elapsed < 7 * DAY => format!("{}天前", elapsed / DAY),
            (Lang::En, elapsed) if elapsed < 7 * DAY => plural(elapsed / DAY, "day"),
            _ => {
                let date = chrono::Local.timestamp_opt(updated_unix, 0).single()?;
                let this_year = chrono::Local
                    .timestamp_opt(now_unix, 0)
                    .single()
                    .is_some_and(|now| now.year() == date.year());
                match (self.0, this_year) {
                    (Lang::Zh, true) => format!("{}月{}日", date.month(), date.day()),
                    (Lang::Zh, false) => {
                        format!("{}年{}月{}日", date.year(), date.month(), date.day())
                    }
                    (Lang::En, true) => date.format("%b %-d").to_string(),
                    (Lang::En, false) => date.format("%b %-d, %Y").to_string(),
                }
            }
        };
        Some(match self.0 {
            Lang::Zh => format!("{time}更新"),
            Lang::En => format!("Updated {time}"),
        })
    }

    pub fn port_fallback(&self, requested: u16, actual: u16) -> String {
        match self.0 {
            Lang::Zh => format!("端口 {requested} 不可用，已改用 {actual}"),
            Lang::En => format!("Port {requested} is unavailable; using {actual}"),
        }
    }

    pub fn port_in_use(&self, requested: u16) -> String {
        match self.0 {
            Lang::Zh => format!("{requested} 已被其他程序占用"),
            Lang::En => format!("Another program uses {requested}"),
        }
    }

    pub fn port_reserved(&self, requested: u16) -> String {
        match self.0 {
            Lang::Zh => format!("{requested} 被系统保留或被其他程序独占"),
            Lang::En => format!("The system reserves {requested}, or another program holds it"),
        }
    }

    pub fn tun_interrupted_tooltip(&self, reason: &str) -> String {
        match self.0 {
            Lang::Zh => format!("TUN 模式意外中断：{reason}"),
            Lang::En => format!("TUN Mode was interrupted: {reason}"),
        }
    }

    pub fn peak(&self, rate: &str) -> String {
        match self.0 {
            Lang::Zh => format!("峰值 {rate}"),
            Lang::En => format!("Peak {rate}"),
        }
    }

    pub fn chart_description(&self, download: &str, upload: &str) -> String {
        match self.0 {
            Lang::Zh => format!("下载 {download}，上传 {upload}"),
            Lang::En => format!("Download {download}, upload {upload}"),
        }
    }

    pub fn cleared(&self, count: usize) -> String {
        match (self.0, count) {
            (Lang::Zh, _) => format!("已清理 {count} 条已结束连接"),
            (Lang::En, 1) => "Cleared 1 finished connection".into(),
            (Lang::En, _) => format!("Cleared {count} finished connections"),
        }
    }

    pub fn connection_count(&self, count: usize) -> String {
        match (self.0, count) {
            (Lang::Zh, _) => format!("{count} 个连接"),
            (Lang::En, 1) => "1 connection".into(),
            (Lang::En, _) => format!("{count} connections"),
        }
    }

    pub fn termination_failure(&self, stage: &str, cause: &str) -> String {
        match self.0 {
            Lang::Zh => format!("{stage}：{cause}"),
            Lang::En => format!("{stage}: {cause}"),
        }
    }

    pub fn failure_io(&self, side: &str, action: &str, message: &str) -> String {
        match self.0 {
            Lang::Zh => format!("{side}{action}：{message}"),
            Lang::En => format!("{side} {action}: {message}"),
        }
    }

    pub fn failure_unattributed_io(&self, message: &str) -> String {
        match self.0 {
            Lang::Zh => format!("读写错误（来源未知）：{message}"),
            Lang::En => format!("I/O error (origin unknown): {message}"),
        }
    }

    pub fn failure_outbound(&self, stage: &str, message: &str) -> String {
        self.termination_failure(stage, message)
    }

    pub fn failure_os_code(&self, code: i32) -> String {
        match self.0 {
            Lang::Zh => format!("系统错误 {code}"),
            Lang::En => format!("OS error {code}"),
        }
    }

    pub fn failure_dial_timeout(&self, seconds: &str) -> String {
        match self.0 {
            Lang::Zh => format!("连接超时（{seconds} 秒）"),
            Lang::En => format!("Connection timed out ({seconds}s)"),
        }
    }

    pub fn failure_first_byte_timeout(&self, seconds: &str) -> String {
        match self.0 {
            Lang::Zh => format!("等待首个响应超时（{seconds} 秒）"),
            Lang::En => format!("First response timed out ({seconds}s)"),
        }
    }

    pub fn failure_idle_timeout(&self, seconds: &str) -> String {
        match self.0 {
            Lang::Zh => format!("空闲超时（{seconds} 秒）"),
            Lang::En => format!("Idle timeout ({seconds}s)"),
        }
    }

    /// "Label（IPv4）": a location or provider that names the family it
    /// describes when the two families leave from different places.
    pub fn qualified(&self, label: &str, family: &str) -> String {
        match self.0 {
            Lang::Zh => format!("{label}（{family}）"),
            Lang::En => format!("{label} ({family})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60;

    #[test]
    fn update_times_read_relative_within_a_week() {
        // Noon on 2026-06-15 UTC: far from a year's edge in any time zone.
        let now = 1_781_524_800;
        let zh = Text(Lang::Zh);
        let en = Text(Lang::En);
        assert_eq!(zh.updated_at(0, now), None);
        assert_eq!(
            en.updated_at(now - 30, now).as_deref(),
            Some("Updated just now")
        );
        assert_eq!(
            zh.updated_at(now - 5 * 60, now).as_deref(),
            Some("5分钟前更新")
        );
        assert_eq!(
            en.updated_at(now - 60, now).as_deref(),
            Some("Updated 1 minute ago")
        );
        assert_eq!(
            en.updated_at(now - 3 * 3600, now).as_deref(),
            Some("Updated 3 hours ago")
        );
        assert_eq!(zh.updated_at(now - DAY, now).as_deref(), Some("昨天更新"));
        assert_eq!(
            en.updated_at(now - DAY, now).as_deref(),
            Some("Updated yesterday")
        );
        assert_eq!(
            zh.updated_at(now - 2 * DAY, now).as_deref(),
            Some("前天更新")
        );
        assert_eq!(
            en.updated_at(now - 3 * DAY, now).as_deref(),
            Some("Updated 3 days ago")
        );
    }

    #[test]
    fn older_update_times_read_as_a_date_with_the_year_when_it_differs() {
        let now = 1_781_524_800;
        let zh = Text(Lang::Zh);
        let en = Text(Lang::En);
        let month_ago = now - 30 * DAY;
        assert!(zh.updated_at(month_ago, now).unwrap().ends_with("日更新"));
        assert!(!en.updated_at(month_ago, now).unwrap().contains(','));
        let year_ago = now - 400 * DAY;
        assert!(zh.updated_at(year_ago, now).unwrap().contains("年"));
        assert!(en.updated_at(year_ago, now).unwrap().contains(", 2025"));
    }
}
