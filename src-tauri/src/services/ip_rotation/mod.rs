//! 上游 429 → cc-switch 直连光猫重拨换 IP(不依赖 ip_panel 面板)。
//!
//! 触发链路:代理 forwarder 在某供应商返回 HTTP 429 且该供应商命中
//! `ipRotation.providerId` 配置时,调用 [`IpRotationHandle::maybe_trigger`]。
//! 重拨流程在后台 tokio 任务中执行,绝不阻塞请求热路径;期间客户端请求
//! 照常走既有 failover 逻辑。
//!
//! 执行器为三段移植(原 ip_panel Python 实现,逻辑逐行对应):
//!   - [`router_cred`]:光猫超管密码 Telnet 自动获取(ARP + telnetenable.cgi
//!     + 分步会话,12h 进程内缓存,登录失败强制刷新自愈);
//!   - [`modem`]:CGI 登录 + `wan_modify` Manual_Setting 2/1 + WAN 状态轮询;
//!   - [`baidu_dns`]:BCE V1 签名,重拨成功后把新全局 IPv6 upsert 到 AAAA 记录。
//!
//! 并发与频控语义(按需求裁定,不做每小时次数上限):
//!   - `inflight` 原子标志:同一时刻至多一次重拨流程;
//!   - `cooldown_secs`:上次触发后的冷却窗口,防止"重拨未换到 IP → 立刻再 429"
//!     造成的死循环式连续重拨;设为 0 可完全关闭冷却。
//!   - 光猫只允许一个管理会话:ip_panel 面板与本功能请勿同时运行。

mod baidu_dns;
mod modem;
mod router_cred;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::settings;

use baidu_dns::{DnsTarget, UpsertOutcome};
use modem::ModemClient;
use router_cred::Credentials;

/// 触发换 IP 的上游响应状态码。forwarder 的通知点与本模块门控共用此常量。
pub const HTTP_TOO_MANY_REQUESTS: u16 = 429;
/// PPPoE 拨号账号的环境变量兜底(优先级低于 settings)。
pub const PPPOE_USERNAME_ENV_KEY: &str = "PPPOE_USERNAME";
pub const PPPOE_PASSWORD_ENV_KEY: &str = "PPPOE_PASSWORD";
/// 百度云 DNS 凭证的环境变量兜底(与 ip_panel 面板同名,便于迁移)。
pub const DNS_ACCESS_KEY_ENV_KEY: &str = "BAIDU_AK";
pub const DNS_SECRET_KEY_ENV_KEY: &str = "BAIDU_SK";
pub const DNS_ZONE_ENV_KEY: &str = "BAIDU_ZONE";
pub const DNS_SUB_ENV_KEY: &str = "BAIDU_SUB";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct IpRotationSettings {
    /// 总开关;缺省 false,不影响任何现有行为。
    pub enabled: bool,
    /// 命中哪个上游供应商 id 的 429 才触发。
    pub provider_id: String,
    /// 光猫 Web 后台地址(重拨会话用)。取密(ARP/Telnet)只取其中的主机部分:
    /// Telnet 固定 23 端口、CGI 固定 80 端口,与面板 router_cred_host 行为一致。
    pub router_url: String,
    /// WAN 连接名(get_allwan_info 检索键)。
    pub wan_name: String,
    /// PPPoE 拨号账号(缺省回退环境变量 PPPOE_USERNAME/PPPOE_PASSWORD)。
    pub pppoe_username: Option<String>,
    pub pppoe_password: Option<String>,
    /// 百度云 DNS(缺省回退环境变量 BAIDU_AK/BAIDU_SK/BAIDU_ZONE/BAIDU_SUB)。
    pub dns_ak: Option<String>,
    pub dns_sk: Option<String>,
    pub dns_zone: Option<String>,
    pub dns_sub: Option<String>,
    /// 百度云 API 端点(测试可指向 mock)。
    pub dns_api_base: Option<String>,
    /// 冷却秒数;0 = 关闭冷却。
    pub cooldown_secs: u64,
    /// 单次换 IP 流程的整体超时秒数(含断开/连接/DNS 等待;各阶段最坏
    /// 合计约 410s,默认 540s 留足余量)。设为 0 会使每次触发立即超时。
    pub rotate_timeout_secs: u64,
}

impl Default for IpRotationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            provider_id: "opencode".to_string(),
            router_url: "http://192.168.1.1".to_string(),
            wan_name: modem::WAN_NAME_DEFAULT.to_string(),
            pppoe_username: None,
            pppoe_password: None,
            dns_ak: None,
            dns_sk: None,
            dns_zone: None,
            dns_sub: None,
            dns_api_base: None,
            cooldown_secs: 600,
            rotate_timeout_secs: 540,
        }
    }
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl IpRotationSettings {
    /// 解析后的 PPPoE 账号:settings 优先,环境变量兜底;两者必须齐备。
    fn effective_pppoe(&self) -> Option<(String, String)> {
        let username = self
            .pppoe_username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| env_value(PPPOE_USERNAME_ENV_KEY))?;
        let password = self
            .pppoe_password
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| env_value(PPPOE_PASSWORD_ENV_KEY))?;
        Some((username, password))
    }

    /// 解析后的 DNS 目标:AK/SK 缺失时返回 None(重拨照常,DNS 跳过)。
    fn effective_dns_target(&self) -> Option<DnsTarget> {
        let access_key = self
            .dns_ak
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| env_value(DNS_ACCESS_KEY_ENV_KEY))?;
        let secret_key = self
            .dns_sk
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| env_value(DNS_SECRET_KEY_ENV_KEY))?;
        let zone = self
            .dns_zone
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| env_value(DNS_ZONE_ENV_KEY))
            .unwrap_or_else(|| baidu_dns::DNS_ZONE_DEFAULT.to_string());
        let sub = self
            .dns_sub
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| env_value(DNS_SUB_ENV_KEY))
            .unwrap_or_else(|| baidu_dns::DNS_SUB_DEFAULT.to_string());
        let api_base = self
            .dns_api_base
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| baidu_dns::DNS_API_BASE_DEFAULT.to_string());
        Some(DnsTarget::new(access_key, secret_key, zone, sub, api_base))
    }

    /// 从 router_url 提取光猫主机/地址(ARP 与 Telnet 用)。剥掉 scheme/
    /// 路径/端口:Telnet 固定 23 端口,拼 port 会产生 "host:port:23"
    /// 这样的非法地址(主机语义与面板 router_cred_host 相同)。
    fn router_ip(&self) -> String {
        let without_scheme = self
            .router_url
            .trim()
            .trim_end_matches('/')
            .split("://")
            .last()
            .unwrap_or("192.168.1.1");
        let host = without_scheme.split('/').next().unwrap_or("192.168.1.1");
        host.split(':').next().unwrap_or(host).to_string()
    }
}

/// 供应商 id 匹配(大小写不敏感,trim 后比较)。
fn provider_matches(config: &IpRotationSettings, provider_id: &str) -> bool {
    let configured = config.provider_id.trim();
    !configured.is_empty() && configured.eq_ignore_ascii_case(provider_id.trim())
}

/// 重拨流程上下文:配置解析产物 + 各阶段超时(测试可注入更短超时)。
pub(crate) struct RotationContext {
    pub settings: IpRotationSettings,
    pub pppoe: (String, String),
    pub dns: Option<DnsTarget>,
    pub disconnect_timeout: Duration,
    pub connect_timeout: Duration,
    pub ipv6_wait_timeout: Duration,
}

impl RotationContext {
    fn from_settings(settings: &IpRotationSettings) -> Option<Self> {
        let pppoe = settings.effective_pppoe()?;
        Some(Self {
            settings: settings.clone(),
            pppoe,
            dns: settings.effective_dns_target(),
            disconnect_timeout: modem::DISCONNECT_TIMEOUT,
            connect_timeout: modem::CONNECT_TIMEOUT,
            ipv6_wait_timeout: baidu_dns::IPV6_WAIT_TIMEOUT,
        })
    }
}

/// 测试注入点:凭证获取 / IPv6 列表 / DNS upsert。
pub(crate) struct RotationHooks {
    /// `force=false` 走缓存懒取,`true` 强制刷新(登录失败自愈)。
    pub cred_fetcher:
        Box<dyn Fn(bool) -> BoxFuture<'static, Result<Credentials, String>> + Send + Sync>,
    pub ipv6_lister: Box<dyn Fn() -> BoxFuture<'static, Vec<String>> + Send + Sync>,
    pub dns_upsert:
        Box<dyn Fn(String) -> BoxFuture<'static, Result<UpsertOutcome, String>> + Send + Sync>,
}

/// 从 URL 提取主机部分(去 scheme/userinfo/端口)。
fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    // IPv6 字面量自带冒号,仅非方括号主机按端口切分
    let host = if host.starts_with('[') {
        host
    } else {
        host.split(':').next()?
    };
    let host = host.trim_matches(['[', ']']);
    (!host.is_empty()).then(|| host.to_string())
}

/// 从 `ip -j route get <host>` 的 JSON 输出提取 dev 字段。
fn parse_route_get_dev(stdout: &[u8]) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    doc.as_array()?
        .first()?
        .get("dev")?
        .as_str()
        .map(str::to_string)
}

/// 推断光猫所在网卡:对 routerUrl 主机做策略路由查询,取其 dev。
/// 查询失败时回退 None(不过滤,保持全接口扫描的旧行为)。
fn modem_facing_interface(router_url: &str) -> Option<String> {
    let host = url_host(router_url)?;
    let output = std::process::Command::new("ip")
        .args(["-j", "route", "get", &host])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_route_get_dev(&output.stdout)
}

fn production_hooks(settings: &IpRotationSettings, dns: Option<DnsTarget>) -> RotationHooks {
    let router_ip = settings.router_ip();
    let iface = modem_facing_interface(&settings.router_url);
    RotationHooks {
        cred_fetcher: Box::new(move |force| {
            let router_ip = router_ip.clone();
            Box::pin(async move {
                if force {
                    router_cred::force_refresh_credentials(&router_ip).await
                } else {
                    router_cred::ensure_credentials(&router_ip).await
                }
            })
        }),
        ipv6_lister: Box::new(move || {
            let iface = iface.clone();
            Box::pin(async move { baidu_dns::get_global_ipv6s_on(iface).await })
        }),
        dns_upsert: Box::new(move |ip| {
            let target = dns.clone();
            Box::pin(async move {
                let target = target.ok_or_else(|| "百度云 DNS 未配置".to_string())?;
                target.upsert_aaaa(&ip).await
            })
        }),
    }
}

#[cfg(unix)]
pub mod manual;

/// 进程内重拨句柄:挂在 ProxyServerState 上,每请求经 forwarder 通知。
#[derive(Clone)]
pub struct IpRotationHandle {
    state: Arc<RotationState>,
}

struct RotationState {
    /// 同一时刻至多一次重拨流程。
    inflight: AtomicBool,
    /// 上次触发时刻(冷却记账)。
    last_attempt: Mutex<Option<Instant>>,
}

/// 手动触发结果(CLI/TUI/信号监听器展示用)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualTriggerOutcome {
    /// 已提交后台执行
    Queued,
    /// 已有换 IP 流程进行中(与自动触发共用单飞)
    Busy,
    /// ipRotation 未配置或未启用
    Disabled,
    /// 缺少 PPPoE 账号
    MissingPppoe,
}

impl ManualTriggerOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Busy => "busy",
            Self::Disabled => "disabled",
            Self::MissingPppoe => "missing-pppoe",
        }
    }
}

impl IpRotationHandle {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RotationState {
                inflight: AtomicBool::new(false),
                last_attempt: Mutex::new(None),
            }),
        }
    }

    /// 上游以 `status` 响应该供应商后调用;仅 429 可能触发换 IP。
    /// 其余状态零开销短路,不读任何配置。
    pub fn maybe_trigger(&self, provider_id: &str, status: u16) {
        if status != HTTP_TOO_MANY_REQUESTS {
            return;
        }
        let Some(config) = settings::get_ip_rotation_settings() else {
            debug!("[IP-ROTATE] 未配置 ipRotation,忽略 429");
            return;
        };
        self.trigger_with_config(&config, provider_id);
    }

    /// 命中配置的 429 触发入口:防重入 + 冷却记账 + 后台单飞。
    pub(crate) fn trigger_with_config(&self, config: &IpRotationSettings, provider_id: &str) {
        if !config.enabled {
            debug!("[IP-ROTATE] ipRotation 未启用,忽略 {provider_id} 的 429");
            return;
        }
        if !provider_matches(config, provider_id) {
            debug!(
                "[IP-ROTATE] 供应商 {provider_id} 不匹配 {},忽略 429",
                config.provider_id
            );
            return;
        }
        // PPPoE 账号缺失:直接拒绝,不占用 inflight、不记账
        let Some(context) = RotationContext::from_settings(config) else {
            debug!(
                "[IP-ROTATE] 缺少 PPPoE 账号(settings 或环境变量 {}),无法换 IP",
                PPPOE_USERNAME_ENV_KEY
            );
            return;
        };
        if !self.try_acquire(config) {
            return;
        }
        self.spawn_rotation(context, &format!("{provider_id} 429"));
    }

    /// 手动触发(CLI/TUI → daemon IPC → worker SIGUSR1):绕过冷却,
    /// 但仍要求 ipRotation 已启用,且与自动 429 触发共享 inflight 单飞与记账。
    /// 记账不省略:手动触发后,自动 429 触发照常进入冷却窗口,防止连环重拨。
    pub fn trigger_manual(&self) -> ManualTriggerOutcome {
        let Some(config) = settings::get_ip_rotation_settings() else {
            return ManualTriggerOutcome::Disabled;
        };
        if !config.enabled {
            return ManualTriggerOutcome::Disabled;
        }
        let Some(context) = RotationContext::from_settings(&config) else {
            return ManualTriggerOutcome::MissingPppoe;
        };
        // 单飞 CAS:与自动触发共用,物理上禁止两次重拨并发(光猫单管理会话)
        if self
            .state
            .inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return ManualTriggerOutcome::Busy;
        }
        *self
            .state
            .last_attempt
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        info!("[IP-ROTATE] 手动触发换 IP(绕过冷却)");
        self.spawn_rotation(context, "手动触发");
        ManualTriggerOutcome::Queued
    }

    /// 构建guard + 后台执行(try_acquire/trigger_manual 已完成门控与记账)。
    /// guard 在 caller 作用域构建后 move 进任务:若 tokio::spawn 因
    /// 无 runtime 而 panic,guard 会在 caller 处被 drop,照常释放 inflight。
    fn spawn_rotation(&self, context: RotationContext, trigger: &str) {
        let hooks = production_hooks(&context.settings, context.dns.clone());
        let guard = InflightGuard {
            state: Arc::clone(&self.state),
        };
        let trigger = trigger.to_string();
        tokio::spawn(async move {
            let _guard = guard;
            match run_rotation_with_hooks(&context, &hooks).await {
                Ok(()) => info!("[IP-ROTATE] {trigger} → 换 IP 流程完成"),
                Err(error) => warn!("[IP-ROTATE] 换 IP 失败: {error}"),
            }
        });
    }

    /// 冷却检查 + inflight CAS + 记账(同步完成,供测试确定性断言)。
    fn try_acquire(&self, config: &IpRotationSettings) -> bool {
        if config.cooldown_secs > 0 {
            let last = *self
                .state
                .last_attempt
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(last) = last {
                let elapsed = last.elapsed();
                let cooldown = Duration::from_secs(config.cooldown_secs);
                if elapsed < cooldown {
                    debug!(
                        "[IP-ROTATE] 冷却期内(距上次 {:.0}s / {}s),跳过",
                        elapsed.as_secs_f32(),
                        config.cooldown_secs
                    );
                    return false;
                }
            }
        }
        // CAS:与 inflight 释放构成 happens-before,保证并发 429 至多一个流程
        if self
            .state
            .inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            debug!("[IP-ROTATE] 已有换 IP 流程进行中,跳过");
            return false;
        }
        *self
            .state
            .last_attempt
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        true
    }
}

impl Default for IpRotationHandle {
    fn default() -> Self {
        Self::new()
    }
}

struct InflightGuard {
    state: Arc<RotationState>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.state.inflight.store(false, Ordering::Release);
    }
}

/// 测试观察口:仅测试构建可见,生产代码零开销。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    impl IpRotationHandle {
        /// 是否有换 IP 流程占用中。
        pub(crate) fn is_rotating(&self) -> bool {
            self.state.inflight.load(Ordering::SeqCst)
        }

        /// 是否已记录冷却起始时间(try_acquire 同步写入,可确定性断言)。
        pub(crate) fn has_cooldown_record(&self) -> bool {
            self.state.last_attempt.lock().unwrap().is_some()
        }
    }
}

/// 直连光猫换 IP 全流程(日志/失败语义与面板 do_redial_flow 对齐):
/// 1. 记录旧全局 IPv6(供 DNS 判新);
/// 2. 取凭证登录(被拒则强制刷新凭证重试一次);
/// 3. Manual_Setting=2 → 轮询 Disconnected;=1 → 轮询 Connected;
/// 4. 读新出口 IPv4;
/// 5. 等待新全局 IPv6 并 upsert 百度云 AAAA(失败仅告警,重拨成果不受影响)。
pub(crate) async fn run_rotation_with_hooks(
    context: &RotationContext,
    hooks: &RotationHooks,
) -> Result<(), String> {
    let started = Instant::now();
    let flow = run_rotation_inner(context, hooks);
    match tokio::time::timeout(
        Duration::from_secs(context.settings.rotate_timeout_secs),
        flow,
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!(
            "换 IP 流程整体超时(>{}s,已耗时 {:.0}s)",
            context.settings.rotate_timeout_secs,
            started.elapsed().as_secs_f32()
        )),
    }
}

async fn run_rotation_inner(
    context: &RotationContext,
    hooks: &RotationHooks,
) -> Result<(), String> {
    let wan_name = context.settings.wan_name.trim();
    if wan_name.is_empty() {
        return Err("wanName 未配置".to_string());
    }
    // 1) 记录重拨前的全局 IPv6 全集(仅光猫网卡):DNS 阶段以全集做排除,
    //    防止重拨残留的旧前缀地址被当成"新地址"写进 DNS
    let old_ipv6s: std::collections::BTreeSet<String> =
        (hooks.ipv6_lister)().await.into_iter().collect();
    debug!(
        "[IP-ROTATE] 重拨前全局 IPv6 共 {} 个: {:?}",
        old_ipv6s.len(),
        old_ipv6s
    );

    // 2) 凭证 + 登录(网络错误直接中止;被拒则强制刷新凭证重试一次)
    let client = ModemClient::new(&context.settings.router_url)?;
    let mut credentials = (hooks.cred_fetcher)(false).await?;
    if !client.login(&credentials.0, &credentials.1).await? {
        info!("[IP-ROTATE] 光猫登录被拒,尝试强制刷新超管凭证后重试");
        credentials = (hooks.cred_fetcher)(true).await?;
        if !client.login(&credentials.0, &credentials.1).await? {
            return Err("光猫登录失败(刷新凭证后仍被拒,请检查光猫管理会话占用)".to_string());
        }
    }
    info!("[IP-ROTATE] 已登录光猫 {wan_name}");

    use base64::Engine;
    let pppoe_password_b64 =
        base64::engine::general_purpose::STANDARD.encode(context.pppoe.1.as_bytes());
    let pppoe = (&context.pppoe.0, pppoe_password_b64.as_str());

    // 3) 断开 → 等待 → 连接 → 等待
    client
        .send_manual_setting(wan_name, pppoe.0, pppoe.1, "2")
        .await?;
    client
        .wait_status(wan_name, "Disconnected", context.disconnect_timeout)
        .await?;
    info!("[IP-ROTATE] PPPoE 已断开,等待重新连接");
    client
        .send_manual_setting(wan_name, pppoe.0, pppoe.1, "1")
        .await?;
    client
        .wait_status(wan_name, "Connected", context.connect_timeout)
        .await?;

    // 4) 新出口 IPv4(光猫可能返回 `10_point_102_…` 编码,先解码再记日志)
    let (_, raw_ip) = client.get_wan_status(wan_name).await?;
    let ip_after = modem::decode_point_ip(&raw_ip);
    info!("[IP-ROTATE] 重拨完成,新出口 IPv4: {ip_after}");

    // 5) DNS AAAA(仅重拨成功后;失败不影响重拨成果)
    if context.dns.is_some() {
        match baidu_dns::wait_new_ipv6_with_interval(
            &old_ipv6s,
            context.ipv6_wait_timeout,
            baidu_dns::IPV6_POLL_INTERVAL,
            || (hooks.ipv6_lister)(),
        )
        .await
        {
            Ok(new_ipv6) => match (hooks.dns_upsert)(new_ipv6).await {
                Ok(outcome) => info!("[IP-ROTATE] DNS AAAA 更新完成: {}", outcome.as_str()),
                Err(error) => warn!("[IP-ROTATE] DNS AAAA 更新失败(重拨已成功): {error}"),
            },
            Err(error) => warn!("[IP-ROTATE] 未获取到新全局 IPv6,跳过 DNS 更新: {error}"),
        }
    } else {
        debug!("[IP-ROTATE] 未配置百度云 DNS,跳过 AAAA 更新");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::OnceLock;

    #[test]
    fn url_host_extracts_bare_host() {
        assert_eq!(
            url_host("http://192.168.1.1/"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            url_host("http://192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            url_host("https://gw.local:8080/x"),
            Some("gw.local".to_string())
        );
        assert_eq!(
            url_host("http://[fe80::1]/cgi"),
            Some("fe80::1".to_string())
        );
        assert_eq!(url_host(""), None);
    }

    #[test]
    fn parse_route_get_dev_picks_first_dev() {
        assert_eq!(
            parse_route_get_dev(br#"[{"dev":"eno1","dst":"192.168.1.1"}]"#),
            Some("eno1".to_string())
        );
        assert_eq!(parse_route_get_dev(b"[]"), None);
        assert_eq!(parse_route_get_dev(b"not json"), None);
    }

    /// 进程全局环境变量的测试互斥:env 修改会泄漏到并行线程,
    /// 凡读/写 PPPOE_*/BAIDU_* 环境变量的测试必须持锁运行。
    static ENV_SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

    use serial_test::serial;

    fn env_serial_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_SERIAL
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn config() -> IpRotationSettings {
        IpRotationSettings {
            enabled: true,
            pppoe_username: Some("pppoe-user".to_string()),
            pppoe_password: Some("pppoe-pass".to_string()),
            // 显式给出 DNS 凭证:trigger 路径不再读进程级环境变量,测试免互斥
            dns_ak: Some("ak".to_string()),
            dns_sk: Some("sk".to_string()),
            ..IpRotationSettings::default()
        }
    }

    #[test]
    fn provider_matches_trims_and_case_folds() {
        let base = config();
        assert!(provider_matches(&base, "opencode"));
        assert!(provider_matches(&base, " OpenCode "));
        assert!(!provider_matches(&base, "zhipu"));
        let blank = IpRotationSettings {
            provider_id: "  ".to_string(),
            ..config()
        };
        assert!(!provider_matches(&blank, "opencode"));
    }

    #[test]
    fn effective_pppoe_prefers_settings_then_env() {
        let _env_guard = env_serial_lock();
        std::env::remove_var(PPPOE_USERNAME_ENV_KEY);
        std::env::remove_var(PPPOE_PASSWORD_ENV_KEY);
        assert_eq!(
            config().effective_pppoe(),
            Some(("pppoe-user".to_string(), "pppoe-pass".to_string()))
        );

        let blank = IpRotationSettings {
            pppoe_username: Some("   ".to_string()),
            pppoe_password: Some("pppoe-pass".to_string()),
            ..IpRotationSettings::default()
        };
        assert_eq!(blank.effective_pppoe(), None);

        std::env::set_var(PPPOE_USERNAME_ENV_KEY, " env-user ");
        std::env::set_var(PPPOE_PASSWORD_ENV_KEY, " env-pass ");
        let from_env = IpRotationSettings::default().effective_pppoe();
        std::env::remove_var(PPPOE_USERNAME_ENV_KEY);
        std::env::remove_var(PPPOE_PASSWORD_ENV_KEY);
        assert_eq!(
            from_env,
            Some(("env-user".to_string(), "env-pass".to_string()))
        );
    }

    #[test]
    fn effective_dns_target_falls_back_to_env_and_defaults() {
        let _env_guard = env_serial_lock();
        std::env::remove_var(DNS_ACCESS_KEY_ENV_KEY);
        std::env::remove_var(DNS_SECRET_KEY_ENV_KEY);
        std::env::remove_var(DNS_ZONE_ENV_KEY);
        std::env::remove_var(DNS_SUB_ENV_KEY);
        // 未配置 AK/SK → None(重拨照常,DNS 跳过)
        assert!(IpRotationSettings::default()
            .effective_dns_target()
            .is_none());

        std::env::set_var(DNS_ACCESS_KEY_ENV_KEY, " env-ak ");
        std::env::set_var(DNS_SECRET_KEY_ENV_KEY, "env-sk");
        let target = IpRotationSettings::default()
            .effective_dns_target()
            .expect("env fallback");
        std::env::remove_var(DNS_ACCESS_KEY_ENV_KEY);
        std::env::remove_var(DNS_SECRET_KEY_ENV_KEY);
        assert_eq!(target.access_key, "env-ak");
        assert_eq!(target.secret_key, "env-sk");
        // zone/sub 走面板同名默认值
        assert_eq!(target.zone, baidu_dns::DNS_ZONE_DEFAULT);
        assert_eq!(target.sub, baidu_dns::DNS_SUB_DEFAULT);
        assert_eq!(target.api_base, baidu_dns::DNS_API_BASE_DEFAULT);
    }

    #[test]
    fn try_acquire_blocks_until_released() {
        let handle = IpRotationHandle::new();
        let mut config = config();
        config.cooldown_secs = 3600; // 长冷却:记账后必然拦截

        assert!(handle.try_acquire(&config), "首次触发应成功");
        assert!(!handle.try_acquire(&config), "inflight 未释放时应被拒");

        handle.state.inflight.store(false, Ordering::Release);
        assert!(
            !handle.try_acquire(&config),
            "冷却期内即使 inflight 已释放也应被拒"
        );

        *handle.state.last_attempt.lock().unwrap() = None;
        assert!(handle.try_acquire(&config), "冷却记账清空后应放行");

        handle.state.inflight.store(false, Ordering::Release);
        *handle.state.last_attempt.lock().unwrap() = None;
        config.cooldown_secs = 0; // 冷却完全关闭:连续触发都放行(仅 inflight 拦截)
        assert!(handle.try_acquire(&config));
        handle.state.inflight.store(false, Ordering::Release);
        assert!(handle.try_acquire(&config), "cooldown=0 不应被冷却拦截");
    }

    #[test]
    fn trigger_ignores_disabled_or_mismatched() {
        let handle = IpRotationHandle::new();
        let disabled = IpRotationSettings {
            enabled: false,
            ..config()
        };
        handle.trigger_with_config(&disabled, "opencode");
        assert!(!handle.state.inflight.load(Ordering::Acquire));

        let enabled = config();
        handle.trigger_with_config(&enabled, "zhipu");
        assert!(!handle.state.inflight.load(Ordering::Acquire));
    }

    #[test]
    fn trigger_with_missing_pppoe_does_not_spawn() {
        // effective_pppoe 会读进程级环境变量,与 env 测试互斥
        let _env_guard = env_serial_lock();
        std::env::remove_var(PPPOE_USERNAME_ENV_KEY);
        std::env::remove_var(PPPOE_PASSWORD_ENV_KEY);
        let handle = IpRotationHandle::new();
        let config = IpRotationSettings {
            pppoe_username: None,
            pppoe_password: None,
            ..IpRotationSettings::default()
        };
        handle.trigger_with_config(&config, "opencode");
        // 无 PPPoE 账号:直接拒绝,不占用 inflight、不记账
        assert!(!handle.state.inflight.load(Ordering::Acquire));
        assert!(handle.state.last_attempt.lock().unwrap().is_none());
    }

    // ===== 手动触发(trigger_manual)=====

    /// 在隔离的测试主目录中把 ipRotation 设置种入 settings 存储。
    fn seed_ip_rotation(cfg: IpRotationSettings) {
        crate::settings::update_settings(crate::settings::AppSettings {
            ip_rotation: Some(cfg),
            ..crate::settings::AppSettings::default()
        })
        .expect("seed ip_rotation settings");
    }

    #[test]
    #[serial]
    fn manual_trigger_reports_disabled_without_settings() {
        let home = tempfile::tempdir().expect("create isolated home");
        let _environment = crate::test_support::TestEnvGuard::isolated(home.path());
        crate::settings::update_settings(crate::settings::AppSettings::default())
            .expect("reset isolated settings");

        let handle = IpRotationHandle::new();
        assert_eq!(handle.trigger_manual(), ManualTriggerOutcome::Disabled);
        assert!(!handle.state.inflight.load(Ordering::Acquire));
        assert!(handle.state.last_attempt.lock().unwrap().is_none());
    }

    #[test]
    #[serial]
    fn manual_trigger_reports_disabled_when_not_enabled() {
        let home = tempfile::tempdir().expect("create isolated home");
        let _environment = crate::test_support::TestEnvGuard::isolated(home.path());
        seed_ip_rotation(IpRotationSettings {
            enabled: false,
            ..config()
        });

        let handle = IpRotationHandle::new();
        assert_eq!(handle.trigger_manual(), ManualTriggerOutcome::Disabled);
        assert!(handle.state.last_attempt.lock().unwrap().is_none());
    }

    #[test]
    #[serial]
    fn manual_trigger_reports_missing_pppoe() {
        // effective_pppoe 会读进程级环境变量,与 env 测试互斥
        let _env_guard = env_serial_lock();
        std::env::remove_var(PPPOE_USERNAME_ENV_KEY);
        std::env::remove_var(PPPOE_PASSWORD_ENV_KEY);
        let home = tempfile::tempdir().expect("create isolated home");
        let _environment = crate::test_support::TestEnvGuard::isolated(home.path());
        seed_ip_rotation(IpRotationSettings {
            pppoe_username: None,
            pppoe_password: None,
            ..config()
        });

        let handle = IpRotationHandle::new();
        assert_eq!(handle.trigger_manual(), ManualTriggerOutcome::MissingPppoe);
        // 缺账号:不占用 inflight、不记账
        assert!(!handle.state.inflight.load(Ordering::Acquire));
        assert!(handle.state.last_attempt.lock().unwrap().is_none());
    }

    #[test]
    #[serial]
    fn manual_trigger_reports_busy_while_inflight() {
        let home = tempfile::tempdir().expect("create isolated home");
        let _environment = crate::test_support::TestEnvGuard::isolated(home.path());
        seed_ip_rotation(config());

        let handle = IpRotationHandle::new();
        // 模拟自动 429 触发占用中
        handle.state.inflight.store(true, Ordering::Release);
        assert_eq!(handle.trigger_manual(), ManualTriggerOutcome::Busy);
        // Busy 不记账:手动触发不得抢先写冷却
        assert!(handle.state.last_attempt.lock().unwrap().is_none());
        handle.state.inflight.store(false, Ordering::Release);
    }

    #[tokio::test]
    #[serial]
    async fn manual_trigger_bypasses_cooldown_and_records() {
        let home = tempfile::tempdir().expect("create isolated home");
        let _environment = crate::test_support::TestEnvGuard::isolated(home.path());
        // 后台任务即使被调度也只打不可达地址,绝不碰真实光猫
        seed_ip_rotation(IpRotationSettings {
            cooldown_secs: 3600,
            router_url: "http://127.0.0.1:1".to_string(),
            ..config()
        });

        let handle = IpRotationHandle::new();
        // 模拟上一次自动触发留下的冷却记账(inflight 已释放)
        *handle.state.last_attempt.lock().unwrap() = Some(Instant::now());

        // 冷却期内手动触发仍应放行
        assert_eq!(handle.trigger_manual(), ManualTriggerOutcome::Queued);
        assert!(handle.state.inflight.load(Ordering::Acquire));
        // 记账保持:后续自动 429 触发照常进入冷却窗口
        assert!(handle.state.last_attempt.lock().unwrap().is_some());
        handle.state.inflight.store(false, Ordering::Release);
    }

    #[test]
    fn maybe_trigger_ignores_non_429_without_touching_settings() {
        let handle = IpRotationHandle::new();
        handle.maybe_trigger("opencode", 500);
        handle.maybe_trigger("opencode", 200);
        // 非 429 在读取任何设置/环境变量之前短路
        assert!(!handle.state.inflight.load(Ordering::Acquire));
        assert!(handle.state.last_attempt.lock().unwrap().is_none());
    }

    // current_thread 测试 runtime 中 spawn 的任务只会在 await 点被调度,
    // 因此紧跟其后的断言是确定性的:inflight 已占用、冷却已记账。
    #[tokio::test]
    async fn trigger_for_matching_provider_acquires_and_records() {
        let handle = IpRotationHandle::new();
        let config = config();
        handle.trigger_with_config(&config, "opencode");
        assert!(handle.state.inflight.load(Ordering::Acquire));
        assert!(handle.state.last_attempt.lock().unwrap().is_some());
        // 触发期间的后续 429 一律跳过
        assert!(!handle.try_acquire(&config));
    }

    #[test]
    fn router_ip_extracts_host_and_strips_port() {
        assert_eq!(config().router_ip(), "192.168.1.1");
        let with_port = IpRotationSettings {
            router_url: "http://192.168.2.253:8080/".to_string(),
            ..config()
        };
        // 端口剥掉:Telnet 固定 23 端口,ARP 查裸主机名(与面板 router_cred_host 一致)
        assert_eq!(with_port.router_ip(), "192.168.2.253");
    }

    #[tokio::test]
    async fn trigger_spawns_background_flow_that_fails_fast_on_unreachable_router() {
        // router_url 指向不可达端口:后台任务应快速失败并释放 inflight
        let handle = IpRotationHandle::new();
        let config = IpRotationSettings {
            router_url: "http://127.0.0.1:1".to_string(),
            rotate_timeout_secs: 10,
            ..config()
        };
        handle.trigger_with_config(&config, "opencode");
        assert!(handle.state.inflight.load(Ordering::SeqCst));
        let released = tokio::time::timeout(Duration::from_secs(15), async {
            while handle.state.inflight.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(released.is_ok(), "unreachable router must release inflight");
    }

    // ---------- 直连光猫全流程(mock 光猫 + 注入 hooks)----------

    use crate::services::ip_rotation::modem::tests::spawn_mock_modem;

    fn base64_of(value: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
    }

    struct ScriptedHooks {
        cred: (String, String),
        forced_cred: Option<(String, String)>,
        /// 每次 ipv6_lister 调用返回的快照(最后一项无限重复)
        ipv6_calls: Vec<Vec<String>>,
        ipv6_call: AtomicUsize,
        dns_seen: Arc<Mutex<Vec<String>>>,
    }

    fn scripted_hooks(script: Arc<ScriptedHooks>) -> RotationHooks {
        RotationHooks {
            cred_fetcher: {
                let script = Arc::clone(&script);
                Box::new(move |force| {
                    let script = Arc::clone(&script);
                    Box::pin(async move {
                        if force {
                            script
                                .forced_cred
                                .clone()
                                .ok_or_else(|| "no forced cred".to_string())
                        } else {
                            Ok(script.cred.clone())
                        }
                    })
                })
            },
            ipv6_lister: {
                let script = Arc::clone(&script);
                Box::new(move || {
                    let script = Arc::clone(&script);
                    Box::pin(async move {
                        let idx = script
                            .ipv6_call
                            .fetch_add(1, Ordering::SeqCst)
                            .min(script.ipv6_calls.len().saturating_sub(1));
                        script.ipv6_calls[idx].clone()
                    })
                })
            },
            dns_upsert: {
                let script = Arc::clone(&script);
                Box::new(move |ip| {
                    let script = Arc::clone(&script);
                    Box::pin(async move {
                        script.dns_seen.lock().unwrap().push(ip);
                        Ok(UpsertOutcome::Updated)
                    })
                })
            },
        }
    }

    fn test_context(settings: IpRotationSettings, dns: Option<DnsTarget>) -> RotationContext {
        RotationContext {
            pppoe: ("pppoe-user".to_string(), "pppoe-pass".to_string()),
            dns,
            disconnect_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            ipv6_wait_timeout: Duration::from_secs(2),
            settings,
        }
    }

    #[tokio::test]
    async fn full_flow_redials_modem_and_updates_dns() {
        let (base, modem_state) = spawn_mock_modem(&base64_of("router-pass")).await;
        let dns_seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(ScriptedHooks {
            cred: ("CMCCAdmin".to_string(), "router-pass".to_string()),
            forced_cred: None,
            ipv6_calls: vec![
                vec!["2408:old::1".to_string()],
                vec!["2408:old::1".to_string()],
                vec!["2408:new::2".to_string()],
            ],
            ipv6_call: AtomicUsize::new(0),
            dns_seen: Arc::clone(&dns_seen),
        });
        let settings = IpRotationSettings {
            router_url: base,
            ..config()
        };
        let context = test_context(
            settings,
            Some(DnsTarget::new(
                "ak".into(),
                "sk".into(),
                "zone".into(),
                "sub".into(),
                "http://127.0.0.1:1".into(),
            )),
        );
        let hooks = scripted_hooks(script);
        run_rotation_with_hooks(&context, &hooks)
            .await
            .expect("full flow ok");
        // 断开+连接各提交一次;最终 Connected;DNS 收到新 IPv6
        assert_eq!(modem_state.redials.load(Ordering::SeqCst), 2);
        assert_eq!(*dns_seen.lock().unwrap(), vec!["2408:new::2".to_string()]);
    }

    #[tokio::test]
    async fn login_failure_forces_credential_refresh_then_retries() {
        let (base, modem_state) = spawn_mock_modem(&base64_of("pppoe-pass")).await;
        // 首次凭证是错的:登录被拒 → force 刷新拿到对的 → 重试成功
        let dns_seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(ScriptedHooks {
            cred: ("CMCCAdmin".to_string(), "stale-pass".to_string()),
            forced_cred: Some(("CMCCAdmin".to_string(), "pppoe-pass".to_string())),
            ipv6_calls: vec![vec!["2408:new::2".to_string()]],
            ipv6_call: AtomicUsize::new(0),
            dns_seen: Arc::clone(&dns_seen),
        });
        let settings = IpRotationSettings {
            router_url: base,
            ..config()
        };
        let context = test_context(settings, None);
        let hooks = scripted_hooks(script);
        run_rotation_with_hooks(&context, &hooks)
            .await
            .expect("retry after refresh must succeed");
        assert_eq!(modem_state.login_hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn aborts_when_disconnect_never_completes() {
        let (base, modem_state) = spawn_mock_modem(&base64_of("pppoe-pass")).await;
        let dns_seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(ScriptedHooks {
            cred: ("CMCCAdmin".to_string(), "pppoe-pass".to_string()),
            forced_cred: None,
            ipv6_calls: vec![vec!["2408:new::2".to_string()]],
            ipv6_call: AtomicUsize::new(0),
            dns_seen: Arc::clone(&dns_seen),
        });
        let settings = IpRotationSettings {
            router_url: base,
            // WAN 连接名不存在 → 状态查询始终失败 → 断开等待超时
            wan_name: "9_MISSING_WAN".to_string(),
            ..config()
        };
        let mut context = test_context(settings, None);
        context.disconnect_timeout = Duration::from_millis(100);
        let hooks = scripted_hooks(script);
        let error = run_rotation_with_hooks(&context, &hooks)
            .await
            .expect_err("missing WAN must abort");
        assert!(error.contains("超时"), "unexpected: {error}");
        assert_eq!(modem_state.redials.load(Ordering::SeqCst), 1);
        assert!(dns_seen.lock().unwrap().is_empty(), "DNS must not run");
    }

    #[tokio::test]
    async fn dns_skipped_when_not_configured() {
        let (base, _modem_state) = spawn_mock_modem(&base64_of("pppoe-pass")).await;
        let dns_seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(ScriptedHooks {
            cred: ("CMCCAdmin".to_string(), "pppoe-pass".to_string()),
            forced_cred: None,
            ipv6_calls: vec![vec!["2408:new::2".to_string()]],
            ipv6_call: AtomicUsize::new(0),
            dns_seen: Arc::clone(&dns_seen),
        });
        let settings = IpRotationSettings {
            router_url: base,
            ..config()
        };
        let context = test_context(settings, None); // dns = None
        let hooks = scripted_hooks(script);
        run_rotation_with_hooks(&context, &hooks)
            .await
            .expect("flow ok without dns");
        assert!(dns_seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dns_upsert_failure_does_not_fail_successful_redial() {
        let (base, _modem_state) = spawn_mock_modem(&base64_of("pppoe-pass")).await;
        let script = Arc::new(ScriptedHooks {
            cred: ("CMCCAdmin".to_string(), "pppoe-pass".to_string()),
            forced_cred: None,
            ipv6_calls: vec![vec!["2408:new::2".to_string()]],
            ipv6_call: AtomicUsize::new(0),
            dns_seen: Arc::new(Mutex::new(Vec::new())),
        });
        let settings = IpRotationSettings {
            router_url: base,
            ..config()
        };
        let context = test_context(
            settings,
            Some(DnsTarget::new(
                "ak".into(),
                "sk".into(),
                "zone".into(),
                "sub".into(),
                "http://127.0.0.1:1".into(),
            )),
        );
        // DNS hook 返回错误:重拨已成功,流程必须仍然 Ok(验收 4)
        let mut hooks = scripted_hooks(script);
        hooks.dns_upsert =
            Box::new(|_ip| Box::pin(async { Err("模拟百度云 API 故障".to_string()) }));
        run_rotation_with_hooks(&context, &hooks)
            .await
            .expect("dns failure must not fail the flow");
    }

    #[tokio::test]
    async fn overall_rotate_timeout_aborts_slow_flow() {
        let (base, _modem_state) = spawn_mock_modem(&base64_of("pppoe-pass")).await;
        let script = Arc::new(ScriptedHooks {
            cred: ("CMCCAdmin".to_string(), "pppoe-pass".to_string()),
            forced_cred: None,
            ipv6_calls: vec![vec!["2408:new::2".to_string()]],
            ipv6_call: AtomicUsize::new(0),
            dns_seen: Arc::new(Mutex::new(Vec::new())),
        });
        let settings = IpRotationSettings {
            router_url: base,
            // 整体超时 1s < 断开等待 5s:外层超时先触发
            rotate_timeout_secs: 1,
            ..config()
        };
        let mut context = test_context(settings, None);
        context.disconnect_timeout = Duration::from_secs(5);
        let hooks = scripted_hooks(script);
        // WAN 名不存在 → 状态轮询持续失败 → 撞上整体超时
        context.settings.wan_name = "9_MISSING_WAN".to_string();
        let error = run_rotation_with_hooks(&context, &hooks)
            .await
            .expect_err("slow flow must hit overall timeout");
        assert!(error.contains("整体超时"), "unexpected: {error}");
    }

    #[tokio::test]
    async fn ipv6_unavailability_skips_dns_but_flow_succeeds() {
        let (base, _modem_state) = spawn_mock_modem(&base64_of("pppoe-pass")).await;
        let dns_seen = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(ScriptedHooks {
            cred: ("CMCCAdmin".to_string(), "pppoe-pass".to_string()),
            forced_cred: None,
            ipv6_calls: vec![vec![]], // 全程无全局 IPv6
            ipv6_call: AtomicUsize::new(0),
            dns_seen: Arc::clone(&dns_seen),
        });
        let settings = IpRotationSettings {
            router_url: base,
            ..config()
        };
        let context = test_context(
            settings,
            Some(DnsTarget::new(
                "ak".into(),
                "sk".into(),
                "zone".into(),
                "sub".into(),
                "http://127.0.0.1:1".into(),
            )),
        );
        let hooks = scripted_hooks(script);
        run_rotation_with_hooks(&context, &hooks)
            .await
            .expect("redial must succeed even without ipv6");
        assert!(dns_seen.lock().unwrap().is_empty());
    }
}
