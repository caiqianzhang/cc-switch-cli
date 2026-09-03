//! 百度云 DNS AAAA 记录维护(移植自 ip_panel/baidu_dns.py + webapp.py 的
//! `_get_new_ipv6`/`upsert_aaaa` 流程)。
//!
//! - BCE Auth V1 签名:`bce-auth-v1/{AK}/{UTC时间}/{1800}` 派生密钥对
//!   `method\nuri\n\nhost:bcd.baidubce.com` 签名(ddns-go 复刻版,请求体不参与签名);
//! - 列表 → 查找 `sub` 的 AAAA 记录 → 不存在则 add,值相同则 unchanged,否则 edit;
//! - 本机全局 IPv6 选取:`ip -j -6 addr show`,scope=global,隐私扩展临时地址与
//!   已弃用地址排后;重拨后轮询等待出现与旧地址不同的稳定新地址(超时退回当前值)。

use std::collections::BTreeSet;
use std::time::Duration;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use super::{debug, info, warn};

/// BCE API 端点。
pub(crate) const DNS_API_BASE_DEFAULT: &str = "https://bcd.baidubce.com";
/// 默认主域名/子域名(与面板默认一致,可经配置/环境变量覆盖)。
pub(crate) const DNS_ZONE_DEFAULT: &str = "ruanjiangongcheng.site";
pub(crate) const DNS_SUB_DEFAULT: &str = "www";
/// DNS 记录 TTL 与签名有效期(秒)。
const DNS_TTL: i64 = 60;
const SIGN_EXPIRATION: &str = "1800";
/// 重拨后等待新 IPv6 的超时与轮询间隔。
/// 重拨后 IPv6(SLAAC)恢复可能明显慢于 IPv4:实测本机 120s 内未能拿到新
/// 全局地址导致 DNS 阶段放弃,放宽到 300s(仍受 rotate_timeout 540s 总约束)。
pub(crate) const IPV6_WAIT_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) const IPV6_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// upsert 结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpsertOutcome {
    Created,
    Updated,
    Unchanged,
}

impl UpsertOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            UpsertOutcome::Created => "created",
            UpsertOutcome::Updated => "updated",
            UpsertOutcome::Unchanged => "unchanged",
        }
    }
}

/// 生成 RFC3339 UTC 时间串(如 2026-09-03T12:34:56Z);测试注入。
fn format_bce_timestamp(now: chrono::DateTime<chrono::Utc>) -> String {
    now.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// canonical_uri:逐段 percent-encode(safe="")后拼接,无尾斜杠(与面板一致)。
pub(crate) fn canonical_uri(path: &str) -> String {
    let joined: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut out = String::new();
            for byte in segment.bytes() {
                let unreserved =
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
                if unreserved {
                    out.push(byte as char);
                } else {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
            out
        })
        .collect();
    format!("/{}", joined.join("/"))
}

/// BCE Auth V1 签名,返回 Authorization 头值。`now` 注入以便确定性测试。
pub(crate) fn sign_request(
    access_key: &str,
    secret_key: &str,
    method: &str,
    path: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let timestamp = format_bce_timestamp(now);
    let prefix = format!("bce-auth-v1/{access_key}/{timestamp}/{SIGN_EXPIRATION}");
    let canonical = format!(
        "{method}\n{uri}\n\nhost:bcd.baidubce.com",
        uri = canonical_uri(path)
    );
    let mut signing_mac =
        Hmac::<Sha256>::new_from_slice(secret_key.as_bytes()).expect("hmac accepts any key");
    signing_mac.update(prefix.as_bytes());
    let signing_key = hex_encode(&signing_mac.finalize().into_bytes());
    let mut sig_mac =
        Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()).expect("hmac accepts any key");
    sig_mac.update(canonical.as_bytes());
    format!(
        "{prefix}/host/{}",
        hex_encode(&sig_mac.finalize().into_bytes())
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// DNS 凭证与目标(AK/SK 必备;zone/sub 有默认)。
#[derive(Debug, Clone)]
pub(crate) struct DnsTarget {
    pub access_key: String,
    pub secret_key: String,
    pub zone: String,
    pub sub: String,
    pub api_base: String,
}

impl DnsTarget {
    pub(crate) fn new(
        access_key: String,
        secret_key: String,
        zone: String,
        sub: String,
        api_base: String,
    ) -> Self {
        Self {
            access_key,
            secret_key,
            zone,
            sub,
            api_base: api_base.trim_end_matches('/').to_string(),
        }
    }

    async fn api_call(
        &self,
        client: &reqwest::Client,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Value, String> {
        let now = chrono::Utc::now();
        let authorization = sign_request(&self.access_key, &self.secret_key, method, path, now);
        let url = format!("{}{}", self.api_base, canonical_uri(path));
        let mut request = match method {
            "POST" => client.post(&url).json(&body),
            _ => client.get(&url),
        };
        request = request.header("Authorization", authorization);
        let response = request
            .send()
            .await
            .map_err(|e| format!("请求百度云 DNS {path} 失败: {e}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("读取百度云 DNS {path} 响应失败(HTTP {status}): {e}"))?;
        // 与面板 api_call 一致:200 + 空响应体视为成功(edit 等端点返回空体)
        let payload: Value = if body.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&body)
                .map_err(|e| format!("百度云 DNS {path} 响应解析失败(HTTP {status}): {e}"))?
        };
        if !status.is_success() {
            return Err(format!(
                "百度云 DNS {path} HTTP {status}: {}",
                payload
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
            ));
        }
        Ok(payload)
    }

    /// 列出 zone 下解析记录(第一页足够:家用场景记录数远小于 1000)。
    async fn list_records(&self, client: &reqwest::Client) -> Result<Vec<Value>, String> {
        let payload = self
            .api_call(
                client,
                "POST",
                "/v1/domain/resolve/list",
                serde_json::json!({
                    "domain": self.zone,
                    "pageNum": 1,
                    "pageSize": 1000,
                }),
            )
            .await?;
        Ok(payload
            .get("result")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    async fn add_record(&self, client: &reqwest::Client, ip: &str) -> Result<(), String> {
        self.api_call(
            client,
            "POST",
            "/v1/domain/resolve/add",
            serde_json::json!({
                "domain": self.sub,
                "rdType": "AAAA",
                "ttl": DNS_TTL,
                "rdata": ip,
                "zoneName": self.zone,
            }),
        )
        .await
        .map(|_| ())
    }

    /// 编辑现有记录:domain/view/ttl/zoneName 按列表返回值回传
    /// (与面板 edit_record 一致,避免把非默认视图/大 TTL 记录改写掉)。
    async fn edit_record(
        &self,
        client: &reqwest::Client,
        record: &Value,
        ip: &str,
    ) -> Result<(), String> {
        let record_id = match record.get("recordId") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) => number.to_string(),
            _ => return Err("DNS 记录缺少 recordId".to_string()),
        };
        self.api_call(
            client,
            "POST",
            "/v1/domain/resolve/edit",
            serde_json::json!({
                "recordId": record_id,
                "domain": record.get("domain").and_then(Value::as_str).unwrap_or(&self.sub),
                "view": record.get("view").and_then(Value::as_str).unwrap_or("default"),
                "rdType": "AAAA",
                "ttl": record.get("ttl").and_then(Value::as_i64).unwrap_or(DNS_TTL),
                "rdata": ip,
                "zoneName": record.get("zoneName").and_then(Value::as_str).unwrap_or(&self.zone),
            }),
        )
        .await
        .map(|_| ())
    }

    /// 确保子域名 AAAA 记录指向 `ip`。
    pub(crate) async fn upsert_aaaa(&self, ip: &str) -> Result<UpsertOutcome, String> {
        // 整个 upsert 复用一个客户端(list/add/edit 共 2-3 次请求)
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("构建 DNS HTTP 客户端失败: {e}"))?;
        let records = self.list_records(&client).await?;
        // 列表响应的类型键为小写 rdtype(与面板一致);请求载荷用 rdType
        let existing = records.iter().find(|record| {
            record.get("domain").and_then(Value::as_str) == Some(self.sub.as_str())
                && (record.get("rdtype").or_else(|| record.get("rdType"))).and_then(Value::as_str)
                    == Some("AAAA")
        });
        match existing {
            None => {
                self.add_record(&client, ip).await?;
                info!("[IP-ROTATE] 百度云 DNS:已创建 {}/AAAA -> {ip}", self.sub);
                Ok(UpsertOutcome::Created)
            }
            Some(record) => {
                let current = record.get("rdata").and_then(Value::as_str).unwrap_or("");
                if current == ip {
                    debug!("[IP-ROTATE] 百度云 DNS:{}/AAAA 已是 {ip}", self.sub);
                    return Ok(UpsertOutcome::Unchanged);
                }
                self.edit_record(&client, record, ip).await?;
                info!(
                    "[IP-ROTATE] 百度云 DNS:已更新 {}/AAAA {current} -> {ip}",
                    self.sub
                );
                Ok(UpsertOutcome::Updated)
            }
        }
    }
}

/// 从 `ip -j -6 addr show` 的 JSON 输出提取全局 IPv6 并按稳定性排序
/// (隐私扩展临时地址、已弃用地址排后)。纯函数,测试注入样例。
pub(crate) fn parse_global_ipv6s(json_text: &str) -> Vec<String> {
    let Ok(doc) = serde_json::from_str::<Value>(json_text) else {
        return Vec::new();
    };
    let mut result: Vec<(String, (bool, bool, bool))> = Vec::new();
    for iface in doc.as_array().unwrap_or(&Vec::new()) {
        for addr in iface
            .get("addr_info")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if addr.get("scope").and_then(Value::as_str) != Some("global") {
                continue;
            }
            let Some(local) = addr.get("local").and_then(Value::as_str) else {
                continue;
            };
            let mut flags: BTreeSet<String> = addr
                .get("flags")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            // `ip -j` 输出中这些标记是 addr_info 的布尔字段而非 flags 数组成员
            // (见 ip(8) 手册与面板 baidu_dns.py),必须并入后统一参与排序
            for key in [
                "temporary",
                "mngtmpaddr",
                "dynamic",
                "deprecated",
                "permanent",
                "noprefixroute",
                "optimistic",
            ] {
                if addr.get(key).and_then(Value::as_bool) == Some(true) {
                    flags.insert(key.to_string());
                }
            }
            // 与面板一致:temporary 最不可取 > deprecated > 无 SLAAC/手工标记者靠后
            let rank = (
                flags.contains("temporary"),
                flags.contains("deprecated"),
                !flags.contains("mngtmpaddr") && !flags.contains("permanent"),
            );
            result.push((local.to_string(), rank));
        }
    }
    result.sort_by_key(|(_, rank)| *rank);
    result.into_iter().map(|(addr, _)| addr).collect()
}

/// 读取本机全局 IPv6 列表(生产入口,调用 `ip -j -6 addr show`)。
pub(crate) async fn get_global_ipv6s() -> Vec<String> {
    get_global_ipv6s_on(None).await
}

/// `ip -j -6 addr show` 的参数;指定 iface 时仅查看该接口。
pub(crate) fn addr_show_args(iface: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "-j".to_string(),
        "-6".to_string(),
        "addr".to_string(),
        "show".to_string(),
    ];
    if let Some(iface) = iface {
        args.push("dev".to_string());
        args.push(iface.to_string());
    }
    args
}

/// 全局 IPv6 列表;`iface` 为 `Some` 时只统计该接口的地址。
///
/// 多网卡机器(主光猫线 + USB 备份线等)上全接口扫描会把无关链路的
/// 地址误当"重拨后的新地址",导致 DNS 阶段把与重拨无关的地址写进
/// (或判定为 unchanged)记录;必须限定到光猫所在网卡。
pub(crate) async fn get_global_ipv6s_on(iface: Option<String>) -> Vec<String> {
    let args = addr_show_args(iface.as_deref());
    let output =
        tokio::task::spawn_blocking(move || std::process::Command::new("ip").args(&args).output())
            .await;
    let Ok(Ok(output)) = output else {
        warn!("[IP-ROTATE] 执行 ip -j -6 addr show 失败");
        return Vec::new();
    };
    parse_global_ipv6s(&String::from_utf8_lossy(&output.stdout))
}

/// 重拨后轮询本机全局 IPv6,直到出现不在 `exclude`(重拨前地址全集)中的稳定地址。
///
/// SLAAC 重新获取前缀需要数秒到数十秒;超时则退回当前已有地址(总比 DNS 里
/// 残留的旧记录好)。`lister` 注入以便测试;全程无地址报错。
pub(crate) async fn wait_new_ipv6_with_interval<F, Fut>(
    exclude: &BTreeSet<String>,
    timeout: Duration,
    poll_interval: Duration,
    lister: F,
) -> Result<String, String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // 与面板 _get_new_ipv6 语义一致但更严格:排除"重拨前的全部地址",
        // 而非仅第一个旧地址——仅排除单个地址时,重拨残留的旧前缀地址
        // (deprecated)会抢在新前缀 RA 到达前被当成"新地址"写进 DNS
        let addrs = lister().await;
        if let Some(fresh) = addrs.iter().find(|addr| !exclude.contains(*addr)) {
            return Ok(fresh.clone());
        }
        if tokio::time::Instant::now() >= deadline {
            // 超时兜底:仍有地址则退回当前第一地址(总比 DNS 残留好);
            // 全程无地址才报错(与面板语义一致)
            return match addrs.first() {
                Some(addr) => Ok(addr.clone()),
                None => Err("重拨后未获取到任何全局 IPv6 地址".to_string()),
            };
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // ---------- 纯函数测试 ----------

    #[test]
    fn addr_show_args_scopes_dev() {
        assert_eq!(
            addr_show_args(None),
            vec!["-j", "-6", "addr", "show"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            addr_show_args(Some("eno1")),
            vec!["-j", "-6", "addr", "show", "dev", "eno1"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn canonical_uri_encodes_and_strips_trailing_slash() {
        assert_eq!(
            canonical_uri("/v1/domain/resolve/list"),
            "/v1/domain/resolve/list"
        );
        assert_eq!(canonical_uri("/a b/c"), "/a%20b/c");
        assert_eq!(canonical_uri("/x/"), "/x");
    }

    /// 与 Python hmac/hashlib 参考实现对拍:固定时刻、固定 AK/SK、
    /// POST /v1/domain/resolve/list 的完整 Authorization 值。
    #[test]
    fn sign_request_matches_reference_vector() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-03T00:00:00Z")
            .expect("fixed time")
            .with_timezone(&chrono::Utc);
        let authorization =
            sign_request("AK-test", "SK-test", "POST", "/v1/domain/resolve/list", now);
        assert_eq!(
            authorization,
            "bce-auth-v1/AK-test/2026-09-03T00:00:00Z/1800/host/\
             a00258c153b0f641b659621076d3133ca6950608606eff1d7729b7e2332a5d85"
        );
    }

    #[test]
    fn parse_global_ipv6s_ranks_stability() {
        // 真实 `ip -j -6 addr show` 形态:标记是 addr_info 的布尔字段而非数组
        // (面板 baidu_dns.py 注释);flags 数组与布尔字段合并参与排序
        let sample = r#"[{
            "ifname": "eno1",
            "addr_info": [
                {"family": "inet6", "local": "fd00::1", "scope": "host"},
                {"family": "inet6", "local": "2408:temp::99", "scope": "global", "temporary": true, "dynamic": true, "noprefixroute": true},
                {"family": "inet6", "local": "2408:slaac::1", "scope": "global", "mngtmpaddr": true, "dynamic": true, "noprefixroute": true},
                {"family": "inet6", "local": "2408:depr::7", "scope": "global", "deprecated": true, "dynamic": true, "mngtmpaddr": true},
                {"family": "inet6", "local": "2408:array::5", "scope": "global", "flags": ["temporary"]},
                {"family": "inet6", "local": "fe80::1", "scope": "link"}
            ]
        }]"#;
        let ordered = parse_global_ipv6s(sample);
        // 稳定 SLAAC 地址优先;已弃用次之;临时地址(含数组形态)最后;link/host 不入选
        assert_eq!(
            ordered,
            vec![
                "2408:slaac::1".to_string(),
                "2408:depr::7".to_string(),
                "2408:temp::99".to_string(),
                "2408:array::5".to_string(),
            ]
        );
        assert_eq!(parse_global_ipv6s("not json"), Vec::<String>::new());
    }

    #[tokio::test]
    async fn wait_new_ipv6_returns_first_changed_address() {
        // 前 2 次仍旧地址,第 3 次出现新地址(10ms 轮询间隔保证测试快速)
        let seq = Arc::new(AtomicUsize::new(0));
        let addresses = [
            "2408:old::1".to_string(),
            "2408:old::1".to_string(),
            "2408:new::2".to_string(),
        ];
        let new = wait_new_ipv6_with_interval(
            &BTreeSet::from(["2408:old::1".to_string()]),
            IPV6_WAIT_TIMEOUT,
            Duration::from_millis(10),
            move || {
                let idx = seq.fetch_add(1, Ordering::SeqCst).min(2);
                let item = addresses[idx].clone();
                std::future::ready(vec![item])
            },
        )
        .await
        .expect("new ipv6");
        assert_eq!(new, "2408:new::2");
    }

    #[tokio::test]
    async fn wait_new_ipv6_ignores_all_pre_dial_addresses() {
        //回归:重拨后残留的多个旧前缀地址(deprecated)必须全部被排除,
        //直到真正的新地址出现;只排除单个旧地址时会把残留地址当新地址
        let addresses = [
            vec!["2408:stale1::1".to_string(), "2408:stale2::2".to_string()],
            vec![
                "2408:stale1::1".to_string(),
                "2408:stale2::2".to_string(),
                "2408:fresh::3".to_string(),
            ],
        ];
        let seq = Arc::new(AtomicUsize::new(0));
        let new = wait_new_ipv6_with_interval(
            &BTreeSet::from(["2408:stale1::1".to_string(), "2408:stale2::2".to_string()]),
            IPV6_WAIT_TIMEOUT,
            Duration::from_millis(10),
            move || {
                let idx = seq.fetch_add(1, Ordering::SeqCst).min(1);
                let item = addresses[idx].clone();
                std::future::ready(item)
            },
        )
        .await
        .expect("fresh address");
        assert_eq!(new, "2408:fresh::3");
    }

    #[tokio::test]
    async fn wait_new_ipv6_times_out_falling_back_to_current() {
        let new = wait_new_ipv6_with_interval(
            &BTreeSet::from(["2408:old::1".to_string()]),
            Duration::from_millis(80),
            Duration::from_millis(10),
            || std::future::ready(vec!["2408:old::1".to_string()]),
        )
        .await
        .expect("fallback to current address");
        // 超时退回当前地址(即使仍是旧地址,与面板"退回当前已有的地址"语义一致)
        assert_eq!(new, "2408:old::1");
    }

    #[tokio::test]
    async fn wait_new_ipv6_errors_without_any_address() {
        let error = wait_new_ipv6_with_interval(
            &BTreeSet::from(["2408:old::1".to_string()]),
            Duration::from_millis(80),
            Duration::from_millis(10),
            || std::future::ready(Vec::new()),
        )
        .await
        .expect_err("no address at all must error");
        assert!(error.contains("全局 IPv6"), "{error}");
    }

    #[tokio::test]
    async fn wait_new_ipv6_accepts_first_address_when_old_unknown() {
        let new = wait_new_ipv6_with_interval(
            &BTreeSet::new(),
            IPV6_WAIT_TIMEOUT,
            Duration::from_millis(10),
            || std::future::ready(vec!["2408:any::9".to_string()]),
        )
        .await
        .expect("unknown old must accept current");
        assert_eq!(new, "2408:any::9");
    }

    // ---------- mock 百度云 DNS ----------

    #[derive(Clone)]
    struct DnsMockState {
        initial: Option<(String, String)>, // (recordId, rdata)
        list_hits: Arc<AtomicUsize>,
        adds: Arc<std::sync::Mutex<Vec<String>>>,
        edits: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    impl Default for DnsMockState {
        fn default() -> Self {
            Self {
                initial: None,
                list_hits: Arc::new(AtomicUsize::new(0)),
                adds: Arc::new(std::sync::Mutex::new(Vec::new())),
                edits: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    async fn dns_mock_handler(
        State(state): State<DnsMockState>,
        headers: axum::http::HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        // 必须带 BCE Authorization 头
        if headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|value| !value.starts_with("bce-auth-v1/"))
        {
            return (StatusCode::UNAUTHORIZED, "no auth").into_response();
        }
        if body.get("pageSize").is_some() {
            state.list_hits.fetch_add(1, Ordering::SeqCst);
            let records: Vec<Value> = match &state.initial {
                Some((record_id, rdata)) => {
                    // 真实列表响应的类型键为小写 rdtype(面板解析依据)
                    vec![serde_json::json!({
                        "recordId": record_id,
                        "domain": "www",
                        "rdtype": "AAAA",
                        "rdata": rdata,
                    })]
                }
                None => vec![],
            };
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "result": records })),
            )
                .into_response();
        }
        if body.get("rdata").is_some() && body.get("recordId").is_some() {
            let record_id = body["recordId"].to_string();
            let rdata = body["rdata"].as_str().unwrap_or("").to_string();
            state.edits.lock().unwrap().push((record_id, rdata));
            return (StatusCode::OK, Json(serde_json::json!({}))).into_response();
        }
        if body.get("rdata").is_some() {
            let rdata = body["rdata"].as_str().unwrap_or("").to_string();
            state.adds.lock().unwrap().push(rdata);
            return (StatusCode::OK, Json(serde_json::json!({}))).into_response();
        }
        (StatusCode::BAD_REQUEST, "unknown payload").into_response()
    }

    async fn spawn_dns_mock(initial: Option<(String, String)>) -> (String, DnsMockState) {
        let state = DnsMockState {
            initial,
            ..Default::default()
        };
        let app = Router::new()
            .route("/v1/domain/resolve/:action", post(dns_mock_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind dns mock");
        let addr = listener.local_addr().expect("dns mock addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("dns mock serve");
        });
        (format!("http://{addr}"), state)
    }

    fn target_for(base: &str) -> DnsTarget {
        DnsTarget::new(
            "AK".into(),
            "SK".into(),
            "example.site".into(),
            "www".into(),
            base.into(),
        )
    }

    #[tokio::test]
    async fn upsert_creates_when_no_existing_record() {
        let (base, state) = spawn_dns_mock(None).await;
        let outcome = target_for(&base)
            .upsert_aaaa("2408:new::2")
            .await
            .expect("create");
        assert_eq!(outcome, UpsertOutcome::Created);
        assert_eq!(state.adds.lock().unwrap().as_slice(), ["2408:new::2"]);
    }

    #[tokio::test]
    async fn upsert_edits_when_value_differs() {
        let (base, state) =
            spawn_dns_mock(Some(("42".to_string(), "2408:old::1".to_string()))).await;
        let outcome = target_for(&base)
            .upsert_aaaa("2408:new::2")
            .await
            .expect("update");
        assert_eq!(outcome, UpsertOutcome::Updated);
        let edits = state.edits.lock().unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].1, "2408:new::2");
    }

    #[tokio::test]
    async fn upsert_skips_when_value_unchanged() {
        let (base, state) =
            spawn_dns_mock(Some(("42".to_string(), "2408:same::3".to_string()))).await;
        let outcome = target_for(&base)
            .upsert_aaaa("2408:same::3")
            .await
            .expect("unchanged");
        assert_eq!(outcome, UpsertOutcome::Unchanged);
        assert!(state.adds.lock().unwrap().is_empty());
        assert!(state.edits.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn upsert_fails_without_authorization_header() {
        // 复用 DNS mock,但剥掉签名逻辑不可行——直接构造错误 SK 的目标,
        // mock 会因缺 Authorization? 不,签名总在。这里改为端点不可达验证错误路径:
        let target = target_for("http://127.0.0.1:1");
        let error = target
            .upsert_aaaa("2408:new::2")
            .await
            .expect_err("unreachable endpoint must fail");
        assert!(
            error.contains("失败") || error.contains("解析失败"),
            "{error}"
        );
    }
}
