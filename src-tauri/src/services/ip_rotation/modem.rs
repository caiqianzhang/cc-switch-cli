//! 光猫 Web CGI 客户端:登录 + PPPoE 重拨(移植自 ip_panel/redial.py)。
//!
//! 并发由调用方保证:cc-switch 侧 inflight 单飞已确保同一时刻只有一个重拨任务;
//! 光猫只允许一个管理会话,若 ip_panel 同时在运行请将其停用。
//!
//! 协议要点(与 redial.py 逐行对应):
//! - 先 `GET /` 预热会话,`get_login_user` 拿 sessionid;
//! - `do_login` 以 base64(密码) 表单登录,`login_result==0` 视为成功;
//! - 每次写操作前重新取 sessionid;`wan_modify` 携带整张 WAN 参数表,仅
//!   `Manual_Setting`(2=断开,1=连接)与 PPPoE 用户名/密码可变;
//! - `get_allwan_info` 按 WAN 连接名查询连接状态与外网地址。
//! - 面板用 requests.Session 自动携带 Cookie;reqwest 未启用 cookie store,
//!   改为手动捕获登录 Set-Cookie 并在后续请求回放。

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::header::{COOKIE, SET_COOKIE};
use serde_json::Value;

use super::{debug, warn};

/// WAN 连接名(移动版固件 4031 VLAN 的互联网连接)。
pub(crate) const WAN_NAME_DEFAULT: &str = "4_INTERNET_R_VID_4031";
/// 断开等待超时(秒)。
pub(crate) const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// 连接等待超时(秒)。
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
/// WAN 状态轮询间隔。
const WAN_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// 光猫返回 `10_point_102_…` 编码;还原为点分十进制(移植 helpers.decode_point_ip)。
pub(crate) fn decode_point_ip(raw: &str) -> String {
    raw.replace("_point_", ".")
}

/// 请求缓存穿透参数(对应 Python `random.random()` 浮点串)。
fn cache_buster() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("0.{nanos:09}")
}

/// WAN 参数表:移植自 redial.py `build_wan_params`,常量字段与面板完全一致,
/// 仅 Username/Password(PPPoE 拨号账号)与 Manual_Setting 可变。
fn build_wan_params(
    wan_name: &str,
    pppoe_username: &str,
    pppoe_password_b64: &str,
    session_id: &str,
    manual_setting: &str,
) -> Vec<(String, String)> {
    vec![
        ("wan_name_old".into(), wan_name.into()),
        ("wan_index".into(), "1".into()),
        ("wan_session_index".into(), "1".into()),
        ("wan_iporppp_old".into(), "2".into()),
        ("wan_iporppp_new".into(), "2".into()),
        ("ConnectionType".into(), "PPPoE_Routed".into()),
        ("ServiceList".into(), "INTERNET".into()),
        ("IPMode".into(), "3".into()),
        ("mtu".into(), "1492".into()),
        ("MulticastVlan".into(), "-1".into()),
        ("VLANEnabled".into(), "2".into()),
        ("vlanid".into(), "4031".into()),
        ("DHCPEnabled".into(), "1".into()),
        ("p8021".into(), "0".into()),
        (
            "LanInterface".into(),
            "dev.eth.1,dev.eth.2,dev.eth.3,dev.eth.4,dev.wla.1".into(),
        ),
        ("AddressingType".into(), "PPPoE".into()),
        ("Username".into(), pppoe_username.into()),
        ("Password".into(), pppoe_password_b64.into()),
        ("ConnectionTrigger".into(), "Manual".into()),
        ("IPv6PrefixDelegationEnabled".into(), "1".into()),
        ("IPv6PrefixOrigin".into(), "PrefixDelegation".into()),
        ("IPv6IPAddressOrigin".into(), "AutoConfigured".into()),
        ("Dslite_Enable".into(), "0".into()),
        ("NATEnabled".into(), "1".into()),
        ("NPTv6Enable".into(), "0".into()),
        ("userData".into(), "admin".into()),
        ("Manual_Setting".into(), manual_setting.into()),
        ("ajaxmethod".into(), "wan_modify".into()),
        ("sessionid".into(), session_id.into()),
        ("_".into(), cache_buster()),
    ]
}

/// 光猫 CGI 客户端。
pub(crate) struct ModemClient {
    http: reqwest::Client,
    base: String,
    /// do_login 后捕获的 Cookie(k=v 列表),后续请求回放。
    cookies: Mutex<Vec<String>>,
}

impl ModemClient {
    pub(crate) fn new(base: &str) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("构建光猫 HTTP 客户端失败: {e}"))?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            cookies: Mutex::new(Vec::new()),
        })
    }

    fn cookie_header(&self) -> Option<String> {
        let guard = self.cookies.lock().unwrap_or_else(|p| p.into_inner());
        (!guard.is_empty()).then(|| guard.join("; "))
    }

    /// 从 Set-Cookie 捕获 k=v(只取第一个分号前的属性段),并按 cookie 名
    /// 替换旧值(模拟 requests.Session 的 jar 语义;登录重试时避免重复 SID)。
    fn capture_cookies(&self, response: &reqwest::Response) {
        let mut captured = Vec::new();
        for value in response.headers().get_all(SET_COOKIE) {
            if let Ok(text) = value.to_str() {
                let pair = text.split(';').next().unwrap_or("").trim();
                if !pair.is_empty() && pair.contains('=') {
                    captured.push(pair.to_string());
                }
            }
        }
        if captured.is_empty() {
            return;
        }
        let mut jar = self.cookies.lock().unwrap_or_else(|p| p.into_inner());
        for pair in captured {
            let name = pair.split('=').next().unwrap_or("").trim().to_string();
            jar.retain(|existing| existing.split('=').next().unwrap_or("").trim() != name);
            jar.push(pair);
        }
    }

    /// `get_login_user` 获取会话 ID。
    async fn get_session_id(&self) -> Result<String, String> {
        let url = format!(
            "{base}/cgi-bin/ajax?ajaxmethod=get_login_user&_={rand}",
            base = self.base,
            rand = cache_buster()
        );
        let mut request = self.http.get(&url).timeout(Duration::from_secs(5));
        if let Some(cookie) = self.cookie_header() {
            request = request.header(COOKIE, cookie);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("请求 get_login_user 失败: {e}"))?;
        self.capture_cookies(&response);
        let body: Value = response
            .json()
            .await
            .map_err(|e| format!("get_login_user 响应解析失败: {e}"))?;
        body.get("sessionid")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "get_login_user 响应缺少 sessionid".to_string())
    }

    /// 登录光猫后台。`Ok(false)` 表示凭证被拒(login_result != 0),网络错误返回 Err。
    pub(crate) async fn login(&self, username: &str, password: &str) -> Result<bool, String> {
        // 会话预热(对应 login() 首个 GET ROUTER_URL)
        let warmup = format!("{base}/", base = self.base);
        let warmup_response = self
            .http
            .get(&warmup)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| format!("光猫 {} 不可达: {e}", self.base))?;
        self.capture_cookies(&warmup_response);

        let session_id = self.get_session_id().await?;
        use base64::Engine;
        let password_b64 = base64::engine::general_purpose::STANDARD.encode(password.as_bytes());
        // 与面板一致:do_login 的 ajaxmethod/_ 仅在表单体中,不在查询串
        let url = format!("{base}/cgi-bin/ajax", base = self.base);
        let mut request = self.http.post(&url).timeout(Duration::from_secs(5)).form(&[
            ("ajaxmethod", "do_login"),
            ("username", username),
            ("password", password_b64.as_str()),
            ("page", "1"),
            ("sessionid", session_id.as_str()),
            ("_", cache_buster().as_str()),
        ]);
        if let Some(cookie) = self.cookie_header() {
            request = request.header(COOKIE, cookie);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("请求 do_login 失败: {e}"))?;
        self.capture_cookies(&response);
        let body: Value = response
            .json()
            .await
            .map_err(|e| format!("do_login 响应解析失败: {e}"))?;
        Ok(body.get("login_result").and_then(Value::as_i64) == Some(0))
    }

    /// 提交 Manual_Setting(2=断开,1=连接);每次写操作前重新取 sessionid。
    pub(crate) async fn send_manual_setting(
        &self,
        wan_name: &str,
        pppoe_username: &str,
        pppoe_password_b64: &str,
        manual_setting: &str,
    ) -> Result<(), String> {
        let session_id = self.get_session_id().await?;
        let params = build_wan_params(
            wan_name,
            pppoe_username,
            pppoe_password_b64,
            &session_id,
            manual_setting,
        );
        let url = format!("{base}/cgi-bin/ajax", base = self.base);
        let mut request = self
            .http
            .post(&url)
            .timeout(Duration::from_secs(60))
            .form(&params);
        if let Some(cookie) = self.cookie_header() {
            request = request.header(COOKIE, cookie);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("提交 wan_modify({manual_setting}) 失败: {e}"))?;
        self.capture_cookies(&response);
        if !response.status().is_success() {
            return Err(format!(
                "wan_modify({manual_setting}) HTTP {}",
                response.status()
            ));
        }
        debug!("[IP-ROTATE] wan_modify({manual_setting}) 已提交");
        Ok(())
    }

    /// 查询 WAN 连接状态与外网 IPv4。
    pub(crate) async fn get_wan_status(&self, wan_name: &str) -> Result<(String, String), String> {
        let url = format!(
            "{base}/cgi-bin/ajax?ajaxmethod=get_allwan_info&_={rand}",
            base = self.base,
            rand = cache_buster()
        );
        let mut request = self.http.get(&url).timeout(Duration::from_secs(10));
        if let Some(cookie) = self.cookie_header() {
            request = request.header(COOKIE, cookie);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("请求 get_allwan_info 失败: {e}"))?;
        self.capture_cookies(&response);
        let body: Value = response
            .json()
            .await
            .map_err(|e| format!("get_allwan_info 响应解析失败: {e}"))?;
        let entries = body
            .get("wan")
            .and_then(Value::as_array)
            .ok_or_else(|| "get_allwan_info 响应缺少 wan 数组".to_string())?;
        for entry in entries {
            if entry.get("Name").and_then(Value::as_str) == Some(wan_name) {
                return Ok((
                    entry
                        .get("ConnectionStatus")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    entry
                        .get("ExternalIPAddress")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                ));
            }
        }
        Err(format!("get_allwan_info 中未找到 WAN 连接 {wan_name}"))
    }

    /// 轮询直到 WAN 状态达到 target 或超时(对应 wait_status)。
    pub(crate) async fn wait_status(
        &self,
        wan_name: &str,
        target: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.get_wan_status(wan_name).await {
                Ok((status, _)) if status == target => return Ok(()),
                Ok((status, _)) => debug!("[IP-ROTATE] WAN 状态: {status},等待 {target}"),
                Err(error) => warn!("[IP-ROTATE] WAN 状态查询失败: {error}"),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "等待光猫 WAN {target} 超时(>{}s)",
                    timeout.as_secs()
                ));
            }
            tokio::time::sleep(WAN_POLL_INTERVAL).await;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// 断言参数表与面板 build_wan_params 完全一致。
    #[test]
    fn build_wan_params_matches_panel_table() {
        let params = build_wan_params("4_INTERNET_R_VID_4031", "user", "cGFzcw==", "sid", "2");
        let get = |k: &str| {
            params
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("Manual_Setting"), "2");
        assert_eq!(get("ajaxmethod"), "wan_modify");
        assert_eq!(get("sessionid"), "sid");
        assert_eq!(get("ConnectionType"), "PPPoE_Routed");
        assert_eq!(get("ServiceList"), "INTERNET");
        assert_eq!(get("IPMode"), "3");
        assert_eq!(get("mtu"), "1492");
        assert_eq!(get("VLANEnabled"), "2");
        assert_eq!(get("vlanid"), "4031");
        assert_eq!(get("DHCPEnabled"), "1");
        assert_eq!(get("AddressingType"), "PPPoE");
        assert_eq!(get("Username"), "user");
        assert_eq!(get("Password"), "cGFzcw==");
        assert_eq!(get("ConnectionTrigger"), "Manual");
        assert_eq!(get("IPv6PrefixDelegationEnabled"), "1");
        assert_eq!(get("IPv6PrefixOrigin"), "PrefixDelegation");
        assert_eq!(get("IPv6IPAddressOrigin"), "AutoConfigured");
        assert_eq!(get("NATEnabled"), "1");
        assert_eq!(get("userData"), "admin");
        assert_eq!(get("wan_name_old"), "4_INTERNET_R_VID_4031");
        assert_eq!(
            get("LanInterface"),
            "dev.eth.1,dev.eth.2,dev.eth.3,dev.eth.4,dev.wla.1"
        );
        assert!(get("_").starts_with("0."));
    }

    #[test]
    fn cache_buster_is_float_like_and_changes() {
        let a = cache_buster();
        assert!(a.starts_with("0.") && a.len() > 3, "{a}");
        assert_ne!(a, cache_buster());
    }

    // ---------- mock 光猫 CGI ----------

    #[derive(Default)]
    pub(crate) struct MockState {
        pub login_hits: AtomicUsize,
        pub redials: AtomicUsize,
        pub connected: AtomicBool,
        /// 登录后是否发过 Set-Cookie(校验 Cookie 回放)
        pub cookie_issued: AtomicBool,
    }

    fn url_decode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn parse_form(body: &str) -> Vec<(String, String)> {
        body.split('&')
            .filter_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                Some((
                    url_decode(&key.replace('+', " ")),
                    url_decode(&value.replace('+', " ")),
                ))
            })
            .collect()
    }

    fn form_value<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// 启动 mock 光猫 CGI,返回 (基地址, 状态)。
    /// `good_password_b64` 为 base64 编码后的正确口令;do_login 成功后
    /// Set-Cookie SID=mock-session;wan_modify 必须携带该 Cookie,
    /// Manual_Setting=2 后 WAN 置 Disconnected,=1 后置 Connected 并给出新 IP。
    pub(crate) async fn spawn_mock_modem(good_password_b64: &str) -> (String, Arc<MockState>) {
        use axum::extract::State;
        use axum::http::{HeaderMap, Method, StatusCode, Uri};
        use axum::response::IntoResponse;
        use axum::routing::any;
        use axum::{Json, Router};

        let good_password = good_password_b64.to_string();
        let ajax = move |State(state): State<Arc<MockState>>,
                         method: Method,
                         uri: Uri,
                         headers: HeaderMap,
                         body: String| async move {
            let query = uri.query().unwrap_or("");
            let form = parse_form(&body);
            // 分发依据表单体里的 ajaxmethod(与真实固件一致,do_login 无查询串)
            let form_method = form_value(&form, "ajaxmethod").unwrap_or("");
            if method == Method::POST && form_method == "do_login" {
                state.login_hits.fetch_add(1, Ordering::SeqCst);
                let password = form_value(&form, "password").unwrap_or("");
                if password != good_password {
                    return (StatusCode::OK, Json(serde_json::json!({"login_result": 1})))
                        .into_response();
                }
                state.cookie_issued.store(true, Ordering::SeqCst);
                let mut response =
                    (StatusCode::OK, Json(serde_json::json!({"login_result": 0}))).into_response();
                response.headers_mut().append(
                    SET_COOKIE,
                    "SID=mock-session; Path=/"
                        .parse()
                        .expect("valid set-cookie"),
                );
                return response;
            }
            if method == Method::POST {
                // wan_modify:必须携带登录 Cookie(模拟 requests.Session 行为)
                let has_cookie = headers
                    .get(COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|cookies| {
                        cookies
                            .split(';')
                            .any(|pair| pair.trim() == "SID=mock-session")
                    });
                if !has_cookie {
                    return (StatusCode::UNAUTHORIZED, "no session").into_response();
                }
                state.redials.fetch_add(1, Ordering::SeqCst);
                let manual = form_value(&form, "Manual_Setting").unwrap_or("");
                state.connected.store(manual == "1", Ordering::SeqCst);
                return (StatusCode::OK, Json(serde_json::json!({"result": 0}))).into_response();
            }
            if query.contains("get_login_user") {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({"sessionid": "sess-1"})),
                )
                    .into_response();
            }
            if query.contains("get_allwan_info") {
                let connected = state.connected.load(Ordering::SeqCst);
                let (status, ip) = if connected {
                    ("Connected", "100.66.77.88")
                } else {
                    ("Disconnected", "0.0.0.0")
                };
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({"wan": [
                        {"Name": "1_INTERNET_R_VID_201", "ConnectionStatus": "Disconnected", "ExternalIPAddress": "0.0.0.0"},
                        {"Name": WAN_NAME_DEFAULT, "ConnectionStatus": status, "ExternalIPAddress": ip},
                    ]})),
                )
                    .into_response();
            }
            (StatusCode::NOT_FOUND, "unknown ajaxmethod").into_response()
        };

        // 单一状态实例:路由与返回值共享,调用方断言的是真实计数
        let state = Arc::new(MockState::default());
        let app = Router::new()
            .route("/cgi-bin/ajax", any(ajax))
            .route("/", axum::routing::get(|| async { "warmup" }))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock modem");
        let addr = listener.local_addr().expect("mock modem addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock modem serve");
        });
        (format!("http://{addr}"), state)
    }

    fn client_for(base: &str) -> ModemClient {
        ModemClient::new(base).expect("modem client")
    }

    #[tokio::test]
    async fn login_success_captures_and_replays_cookie() {
        let (base, state) = spawn_mock_modem("cHc=").await; // base64("pw")
        let client = client_for(&base);
        assert!(client.login("CMCCAdmin", "pw").await.expect("login ok"));
        assert_eq!(state.login_hits.load(Ordering::SeqCst), 1);
        // wan_modify 需要 Cookie 回放才能通过(否则 401 → Err)
        client
            .send_manual_setting(WAN_NAME_DEFAULT, "u", "cHc=", "2")
            .await
            .expect("wan_modify with replayed cookie");
        assert_eq!(state.redials.load(Ordering::SeqCst), 1);
        assert!(!state.connected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn login_rejects_wrong_password_without_cookie() {
        let (base, state) = spawn_mock_modem("cHc=").await;
        let client = client_for(&base);
        assert!(
            !client.login("CMCCAdmin", "bad").await.expect("login call"),
            "wrong password must return Ok(false)"
        );
        assert!(!state.cookie_issued.load(Ordering::SeqCst));
        // 未登录 → wan_modify 因缺 Cookie 被 mock 拒绝
        let error = client
            .send_manual_setting(WAN_NAME_DEFAULT, "u", "cHc=", "2")
            .await
            .expect_err("no-cookie wan_modify must fail");
        assert!(error.contains("401"), "unexpected: {error}");
    }

    #[tokio::test]
    async fn wan_status_and_wait_follow_state_machine() {
        let (base, _state) = spawn_mock_modem("cHc=").await;
        let client = client_for(&base);
        assert!(client.login("CMCCAdmin", "pw").await.expect("login"));
        client
            .send_manual_setting(WAN_NAME_DEFAULT, "u", "cHc=", "2")
            .await
            .expect("disconnect");
        let (status, ip) = client
            .get_wan_status(WAN_NAME_DEFAULT)
            .await
            .expect("status");
        assert_eq!(status, "Disconnected");
        assert_eq!(ip, "0.0.0.0");
        client
            .wait_status(WAN_NAME_DEFAULT, "Disconnected", DISCONNECT_TIMEOUT)
            .await
            .expect("wait disconnected");

        client
            .send_manual_setting(WAN_NAME_DEFAULT, "u", "cHc=", "1")
            .await
            .expect("connect");
        client
            .wait_status(WAN_NAME_DEFAULT, "Connected", CONNECT_TIMEOUT)
            .await
            .expect("wait connected");
        let (status, ip) = client
            .get_wan_status(WAN_NAME_DEFAULT)
            .await
            .expect("status2");
        assert_eq!(status, "Connected");
        assert_eq!(ip, "100.66.77.88");
    }

    #[tokio::test]
    async fn wait_status_times_out_when_target_never_reached() {
        let (base, _state) = spawn_mock_modem("cHc=").await;
        let client = client_for(&base);
        assert!(client.login("CMCCAdmin", "pw").await.expect("login"));
        // 初始 Disconnected:等 Connected 且超时 0 → 立即报超时
        let error = client
            .wait_status(WAN_NAME_DEFAULT, "Connected", Duration::from_secs(0))
            .await
            .expect_err("never-connected must time out");
        assert!(error.contains("超时"), "unexpected: {error}");
    }
}
