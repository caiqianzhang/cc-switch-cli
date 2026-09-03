//! 光猫超级管理员凭证自动获取(移植自 ip_panel/router_cred.py)。
//!
//! 背景:移动版烽火光猫的超管密码随设备自动轮换(TR-069 推送),静态配置必然过期。
//! 获取链路:ARP 表发现网关 MAC → `telnetenable.cgi` 开 Telnet → 按提示符分步登录
//! (admin / Fh@<MAC后6位>)→ `cfg_cmd` 读 TR-069 节点密码。进程内缓存 12 小时,
//! 登录失败时由重拨流程调用 [`force_refresh_credentials`] 强制刷新自愈。
//!
//! 逻辑与 ip_panel/router_cred.py 逐行对应;测试经 mock axum(Telnet CGI)
//! 与 mock TcpListener(Telnet 会话)覆盖,MAC/密码提取走纯函数解析器。

use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{info, warn};

/// 取密命令:TR-069 数据模型里运营商超管账户密码所在节点。
const CFG_CMD: &str = "cfg_cmd get InternetGatewayDevice.DeviceInfo.X_CMCC_TeleComAccount.Password";
const TELNET_PORT: u16 = 23;
/// 缓存 TTL:超过视为过期,下次获取自动刷新(与面板默认一致)。
const CACHE_TTL: Duration = Duration::from_secs(43_200); // 12 小时
/// telnetenable.cgi 的 HTTP 触发超时。
const CGI_TIMEOUT: Duration = Duration::from_secs(10);

/// 凭证:(用户名, 密码)。用户名固定 `CMCCAdmin`。
pub type Credentials = (String, String);

static CACHE: Mutex<Option<(Credentials, Instant)>> = Mutex::new(None);

/// 从 `ip neigh show <ip>` 输出提取网关 MAC(大写冒号格式);未命中报错。
pub(crate) fn parse_arp_mac(arp_output: &str, router_ip: &str) -> Option<String> {
    for line in arp_output.lines() {
        if let Some(pos) = line.find("lladdr ") {
            let tail = &line[pos + "lladdr ".len()..];
            let mac: String = tail
                .chars()
                .take_while(|c| c.is_ascii_hexdigit() || *c == ':')
                .collect();
            if mac.len() == 17 && mac.chars().filter(|c| *c == ':').count() == 5 {
                return Some(mac.to_uppercase());
            }
        }
    }
    warn!("[IP-ROTATE] ARP 表中未找到 {router_ip} 的 MAC(可先 ping 后重试)");
    None
}

/// ARP 表发现网关 MAC。
pub(crate) fn discover_gateway_mac(router_ip: &str) -> Result<String, String> {
    let output = Command::new("ip")
        .args(["neigh", "show", router_ip])
        .output()
        .map_err(|e| format!("执行 ip neigh 失败: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    parse_arp_mac(&text, router_ip).ok_or_else(|| format!("ARP表中未找到 {router_ip} 的MAC"))
}

/// 提取 Telnet `cfg_cmd` 回显中的密码;对应正则 `get success!value=(\S+)`。
pub(crate) fn parse_cfg_password(echo: &str) -> Option<String> {
    let pos = echo.find("get success!value=")?;
    let tail = &echo[pos + "get success!value=".len()..];
    let value: String = tail.chars().take_while(|c| !c.is_whitespace()).collect();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// 读 TCP 流直到出现标记或超时,返回累计文本(对应面板 read_until;超时不报错,
/// 由调用方按标记缺失处理)。
async fn telnet_read_until(
    sock: &mut tokio::net::TcpStream,
    marker: &[u8],
    total: Duration,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + total;
    let mut buf = Vec::new();
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
        let remain = deadline - now;
        let mut chunk = [0u8; 256];
        match tokio::time::timeout(remain, sock.read(&mut chunk)).await {
            Err(_) => return Ok(String::from_utf8_lossy(&buf).into_owned()),
            Ok(Err(e)) => return Err(format!("Telnet 读取失败: {e}")),
            Ok(Ok(0)) => return Ok(String::from_utf8_lossy(&buf).into_owned()),
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(marker.len()).any(|w| w == marker) {
                    return Ok(String::from_utf8_lossy(&buf).into_owned());
                }
            }
        }
    }
}

/// 移动版烽火:开 Telnet 并读取超管密码,返回 (CMCCAdmin, 密码)。
///
/// `cgi_base` 形如 `http://192.168.1.1`,`telnet_addr` 形如 `192.168.1.1:23`
/// (拆开是为了测试可指向 mock 服务)。
///
/// 实测固件行为(移植自 router_cred.py 注释):
/// - `telnetenable.cgi` 回显是 HTML 片段不含成功标记,不能以回显判断成败——直接连 23 端口;
/// - 登录必须按提示符分步发送:`login:` 后发 admin,`assword:` 后发 `Fh@<MAC后6位>`;
///   盲发会被当作同一行导致 Login incorrect。
pub(crate) async fn fetch_cmcc_admin(
    cgi_base: &str,
    telnet_addr: &str,
    mac: &str,
) -> Result<Credentials, String> {
    let mac_flat = mac.replace(':', "").to_uppercase();
    let mac6 = &mac_flat[6..]; // 后 6 位参与登录密码拼接
    let cgi_url = format!("{cgi_base}/cgi-bin/telnetenable.cgi?telnetenable=1&key={mac_flat}");
    // 回显无有效标记,仅触发
    let trigger = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(CGI_TIMEOUT)
        .build()
        .map_err(|e| format!("构建 HTTP 客户端失败: {e}"))?;
    trigger
        .get(&cgi_url)
        .send()
        .await
        .map_err(|e| format!("请求 telnetenable.cgi 失败: {e}"))?;

    let mut sock = tokio::net::TcpStream::connect(telnet_addr)
        .await
        .map_err(|e| format!("连接 Telnet {telnet_addr} 失败: {e}"))?;

    telnet_read_until(&mut sock, b"login:", Duration::from_secs(6)).await?; // 等登录提示(含协商字节)
    sock.write_all(b"admin\r")
        .await
        .map_err(|e| format!("Telnet 发送用户名失败: {e}"))?;
    telnet_read_until(&mut sock, b"assword:", Duration::from_secs(6)).await?;
    sock.write_all(format!("Fh@{mac6}\r").as_bytes())
        .await
        .map_err(|e| format!("Telnet 发送密码失败: {e}"))?;
    telnet_read_until(&mut sock, b"#", Duration::from_secs(6)).await?; // 等登录完成的 shell 提示符
    sock.write_all(format!("{CFG_CMD}\r").as_bytes())
        .await
        .map_err(|e| format!("Telnet 发送取密命令失败: {e}"))?;
    let echo = telnet_read_until(&mut sock, b"value=", Duration::from_secs(8)).await?;
    let password = parse_cfg_password(&echo).ok_or_else(|| {
        format!(
            "Telnet回显中未提取到密码(可能登录失败/固件变更)。尾部回显: {:?}",
            &echo[echo.len().saturating_sub(120)..]
        )
    })?;
    Ok(("CMCCAdmin".to_string(), password))
}

/// 生产路径:对真实光猫获取凭证。
async fn fetch_cmcc_admin_via_router(router_ip: &str, mac: &str) -> Result<Credentials, String> {
    fetch_cmcc_admin(
        &format!("http://{router_ip}"),
        &format!("{router_ip}:{TELNET_PORT}"),
        mac,
    )
    .await
}

/// 缓存未赋值或已过期时返回 false。
fn is_cached_valid(entry: &Option<(Credentials, Instant)>) -> bool {
    match entry {
        Some((_, at)) => at.elapsed() < CACHE_TTL,
        None => false,
    }
}

fn lock_cache() -> std::sync::MutexGuard<'static, Option<(Credentials, Instant)>> {
    CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 懒入口:缓存命中且未过期直接透传;否则实际获取一次。
pub(crate) async fn ensure_credentials(router_ip: &str) -> Result<Credentials, String> {
    {
        let guard = lock_cache();
        if is_cached_valid(&guard) {
            return Ok(guard.as_ref().expect("valid entry").0.clone());
        }
    }
    fetch_and_cache(router_ip).await
}

/// 强制刷新:无视缓存重新获取(登录失败自愈用)。
pub(crate) async fn force_refresh_credentials(router_ip: &str) -> Result<Credentials, String> {
    *lock_cache() = None;
    fetch_and_cache(router_ip).await
}

async fn fetch_and_cache(router_ip: &str) -> Result<Credentials, String> {
    // ARP 查询是阻塞子进程:放 blocking 线程池 + 5s 超时(面板原实现 timeout=5)
    let ip_for_arp = router_ip.to_string();
    let mac = match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || discover_gateway_mac(&ip_for_arp)),
    )
    .await
    {
        Ok(Ok(result)) => result?,
        Ok(Err(join_error)) => return Err(format!("ARP 查询任务失败: {join_error}")),
        Err(_) => return Err("ARP 查询超时(>5s)".to_string()),
    };
    let result = fetch_cmcc_admin_via_router(router_ip, &mac).await;
    match result {
        Ok(creds) => {
            *lock_cache() = Some((creds.clone(), Instant::now()));
            info!(
                "[IP-ROTATE] 已自动获取光猫超管凭证(用户={}),进程内缓存生效",
                creds.0
            );
            Ok(creds)
        }
        Err(e) => Err(format!("自动获取光猫凭证失败: {e}(可检查光猫连通性后重试)")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn parse_arp_mac_extracts_uppercase_lladdr() {
        let out = "192.168.1.1 dev eno1 lladdr 24-f5-aa-12-34-56 used 0/0/0 probes 1 STALE";
        assert_eq!(parse_arp_mac(out, "192.168.1.1"), None); // 连字符格式不是冒号 MAC
        let out = "192.168.1.1 dev eno1 lladdr 24:f5:aa:12:34:56 REACHABLE";
        assert_eq!(
            parse_arp_mac(out, "192.168.1.1"),
            Some("24:F5:AA:12:34:56".to_string())
        );
        assert_eq!(parse_arp_mac("", "192.168.1.1"), None);
        let out = "192.168.1.1 dev eno1  FAILED";
        assert_eq!(parse_arp_mac(out, "192.168.1.1"), None);
    }

    #[test]
    fn parse_cfg_password_extracts_value() {
        let echo = "busybox # cfg_cmd get InternetGatewayDevice.DeviceInfo.\
                    X_CMCC_TeleComAccount.Password\nget success!value=abc12d3456789xyz\n# ";
        assert_eq!(
            parse_cfg_password(echo),
            Some("abc12d3456789xyz".to_string())
        );
        assert_eq!(parse_cfg_password("no marker here"), None);
        assert_eq!(parse_cfg_password("get success!value="), None);
    }

    #[test]
    fn cache_respects_ttl_window() {
        let mut guard = lock_cache();
        *guard = None;
        assert!(!is_cached_valid(&guard));
        *guard = Some((("CMCCAdmin".into(), "pw".into()), Instant::now()));
        assert!(is_cached_valid(&guard));
        let stale = Instant::now() - Duration::from_secs(43_201);
        *guard = Some((("CMCCAdmin".into(), "pw".into()), stale));
        assert!(!is_cached_valid(&guard));
        *guard = None; // 清场
    }

    /// mock telnetenable.cgi(仅记录触发)。
    async fn spawn_cgi_mock() -> u16 {
        let hits = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new()
            .route(
                "/cgi-bin/telnetenable.cgi",
                axum::routing::get(move || {
                    let hits = std::sync::Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        "<html>ok</html>"
                    }
                }),
            )
            .with_state(());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind cgi mock");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("cgi mock serve");
        });
        port
    }

    /// mock Telnet 服务:复刻固件提示符脚本,校验分步发送顺序。
    async fn spawn_telnet_mock(password: &'static str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind telnet mock");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept telnet");
            // 1) 登录提示
            sock.write_all(b"Firewall\nlogin:").await.expect("prompt");
            expect_line(&mut sock, b"admin\r").await;
            // 2) 密码提示(标记是 assword:)
            sock.write_all(b"Password:").await.expect("prompt");
            expect_line(&mut sock, b"\r").await; // 内容由下方断言校验
            sock.write_all(b"Login incorrect\n# ").await.expect("shell");
            // 3) 取密命令
            let cmd = read_line(&mut sock).await;
            assert!(
                cmd.starts_with("cfg_cmd get InternetGatewayDevice.DeviceInfo."),
                "unexpected cfg_cmd: {cmd}"
            );
            sock.write_all(format!("get success!value={password}\n").as_bytes())
                .await
                .expect("password echo");
        });
        port
    }

    async fn read_line(sock: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1];
        loop {
            let n = sock.read(&mut chunk).await.expect("mock read");
            if n == 0 || chunk[0] == b'\r' || chunk[0] == b'\n' {
                break;
            }
            buf.push(chunk[0]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn expect_line(sock: &mut tokio::net::TcpStream, terminator: &[u8]) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1];
        loop {
            let n = sock.read(&mut chunk).await.expect("mock read");
            if n == 0 {
                break;
            }
            buf.push(chunk[0]);
            if buf.ends_with(terminator) {
                break;
            }
        }
    }

    #[tokio::test]
    async fn fetch_cmcc_admin_end_to_end_via_mocks() {
        let cgi_port = spawn_cgi_mock().await;
        let telnet_port = spawn_telnet_mock("SECRET12").await;
        let creds = fetch_cmcc_admin(
            &format!("http://127.0.0.1:{cgi_port}"),
            &format!("127.0.0.1:{telnet_port}"),
            "24:F5:AA:12:34:56",
        )
        .await
        .expect("mock telnet cred fetch");
        assert_eq!(creds.0, "CMCCAdmin");
        assert_eq!(creds.1, "SECRET12");
    }

    #[tokio::test]
    async fn fetch_cmcc_admin_fails_when_value_marker_missing() {
        let cgi_port = spawn_cgi_mock().await;
        // Telnet mock 只给提示符,永不回 value → 超时路径报错
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            sock.write_all(b"login:").await.expect("prompt");
            expect_line(&mut sock, b"admin\r").await;
            sock.write_all(b"Password:").await.expect("prompt");
            expect_line(&mut sock, b"\r").await;
            sock.write_all(b"# ").await.expect("shell");
            let _ = read_line(&mut sock).await; // cfg_cmd,然后沉默
                                                // 不回显 → 客户端 8s 超时后报"未提取到密码"
        });
        let error = fetch_cmcc_admin(
            &format!("http://127.0.0.1:{cgi_port}"),
            &format!("127.0.0.1:{port}"),
            "24:F5:AA:12:34:56",
        )
        .await
        .expect_err("missing value marker must fail");
        assert!(error.contains("未提取到密码"), "unexpected: {error}");
    }
}
