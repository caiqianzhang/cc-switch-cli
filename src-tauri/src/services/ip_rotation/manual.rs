//! 手动换 IP 触发入口:CLI 与 TUI 共用,经 daemon IPC 转发给代理 worker。
//!
//! 执行体在 worker 进程内(与自动 429 触发同一个 [`IpRotationHandle`]),
//! 与自动触发共享单飞门控;实际执行结果(Queued/Busy/…)由 worker 写入
//! daemon 日志,本模块的返回值只表示"信号已被 daemon 接受"。

use crate::daemon::ipc::client;
use crate::daemon::ipc::protocol::{Request, Response};

/// 手动触发已被 daemon 接受(worker 信号已发出)。
pub struct RotateIpQueued {
    /// 收到信号的 worker pid 列表。
    pub worker_pids: Vec<u32>,
}

/// 向运行中的 daemon 请求手动换 IP。
///
/// daemon 未运行、无 worker 或信号发送失败时返回 `Err`(内容可直接展示)。
pub fn request_via_daemon() -> Result<RotateIpQueued, String> {
    let socket = crate::daemon::paths::socket_path();
    let response = match client::round_trip(&socket, &Request::RotateIp) {
        Ok(response) => response,
        Err(error) => {
            let en = format!("daemon control socket error: {error}");
            let zh = format!("daemon 控制套接字通信失败：{error}");
            return Err(crate::t!(en, zh));
        }
    };
    match response {
        Response::RotateIpQueued { worker_pids } => Ok(RotateIpQueued { worker_pids }),
        Response::Error { message } => Err(message),
        other => {
            let en = format!("unexpected daemon response: {other:?}");
            let zh = format!("daemon 返回意外响应：{other:?}");
            Err(crate::t!(en, zh))
        }
    }
}
