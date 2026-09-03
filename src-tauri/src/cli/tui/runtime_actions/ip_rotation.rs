use crate::cli::i18n::texts;
use crate::error::AppError;

use super::super::app::ToastKind;
use super::RuntimeActionContext;

/// 手动换 IP:经 daemon IPC 转发给代理 worker,与自动 429 触发共用单飞。
/// 结果(Queued/Busy/…)由 worker 写入 daemon 日志,这里只反馈提交状态。
pub(super) fn request_manual_rotate(ctx: &mut RuntimeActionContext<'_>) -> Result<(), AppError> {
    match crate::services::ip_rotation::manual::request_via_daemon() {
        Ok(queued) => {
            let pids = queued
                .worker_pids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            ctx.app.push_toast(
                format!(
                    "{} (worker pid: {pids})",
                    texts::tui_toast_rotate_ip_submitted()
                ),
                ToastKind::Success,
            );
            Ok(())
        }
        Err(message) => {
            ctx.app.push_toast(
                format!("{}: {message}", texts::tui_toast_rotate_ip_failed()),
                ToastKind::Warning,
            );
            Ok(())
        }
    }
}
