use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    SystemProxy,
    ProxyBypass,
    ProxyOwner,
    HttpsTls,
    ExitRegion,
    ExitStability,
    Dns,
    Route,
    Ipv6,
    Timezone,
    Clock,
    ClientSignature,
    Environment,
    ExistingClients,
    FinalRecheck,
}
impl RuleId {
    pub const ALL: [Self; 15] = [
        Self::SystemProxy,
        Self::ProxyBypass,
        Self::ProxyOwner,
        Self::HttpsTls,
        Self::ExitRegion,
        Self::ExitStability,
        Self::Dns,
        Self::Route,
        Self::Ipv6,
        Self::Timezone,
        Self::Clock,
        Self::ClientSignature,
        Self::Environment,
        Self::ExistingClients,
        Self::FinalRecheck,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::SystemProxy => "系统代理",
            Self::ProxyBypass => "代理旁路",
            Self::ProxyOwner => "代理端口身份",
            Self::HttpsTls => "HTTPS 与证书",
            Self::ExitRegion => "代理出口",
            Self::ExitStability => "短时出口稳定性",
            Self::Dns => "系统 DNS",
            Self::Route => "路由 / TUN",
            Self::Ipv6 => "IPv6 本地配置",
            Self::Timezone => "系统与进程时区",
            Self::Clock => "时钟参考",
            Self::ClientSignature => "官方程序签名",
            Self::Environment => "启动环境冲突",
            Self::ExistingClients => "已有客户端进程",
            Self::FinalRecheck => "检测后复核",
        }
    }
    pub fn core(self) -> bool {
        matches!(
            self,
            Self::SystemProxy
                | Self::ProxyBypass
                | Self::ProxyOwner
                | Self::HttpsTls
                | Self::ExitRegion
                | Self::ExitStability
                | Self::Environment
                | Self::FinalRecheck
        )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Info,
    Warning,
    Fail,
    Skipped,
}
impl Status {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Pass | Self::Info)
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub id: RuleId,
    pub status: Status,
    pub detail: String,
    pub elapsed_ms: u64,
}
impl Check {
    pub fn new(id: RuleId, status: Status, detail: impl Into<String>) -> Self {
        Self {
            id,
            status,
            detail: detail.into(),
            elapsed_ms: 0,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSnapshot {
    pub proxy_fingerprint: String,
    pub owner_pid: u32,
    pub routes: String,
}
/// Never Serialize or Debug: the complete exit IP remains inside the core.
#[derive(Clone)]
pub struct Probe {
    pub country: String,
    pub ip: IpAddr,
    pub duration_ms: u64,
    pub server_time: Option<f64>,
    pub local_midpoint: f64,
    pub sampled_at: u64,
}
#[derive(Clone)]
pub struct Baseline {
    pub local: LocalSnapshot,
    pub exit: Probe,
}
#[derive(Clone)]
pub struct Report {
    pub checks: Vec<Check>,
    pub checked_at: u64,
    pub baseline: Option<Baseline>,
}
impl Report {
    pub fn complete(&self) -> bool {
        self.checks.len() == RuleId::ALL.len()
            && RuleId::ALL
                .iter()
                .all(|id| self.checks.iter().filter(|c| c.id == *id).count() == 1)
            && self
                .checks
                .iter()
                .all(|c| c.status.accepted() && (!c.id.core() || c.status == Status::Pass))
    }
    pub fn fresh(&self, now: u64) -> bool {
        self.complete()
            && self.baseline.as_ref().is_some_and(|b| {
                now >= self.checked_at
                    && now - self.checked_at < 20_000
                    && now >= b.exit.sampled_at
                    && now - b.exit.sampled_at < 20_000
            })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTarget {
    Cli,
    Desktop,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAvailability {
    pub cli: bool,
    pub desktop: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportView {
    pub policy_version: u32,
    pub checks: Vec<Check>,
}
impl From<&Report> for ReportView {
    fn from(r: &Report) -> Self {
        Self {
            policy_version: crate::config::POLICY_VERSION,
            checks: r.checks.clone(),
        }
    }
}
