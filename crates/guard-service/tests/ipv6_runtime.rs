//! Exercise the real macOS parser + strict local gate through Controller, with
//! recorded command output, virtual time, and a harmless submission counter.
#![cfg(target_os = "macos")]
use guard_core::{config::Profile, domain::*};
use guard_platform::{
    command::{CommandRunner, Output},
    demo::DemoPlatform,
    macos::{ApplicationRegistry, MacPlatform},
    Clock, Fault, Platform,
};
use guard_service::controller::Controller;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
#[derive(Default)]
struct VirtualClock(AtomicU64);
impl Clock for VirtualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn wall_seconds(&self) -> f64 {
        1_800_000_000. + self.now_ms() as f64 / 1000.
    }
}
#[derive(Default)]
struct RecordedRunner {
    mode: AtomicUsize,
    calls: Mutex<Vec<String>>,
}
impl CommandRunner for RecordedRunner {
    fn run(&self, exe: &str, args: &[String], _: Duration) -> Result<Output, Fault> {
        self.calls.lock().unwrap().push(exe.into());
        let mode = self.mode.load(Ordering::SeqCst);
        let stdout = match (exe,args.first().map(String::as_str)) {
            ("/usr/sbin/scutil",Some("--proxy"))=>"HTTPEnable : 1\nHTTPProxy : 127.0.0.1\nHTTPPort : 17890\nHTTPSEnable : 1\nHTTPSProxy : 127.0.0.1\nHTTPSPort : 17890\n".into(),
            ("/usr/sbin/lsof",_)=>"p123\nn127.0.0.1:17890\n".into(),
            ("/bin/ps",Some("-p"))=>"/fixture/proxy".into(),
            ("/sbin/ifconfig",_) if mode==3=>"".into(),
            ("/sbin/ifconfig",_)=>format!("en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet6 fe80::1%en0 prefixlen 64\n\tstatus: active\n{}",if mode==1 {"\tinet6 2001:db8::7 prefixlen 64\n"} else {""}),
            ("/usr/sbin/netstat",_) if args.last().map(String::as_str)==Some("inet6")=>format!("Routing tables\n\nInternet6:\nDestination Gateway Flags Netif Expire\nfe80::%en0/64 link#1 UCI en0\n{}",if mode==2 {"default fe80::1%en0 UG en0\n"} else {""}),
            ("/usr/sbin/netstat",_)=>"default 192.168.1.1 UGScg en0".into(),
            _=>panic!("simulation forbids any other command: {exe}"),
        };
        Ok(Output { code: 0, stdout })
    }
}
struct NoApplications;
impl ApplicationRegistry for NoApplications {
    fn has_running_bundle(&self, _: &str) -> Result<bool, Fault> {
        Ok(false)
    }
}
struct SimulatedPlatform {
    runner: Arc<RecordedRunner>,
    mac: MacPlatform,
    demo: DemoPlatform,
    probes: AtomicUsize,
    submitted: AtomicUsize,
    change_during_preparation: AtomicBool,
    change_on_final_probe: AtomicBool,
}
impl Platform for SimulatedPlatform {
    fn name(&self) -> &'static str {
        "ipv6-simulation"
    }
    fn clients(&self) -> ClientAvailability {
        self.demo.clients()
    }
    fn inspect(&self, id: RuleId, p: &Profile, c: &dyn Clock) -> Check {
        if id == RuleId::Ipv6 {
            self.mac.inspect(id, p, c)
        } else {
            self.demo.inspect(id, p, c)
        }
    }
    fn local(&self, p: &Profile) -> Result<LocalSnapshot, Fault> {
        self.mac.local(p)
    }
    fn probe(&self, p: &Profile, c: &dyn Clock) -> Result<Probe, Fault> {
        let count = self.probes.fetch_add(1, Ordering::SeqCst);
        let probe = self.demo.probe(p, c);
        if count == 3 && self.change_on_final_probe.load(Ordering::SeqCst) {
            self.runner.mode.store(1, Ordering::SeqCst);
        }
        probe
    }
    fn launch(
        &self,
        _: ClientTarget,
        _: &Profile,
        _: &Path,
        _: Option<&Path>,
        authorize: &dyn Fn() -> bool,
    ) -> Result<(), Fault> {
        if self.change_during_preparation.load(Ordering::SeqCst) {
            self.runner.mode.store(1, Ordering::SeqCst);
        }
        if !authorize() {
            return Err(Fault::Client);
        }
        self.submitted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn fixture() -> (Controller, Arc<SimulatedPlatform>, Arc<VirtualClock>) {
    let clock = Arc::new(VirtualClock(AtomicU64::new(100_000)));
    let runner = Arc::new(RecordedRunner::default());
    let platform = Arc::new(SimulatedPlatform {
        mac: MacPlatform::with_dependencies(runner.clone(), Arc::new(NoApplications)),
        runner,
        demo: DemoPlatform::default(),
        probes: AtomicUsize::new(0),
        submitted: AtomicUsize::new(0),
        change_during_preparation: AtomicBool::new(false),
        change_on_final_probe: AtomicBool::new(false),
    });
    let profile = Profile {
        schema_version: 1,
        proxy_url: "http://127.0.0.1:17890".into(),
        expected_country: None,
        expected_proxy_executable: "/fixture/proxy".into(),
        non_mainland_timezone: false,
    };
    (
        Controller::new(platform.clone(), clock.clone(), profile, false).unwrap(),
        platform,
        clock,
    )
}
#[test]
fn unresolved_ipv6_never_probes_or_submits_either_client() {
    for mode in [1, 2, 3] {
        let (controller, platform, _) = fixture();
        platform.runner.mode.store(mode, Ordering::SeqCst);
        let report = controller.scan().unwrap();
        assert!(!report.complete());
        assert!(report.checks.iter().all(|c| c.status != Status::Fail));
        assert_eq!(
            report
                .checks
                .iter()
                .find(|c| c.id == RuleId::HttpsTls)
                .unwrap()
                .status,
            Status::Skipped
        );
        assert_eq!(
            report
                .checks
                .iter()
                .find(|c| c.id == RuleId::Ipv6)
                .unwrap()
                .status,
            Status::Warning
        );
        for target in [ClientTarget::Cli, ClientTarget::Desktop] {
            assert!(controller
                .launch(target, Path::new("/fixture/checker"), None)
                .is_err());
        }
        assert_eq!(platform.probes.load(Ordering::SeqCst), 0);
        assert_eq!(platform.submitted.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn runtime_ipv6_change_notifies_once_and_stable_recovery_never_unlocks_launch() {
    for mode in [1, 2, 3] {
        let (controller, platform, clock) = fixture();
        assert!(controller.scan().unwrap().complete());
        assert!(controller.snapshot().can_launch);
        platform.runner.mode.store(mode, Ordering::SeqCst);
        for at in (105_000..=130_000).step_by(5_000) {
            clock.0.store(at, Ordering::SeqCst);
            controller.tick();
        }
        let notices = controller.take_notices();
        assert_eq!(notices.len(), 1);
        assert!(controller
            .snapshot()
            .issue
            .as_ref()
            .unwrap()
            .contains("IPv6"));
        assert!(!controller.snapshot().can_launch);
        assert_eq!(platform.probes.load(Ordering::SeqCst), 4);
        platform.runner.mode.store(0, Ordering::SeqCst);
        for at in (135_000..=200_000).step_by(5_000) {
            clock.0.store(at, Ordering::SeqCst);
            controller.tick();
        }
        assert!(controller.snapshot().issue.is_none());
        assert!(!controller.snapshot().can_launch);
        assert!(controller.snapshot().requires_recheck);
        let text = serde_json::to_string(&controller.snapshot()).unwrap();
        assert!(!text.contains("2001:db8"));
        assert_eq!(platform.submitted.load(Ordering::SeqCst), 0);
        assert!(controller.scan().unwrap().complete());
        assert!(controller.snapshot().can_launch);
    }
}
#[test]
fn ipv6_appearing_during_launch_preparation_invalidates_final_authorization() {
    for target in [ClientTarget::Cli, ClientTarget::Desktop] {
        let (controller, platform, _) = fixture();
        assert!(controller.scan().unwrap().complete());
        platform
            .change_during_preparation
            .store(true, Ordering::SeqCst);
        assert!(controller
            .launch(target, Path::new("/fixture/checker"), None)
            .is_err());
        assert_eq!(platform.submitted.load(Ordering::SeqCst), 0);
        assert!(!controller.snapshot().can_launch);
        assert!(controller.snapshot().requires_recheck);
        assert!(controller
            .snapshot()
            .issue
            .as_ref()
            .unwrap()
            .contains("IPv6"));
    }
}

#[test]
fn ipv6_appearing_after_final_probe_is_uncertainty_and_never_a_successful_baseline() {
    let (controller, platform, _) = fixture();
    platform.change_on_final_probe.store(true, Ordering::SeqCst);
    let report = controller.scan().unwrap();
    assert!(!report.complete());
    assert!(report.baseline.is_none());
    assert_eq!(
        report
            .checks
            .iter()
            .find(|c| c.id == RuleId::FinalRecheck)
            .unwrap()
            .status,
        Status::Warning
    );
    assert!(report.checks.iter().all(|c| c.status != Status::Fail));
    assert!(!controller.snapshot().can_launch);
    assert_eq!(platform.submitted.load(Ordering::SeqCst), 0);
}
