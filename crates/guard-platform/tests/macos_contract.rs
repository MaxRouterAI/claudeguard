#![allow(clippy::field_reassign_with_default)] // Fixtures deliberately mutate one policy input at a time.
#![cfg(target_os = "macos")]
use guard_core::domain::{RuleId, Status};
use guard_platform::{
    command::{CommandRunner, Output, SystemRunner},
    macos::{ApplicationRegistry, MacPlatform, DESKTOP_ID},
    Clock, Fault, Platform,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
struct FixedClock;
impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        100_000
    }
    fn wall_seconds(&self) -> f64 {
        1_800_000_000.0
    }
}
struct Runner {
    dns: String,
    proxy: String,
    owner: String,
    exe: String,
    calls: Mutex<Vec<(String, Vec<String>)>>,
}
impl Runner {
    fn new() -> Self {
        Self{dns:"nameserver[0] : 192.168.1.1".into(),proxy:"HTTPEnable : 1\nHTTPProxy : 127.0.0.1\nHTTPPort : 17890\nHTTPSEnable : 1\nHTTPSProxy : 127.0.0.1\nHTTPSPort : 17890\n".into(),owner:"p123\ncFixtureProxy\nn127.0.0.1:17890".into(),exe:fixture_profile().expected_proxy_executable,calls:Mutex::default()}
    }
}
impl CommandRunner for Runner {
    fn run(&self, exe: &str, args: &[String], _: Duration) -> Result<Output, Fault> {
        self.calls.lock().unwrap().push((exe.into(), args.to_vec()));
        let raw = match (exe, args.first().map(String::as_str)) {
            ("/usr/sbin/scutil", Some("--dns")) => self.dns.clone(),
            ("/usr/sbin/scutil", Some("--proxy")) => self.proxy.clone(),
            ("/usr/sbin/lsof", _) => self.owner.clone(),
            ("/bin/ps", Some("-p")) => self.exe.clone(),
            ("/usr/sbin/netstat", _) => "default 192.168.1.1 UGScg en0".into(),
            ("/usr/bin/curl", _) => {
                "ip=203.0.113.1\nloc=US\nts=1800000000\nCHECK_META:200:127.0.0.1:0.02:0".into()
            }
            _ => return Err(Fault::Local),
        };
        Ok(Output {
            code: 0,
            stdout: raw,
        })
    }
}
struct Applications {
    ids: Vec<String>,
}
impl ApplicationRegistry for Applications {
    fn has_running_bundle(&self, id: &str) -> Result<bool, Fault> {
        Ok(self.ids.iter().any(|v| v == id))
    }
}
fn platform(r: Arc<Runner>) -> MacPlatform {
    MacPlatform::with_dependencies(r, Arc::new(Applications { ids: vec![] }))
}
#[test]
fn empty_or_garbage_dns_is_not_accepted() {
    for raw in [
        "",
        "nameserver[0] : garbage",
        "nameserver[0] : 192.168.1.1\0",
        "resolver #1",
    ] {
        let mut r = Runner::new();
        r.dns = raw.into();
        assert_eq!(
            platform(Arc::new(r))
                .inspect(RuleId::Dns, &fixture_profile(), &FixedClock)
                .status,
            Status::Warning
        );
    }
    assert_eq!(
        platform(Arc::new(Runner::new()))
            .inspect(RuleId::Dns, &fixture_profile(), &FixedClock)
            .status,
        Status::Info
    );
}
#[test]
fn local_requires_matching_owner_not_only_an_open_port() {
    let mut r = Runner::new();
    r.exe = "/tmp/other-listener".into();
    assert!(platform(Arc::new(r)).local(&fixture_profile()).is_err());
    assert!(platform(Arc::new(Runner::new()))
        .local(&fixture_profile())
        .is_ok());
}
#[test]
fn ambiguous_listener_and_pac_are_blocked() {
    let mut r = Runner::new();
    r.owner.push_str("\np999\nn127.0.0.1:17890");
    assert!(platform(Arc::new(r)).local(&fixture_profile()).is_err());
    let mut r = Runner::new();
    r.proxy.push_str("ProxyAutoConfigEnable : 1");
    assert!(platform(Arc::new(r)).local(&fixture_profile()).is_err());
}
#[test]
fn probe_uses_only_fixed_cloudflare_and_explicit_profile_proxy() {
    let r = Arc::new(Runner::new());
    let p = platform(r.clone());
    assert!(p.probe(&fixture_profile(), &FixedClock).is_ok());
    let calls = r.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "/usr/bin/curl");
    assert_eq!(calls[0].1, fixture_profile().curl_arguments());
}
#[test]
fn renamed_or_moved_desktop_is_blocked_by_bundle_identity() {
    // Registry records identity independently of executable or bundle location.
    let p = MacPlatform::with_dependencies(
        Arc::new(Runner::new()),
        Arc::new(Applications {
            ids: vec![DESKTOP_ID.into()],
        }),
    );
    assert!(p.ensure_desktop_not_running().is_err());
    assert!(platform(Arc::new(Runner::new()))
        .ensure_desktop_not_running()
        .is_ok());
}
#[test]
fn inspection_runner_never_accepts_a_client_or_a_shell() {
    for exe in [
        "/Applications/Claude.app/Contents/MacOS/Claude",
        "/usr/local/bin/claude",
        "/bin/zsh",
        "/usr/bin/open",
    ] {
        assert!(SystemRunner.run(exe, &[], Duration::ZERO).is_err());
    }
}
#[test]
fn static_signature_has_its_own_budget_and_never_executes_target() {
    use guard_core::domain::ClientTarget;
    use std::path::Path;
    struct SignatureRunner;
    impl CommandRunner for SignatureRunner {
        fn run(&self, exe: &str, args: &[String], timeout: Duration) -> Result<Output, Fault> {
            assert_eq!(exe, "/usr/bin/codesign");
            assert_eq!(timeout, Duration::from_secs(15));
            assert_eq!(&args[..3], ["--verify", "--strict", "-R"]);
            assert_eq!(args.last().unwrap(), "/fixture/client.app");
            assert!(args[3].contains("Q6L2SF6YDW"));
            assert!(args[3].contains("com.anthropic.claudefordesktop"));
            Ok(Output {
                code: 0,
                stdout: String::new(),
            })
        }
    }
    let platform = MacPlatform::with_dependencies(
        Arc::new(SignatureRunner),
        Arc::new(Applications { ids: vec![] }),
    );
    assert!(platform
        .verify_file(Path::new("/fixture/client.app"), ClientTarget::Desktop)
        .is_ok());
    let args = fixture_profile().curl_arguments();
    assert!(args.windows(2).any(|a| a == ["--max-filesize", "65536"]));
}

#[cfg(test)]
fn fixture_profile() -> guard_core::config::Profile {
    guard_core::config::Profile {
        schema_version: 1,
        proxy_url: "http://127.0.0.1:17890".into(),
        expected_country: Some("US".into()),
        expected_proxy_executable: "/fixture/proxy".into(),
        non_mainland_timezone: true,
    }
}

#[test]
fn discovery_reads_only_the_system_proxy_and_listener_without_network_or_client_inspection() {
    let r = Arc::new(Runner::new());
    let result = platform(r.clone()).discover_proxy();
    assert_eq!(result.candidates.len(), 1);
    let profile = &result.candidates[0].profile;
    assert_eq!(profile.proxy_url, "http://127.0.0.1:17890");
    assert_eq!(profile.expected_proxy_executable, "/fixture/proxy");
    assert_eq!(profile.expected_country, None);
    assert!(!profile.non_mainland_timezone);
    let calls = r.calls.lock().unwrap();
    assert!(calls.iter().all(|(exe, args)| match exe.as_str() {
        "/usr/sbin/scutil" => args == &["--proxy"],
        "/usr/sbin/lsof" => args.iter().any(|a| a == "-iTCP:17890"),
        "/bin/ps" => args == &["-p", "123", "-o", "comm="],
        _ => false,
    }));
}
#[test]
fn discovery_does_not_guess_ports_or_follow_pac_and_rejects_unknown_owner() {
    for kind in 0..3 {
        let mut r = Runner::new();
        match kind {
            0 => r.proxy.clear(),
            1 => r.proxy.push_str("ProxyAutoConfigEnable : 1\n"),
            _ => r.exe = "relative-path".into(),
        }
        let r = Arc::new(r);
        assert!(platform(r.clone()).discover_proxy().candidates.is_empty());
        let calls = r.calls.lock().unwrap();
        assert!(!calls.iter().any(|(exe, _)| exe == "/usr/bin/curl"));
        if kind < 2 {
            assert_eq!(calls.len(), 1);
        }
    }
}

#[test]
fn discovery_rejects_configuration_or_pid_changes_during_observation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Drifting {
        base: Runner,
        mode: u8,
        reads: AtomicUsize,
    }
    impl CommandRunner for Drifting {
        fn run(&self, exe: &str, args: &[String], timeout: Duration) -> Result<Output, Fault> {
            assert!(matches!(
                exe,
                "/usr/sbin/scutil" | "/usr/sbin/lsof" | "/bin/ps"
            ));
            let mut output = self.base.run(exe, args, timeout)?;
            let selected = if self.mode == 0 {
                exe == "/usr/sbin/scutil"
            } else {
                exe == "/usr/sbin/lsof"
            };
            if selected && self.reads.fetch_add(1, Ordering::SeqCst) > 0 {
                output.stdout = if self.mode == 0 {
                    output.stdout.replace("17890", "8899")
                } else {
                    output.stdout.replace("p123", "p124")
                };
            }
            Ok(output)
        }
    }
    for mode in 0..2 {
        let p = MacPlatform::with_dependencies(
            Arc::new(Drifting {
                base: Runner::new(),
                mode,
                reads: AtomicUsize::new(0),
            }),
            Arc::new(Applications { ids: vec![] }),
        );
        let found = p.discover_proxy();
        assert!(found.candidates.is_empty());
        assert!(found.message.contains("发生变化"));
    }
}

#[test]
fn empty_proxy_cannot_reach_the_command_runner_even_when_platform_is_called_directly() {
    let r = Arc::new(Runner::new());
    let p = platform(r.clone());
    let empty = guard_core::config::Profile::default();
    assert!(p.probe(&empty, &FixedClock).is_err());
    assert!(p.local(&empty).is_err());
    assert!(r.calls.lock().unwrap().is_empty());
}
