//! Windows boundary intentionally reports Unsupported until native verification.
//! WinINET/WinHTTP/environment proxy and WSL must be evaluated separately.
use crate::*;
pub struct WindowsPlatform;
impl Platform for WindowsPlatform {
    fn name(&self) -> &'static str {
        "windows-preparation"
    }
    fn clients(&self) -> ClientAvailability {
        ClientAvailability::default()
    }
    fn inspect(&self, id: RuleId, _: &Profile, _: &dyn Clock) -> Check {
        Check::new(id, Status::Skipped, Fault::Unsupported.message())
    }
    fn local(&self, _: &Profile) -> Result<LocalSnapshot, Fault> {
        Err(Fault::Unsupported)
    }
    fn probe(&self, _: &Profile, _: &dyn Clock) -> Result<Probe, Fault> {
        Err(Fault::Unsupported)
    }
}
