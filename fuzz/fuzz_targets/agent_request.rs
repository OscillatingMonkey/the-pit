//! Anything on the socket is parsed as a request; names and scopes inside it are
//! validated. None of it may panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<the_pit::protocol::Request>(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = the_pit::model::Scope::parse(text);
        let _ = the_pit::model::valid_name("secret", text);
        let _ = the_pit::model::valid_slug("project", text);
        let _ = the_pit::model::safe_relative(text);
    }
});
