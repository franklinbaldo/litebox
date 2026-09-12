// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

//! Deliberately invalid child used to verify the host's failure paths.
use std::io::Write;

fn main() {
    match std::env::var("LITEBOX_HOST_TEST_FAILURE").as_deref() {
        Ok("nonzero") => std::process::exit(7),
        Ok("truncated") => {
            std::io::stdout().write_all(b"FRAM\xa0\0\x78\0short").unwrap();
        }
        Ok("malformed") => {
            std::io::stdout().write_all(b"NOPE").unwrap();
            std::io::stdout().flush().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        _ => panic!("set LITEBOX_HOST_TEST_FAILURE to select a failure"),
    }
}
