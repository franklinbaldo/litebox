use std::env;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Instant;

const DEFAULT_UNITS: u64 = 32;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let case = args.next().unwrap_or_else(|| "startup".to_owned());
    let units = args
        .next()
        .map(|v| v.parse::<u64>().map_err(|_| "UNITS must be an integer"))
        .transpose()?
        .unwrap_or(DEFAULT_UNITS);
    if args.next().is_some() {
        return Err(
            "usage: litebox-perf-workload [startup|cpu|memory|filesystem|fsync|syscall|clock|threads|unlink_open|hostinfo|power|cpu_device] [UNITS]"
                .into(),
        );
    }
    let started = Instant::now();
    let checksum = match case.as_str() {
        "startup" => 0,
        "cpu" => cpu(units),
        "memory" => memory(units)?,
        "filesystem" => filesystem(units)?,
        "fsync" => fsync_probe()?,
        "syscall" => syscall(units)?,
        "clock" => clock(units),
        "threads" => threads(units)?,
        "unlink_open" => unlink_open_probe()?,
        "hostinfo" => hostinfo_probe()?,
        "power" => power_probe()?,
        "cpu_device" => cpu_device_probe()?,
        _ => return Err(format!("unknown benchmark case: {case}")),
    };
    let elapsed_ns = started.elapsed().as_nanos();
    println!("{{\"case\":\"{case}\",\"units\":{units},\"elapsed_ns\":{elapsed_ns},\"checksum\":{checksum}}}");
    Ok(())
}

fn cpu(units: u64) -> u64 {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for index in 0..units.saturating_mul(1_000_000) {
        state ^= index.wrapping_add(state.rotate_left(17));
        state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9).rotate_left(23);
    }
    black_box(state)
}

fn memory(units: u64) -> Result<u64, String> {
    let bytes = usize::try_from(units.saturating_mul(1024 * 1024))
        .map_err(|_| "memory workload is too large")?;
    let mut source = vec![0_u8; bytes];
    for (index, byte) in source.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(31);
    }
    let mut destination = vec![0_u8; bytes];
    for _ in 0..8 {
        destination.copy_from_slice(&source);
        std::mem::swap(&mut source, &mut destination);
    }
    Ok(black_box(
        source.iter().step_by(4096).map(|v| u64::from(*v)).sum(),
    ))
}

fn filesystem(units: u64) -> Result<u64, String> {
    let path = temporary_path("io");
    let block = vec![0x5a_u8; 1024 * 1024];
    let result = (|| {
        let mut file =
            File::create(&path).map_err(|e| format!("create {}: {e}", path.display()))?;
        for _ in 0..units {
            file.write_all(&block)
                .map_err(|e| format!("write {}: {e}", path.display()))?;
        }
        drop(file);
        let mut file = File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut checksum = 0_u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            if read == 0 {
                break;
            }
            checksum =
                checksum.wrapping_add(buffer[..read].iter().map(|b| u64::from(*b)).sum::<u64>());
        }
        Ok(checksum)
    })();
    let _ = fs::remove_file(path);
    result
}

fn fsync_probe() -> Result<u64, String> {
    let path = temporary_path("fsync");
    let result = (|| {
        let mut file =
            File::create(&path).map_err(|e| format!("create {}: {e}", path.display()))?;
        file.write_all(b"litebox")
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        file.sync_all()
            .map_err(|e| format!("sync {}: {e}", path.display()))?;
        Ok(7)
    })();
    let _ = fs::remove_file(path);
    result
}

fn unlink_open_probe() -> Result<u64, String> {
    let path = temporary_path("unlink-open");
    let result = (|| {
        let mut file =
            File::create(&path).map_err(|e| format!("create {}: {e}", path.display()))?;
        file.write_all(b"litebox")
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        fs::remove_file(&path).map_err(|e| format!("unlink open {}: {e}", path.display()))?;
        Ok(7)
    })();
    let _ = fs::remove_file(path);
    result
}

fn hostinfo_probe() -> Result<u64, String> {
    let data = fs::read("/run/litebox/hostinfo.json")
        .map_err(|e| format!("read /run/litebox/hostinfo.json: {e}"))?;
    println!("{}", String::from_utf8_lossy(&data));
    Ok(data.iter().map(|byte| u64::from(*byte)).sum())
}

fn power_probe() -> Result<u64, String> {
    let data = fs::read("/run/litebox/power.json")
        .map_err(|e| format!("read /run/litebox/power.json: {e}"))?;
    println!("{}", String::from_utf8_lossy(&data));
    Ok(data.iter().map(|byte| u64::from(*byte)).sum())
}

#[cfg(target_arch = "x86_64")]
fn cpu_device_probe() -> Result<u64, String> {
    use std::arch::x86_64::{__cpuid, _rdrand64_step, _rdtsc};

    // These instructions execute directly on the host CPU. There is no LiteBox
    // filesystem node or Windows broker in this path.
    let vendor = {
        let leaf = __cpuid(0);
        [
            leaf.ebx.to_le_bytes(),
            leaf.edx.to_le_bytes(),
            leaf.ecx.to_le_bytes(),
        ]
        .concat()
    };
    let vendor = String::from_utf8_lossy(&vendor);
    let before = unsafe { _rdtsc() };
    let mut random = 0_u64;
    let rdrand_supported = std::is_x86_feature_detected!("rdrand");
    let rdrand_ok = rdrand_supported && unsafe { _rdrand64_step(&mut random) } == 1;
    let after = unsafe { _rdtsc() };
    println!(
        "{{\"access\":\"direct-cpu-instructions\",\"vendor\":\"{vendor}\",\"tsc_delta\":{},\"rdrand_supported\":{rdrand_supported},\"rdrand_ok\":{rdrand_ok}}}",
        after.wrapping_sub(before)
    );
    Ok(random ^ before ^ after)
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_device_probe() -> Result<u64, String> {
    Err("cpu_device is implemented only for x86_64".into())
}

fn clock(units: u64) -> u64 {
    let started = Instant::now();
    let mut changes = 0_u64;
    let mut previous = started;
    for _ in 0..units.saturating_mul(100_000) {
        let now = Instant::now();
        changes += u64::from(now != previous);
        previous = now;
    }
    black_box(changes ^ started.elapsed().as_nanos() as u64)
}

fn threads(units: u64) -> Result<u64, String> {
    let count = usize::try_from(units.clamp(1, 8)).map_err(|_| "invalid thread count")?;
    let mut handles = Vec::with_capacity(count);
    for worker in 0..count {
        handles.push(thread::spawn(move || cpu((worker + 1) as u64)));
    }
    handles.into_iter().try_fold(0_u64, |checksum, handle| {
        handle
            .join()
            .map(|value| checksum ^ value)
            .map_err(|_| "worker thread panicked".to_owned())
    })
}

fn syscall(units: u64) -> Result<u64, String> {
    let path = PathBuf::from(env::args().next().ok_or("missing argv[0]")?);
    let mut checksum = 0_u64;
    for _ in 0..units.saturating_mul(10_000) {
        checksum = checksum.wrapping_add(
            fs::metadata(&path)
                .map_err(|e| format!("metadata {}: {e}", path.display()))?
                .len(),
        );
    }
    Ok(black_box(checksum))
}

fn temporary_path(label: &str) -> PathBuf {
    let mut path = env::temp_dir();
    path.push(format!("litebox-perf-{label}-{}.tmp", std::process::id()));
    path
}
