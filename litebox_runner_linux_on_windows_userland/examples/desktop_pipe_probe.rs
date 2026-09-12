//! Real ELF guest exercising dedicated pipes, independently of standard streams.

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod probe {
    use litebox_platform_windows_userland::WindowsUserland;
    use litebox_shim_linux::host_pipe::{HostReader, HostWriter};
    use std::io;

    struct Reader(HostReader<WindowsUserland>);
    impl io::Read for Reader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0
                .read(buf)
                .map_err(|e| io::Error::other(format!("{e:?}")))
        }
    }
    struct Writer(HostWriter<WindowsUserland>);
    impl io::Write for Writer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .write(buf)
                .map_err(|e| io::Error::other(format!("{e:?}")))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub fn run() -> anyhow::Result<()> {
        let tar = std::fs::read(std::env::args_os().nth(1).expect("probe TAR path"))?;
        let platform = WindowsUserland::new();
        let builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
        let fs = builder.default_fs(
            litebox::fs::in_mem::InMem::new_initialized::<&str>([]),
            tar.into(),
        );
        let shim = builder.build();
        let mut program = shim.load_program(
            std::sync::Arc::new(fs),
            platform.init_task(),
            "/bin/probe",
            vec![std::ffi::CString::new("probe")?],
            vec![],
        )?;
        let (input, writer) = program.attach_host_input()?;
        let (output, reader) = program.attach_host_output()?;
        // This fixture has no other open files. Product callers must communicate
        // the returned descriptor numbers rather than assume this allocation.
        anyhow::ensure!((input, output) == (3, 4), "unexpected fixture descriptors");
        let host = std::thread::spawn(move || -> Result<(), String> {
            let check = || -> Result<(), Box<dyn std::error::Error>> {
                let mut wire =
                    litebox_desktop_transport::Framed::new(Reader(reader), Writer(writer), 1024)?;
                assert_eq!(wire.handshake(0)?, 1024);
                wire.send(b"desktop ping")?;
                assert_eq!(wire.recv()?.as_deref(), Some(b"desktop ping".as_slice()));
                assert!(wire.recv()?.is_none(), "guest writer must close cleanly");
                Ok(())
            };
            check().map_err(|e| e.to_string())
        });
        // SAFETY: the entrypoints and register state belong to this loaded guest.
        unsafe {
            litebox_platform_windows_userland::run_thread(
                program.entrypoints,
                &mut litebox_common_linux::PtRegs::default(),
            );
        }
        anyhow::ensure!(program.process.wait() == 0, "guest failed");
        host.join()
            .expect("host thread panicked")
            .map_err(anyhow::Error::msg)?;
        println!("DESKTOP_PIPE_OK: handshake, framed echo, EOF; guest stdout remains separate");
        Ok(())
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() -> anyhow::Result<()> {
    probe::run()
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn main() {
    eprintln!("This probe is only supported on Windows x86_64");
    std::process::exit(1);
}
