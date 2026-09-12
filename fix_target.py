import sys
import glob

# Remove everything and reset
for fpath in ["litebox_runner_linux_on_windows_userland/examples/sdl_combined_probe.rs"]:
    content = open(fpath).read()

    if '#[cfg(not(windows))]\nfn main() -> anyhow::Result<()> { Ok(()) }\n' in content:
        content = content.replace('#[cfg(windows)]\nfn main() -> anyhow::Result<()> {', 'fn main() -> anyhow::Result<()> {')
        content = content.replace('#[cfg(not(windows))]\nfn main() -> anyhow::Result<()> { Ok(()) }\n', '')

    open(fpath, 'w').write(content)
