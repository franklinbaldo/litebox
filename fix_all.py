import sys
import glob

for fpath in glob.glob("litebox_runner_linux_on_windows_userland/examples/*.rs"):
    content = open(fpath).read()

    # Remove the bad #[cfg(windows)] annotations we just added
    content = content.replace('#[cfg(windows)]\nstruct Reader', 'struct Reader')
    content = content.replace('#[cfg(windows)]\nstruct Writer', 'struct Writer')
    content = content.replace('#[cfg(windows)]\n    let platform', '    let platform')
    content = content.replace('#[cfg(windows)]\nfn main', 'fn main')
    content = content.replace('#[cfg(not(windows))]\nfn main() -> anyhow::Result<()> { Ok(()) }\n', '')

    open(fpath, 'w').write(content)
