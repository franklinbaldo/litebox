import sys
import glob

for fpath in glob.glob("litebox_runner_linux_on_windows_userland/examples/*.rs"):
    content = open(fpath).read()

    # We must only apply #[cfg(windows)] on the imported items that are only available on windows,
    # OR we can just `use litebox_platform_windows_userland::WindowsUserland;`
    # but the CI error was because `litebox_platform_windows_userland` itself is only available on windows,
    # Let's check `cargo check -p litebox_runner_linux_on_windows_userland` again on Linux
    if '#![cfg(windows)]\n' not in content:
        open(fpath, 'w').write('#![cfg(windows)]\n' + content)
