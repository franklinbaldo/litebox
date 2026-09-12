import sys
import glob

for fpath in glob.glob("litebox_runner_linux_on_windows_userland/examples/*.rs"):
    content = open(fpath).read()
    if 'use litebox_platform_windows_userland::WindowsUserland;' in content:
        content = content.replace('use litebox_platform_windows_userland::WindowsUserland;', '#[cfg(windows)]\nuse litebox_platform_windows_userland::{WindowsUserland, run_test_thread as run_thread};')
        open(fpath, 'w').write(content)
