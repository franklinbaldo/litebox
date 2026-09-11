# Desktop acceptance tools

These are developer tools. Installed games do not depend on Python or these packages.

Resource sample (one logical CPU = 100%, descendants included):

```powershell
python tools/desktop_acceptance/measure.py --pid <host-pid> --seconds 60 --output target/desktop-acceptance/resources.json
```

The report records its sampling limitations. Use the same scene, resolution and
duration for comparisons. CPU and memory do not establish FPS or audio quality.

Optional audio energy check, while only the test game is making sound:

```powershell
uv run --with pyaudiowpatch==0.2.12.8 python tools/desktop_acceptance/audio_probe.py --seconds 10 --output target/desktop-acceptance/audio.json
```

This checks default system-output loopback and retains only energy statistics,
not the recording. It cannot attribute sound to one process or verify music,
latency or absence of audible glitches. Unsupported devices produce status
`unavailable` and exit 2, never a passing audio result.

On the development machine, 2026-09-11, the counter tool observed approximately
one core of CPU load from a controlled busy-loop child. All four advertised
WASAPI loopback devices failed opening with `Invalid device`; automated loopback
verification is unavailable here. The earlier human confirmation applies to the
Python Breakout demo and must not be transferred to a new host or SDL game.

Window/input regression probe:

```powershell
uv run --with pillow python tools/desktop_acceptance/native_input_probe.py --host <host.exe> --runner <runner.exe> --tar <game.tar>
```

It launches its own test instance, sends keys only to that window, checks paddle
pixels, tests focus loss, and closes the window. Captures and logs remain under
`target/desktop-acceptance/input`. The first AGY host failed this check: after
focus loss, the paddle moved from x=149.5 to x=86.5 rather than stopping. This
establishes that the regression probe detects the observed focus-handling bug.
