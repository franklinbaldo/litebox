"""Report loopback energy on the default Windows output, without saving audio.

Development only: uv run --with pyaudiowpatch python audio_probe.py --seconds 10
Run while only the test game is producing sound. Nonzero energy alone is not
proof of the source, correct music, acceptable latency or absence of dropouts.
"""

import argparse
from array import array
import json
import math
from pathlib import Path
import threading
import time


def capture(seconds):
    import pyaudiowpatch as audio

    lock = threading.Lock()
    counts = {"samples": 0, "sum_squares": 0.0, "peak": 0.0,
              "callback_errors": 0, "active_blocks": 0, "blocks": 0}

    def callback(data, frame_count, time_info, status):
        samples = array("f", data)
        peak = max((abs(v) for v in samples), default=0.0)
        with lock:
            counts["samples"] += len(samples)
            counts["sum_squares"] += sum(v * v for v in samples)
            counts["peak"] = max(counts["peak"], peak)
            counts["callback_errors"] += int(status != 0)
            counts["active_blocks"] += int(peak > 0.0001)
            counts["blocks"] += 1
        return None, audio.paContinue

    with audio.PyAudio() as manager:
        device = manager.get_default_wasapi_loopback()
        with manager.open(format=audio.paFloat32, channels=device["maxInputChannels"],
                          rate=int(device["defaultSampleRate"]), input=True,
                          input_device_index=device["index"], frames_per_buffer=1024,
                          stream_callback=callback):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    rms = math.sqrt(counts.pop("sum_squares") / max(1, counts["samples"]))
    return {"device": device["name"], "seconds_requested": seconds,
            "sample_rate": int(device["defaultSampleRate"]),
            "channels": device["maxInputChannels"], **counts, "rms": rms,
            "rms_dbfs": 20 * math.log10(rms) if rms else None,
            "scope": "system output loopback; source attribution requires isolated test"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 0 < args.seconds <= 60:
        parser.error("seconds must be in (0, 60]")
    try:
        result = {"status": "captured", **capture(args.seconds)}
    except (OSError, RuntimeError) as exc:
        result = {"status": "unavailable", "error": str(exc),
                  "audio_verified": False}
    report = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)
    if result["status"] == "unavailable":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
