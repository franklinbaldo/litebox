import re, subprocess, sys

exe = r'.\target\release\litebox_runner_windows_userland.exe'
tar = r'C:\Users\wdcui\tmp\node_windows.tar'
pe = r'C:\Users\wdcui\tmp\tls_heavy16.exe'
args = [exe, '--dll-tar', tar, '--pe-file', pe]

n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
timeout_s = int(sys.argv[2]) if len(sys.argv) > 2 else 10
p, f, t = 0, 0, 0

def trace_filter(line):
    return any(k in line for k in ['[shim-exit]', '[shim-crash]', '[shim-diag]', '[seh-fwd]', '[runner]', '[watchdog]', '[EARLY-VEH]', '[CRASH]', 'NtTerminateProcess', 'NtTerminateThread', '[real-dlls]', '__fastfail'])

def run_has_stuck_threads(stderr_text):
    if '[watchdog]' in stderr_text:
        return True
    match = re.search(r"threads: created=\d+ terminated=\d+ live=(\d+)", stderr_text)
    return bool(match and int(match.group(1)) != 0)

def run_has_shim_fault(stderr_text):
    return '[shim-crash]' in stderr_text or '[shim-diag]' in stderr_text

for i in range(1, n + 1):
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout=timeout_s)
        code = proc.returncode
        out_s = out.decode(errors="replace").strip()
        err_s = err.decode(errors="replace")
        exit_lines = [l for l in err_s.split('\n') if trace_filter(l)]
        exit_summary = '\n'.join(exit_lines[-30:])
        stuck = run_has_stuck_threads(err_s)
        shim_fault = run_has_shim_fault(err_s)
        if code == 0 and not stuck and not shim_fault:
            p += 1
            if p <= 3:
                print(f"=== Run {i} PASS (exit=0) ===")
                print(f"EXIT TRACE:\n{exit_summary}")
        else:
            f += 1
            if stuck and code == 0:
                print(f"=== Run {i} FAIL exit=0 (stuck threads) ===")
            elif shim_fault and code == 0:
                print(f"=== Run {i} FAIL exit=0 (shim diagnostics) ===")
            else:
                print(f"=== Run {i} FAIL exit={code} ===")
            print(f"STDOUT: {out_s}")
            print(f"EXIT TRACE:\n{exit_summary}")
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        t += 1
        out_s = out.decode(errors="replace").strip()
        err_s = err.decode(errors="replace")
        exit_lines = [l for l in err_s.split('\n') if trace_filter(l)]
        exit_summary = '\n'.join(exit_lines[-30:])
        print(f"=== Run {i} TIMEOUT ===")
        print(f"STDOUT: {out_s}")
        print(f"EXIT TRACE:\n{exit_summary}")

print(f"\nResults: {p} pass, {f} fail, {t} timeout (out of {n})")
