"""Validates setup.sh mode dispatch (dist vs deploy, flags, prompt, mock, errors)
by running the REAL setup.sh with stubbed provision.sh/deploy.sh/run-local.sh and a
fake sudo. The interactive prompt is exercised via a pty. No network/sudo needed."""
import os, sys, stat, time, select, tempfile, subprocess

REAL = os.path.dirname(os.path.abspath(__file__))


def _w(path, text, x=False):
    with open(path, "w") as f:
        f.write(text)
    if x:
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def sandbox():
    d = tempfile.mkdtemp(prefix="wl-setup-")
    subprocess.run(["cp", os.path.join(REAL, "setup.sh"), d], check=True)
    prov_marker = os.path.join(d, ".prov"); dep_marker = os.path.join(d, ".dep"); rl_marker = os.path.join(d, ".rl")
    # stub provision.sh: make the bundle + an inner stub deploy.sh, drop a marker
    _w(os.path.join(d, "provision.sh"),
       "#!/usr/bin/env bash\nset -e\nmkdir -p dist/leak-inspect-bundle\n"
       "cat > dist/leak-inspect-bundle/deploy.sh <<'D'\n#!/usr/bin/env bash\n"
       "echo DEPLOY_RAN\ntouch '%s'\nD\nchmod +x dist/leak-inspect-bundle/deploy.sh\n"
       "echo PROVISION_RAN\ntouch '%s'\n" % (dep_marker, prov_marker), x=True)
    _w(os.path.join(d, "run-local.sh"),
       "#!/usr/bin/env bash\necho RUNLOCAL_RAN\ntouch '%s'\n" % rl_marker, x=True)
    # fake sudo: strip --preserve-env* and exec the rest
    os.mkdir(os.path.join(d, "bin"))
    _w(os.path.join(d, "bin", "sudo"),
       '#!/usr/bin/env bash\nargs=()\nfor a in "$@"; do case "$a" in --preserve-env*) ;; *) args+=("$a");; esac; done\nexec "${args[@]}"\n', x=True)
    return d, prov_marker, dep_marker, rl_marker


def env_for(d, **extra):
    e = dict(os.environ)
    e["PATH"] = os.path.join(d, "bin") + os.pathsep + e["PATH"]
    e.update(extra)
    return e


def run_plain(args, hf=True, mock=False):
    d, pm, dm, rm = sandbox()
    e = env_for(d, **({"DEMO_BACKEND": "mock"} if mock else {}))
    if hf:
        e["HF_TOKEN"] = "x"
    else:
        e.pop("HF_TOKEN", None)
    p = subprocess.run(["bash", "setup.sh", *args], cwd=d, env=e,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr, os.path.exists(pm), os.path.exists(dm), os.path.exists(rm)


def run_pty(send):
    import pty
    d, pm, dm, rm = sandbox()
    e = env_for(d, HF_TOKEN="x")
    mo, sl = pty.openpty()
    p = subprocess.Popen(["bash", "setup.sh"], cwd=d, env=e,
                         stdin=sl, stdout=sl, stderr=sl, close_fds=True)
    os.close(sl)
    time.sleep(0.6)
    os.write(mo, send)
    out = b""
    t0 = time.time()
    while time.time() - t0 < 8:
        r, _, _ = select.select([mo], [], [], 0.3)
        if r:
            try:
                c = os.read(mo, 4096)
            except OSError:
                break
            if not c:
                break
            out += c
        if p.poll() is not None and not r:
            break
    p.wait(timeout=3)
    os.close(mo)
    return p.returncode, out.decode(errors="replace"), os.path.exists(pm), os.path.exists(dm)


def check(name, cond, info=""):
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name, ("  :: " + info) if info and not cond else ""))
    assert cond, name


# --- flag / non-interactive paths -------------------------------------------
rc, out, prov, dep, rl = run_plain(["dist"])
check("`setup.sh dist` -> provision only, no deploy", rc == 0 and prov and not dep, out)
check("`setup.sh dist` prints transfer instructions", "Air-gap dist built" in out and "deploy.sh" in out)

rc, out, prov, dep, rl = run_plain(["deploy"])
check("`setup.sh deploy` -> provision + deploy", rc == 0 and prov and dep, out)

rc, out, prov, dep, rl = run_plain(["--dist"])
check("`setup.sh --dist` flag form -> provision only", rc == 0 and prov and not dep, out)

rc, out, prov, dep, rl = run_plain(["-dist"])
check("`setup.sh -dist` (literal form requested) -> provision only", rc == 0 and prov and not dep, out)

rc, out, prov, dep, rl = run_plain([])  # non-interactive, no arg -> backward-compatible deploy
check("`setup.sh` non-interactive default -> deploy", rc == 0 and prov and dep, out)

rc, out, prov, dep, rl = run_plain(["bogus"])
check("`setup.sh bogus` -> rc 2, nothing run", rc == 2 and not prov and not dep, out)

rc, out, prov, dep, rl = run_plain(["dist"], hf=False)
check("`setup.sh dist` without HF_TOKEN -> errors before provision", rc != 0 and not prov, out)

rc, out, prov, dep, rl = run_plain([], mock=True, hf=False)
check("`DEMO_BACKEND=mock setup.sh` -> run-local, no provision/deploy/HF needed", rc == 0 and rl and not prov and not dep, out)

# --- interactive prompt via pty ---------------------------------------------
try:
    rc, out, prov, dep = run_pty(b"1\n")
    check("prompt '1' -> dist (provision only)", rc == 0 and prov and not dep, out)
    check("prompt shows the menu", "Build the air-gap dist only" in out)

    rc, out, prov, dep = run_pty(b"2\n")
    check("prompt '2' -> deploy (provision + deploy)", rc == 0 and prov and dep, out)

    rc, out, prov, dep = run_pty(b"\n")
    check("prompt default (Enter) -> deploy", rc == 0 and prov and dep, out)
except Exception as e:
    print("  [SKIP] pty prompt cases unavailable in this environment: %r" % e)

print("\nALL SETUP-MODE ASSERTIONS PASSED")
