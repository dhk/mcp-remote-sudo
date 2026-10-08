import io, json, sys
from pathlib import Path

import pytest
import yaml

from mcp_remote_sudo import admin as admin_mod
from mcp_remote_sudo import pack_install, packs
from mcp_remote_sudo.admin import Admin, AdminError
from mcp_remote_sudo.pack_install import PackInstallError, parse_lockfile

H = "a" * 64


def lock(*entries):
    return "\n".join(f"{e} --hash=sha256:{H}" for e in entries) + "\n"


@pytest.mark.parametrize("text,match", [
    ("example-pack>=1.0 --hash=sha256:" + H, "exact pin"),
    ("example-pack==1.0", "--hash"),
    ("example-pack==1.0 --hash=sha256:abc", "--hash"),
    ("example-pack==1.0 --hash=sha256:" + H + " --index-url https://evil", "--hash"),
    ("-e ./local --hash=sha256:" + H, "exact pin"),
    ("https://x/y.whl --hash=sha256:" + H, "exact pin"),
    ("-r other.txt", "exact pin"),
    ("-c constraints.txt", "exact pin"),
    ("--index-url https://evil", "exact pin"),
    ("example-pack==1.0 ; python_version>'3' --hash=sha256:" + H, "--hash"),
    ("example-pack @ https://evil/x.whl --hash=sha256:" + H, "exact pin"),
    ("example-pack==1.0\t# comment --hash=sha256:" + H, "--hash"),
    (lock("a==1", "A==2"), "more than once"),
    ("# only a comment\n", "no requirements"),
])
def test_lockfile_must_be_exact_and_hashed(text, match):
    with pytest.raises(PackInstallError, match=match): parse_lockfile(text)


def test_lockfile_accepts_continuations_and_comments():
    pins = parse_lockfile(f"# packs\nExample_Pack==1.0 \\\n    --hash=sha256:{H} \\\n    --hash=sha256:{'b'*64}  # pinned\n")
    assert [(p.name, p.version, len(p.hashes)) for p in pins] == [("example-pack", "1.0", 2)]


def fake_wheel(target: Path, name="example-pack", version="1.0", top="example_pack", declared=None, requires=(), extra=()):
    target.mkdir(parents=True, exist_ok=True)
    info = target / f"{name.replace('-', '_')}-{version}.dist-info"; info.mkdir()
    meta = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n" + "".join(f"Requires-Dist: {r}\n" for r in requires)
    (info / "METADATA").write_text(meta)
    (info / "top_level.txt").write_text((declared if declared is not None else top) + "\n")
    (info / "entry_points.txt").write_text(f"[mcp_remote_sudo.packs]\nexample = {top}:PACK\n")
    pkg = target / top; pkg.mkdir()
    (pkg / "__init__.py").write_text("raise RuntimeError('pack code must never be imported by the installer')\n")
    for e in extra:
        (target / e).mkdir(parents=True, exist_ok=True)
    (info / "RECORD").write_text(f"{top}/__init__.py,,\n")


class FakePip:
    """Writes the wheel described for the pinned name into pip's --target tree."""
    def __init__(self, wheels): self.wheels = wheels; self.calls = []
    def __call__(self, argv):
        argv = list(argv); self.calls.append(argv)
        class R: returncode = 0; stdout = ""; stderr = ""
        if "pip" in argv:
            target = Path(argv[argv.index("--target") + 1])
            name = Path(argv[argv.index("-r") + 1]).read_text().split("==")[0]
            fake_wheel(target, **self.wheels.get(name, {"name": name, "top": name.replace("-", "_")}))
        return R()


def install(tmp_path, pins, wheels):
    lf = tmp_path / "lock.txt"; lf.write_text(lock(*pins))
    return pack_install.install(lf, tmp_path / "packs", FakePip(wheels))


def test_install_is_per_distribution_wheel_only_and_never_imports(tmp_path):
    pip = FakePip({}); lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    txn = pack_install.install(lf, tmp_path / "packs", pip); txn.commit()
    argv = pip.calls[0]
    assert argv[1:4] == ["-I", "-m", "pip"]
    for flag in ("--only-binary", ":all:", "--require-hashes", "--no-deps", "--no-compile", "--target"):
        assert flag in argv
    assert (tmp_path / "packs" / "example-pack" / "example_pack" / "__init__.py").exists()
    assert "example_pack" not in sys.modules
    assert not [p for p in (tmp_path / "packs").iterdir() if p.name.startswith(".")]
    assert pack_install.installed(tmp_path / "packs") == [{"distribution": "example-pack", "version": "1.0", "entry_points": ["example"]}]
    assert pack_install.search_paths(tmp_path / "packs") == [str(tmp_path / "packs" / "example-pack")]


@pytest.mark.parametrize("wheel,pinned,match", [
    ({"name": "pyyaml", "top": "yaml_alt"}, "pyyaml==6.0", "refusing to replace mcp-remote-sudo"),
    ({"name": "mcp-remote-sudo", "top": "mrs_alt"}, "mcp-remote-sudo==9.9", "refusing to replace"),
    ({"name": "evil-pack", "top": "json"}, "evil-pack==1.0", "shadows the standard library"),
    ({"name": "evil-pack", "top": "yaml"}, "evil-pack==1.0", "collides with the core"),
    ({"name": "evil-pack", "top": "mcp_remote_sudo"}, "evil-pack==1.0", "collides with the core"),
    ({"name": "surprise", "top": "surprise"}, "evil-pack==1.0", "exactly that one distribution"),
    # Undeclared files are checked too: the collision check uses what is actually staged, not top_level.txt.
    ({"name": "evil-pack", "top": "evil_pack", "declared": "evil_pack", "extra": ("json",)}, "evil-pack==1.0", "standard library"),
    ({"name": "evil-pack", "top": "evil_pack", "extra": ("not-an-identifier",)}, "evil-pack==1.0", "unexpected top-level entry"),
])
def test_install_refusals_leave_packs_dir_untouched(tmp_path, wheel, pinned, match):
    with pytest.raises(PackInstallError, match=match):
        install(tmp_path, [pinned], {pinned.split("==")[0]: wheel})
    assert pack_install.installed_trees(tmp_path / "packs") == {}
    assert not any((tmp_path / "packs").iterdir())


def test_collision_with_another_pack_uses_actual_files(tmp_path):
    install(tmp_path, ["example-pack==1.0"], {}).commit()
    with pytest.raises(PackInstallError, match="installed pack example-pack"):
        install(tmp_path, ["other-pack==1.0"], {"other-pack": {"name": "other-pack", "top": "other_pack",
                                                              "declared": "other_pack", "extra": ("example_pack",)}})


def test_hostile_top_level_metadata_cannot_direct_removal(tmp_path):
    """Regression (review of #64): top_level.txt was used as filesystem paths for rmtree."""
    victim = tmp_path / "victim"; victim.mkdir(); (victim / "keep").write_text("x")
    install(tmp_path, ["example-pack==1.0"], {"example-pack": {"declared": f"../../{victim.name}\n/etc"}}).commit()
    assert pack_install.remove(tmp_path / "packs", "example-pack")
    assert (victim / "keep").exists() and not (tmp_path / "packs" / "example-pack").exists()
    assert pack_install.remove(tmp_path / "packs", "../victim") is False


def test_two_packs_with_console_scripts_coexist(tmp_path):
    install(tmp_path, ["a-pack==1.0"], {"a-pack": {"name": "a-pack", "top": "a_pack", "extra": ("bin",)}}).commit()
    install(tmp_path, ["b-pack==1.0"], {"b-pack": {"name": "b-pack", "top": "b_pack", "extra": ("bin",)}}).commit()
    assert sorted(pack_install.installed_trees(tmp_path / "packs")) == ["a-pack", "b-pack"]


def test_upgrade_keeps_previous_until_commit_and_rollback_restores(tmp_path):
    install(tmp_path, ["example-pack==1.0"], {}).commit()
    txn = install(tmp_path, ["example-pack==2.0"], {"example-pack": {"version": "2.0"}})
    assert [d["version"] for d in pack_install.installed(tmp_path / "packs")] == ["2.0"]
    txn.rollback()
    assert [d["version"] for d in pack_install.installed(tmp_path / "packs")] == ["1.0"]
    install(tmp_path, ["example-pack==2.0"], {"example-pack": {"version": "2.0"}}).commit()
    assert [d["version"] for d in pack_install.installed(tmp_path / "packs")] == ["2.0"]
    assert not [p for p in (tmp_path / "packs").iterdir() if p.name.startswith(".")]


def test_pip_failure_is_reported_and_nothing_changes(tmp_path):
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    def failing(argv):
        class R: returncode = 1; stdout = ""; stderr = "ERROR: Hashes are required"
        return R()
    with pytest.raises(PackInstallError, match="Hashes are required"):
        pack_install.install(lf, tmp_path / "packs", failing)
    assert pack_install.installed_trees(tmp_path / "packs") == {}


def test_dependents_are_found_from_metadata(tmp_path):
    install(tmp_path, ["example-pack==1.0", "helper-lib==1.0"],
            {"example-pack": {"requires": ("Helper_Lib>=1.0",)}, "helper-lib": {"name": "helper-lib", "top": "helper_lib"}}).commit()
    assert pack_install.dependents(tmp_path / "packs", "helper-lib") == ["example-pack"]
    assert pack_install.dependents(tmp_path / "packs", "example-pack") == []


def test_registry_describe_reports_distributions():
    d = packs.default_registry().describe()
    assert d["core"]["distribution"] == "mcp-remote-sudo" and "journal.query" in d["core"]["operations"]


class Svc:
    """Fake host for admin pack commands: status file + systemctl restart that reports what it 'loaded'."""
    def __init__(self, tmp_path, monkeypatch, allow=("system.info",), loads_external=True, wheels=None):
        self.tmp = tmp_path; self.state = tmp_path / "state"; self.state.mkdir()
        self.manifest = tmp_path / "authority.yaml"; self.packs_dir = tmp_path / "packs"
        self.manifest.write_text(yaml.safe_dump({"apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority",
            "metadata": {"id": "m"}, "binding": {"agent": "a", "session": "s", "host": "h"},
            "lifetime": {"notAfter": "2099-01-01T00:00:00Z", "renewable": False, "expansion": "prohibited"},
            "allow": [{"tool": t} for t in allow]}))
        self.loads_external = loads_external; self.n = 0; self.calls = []; self.pip = FakePip(wheels or {})
        self.write_status()
        def fake_run(argv):
            argv = list(argv); self.calls.append(argv)
            if argv[:2] == ["systemctl", "restart"]: self.write_status()
            if "pip" in argv: return self.pip(argv)
            class R: returncode = 0; stdout = ""; stderr = ""
            return R()
        monkeypatch.setattr(admin_mod, "run", fake_run)
        self.out = io.StringIO()
        self.admin = Admin(str(self.manifest), str(self.state), str(tmp_path / "r.jsonl"), "svc",
                           out=self.out, packs_dir=str(self.packs_dir))

    def write_status(self):
        self.n += 1
        loaded = {d["distribution"]: {"version": d["version"], "distribution": d["distribution"], "operations": ["example.ping"] if d["distribution"] == "example-pack" else []}
                  for d in pack_install.installed(self.packs_dir) if d["entry_points"]} if self.loads_external else {}
        (self.state / "authority-status.json").write_text(json.dumps(
            {"ok": True, "manifest_hash": "h", "at": f"t{self.n}", "packs": loaded}))


def test_admin_pack_install_confirms_the_service_loaded_it(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch)
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    assert s.admin.pack_install(str(lf), yes=True, timeout=2) == ["example-pack==1.0"]
    assert ["systemctl", "restart", "svc"] in s.calls and "example-pack 1.0 (external" in s.out.getvalue()


def test_admin_pack_install_rolls_back_when_the_service_does_not_load_it(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch, loads_external=False)          # e.g. unit lacks --packs-dir
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    with pytest.raises(AdminError, match="did not load.*previous packs restored"):
        s.admin.pack_install(str(lf), yes=True, timeout=2)
    assert pack_install.installed_trees(s.packs_dir) == {}
    assert sum(1 for c in s.calls if c[:2] == ["systemctl", "restart"]) == 2


def test_admin_pack_remove_refused_while_referenced_or_depended_on(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch, allow=("system.info", "example.ping"),
            wheels={"example-pack": {"requires": ("helper-lib",)}, "helper-lib": {"name": "helper-lib", "top": "helper_lib"}})
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0", "helper-lib==1.0"))
    s.admin.pack_install(str(lf), yes=True, timeout=2)
    with pytest.raises(AdminError, match=r"still allows \['example.ping'\]"):
        s.admin.pack_remove("example-pack", yes=True, timeout=2)
    with pytest.raises(AdminError, match="required by installed packs"):
        s.admin.pack_remove("helper-lib", yes=True, timeout=2)
    assert sorted(pack_install.installed_trees(s.packs_dir)) == ["example-pack", "helper-lib"]


def test_admin_pack_remove_when_unreferenced(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch)
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    s.admin.pack_install(str(lf), yes=True, timeout=2)
    s.admin.pack_remove("example-pack", yes=True, timeout=2)
    assert pack_install.installed_trees(s.packs_dir) == {}


def test_admin_pack_remove_refuses_without_service_status(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch); (s.state / "authority-status.json").unlink()
    with pytest.raises(AdminError, match="status unavailable"):
        s.admin.pack_remove("example-pack", yes=True, timeout=2)


def test_concurrent_pack_operations_are_refused(tmp_path, monkeypatch):
    import fcntl
    s = Svc(tmp_path, monkeypatch); s.packs_dir.mkdir()
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    with open(s.packs_dir / ".lock", "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(AdminError, match="in progress"):
            s.admin.pack_install(str(lf), yes=True, timeout=1)
        with pytest.raises(AdminError, match="in progress"):
            s.admin.pack_remove("example-pack", yes=True, timeout=1)


def test_swap_failure_after_moving_the_old_version_restores_it(tmp_path, monkeypatch):
    install(tmp_path, ["example-pack==1.0"], {}).commit()
    real_replace = pack_install.os.replace
    def flaky(src, dst):
        if Path(src).name == "example-pack" and ".staging-" in str(src):
            raise OSError("disk full")
        return real_replace(src, dst)
    monkeypatch.setattr(pack_install.os, "replace", flaky)
    with pytest.raises(OSError, match="disk full"):
        install(tmp_path, ["example-pack==2.0"], {"example-pack": {"version": "2.0"}})
    monkeypatch.setattr(pack_install.os, "replace", real_replace)
    assert [d["version"] for d in pack_install.installed(tmp_path / "packs")] == ["1.0"]


def test_interrupt_during_confirmation_rolls_back(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch)
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    real = s.admin._restart_and_confirm; calls = {"n": 0}
    def interrupted(timeout):
        calls["n"] += 1
        if calls["n"] == 1: raise KeyboardInterrupt
        return real(timeout)
    monkeypatch.setattr(s.admin, "_restart_and_confirm", interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.admin.pack_install(str(lf), yes=True, timeout=2)
    assert pack_install.installed_trees(s.packs_dir) == {} and calls["n"] == 2


def test_stale_directories_from_an_interrupted_run_are_cleaned_up(tmp_path):
    packs_dir = tmp_path / "packs"; (packs_dir / ".staging-999" / "x").mkdir(parents=True); (packs_dir / ".previous-999").mkdir()
    with pack_install.locked(packs_dir):
        pass
    assert sorted(p.name for p in packs_dir.iterdir()) == [".lock"]


def test_compiled_extension_modules_are_accepted_and_checked(tmp_path):
    import importlib.machinery
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    def with_ext(target: Path, **kw):
        fake_wheel(target, **kw); (target / f"_example_backend{suffix}").write_bytes(b"\x7fELF")
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    class Pip(FakePip):
        def __call__(self, argv):
            argv = list(argv)
            class R: returncode = 0; stdout = ""; stderr = ""
            with_ext(Path(argv[argv.index("--target") + 1])); return R()
    pack_install.install(lf, tmp_path / "packs", Pip({})).commit()
    assert (tmp_path / "packs" / "example-pack" / f"_example_backend{suffix}").exists()
    assert pack_install._module_name(f"_ssl{suffix}") == "_ssl" and "_ssl" in sys.stdlib_module_names


def test_a_crash_after_the_swap_is_recovered_by_the_next_run(tmp_path):
    """Regression (review of #64): .previous-* is the rollback copy, not junk."""
    install(tmp_path, ["example-pack==1.0"], {}).commit()
    txn = install(tmp_path, ["example-pack==2.0"], {"example-pack": {"version": "2.0"}})   # ... then the process dies
    assert [d["version"] for d in pack_install.installed(tmp_path / "packs")] == ["2.0"]
    with pack_install.locked(tmp_path / "packs") as recovered:
        assert recovered == ["example-pack"]
    assert [d["version"] for d in pack_install.installed(tmp_path / "packs")] == ["1.0"]
    assert not [p for p in (tmp_path / "packs").iterdir() if p.name.startswith(".") and p.name != ".lock"]


def test_auditwheel_libs_directories_are_allowed_but_unique(tmp_path):
    install(tmp_path, ["a-pack==1.0"], {"a-pack": {"name": "a-pack", "top": "a_pack", "extra": ("a_pack.libs",)}}).commit()
    with pytest.raises(PackInstallError, match="a_pack.libs.*collides"):
        install(tmp_path, ["b-pack==1.0"], {"b-pack": {"name": "b-pack", "top": "b_pack", "extra": ("a_pack.libs",)}})
    with pytest.raises(PackInstallError, match="unexpected top-level entry"):
        install(tmp_path, ["c-pack==1.0"], {"c-pack": {"name": "c-pack", "top": "c_pack", "extra": ("not-ident.libs",)}})


def test_install_confirmation_matches_whole_distribution_names(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch)
    fake_wheel(s.packs_dir / "pack", name="pack", top="pack_mod")          # pre-existing, never loaded by the service
    real = s.write_status
    def status_without_pack():
        real(); st = json.loads((s.state / "authority-status.json").read_text()); st["packs"].pop("pack", None)
        (s.state / "authority-status.json").write_text(json.dumps(st))
    s.write_status = status_without_pack
    lf = tmp_path / "lock.txt"; lf.write_text(lock("my-pack==1.0"))
    s.pip = FakePip({"my-pack": {"name": "my-pack", "top": "my_pack"}})
    assert s.admin.pack_install(str(lf), yes=True, timeout=2) == ["my-pack==1.0"]


def test_pack_operations_wait_their_turn_behind_grants(tmp_path, monkeypatch):
    import fcntl
    s = Svc(tmp_path, monkeypatch)
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    with open(s.manifest.with_name(f".{s.manifest.name}.admin.lock"), "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(AdminError, match="in progress"):
            s.admin.pack_install(str(lf), yes=True, timeout=1)
        with pytest.raises(AdminError, match="in progress"):
            s.admin.pack_remove("example-pack", yes=True, timeout=1)
