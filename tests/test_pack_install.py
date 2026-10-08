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
    (lock("a==1", "A==2"), "more than once"),
    ("# only a comment\n", "no requirements"),
])
def test_lockfile_must_be_exact_and_hashed(text, match):
    with pytest.raises(PackInstallError, match=match): parse_lockfile(text)


def test_lockfile_accepts_continuations_and_comments():
    pins = parse_lockfile(f"# packs\nExample_Pack==1.0 \\\n    --hash=sha256:{H} \\\n    --hash=sha256:{'b'*64}  # pinned\n")
    assert [(p.name, p.version, len(p.hashes)) for p in pins] == [("example-pack", "1.0", 2)]


def fake_wheel(target: Path, name="example-pack", version="1.0", top="example_pack"):
    info = target / f"{name.replace('-', '_')}-{version}.dist-info"; info.mkdir(parents=True)
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
    (info / "top_level.txt").write_text(top + "\n")
    (info / "entry_points.txt").write_text(f"[mcp_remote_sudo.packs]\nexample = {top}:PACK\n")
    pkg = target / top; pkg.mkdir()
    (pkg / "__init__.py").write_text("raise RuntimeError('pack code must never be imported by the installer')\n")
    (info / "RECORD").write_text(f"{top}/__init__.py,,\n{info.name}/METADATA,,\n")


class FakePip:
    def __init__(self, wheels): self.wheels = wheels; self.calls = []
    def __call__(self, argv):
        argv = list(argv); self.calls.append(argv)
        class R: returncode = 0; stdout = ""; stderr = ""
        if "pip" in argv:
            target = Path(argv[argv.index("--target") + 1])
            for w in self.wheels: fake_wheel(target, **w)
        return R()


def test_install_is_wheel_only_hashed_isolated_and_never_imports(tmp_path):
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    pip = FakePip([{}]); packs_dir = tmp_path / "packs"
    assert pack_install.install(lf, packs_dir, pip) == ["example-pack==1.0"]
    argv = pip.calls[0]
    assert argv[1:4] == ["-I", "-m", "pip"]
    for flag in ("--only-binary", ":all:", "--require-hashes", "--no-deps", "--no-compile", "--target"):
        assert flag in argv
    assert (packs_dir / "example_pack" / "__init__.py").exists()
    assert "example_pack" not in sys.modules
    assert not list(tmp_path.glob(".packs.staging-*"))
    assert pack_install.installed(packs_dir) == [{"distribution": "example-pack", "version": "1.0", "entry_points": ["example"]}]


@pytest.mark.parametrize("wheel,pinned,match", [
    ({"name": "pyyaml", "top": "yaml_alt"}, "pyyaml==6.0", "refusing to replace mcp-remote-sudo"),
    ({"name": "mcp-remote-sudo", "top": "mrs_alt"}, "mcp-remote-sudo==9.9", "refusing to replace"),
    ({"name": "evil-pack", "top": "json"}, "evil-pack==1.0", "shadows the standard library"),
    ({"name": "evil-pack", "top": "yaml"}, "evil-pack==1.0", "collides with"),
    ({"name": "evil-pack", "top": "mcp_remote_sudo"}, "evil-pack==1.0", "collides with|already importable"),
    ({"name": "surprise", "top": "surprise"}, "example-pack==1.0", "lockfile pins"),
])
def test_install_refusals_leave_packs_dir_untouched(tmp_path, wheel, pinned, match):
    lf = tmp_path / "lock.txt"; lf.write_text(lock(pinned)); packs_dir = tmp_path / "packs"
    with pytest.raises(PackInstallError, match=match):
        pack_install.install(lf, packs_dir, FakePip([wheel]))
    assert not any(packs_dir.iterdir())


def test_install_refuses_collision_with_another_pack_and_upgrades_in_place(tmp_path):
    packs_dir = tmp_path / "packs"; lf = tmp_path / "lock.txt"
    lf.write_text(lock("example-pack==1.0")); pack_install.install(lf, packs_dir, FakePip([{}]))
    lf.write_text(lock("other-pack==1.0"))
    with pytest.raises(PackInstallError, match="installed pack example-pack"):
        pack_install.install(lf, packs_dir, FakePip([{"name": "other-pack", "top": "example_pack"}]))
    lf.write_text(lock("example-pack==2.0")); pack_install.install(lf, packs_dir, FakePip([{"version": "2.0"}]))
    assert [d["version"] for d in pack_install.installed(packs_dir)] == ["2.0"]


def test_pip_failure_is_reported(tmp_path):
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    def failing(argv):
        class R: returncode = 1; stdout = ""; stderr = "ERROR: Hashes are required"
        return R()
    with pytest.raises(PackInstallError, match="Hashes are required"):
        pack_install.install(lf, tmp_path / "packs", failing)


def test_registry_describe_reports_distributions():
    d = packs.default_registry().describe()
    assert d["core"]["distribution"] == "mcp-remote-sudo" and "journal.query" in d["core"]["operations"]


class Svc:
    """Fake host for admin pack commands: status file + systemctl restart that rewrites it."""
    def __init__(self, tmp_path, monkeypatch, allow=("system.info",), loaded_packs=None):
        self.tmp = tmp_path; self.state = tmp_path / "state"; self.state.mkdir()
        self.manifest = tmp_path / "authority.yaml"
        self.manifest.write_text(yaml.safe_dump({"apiVersion": "mcp-remote-sudo/v1", "kind": "TaskAuthority",
            "metadata": {"id": "m"}, "binding": {"agent": "a", "session": "s", "host": "h"},
            "lifetime": {"notAfter": "2099-01-01T00:00:00Z", "renewable": False, "expansion": "prohibited"},
            "allow": [{"tool": t} for t in allow]}))
        self.loaded = loaded_packs or {}; self.n = 0; self.calls = []; self.write_status()
        def fake_run(argv):
            argv = list(argv); self.calls.append(argv)
            if argv[:2] == ["systemctl", "restart"]: self.write_status()
            if "pip" in argv: fake_wheel(Path(argv[argv.index("--target") + 1]))
            class R: returncode = 0; stdout = ""; stderr = ""
            return R()
        monkeypatch.setattr(admin_mod, "run", fake_run)
        self.out = io.StringIO()
        self.admin = Admin(str(self.manifest), str(self.state), str(tmp_path / "r.jsonl"), "svc",
                           out=self.out, packs_dir=str(tmp_path / "packs"))

    def write_status(self):
        self.n += 1
        (self.state / "authority-status.json").write_text(json.dumps(
            {"ok": True, "manifest_hash": "h", "at": f"t{self.n}", "packs": self.loaded}))


def test_admin_pack_install_restarts_and_lists(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch)
    lf = tmp_path / "lock.txt"; lf.write_text(lock("example-pack==1.0"))
    assert s.admin.pack_install(str(lf), yes=True, timeout=2) == ["example-pack==1.0"]
    assert ["systemctl", "restart", "svc"] in s.calls
    assert "example-pack 1.0 (external" in s.out.getvalue()


def test_admin_pack_remove_refused_while_referenced(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch, allow=("system.info", "example.ping"),
            loaded_packs={"example": {"version": "1", "distribution": "example-pack", "operations": ["example.ping"]}})
    fake_wheel(tmp_path / "packs")
    with pytest.raises(AdminError, match=r"still allows \['example.ping'\]"):
        s.admin.pack_remove("example-pack", yes=True, timeout=2)
    assert (tmp_path / "packs" / "example_pack").exists()


def test_admin_pack_remove_when_unreferenced(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch,
            loaded_packs={"example": {"version": "1", "distribution": "example-pack", "operations": ["example.ping"]}})
    fake_wheel(tmp_path / "packs")
    s.admin.pack_remove("example-pack", yes=True, timeout=2)
    assert not (tmp_path / "packs" / "example_pack").exists() and pack_install.installed(tmp_path / "packs") == []
    assert ["systemctl", "restart", "svc"] in s.calls


def test_admin_pack_remove_refuses_without_service_status(tmp_path, monkeypatch):
    s = Svc(tmp_path, monkeypatch); (s.state / "authority-status.json").unlink()
    with pytest.raises(AdminError, match="status unavailable"):
        s.admin.pack_remove("example-pack", yes=True, timeout=2)
