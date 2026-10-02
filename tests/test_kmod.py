"""Tests du handler kmod : logique à deux signaux + parsing modprobe.d."""

import cis_tool.handlers.kmod as kmod_mod
from cis_tool.handlers.kmod import KmodHandler
from cis_tool.models import Rule, Status


def make_rule(module="cramfs"):
    return Rule(id="r", cis_id="1.1.1.1", title="T", level=1,
                category="filesystem", type="kmod", params={"module": module})


# --- logique de conformité (helpers monkeypatchés) --------------------------
def test_compliant_not_loaded_and_blocked(monkeypatch):
    h = KmodHandler()
    monkeypatch.setattr(h, "_is_loaded", lambda m: False)
    monkeypatch.setattr(h, "_is_load_blocked", lambda m: True)
    assert h.check(make_rule()).status is Status.COMPLIANT


def test_non_compliant_when_loaded(monkeypatch):
    h = KmodHandler()
    monkeypatch.setattr(h, "_is_loaded", lambda m: True)
    monkeypatch.setattr(h, "_is_load_blocked", lambda m: True)
    res = h.check(make_rule())
    assert res.status is Status.NON_COMPLIANT
    assert "chargé" in res.detail


def test_non_compliant_when_not_blocked(monkeypatch):
    h = KmodHandler()
    monkeypatch.setattr(h, "_is_loaded", lambda m: False)
    monkeypatch.setattr(h, "_is_load_blocked", lambda m: False)
    res = h.check(make_rule())
    assert res.status is Status.NON_COMPLIANT
    assert "bloqué" in res.detail


# --- parsing des fichiers modprobe.d ----------------------------------------
def _make_dir(tmp_path, monkeypatch):
    d = tmp_path / "modprobe.d"
    d.mkdir()
    monkeypatch.setattr(kmod_mod, "MODPROBE_DIRS", (str(d),))
    return d


def test_load_blocked_detects_install_false(tmp_path, monkeypatch):
    d = _make_dir(tmp_path, monkeypatch)
    (d / "cis.conf").write_text("install cramfs /bin/false\n", encoding="utf-8")
    assert KmodHandler()._is_load_blocked("cramfs") is True


def test_load_blocked_accepts_hyphen_and_underscore(tmp_path, monkeypatch):
    # fichier écrit avec underscore, module demandé avec tiret → doit matcher
    d = _make_dir(tmp_path, monkeypatch)
    (d / "cis.conf").write_text("install usb_storage /bin/true\n", encoding="utf-8")
    assert KmodHandler()._is_load_blocked("usb-storage") is True


def test_load_not_blocked_when_absent(tmp_path, monkeypatch):
    d = _make_dir(tmp_path, monkeypatch)
    (d / "other.conf").write_text("install autremodule /bin/false\n", encoding="utf-8")
    assert KmodHandler()._is_load_blocked("cramfs") is False


def test_commented_install_line_ignored(tmp_path, monkeypatch):
    d = _make_dir(tmp_path, monkeypatch)
    (d / "cis.conf").write_text("#install cramfs /bin/false\n", encoding="utf-8")
    assert KmodHandler()._is_load_blocked("cramfs") is False