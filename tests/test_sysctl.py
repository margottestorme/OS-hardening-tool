"""Tests du handler sysctl.

L'audit lit /proc/sys ; on remplace _read par monkeypatch pour tester les
branches sans dépendre du vrai noyau. L'idempotence de la persistance est
testée sur un fichier temporaire, sans écrire dans /proc.
"""

from cis_tool.handlers.sysctl import SysctlHandler
from cis_tool.models import Rule, Status


def make_rule(key="net.ipv4.ip_forward", expected=0, **extra):
    params = {"key": key, "expected": expected, **extra}
    return Rule(id="r", cis_id="3.3.1", title="T", level=1,
                category="network", type="sysctl", params=params)


def test_compliant(monkeypatch):
    h = SysctlHandler()
    monkeypatch.setattr(h, "_read", lambda key: "0")
    res = h.check(make_rule(expected=0))
    assert res.status is Status.COMPLIANT
    assert res.actual == "0"


def test_non_compliant(monkeypatch):
    h = SysctlHandler()
    monkeypatch.setattr(h, "_read", lambda key: "1")
    assert h.check(make_rule(expected=0)).status is Status.NON_COMPLIANT


def test_key_not_found_is_error(monkeypatch):
    h = SysctlHandler()
    monkeypatch.setattr(h, "_read", lambda key: None)
    assert h.check(make_rule()).status is Status.ERROR


def test_expected_int_matches_proc_string(monkeypatch):
    # expected: 1 (int dans le YAML) doit matcher "1" lu depuis /proc
    h = SysctlHandler()
    monkeypatch.setattr(h, "_read", lambda key: "1")
    assert h.check(make_rule(expected=1)).status is Status.COMPLIANT


def test_normalize_collapses_whitespace():
    assert SysctlHandler._normalize("1\t\t2   3") == "1 2 3"


def test_proc_path_translation():
    p = SysctlHandler._proc_path("net.ipv4.ip_forward")
    assert str(p) == "/proc/sys/net/ipv4/ip_forward"


def test_apply_persist_idempotent(tmp_path, monkeypatch):
    h = SysctlHandler()
    persist = tmp_path / "60-cis.conf"
    # rediriger l'écriture "à chaud" vers un fichier temporaire (pas /proc)
    fake_proc = tmp_path / "proc_value"
    monkeypatch.setattr(h, "_proc_path", lambda key: fake_proc)

    rule = make_rule(key="net.ipv4.conf.all.send_redirects", expected=0,
                     persist_file=str(persist))

    h.apply(rule)
    first = persist.read_text()
    h.apply(rule)
    second = persist.read_text()

    assert first == second
    assert first.count("net.ipv4.conf.all.send_redirects") == 1
    assert "net.ipv4.conf.all.send_redirects = 0" in first