"""Tests du handler file_perms (stat, comparaison de mode, owner/group)."""

import grp
import os
import pwd

from cis_tool.handlers.file_perms import FilePermsHandler
from cis_tool.models import Rule, Status


def make_rule(path, **params):
    p = {"path": str(path)}
    p.update(params)
    return Rule(id="r", cis_id="7.1.1", title="T", level=1,
                category="permissions", type="file_perms", params=p)


def _owner():
    return pwd.getpwuid(os.getuid()).pw_name


def _group():
    return grp.getgrgid(os.getgid()).gr_name


def _make_file(tmp_path, mode):
    f = tmp_path / "x"
    f.write_text("", encoding="utf-8")
    f.chmod(mode)
    return f


def test_mode_compliant_more_restrictive(tmp_path):
    # 0600 est plus strict que 0644 → conforme
    f = _make_file(tmp_path, 0o600)
    assert FilePermsHandler().check(make_rule(f, mode_max="644")).status is Status.COMPLIANT


def test_mode_non_compliant_too_permissive(tmp_path):
    f = _make_file(tmp_path, 0o666)
    assert FilePermsHandler().check(make_rule(f, mode_max="644")).status is Status.NON_COMPLIANT


def test_owner_match(tmp_path):
    f = _make_file(tmp_path, 0o644)
    rule = make_rule(f, owner=_owner(), group=_group(), mode_max="644")
    assert FilePermsHandler().check(rule).status is Status.COMPLIANT


def test_owner_mismatch(tmp_path):
    f = _make_file(tmp_path, 0o644)
    rule = make_rule(f, owner=_owner() + "_nope", mode_max="644")
    assert FilePermsHandler().check(rule).status is Status.NON_COMPLIANT


def test_missing_file_is_error(tmp_path):
    assert FilePermsHandler().check(make_rule(tmp_path / "absent", mode_max="644")).status is Status.ERROR


def test_apply_sets_mode(tmp_path):
    f = _make_file(tmp_path, 0o666)
    FilePermsHandler().apply(make_rule(f, mode_max="600"))
    assert (f.stat().st_mode & 0o777) == 0o600