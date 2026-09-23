"""Tests du handler file_directive : audit et idempotence de la remédiation."""

from cis_tool.handlers.file_directive import FileDirectiveHandler
from cis_tool.models import Rule, Status


def make_rule(**params):
    base = {"directive": "PermitRootLogin", "expected": "no", "separator": " "}
    base.update(params)
    return Rule(id="r", cis_id="5.1.20", title="T", level=1,
                category="ssh", type="file_directive", params=base)


def write_cfg(tmp_path, text):
    p = tmp_path / "sshd_config"
    p.write_text(text, encoding="utf-8")
    return p


# --- audit -------------------------------------------------------------------
def test_compliant_eq(tmp_path):
    cfg = write_cfg(tmp_path, "PermitRootLogin no\n")
    res = FileDirectiveHandler().check(make_rule(file=str(cfg)))
    assert res.status is Status.COMPLIANT
    assert res.actual == "no"


def test_non_compliant_wrong_value(tmp_path):
    cfg = write_cfg(tmp_path, "PermitRootLogin yes\n")
    res = FileDirectiveHandler().check(make_rule(file=str(cfg)))
    assert res.status is Status.NON_COMPLIANT
    assert res.actual == "yes"


def test_absent_directive_is_non_compliant(tmp_path):
    cfg = write_cfg(tmp_path, "# rien ici\nPort 22\n")
    res = FileDirectiveHandler().check(make_rule(file=str(cfg)))
    assert res.status is Status.NON_COMPLIANT
    assert res.actual is None


def test_missing_file_is_error(tmp_path):
    res = FileDirectiveHandler().check(make_rule(file=str(tmp_path / "absent")))
    assert res.status is Status.ERROR


def test_case_insensitive_eq(tmp_path):
    cfg = write_cfg(tmp_path, "PermitRootLogin NO\n")
    res = FileDirectiveHandler().check(make_rule(file=str(cfg)))
    assert res.status is Status.COMPLIANT


def test_commented_line_ignored(tmp_path):
    cfg = write_cfg(tmp_path, "#PermitRootLogin no\nPermitRootLogin yes\n")
    res = FileDirectiveHandler().check(make_rule(file=str(cfg)))
    assert res.status is Status.NON_COMPLIANT
    assert res.actual == "yes"


def test_first_occurrence_wins(tmp_path):
    # sshd retient la 1re occurrence non commentée → "no" → conforme
    cfg = write_cfg(tmp_path, "PermitRootLogin no\nPermitRootLogin yes\n")
    res = FileDirectiveHandler().check(make_rule(file=str(cfg)))
    assert res.status is Status.COMPLIANT
    assert res.actual == "no"


def test_operator_le_pass(tmp_path):
    cfg = write_cfg(tmp_path, "MaxAuthTries 3\n")
    rule = make_rule(file=str(cfg), directive="MaxAuthTries", expected=4, operator="le")
    assert FileDirectiveHandler().check(rule).status is Status.COMPLIANT


def test_operator_le_fail(tmp_path):
    cfg = write_cfg(tmp_path, "MaxAuthTries 10\n")
    rule = make_rule(file=str(cfg), directive="MaxAuthTries", expected=4, operator="le")
    assert FileDirectiveHandler().check(rule).status is Status.NON_COMPLIANT


# --- remédiation : idempotence ----------------------------------------------
def test_apply_is_idempotent(tmp_path):
    cfg = write_cfg(tmp_path, "PermitRootLogin yes\nPort 22\n")
    rule = make_rule(file=str(cfg))
    h = FileDirectiveHandler()

    h.apply(rule)
    first = cfg.read_text()
    h.apply(rule)
    second = cfg.read_text()

    assert first == second                      # 2e apply : aucun changement
    assert first.count("PermitRootLogin") == 1  # pas d'empilement de la directive
    assert "PermitRootLogin no" in first