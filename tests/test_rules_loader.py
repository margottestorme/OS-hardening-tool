"""Tests du chargement / validation des règles YAML."""

import pytest

from cis_tool.rules_loader import RuleValidationError, load_rules

VALID = """
defaults:
  file: /etc/ssh/sshd_config
  separator: " "
rules:
  - id: r1
    cis_id: "5.1.20"
    title: "T1"
    level: 1
    category: ssh
    type: file_directive
    params:
      directive: PermitRootLogin
      expected: "no"
"""


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_loads_valid_rule_and_merges_defaults(tmp_path):
    rule = load_rules(_write(tmp_path, "a.yaml", VALID))[0]
    assert rule.id == "r1"
    assert rule.type == "file_directive"
    # defaults fusionnés dans les params…
    assert rule.params["file"] == "/etc/ssh/sshd_config"
    assert rule.params["separator"] == " "
    # …et params propres à la règle conservés
    assert rule.params["directive"] == "PermitRootLogin"


def test_rule_params_override_defaults(tmp_path):
    content = """
defaults:
  file: /default/path
rules:
  - id: r1
    cis_id: "1.1"
    title: "T"
    level: 1
    category: ssh
    type: file_directive
    params:
      file: /override/path
      directive: X
      expected: "y"
"""
    rule = load_rules(_write(tmp_path, "a.yaml", content))[0]
    assert rule.params["file"] == "/override/path"


def test_missing_required_field_raises(tmp_path):
    content = """
rules:
  - id: r1
    title: "sans cis_id, level, category, type"
"""
    with pytest.raises(RuleValidationError):
        load_rules(_write(tmp_path, "a.yaml", content))


def test_invalid_level_raises(tmp_path):
    content = """
rules:
  - id: r1
    cis_id: "1.1"
    title: "T"
    level: 3
    category: ssh
    type: file_directive
    params: {directive: X, expected: "y"}
"""
    with pytest.raises(RuleValidationError):
        load_rules(_write(tmp_path, "a.yaml", content))


def test_duplicate_id_raises(tmp_path):
    content = """
rules:
  - id: dup
    cis_id: "1.1"
    title: "A"
    level: 1
    category: ssh
    type: file_directive
    params: {directive: X, expected: "y"}
  - id: dup
    cis_id: "1.2"
    title: "B"
    level: 1
    category: ssh
    type: file_directive
    params: {directive: Y, expected: "z"}
"""
    with pytest.raises(RuleValidationError):
        load_rules(_write(tmp_path, "a.yaml", content))


def test_loads_directory_of_files(tmp_path):
    _write(tmp_path, "a.yaml", VALID)
    _write(tmp_path, "b.yaml", VALID.replace("r1", "r2"))
    ids = {r.id for r in load_rules(tmp_path)}
    assert ids == {"r1", "r2"}


def test_missing_path_raises(tmp_path):
    with pytest.raises(RuleValidationError):
        load_rules(tmp_path / "n_existe_pas.yaml")