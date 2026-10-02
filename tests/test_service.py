"""Tests du handler service : modes 'absent' (dpkg) et 'disabled' (systemctl).

On remplace _run par monkeypatch pour simuler les sorties de dpkg-query et
systemctl sans dépendre de l'état réel de la machine.
"""

from cis_tool.handlers.service import ServiceHandler
from cis_tool.models import Rule, Status


def pkg_rule(package="cups"):
    return Rule(id="r", cis_id="2.1.2", title="T", level=1, category="services",
                type="service", params={"package": package, "state": "absent"})


def svc_rule(unit="rpcbind.service"):
    return Rule(id="r", cis_id="2.1.8", title="T", level=1, category="services",
                type="service", params={"unit": unit, "state": "disabled"})


# --- mode 'absent' (paquet) -------------------------------------------------
def test_package_installed_is_non_compliant(monkeypatch):
    h = ServiceHandler()
    monkeypatch.setattr(h, "_run", lambda cmd: (0, "install ok installed"))
    res = h.check(pkg_rule())
    assert res.status is Status.NON_COMPLIANT
    assert res.actual == "installé"


def test_package_unknown_is_compliant(monkeypatch):
    # dpkg-query renvoie != 0 quand le paquet n'existe pas
    h = ServiceHandler()
    monkeypatch.setattr(h, "_run", lambda cmd: (1, ""))
    assert h.check(pkg_rule()).status is Status.COMPLIANT


def test_package_removed_configfiles_is_compliant(monkeypatch):
    # paquet retiré mais fichiers de conf restants → binaires absents → conforme
    h = ServiceHandler()
    monkeypatch.setattr(h, "_run", lambda cmd: (0, "deinstall ok config-files"))
    assert h.check(pkg_rule()).status is Status.COMPLIANT


# --- mode 'disabled' (service) ----------------------------------------------
def test_service_enabled_is_non_compliant(monkeypatch):
    h = ServiceHandler()
    monkeypatch.setattr(h, "_run", lambda cmd: (0, "enabled\n"))
    res = h.check(svc_rule())
    assert res.status is Status.NON_COMPLIANT
    assert res.actual == "enabled"


def test_service_masked_is_compliant(monkeypatch):
    h = ServiceHandler()
    monkeypatch.setattr(h, "_run", lambda cmd: (1, "masked\n"))
    assert h.check(svc_rule()).status is Status.COMPLIANT


def test_service_not_found_is_compliant(monkeypatch):
    h = ServiceHandler()
    monkeypatch.setattr(h, "_run", lambda cmd: (1, "not-found\n"))
    assert h.check(svc_rule()).status is Status.COMPLIANT


# --- garde-fou --------------------------------------------------------------
def test_unknown_state_is_error():
    rule = Rule(id="r", cis_id="2.1", title="T", level=1, category="services",
                type="service", params={"package": "x", "state": "weird"})
    assert ServiceHandler().check(rule).status is Status.ERROR