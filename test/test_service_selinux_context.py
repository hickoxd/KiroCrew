"""The system unit runs the gateway in the installer's SELinux context.

Without ``SELinuxContext=`` a system unit's gateway runs as ``system_u``, and
every cache it writes under the user's home (``~/.npm/_cacache``) is labelled
``system_u``; the user's own shell is then refused hardlinks inside it. These
tests point the module at a tmp_path selinuxfs and a fake ``/proc/self/attr``,
so the verdict never depends on the host running the suite.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from kiro_crew.service import linux as svc_linux
from kiro_crew.service import selinux as sel

USER_CTX = "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A host whose selinuxfs and installer context each test sets."""
    enforce = tmp_path / "selinux" / "enforce"
    attr = tmp_path / "attr-current"
    monkeypatch.setattr(sel, "_ENFORCE_PATH", enforce)
    monkeypatch.setattr(sel, "_INSTALLER_ATTR", attr, raising=False)

    def configure(*, enforce_value: str | None = "1", context: str | None = USER_CTX) -> None:
        if enforce_value is not None:
            enforce.parent.mkdir(exist_ok=True)
            enforce.write_text(enforce_value)
        if context is not None:
            # The kernel NUL-terminates the attribute.
            attr.write_text(context + "\x00")

    return configure


def _render(*, user_scope: bool = False) -> str:
    gid = MagicMock(returncode=0, stdout="tester\n", stderr="")
    with (
        patch(
            "kiro_crew.service.common.shutil.which", return_value="/home/tester/.local/bin/kirocrew"
        ),
        patch("kiro_crew.service.linux.subprocess.run", return_value=gid),
        patch("kiro_crew.service.linux.trusted_system_bin", return_value="/usr/bin/id"),
    ):
        return svc_linux.render_unit(user_scope=user_scope)


class TestInstallerContext:
    @pytest.mark.parametrize("enforce_value", ["1", "0"])
    def test_enforcing_and_permissive_hosts_both_get_the_context(self, host, enforce_value):
        host(enforce_value=enforce_value)
        assert sel.installer_context() == USER_CTX

    def test_no_selinux_is_none(self, host):
        host(enforce_value=None)
        assert sel.installer_context() is None

    def test_unreadable_context_is_none(self, host):
        host(context=None)
        assert sel.installer_context() is None

    def test_a_system_u_installer_is_none(self, host):
        host(context="system_u:system_r:initrc_t:s0")
        assert sel.installer_context() is None

    @pytest.mark.parametrize(
        "bad",
        ["", "kernel", "unconfined_u::unconfined_t", "a:b:c\nExecStartPre=/bin/sh", "a:b:c d"],
    )
    def test_a_malformed_context_is_none(self, host, bad):
        host(context=bad)
        assert sel.installer_context() is None


class TestRenderedUnit:
    @pytest.fixture(autouse=True)
    def _user(self, monkeypatch):
        monkeypatch.setenv("USER", "tester")
        monkeypatch.delenv("SUDO_USER", raising=False)

    def test_selinux_host_unit_runs_in_the_installer_context(self, host):
        host()
        unit = _render()
        assert f"\nSELinuxContext={USER_CTX}\n" in unit
        # Inside [Service], next to the account it applies to.
        service = unit.split("[Service]\n", 1)[1].split("\n[Install]", 1)[0]
        assert f"SELinuxContext={USER_CTX}" in service.splitlines()

    def test_non_selinux_host_unit_has_no_context_line(self, host):
        host(enforce_value=None)
        assert "SELinuxContext=" not in _render()

    def test_user_scope_unit_never_carries_it(self, host):
        host()
        assert "SELinuxContext=" not in _render(user_scope=True)
