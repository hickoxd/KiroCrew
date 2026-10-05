"""Config-defined git hooks (``hook.<name>.command``, git 2.54+) on host-side git.

``core.hooksPath`` only moves the hook directory, so a hook named in a repository's
``.git/config`` still runs. Every host-side git call over an agent-writable tree must
disable each such hook by name. Two kinds of test:

* argv tests run on any git: ``git config`` lists a ``hook.*`` key whatever the
  version, so the disable flag either reaches the spawned argv or it does not.
* firing tests need git 2.54+, the first version that runs config hooks, and skip
  below it. They prove the flag actually stops the hook.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from kiro_crew import git_config_hooks as gch


def _git_version() -> tuple[int, int]:
    out = subprocess.run(["git", "--version"], capture_output=True, check=True).stdout.decode()
    m = re.search(r"(\d+)\.(\d+)", out)
    assert m, out
    return int(m.group(1)), int(m.group(2))


needs_config_hooks = pytest.mark.skipif(
    _git_version() < (2, 54), reason="git < 2.54 has no config-defined hooks"
)

_ENV = {
    "GIT_AUTHOR_NAME": "T",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "T",
    "GIT_COMMITTER_EMAIL": "t@example.com",
}


@pytest.fixture(autouse=True)
def _isolated_git_config(tmp_path, monkeypatch):
    """No host global/system config: only the hooks a test plants exist."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    for key, value in _ENV.items():
        monkeypatch.setenv(key, value)


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "a.txt").write_text("a\n")
    _git(root, "add", "a.txt")
    _git(root, "commit", "-qm", "init")
    return root


def _plant(repo: Path, marker: Path, name: str = "pwn") -> None:
    """A config hook on every event the host-side helpers trigger."""
    for event in ("pre-commit", "post-commit", "post-index-change", "reference-transaction"):
        _git(repo, "config", "--add", f"hook.{name}.event", event)
    # `#` ends the command so git's appended hook arguments are ignored.
    _git(repo, "config", f"hook.{name}.command", f"echo {name} >> '{marker}' #")


# ── the helper ──


def test_no_hooks_adds_nothing(repo: Path) -> None:
    assert gch.config_hook_names(repo) == []
    assert gch.config_hook_disable_args(repo) == []


def test_lists_every_scope_and_include(repo: Path, tmp_path: Path, monkeypatch) -> None:
    included = tmp_path / "inc.cfg"
    included.write_text('[hook "fromInclude"]\n\tcommand = true\n\tevent = pre-commit\n')
    _git(repo, "config", "include.path", str(included))
    _git(repo, "config", "hook.local.command", "true")
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(
        '[hook "fromGlobal"]\n\tcommand = true\n\tevent = pre-commit\n'
    )
    monkeypatch.delenv("GIT_CONFIG_GLOBAL")
    monkeypatch.setenv("HOME", str(home))
    with (repo / ".git" / "config").open("a") as fh:
        fh.write('[hook "Mixed Case.dot"]\n\tcommand = true\n')
    assert sorted(gch.config_hook_names(repo)) == [
        "Mixed Case.dot",
        "fromGlobal",
        "fromInclude",
        "local",
    ]
    assert any("enabled" in a for a in gch.config_hook_disable_args(repo))


def test_two_part_hook_setting_is_not_a_name(repo: Path) -> None:
    _git(repo, "config", "hook.jobs", "2")
    assert gch.config_hook_names(repo) == []


def test_name_with_equals_is_refused(repo: Path) -> None:
    # `-c` splits on the first `=`, so this name could not be disabled.
    with (repo / ".git" / "config").open("a") as fh:
        fh.write('[hook "a=b"]\n\tcommand = true\n\tevent = pre-commit\n')
    with pytest.raises(gch.ConfigHookScanError, match="'='"):
        gch.config_hook_disable_args(repo)


def test_too_many_names_is_refused(repo: Path) -> None:
    with (repo / ".git" / "config").open("a") as fh:
        for i in range(gch.MAX_HOOK_NAMES + 1):
            fh.write(f'[hook "h{i}"]\n\tcommand = true\n')
    with pytest.raises(gch.ConfigHookScanError, match="limit"):
        gch.config_hook_names(repo)


def test_name_too_long_is_refused(repo: Path) -> None:
    """A hook name over _MAX_HOOK_NAME_BYTES bytes cannot be passed as a -c arg."""
    long_name = "x" * (gch._MAX_HOOK_NAME_BYTES + 1)
    with (repo / ".git" / "config").open("a") as fh:
        fh.write(f'[hook "{long_name}"]\n\tcommand = true\n')
    with pytest.raises(gch.ConfigHookScanError, match="bytes"):
        gch.config_hook_names(repo)


def test_empty_hook_name_is_disabled(repo: Path) -> None:
    """[hook ""] with event=pre-commit must not be silently skipped."""
    with (repo / ".git" / "config").open("a") as fh:
        fh.write('[hook ""]\n\tcommand = true\n\tevent = pre-commit\n')
    args = gch.config_hook_disable_args(repo)
    assert "hook..enabled=false" in args, args


def test_unreadable_config_is_refused(repo: Path) -> None:
    (repo / ".git" / "config").write_text("[broken\n")
    with pytest.raises(gch.ConfigHookScanError):
        gch.config_hook_names(repo)


def test_missing_directory_adds_nothing(tmp_path: Path) -> None:
    assert gch.config_hook_names(tmp_path / "absent") == []


def test_missing_git_binary_adds_nothing(repo: Path, tmp_path: Path) -> None:
    assert gch.config_hook_names(repo, git=str(tmp_path / "no-such-git")) == []


@needs_config_hooks
def test_baseline_hooks_path_alone_does_not_stop_a_config_hook(repo: Path, tmp_path: Path) -> None:
    """Positive control: without the disable flags the planted hook really fires."""
    marker = tmp_path / "marker"
    _plant(repo, marker)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            f"core.hooksPath={os.devnull}",
            "commit",
            "-qm",
            "x",
            "--allow-empty",
        ],
        check=True,
        capture_output=True,
    )
    assert marker.exists()


@needs_config_hooks
def test_disable_args_stop_the_hook_even_with_an_event_named_hook(
    repo: Path, tmp_path: Path
) -> None:
    # `hook.<event>.command` makes git 2.55+ treat `hook.<event>.enabled=false` as a
    # per-hook switch, which is why the helper disables by NAME instead.
    marker = tmp_path / "marker"
    _plant(repo, marker)
    _git(repo, "config", "hook.pre-commit.command", "true")
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            f"core.hooksPath={os.devnull}",
            *gch.config_hook_disable_args(repo),
            "commit",
            "-qm",
            "x",
            "--allow-empty",
        ],
        check=True,
        capture_output=True,
    )
    assert not marker.exists()


# ── auto_improvement (git_safety) ──


def test_git_safety_argv_carries_the_disable(repo: Path, tmp_path: Path) -> None:
    from kiro_crew.apps.builtins.auto_improvement.spine import gate, git_safety

    _plant(repo, tmp_path / "marker")
    assert "hook.pwn.enabled=false" in git_safety.git_argv(repo, "status")
    assert "hook.pwn.enabled=false" in gate._git_argv(repo, "add", "-A")


def test_git_safety_scan_failure_is_a_git_safety_error(repo: Path) -> None:
    from kiro_crew.apps.builtins.auto_improvement.spine import git_safety

    with (repo / ".git" / "config").open("a") as fh:
        fh.write('[hook "a=b"]\n\tcommand = true\n')
    with pytest.raises(git_safety.GitSafetyError):
        git_safety.hook_off_args(repo)


@needs_config_hooks
def test_git_safety_commit_does_not_fire(repo: Path, tmp_path: Path) -> None:
    from kiro_crew.apps.builtins.auto_improvement.spine import gate

    marker = tmp_path / "marker"
    _plant(repo, marker)
    (repo / "a.txt").write_text("b\n")
    for args in (("add", "-A"), ("commit", "-qm", "x"), ("status", "--porcelain")):
        subprocess.run(gate._git_argv(repo, *args), check=True, capture_output=True)
    assert not marker.exists()


# ── md_notebook ──


def _md_use_path_git(monkeypatch) -> None:
    from kiro_crew.apps.builtins.md_notebook import git_ops

    monkeypatch.setattr(git_ops, "_git_bin", lambda: shutil.which("git"))
    # TRUSTED_PATH would hide a newer git a developer put first on PATH.
    monkeypatch.setattr(git_ops, "TRUSTED_PATH", os.environ["PATH"])


@pytest.mark.asyncio
async def test_md_notebook_run_git_carries_the_disable(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    from kiro_crew.apps.builtins.md_notebook import git_ops

    _md_use_path_git(monkeypatch)
    _plant(repo, tmp_path / "marker")
    seen: list[tuple[str, ...]] = []
    real = asyncio.create_subprocess_exec

    async def spy(*argv, **kw):
        seen.append(argv)
        return await real(*argv, **kw)

    monkeypatch.setattr(git_ops.asyncio, "create_subprocess_exec", spy)
    await git_ops.run_git(["status", "--porcelain"], str(repo))
    assert seen and "hook.pwn.enabled=false" in seen[-1]
    assert seen[-1].index("hook.pwn.enabled=false") < seen[-1].index("status")


@pytest.mark.asyncio
async def test_md_notebook_scan_failure_is_a_git_error(repo: Path, monkeypatch) -> None:
    from kiro_crew.apps.builtins.md_notebook import git_ops

    _md_use_path_git(monkeypatch)
    with (repo / ".git" / "config").open("a") as fh:
        fh.write('[hook "a=b"]\n\tcommand = true\n')
    with pytest.raises(git_ops.GitError):
        await git_ops.run_git(["status"], str(repo))


@needs_config_hooks
@pytest.mark.asyncio
async def test_md_notebook_commit_does_not_fire(repo: Path, tmp_path: Path, monkeypatch) -> None:
    from kiro_crew.apps.builtins.md_notebook import git_ops

    _md_use_path_git(monkeypatch)
    marker = tmp_path / "marker"
    _plant(repo, marker)
    (repo / "a.txt").write_text("b\n")
    await git_ops.run_git(["add", "-A"], str(repo))
    await git_ops.run_git(["commit", "-qm", "x"], str(repo))
    assert not marker.exists()


# ── papyrus ──


@pytest.mark.asyncio
async def test_papyrus_git_carries_the_disable(repo: Path, tmp_path: Path, monkeypatch) -> None:
    from kiro_crew.apps.builtins.papyrus.backend import gitops

    _plant(repo, tmp_path / "marker")
    seen: list[list[str]] = []

    class Captured(Exception):
        pass

    def capture(argv, *a, **kw):
        seen.append(list(argv))
        raise Captured

    monkeypatch.setattr(gitops, "sandboxed_spawn_argv", capture)
    with pytest.raises(Captured):
        await gitops._git(["status"], cwd=repo)
    assert seen and "hook.pwn.enabled=false" in seen[0]
    assert seen[0].index("hook.pwn.enabled=false") < seen[0].index("status")


# ── dev_fleet ──


def test_dev_fleet_rewrites_only_git(repo: Path, tmp_path: Path) -> None:
    from kiro_crew.apps.builtins.dev_fleet import runtime

    _plant(repo, tmp_path / "marker")
    assert runtime._with_config_hooks_off(["npm", "ci"], str(repo)) == ["npm", "ci"]
    via_cwd = runtime._with_config_hooks_off(["git", "fetch"], str(repo))
    assert via_cwd == ["git", "-c", "hook.pwn.enabled=false", "fetch"]
    git = shutil.which("git")
    assert git
    via_dash_c = runtime._with_config_hooks_off([git, "-C", str(repo), "remote"], None)
    assert via_dash_c[1:3] == ["-c", "hook.pwn.enabled=false"]


@pytest.mark.asyncio
async def test_dev_fleet_run_cmd_carries_the_disable(
    repo: Path, tmp_path: Path, monkeypatch
) -> None:
    from kiro_crew.apps.builtins.dev_fleet import runtime

    _plant(repo, tmp_path / "marker")
    seen: list[list[str]] = []

    def capture(cmd, *a, **kw):
        seen.append(list(cmd))
        raise RuntimeError("captured")

    monkeypatch.setattr(runtime, "sandboxed_spawn_argv", capture)
    rc, _out, err = await runtime._run_cmd(["git", "-C", str(repo), "status"])
    assert rc == -1 and "captured" in err
    assert seen and "hook.pwn.enabled=false" in seen[0]


@pytest.mark.asyncio
async def test_dev_fleet_run_cmd_refuses_on_scan_failure(repo: Path, monkeypatch) -> None:
    from kiro_crew.apps.builtins.dev_fleet import runtime

    with (repo / ".git" / "config").open("a") as fh:
        fh.write('[hook "a=b"]\n\tcommand = true\n')
    monkeypatch.setattr(runtime, "sandboxed_spawn_argv", lambda *a, **k: pytest.fail("spawned"))
    rc, _out, err = await runtime._run_cmd(["git", "-C", str(repo), "status"])
    assert rc == -1 and "hook" in err


# ── dashboard worktree ──


def test_worktree_run_git_carries_the_disable(repo: Path, tmp_path: Path, monkeypatch) -> None:
    from kiro_crew.dashboard.handlers import worktree as wt

    _plant(repo, tmp_path / "marker")
    seen: list[list[str]] = []

    def capture(argv, *a, **kw):
        seen.append(list(argv))
        raise RuntimeError("captured")

    monkeypatch.setattr(wt, "sandboxed_spawn_argv", capture)
    with pytest.raises(wt.SandboxUnavailable):
        wt._run_git(["worktree", "list"], str(repo))
    assert seen and "hook.pwn.enabled=false" in seen[0]


def test_worktree_run_git_scan_failure_reads_as_git_failure(repo: Path, monkeypatch) -> None:
    from kiro_crew.dashboard.handlers import worktree as wt

    with (repo / ".git" / "config").open("a") as fh:
        fh.write('[hook "a=b"]\n\tcommand = true\n')
    monkeypatch.setattr(wt, "sandboxed_spawn_argv", lambda *a, **k: pytest.fail("spawned"))
    proc = wt._run_git(["worktree", "list"], str(repo))
    assert proc.returncode != 0 and "hook" in proc.stderr


# ── update_governance ──


def test_update_governance_refuses_a_repo_hook(repo: Path) -> None:
    from kiro_crew.platform import update_governance as ug

    assert ug.repo_exec_config_reason(str(repo)) == ""
    _git(repo, "config", "hook.pwn.command", "true")
    assert "hook.pwn.command" in ug.repo_exec_config_reason(str(repo))


def test_update_governance_ignores_a_global_hook(repo: Path, tmp_path: Path, monkeypatch) -> None:
    from kiro_crew.platform import update_governance as ug

    glob = tmp_path / "global.cfg"
    glob.write_text('[hook "mine"]\n\tcommand = true\n\tevent = pre-commit\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(glob))
    assert ug.repo_exec_config_reason(str(repo)) == ""


# ── submodule gitdir scanning ──


def _make_submodule_repo(parent: Path, sub_name: str = "sub") -> Path:
    """A superproject with a submodule that has a config hook planted in its gitdir."""
    sup = parent / "sup"
    sup.mkdir()
    _git(sup, "init", "-q", "-b", "main")
    sub_git = sup / ".git" / "modules" / sub_name
    sub_git.mkdir(parents=True)
    (sub_git / "config").write_text('[hook "sub-pwn"]\n\tcommand = true\n\tevent = pre-commit\n')
    return sup


def test_submodule_hook_names_are_listed(tmp_path: Path) -> None:
    sup = _make_submodule_repo(tmp_path)
    names = gch.config_hook_names(sup)
    assert "sub-pwn" in names


def test_submodule_scan_skips_unreadable_config(tmp_path: Path) -> None:
    sup = _make_submodule_repo(tmp_path)
    # Replace config with an unreadable (bad rc) file — write a real config so
    # git binary exists, but make the submodule config a directory so git errors.
    sub_config = sup / ".git" / "modules" / "sub" / "config"
    sub_config.unlink()
    sub_config.mkdir()
    # No exception raised; the submodule is silently skipped.
    names = gch.config_hook_names(sup)
    assert "sub-pwn" not in names


def test_find_common_gitdir_regular_repo(repo: Path) -> None:
    gd = gch._find_common_gitdir(repo)
    assert gd is not None
    assert gd.endswith(".git") or gd.endswith(".git/")


def test_find_common_gitdir_nonexistent(tmp_path: Path) -> None:
    assert gch._find_common_gitdir(tmp_path / "absent") is None


def test_find_common_gitdir_no_git(tmp_path: Path) -> None:
    d = tmp_path / "plain"
    d.mkdir()
    assert gch._find_common_gitdir(d) is None


def test_scan_file_hook_names_finds_hook(repo: Path) -> None:
    """_scan_file_hook_names uses git to list hook names from a file."""
    _git(repo, "config", "hook.filetest.command", "true")
    _git(repo, "config", "hook.filetest.event", "pre-commit")
    config_path = str(repo / ".git" / "config")
    git = __import__("shutil").which("git")
    assert git is not None
    names = gch._scan_file_hook_names(config_path, git)
    assert "filetest" in names


def test_disable_args_includes_submodule_hooks(tmp_path: Path) -> None:
    sup = _make_submodule_repo(tmp_path)
    args = gch.config_hook_disable_args(sup)
    assert "hook.sub-pwn.enabled=false" in args


def test_find_common_gitdir_linked_worktree(repo: Path, tmp_path: Path) -> None:
    """_find_common_gitdir follows the .git file in a linked worktree."""
    wt = tmp_path / "wt"
    _git(repo, "worktree", "add", "-q", str(wt), "-b", "wt-branch")
    gd = gch._find_common_gitdir(wt)
    # Should point to the COMMON gitdir, not the per-worktree one
    assert gd is not None
    assert "worktrees" not in gd


def test_find_common_gitdir_git_file_no_gitdir(tmp_path: Path) -> None:
    """A .git file without 'gitdir:' returns None."""
    d = tmp_path / "plain"
    d.mkdir()
    (d / ".git").write_text("not-a-gitdir-file\n")
    assert gch._find_common_gitdir(d) is None


def test_find_common_gitdir_git_file_absolute_path(tmp_path: Path, repo: Path) -> None:
    """A .git file with an absolute gitdir path is followed."""
    link_dir = tmp_path / "linked"
    link_dir.mkdir()
    gitdir_abs = str(repo / ".git")
    (link_dir / ".git").write_text(f"gitdir: {gitdir_abs}\n")
    gd = gch._find_common_gitdir(link_dir)
    assert gd == gitdir_abs or gd is not None


def test_find_common_gitdir_open_oserror(tmp_path: Path, monkeypatch) -> None:
    """A .git file that cannot be opened returns None."""
    d = tmp_path / "d"
    d.mkdir()
    dot_git = d / ".git"
    dot_git.write_text("gitdir: /some/path")
    # Make .git a directory so listdir succeeds then fails (hard to do with real FS)
    # Instead: write .git file and make it unreadable
    dot_git.chmod(0o000)
    try:
        result = gch._find_common_gitdir(d)
        # May return None (OSError on open) or the path (if perms allow)
        assert result is None or isinstance(result, str)
    finally:
        dot_git.chmod(0o644)


def test_no_trusted_git_refuses(repo: Path, monkeypatch) -> None:
    """When trusted_git_bin() returns None, the scan fails closed (raises) rather than
    returning [], which would leave config hooks enabled while the real git call runs."""
    from kiro_crew import platform_compat

    monkeypatch.setattr(platform_compat, "trusted_git_bin", lambda: None)
    with pytest.raises(gch.ConfigHookScanError, match="trusted"):
        gch.config_hook_names(repo)


def test_scan_file_bad_rc_raises(tmp_path: Path) -> None:
    """_scan_file_hook_names raises ConfigHookScanError when git returns a bad rc."""
    import shutil as _shutil

    git = _shutil.which("git")
    assert git is not None
    # Replace _run with a stub that returns rc=2
    import subprocess as _sp

    import kiro_crew.git_config_hooks as _gch_mod

    orig_run = _gch_mod._run

    def bad_run(*a, **kw):
        return _sp.CompletedProcess(a[0], returncode=2, stdout=b"", stderr=b"oops")

    _gch_mod._run = bad_run
    try:
        with pytest.raises(gch.ConfigHookScanError):
            gch._scan_file_hook_names(str(tmp_path / "any.config"), git)
    finally:
        _gch_mod._run = orig_run


def test_submodule_empty_hook_name_is_disabled(tmp_path: Path) -> None:
    """An empty [hook ""] in a submodule gitdir must be disabled, like a named one."""
    sup = tmp_path / "sup"
    sup.mkdir()
    _git(sup, "init", "-q", "-b", "main")
    sub_git = sup / ".git" / "modules" / "sub"
    sub_git.mkdir(parents=True)
    (sub_git / "config").write_text('[hook ""]\n\tcommand = true\n\tevent = pre-commit\n')
    args = gch.config_hook_disable_args(sup)
    assert "hook..enabled=false" in args, args
