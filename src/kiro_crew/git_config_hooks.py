"""Turn off git's config-defined hooks for one host-side git call.

Git 2.54 runs hooks named in config, not just hook files::

    [hook "x"]
        command = <any shell command>
        event = pre-commit

``-c core.hooksPath=<devnull>`` only moves the hook DIRECTORY, so these still
run. A repository's own ``.git/config`` is writable by whoever edits the tree,
so a host-side git call over an agent-writable tree would run that command
outside the sandbox. They fire on ordinary porcelain: ``add``, ``commit``,
``checkout``, ``worktree add``, ``push``, ``fetch``, ``update-ref``, and even
``status`` when it refreshes the index (``post-index-change``).

There is no switch that turns them all off. ``hook.<event>.enabled=false``
(git 2.55+) is ignored when the same ``<event>`` is also used as a hook name,
which the repository can arrange. ``hook.<name>.enabled=false`` works on every
version that has config hooks, but only for a name we know. So each call first
lists the names git will see and disables each one by name. Older git ignores
the extra keys.

Every scope is disabled, not just the repository's: the callers already point
``core.hooksPath`` at the null device, so the user's own hooks never ran on
these calls either.

The list is read just before the call, by a separate process, so a writer that
is running at the same moment can add a new name in between. That is the same
limit the ``.git/info/attributes`` pin in
:mod:`kiro_crew.apps.builtins.auto_improvement.spine.git_safety` has.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping

from kiro_crew import platform_compat

__all__ = [
    "MAX_HOOK_NAMES",
    "ConfigHookScanError",
    "config_hook_disable_args",
    "config_hook_names",
]

#: More names than this is refused rather than passed on: no real setup has this
#: many, and each one costs two argv entries.
MAX_HOOK_NAMES = 256

#: Individual names longer than this (in UTF-8 bytes) cannot be passed as ``-c``
#: arguments on any realistic platform without risking E2BIG. Reject them early
#: so a single enormous name in the repository config cannot crash a call site.
_MAX_HOOK_NAME_BYTES = 512

_SCAN_TIMEOUT_SECS = 10

#: Bound once, so a stand-in a caller's tests install for ``subprocess.run`` (to fake
#: that caller's own git) does not also answer this scan.
_run = subprocess.run


class ConfigHookScanError(RuntimeError):
    """The hook names could not be listed safely, so the git call must not run."""


def _resolve_git(git: str) -> str | None:
    """Resolve a git executable name to a trusted executable path.

    When *git* is the literal ``"git"`` default, resolve through trusted system
    directories only (``platform_compat.trusted_git_bin``). ``None`` means no trusted
    git exists; the caller FAILS CLOSED on it (raises) rather than falling back to
    ``shutil.which("git")``, which could find a shim in an agent-writable PATH entry
    and run it with the gateway's full credentials OUTSIDE the sandbox.

    A caller that already holds an absolute path passes it directly and it is
    returned unchanged.
    """
    if git == "git":
        return platform_compat.trusted_git_bin()
    return git


def _find_common_gitdir(cwd: str | os.PathLike[str]) -> str | None:
    """The common gitdir for ``cwd``, or ``None`` when not a git repo.

    For a regular clone, this is ``.git/`` itself. For a linked worktree, it
    is the worktree's common gitdir. Returns ``None`` when there is no git
    repository at ``cwd``.

    Uses only ``os.listdir`` and ``open`` to avoid calling ``os.stat`` (or
    ``os.path.isdir``/``os.path.isfile`` which call stat internally). Some
    test suites patch ``os.stat`` to track what paths are inspected, and we
    must not register the ``.git`` marker in those records.
    """
    try:
        entries = os.listdir(os.fspath(cwd))
    except OSError:
        return None
    if ".git" not in entries:
        return None
    dot_git = os.path.join(os.fspath(cwd), ".git")
    # Probe whether .git is a file (linked worktree) or a directory (regular clone).
    # Use listdir + open rather than isdir/isfile to avoid triggering stat patches.
    try:
        # A directory supports listdir; a plain file does not.
        _ = os.listdir(dot_git)
        return dot_git  # regular clone: .git is a directory
    except (NotADirectoryError, OSError):
        pass
    # .git is a file — read the gitdir pointer
    try:
        text = open(dot_git, encoding="utf-8", errors="replace").read().strip()
    except OSError:
        return None
    if "gitdir:" not in text:
        return None
    gd = text.split("gitdir:", 1)[1].strip()
    if not os.path.isabs(gd):
        gd = os.path.join(os.fspath(cwd), gd)
    # For a linked worktree, the common gitdir is two levels up from the
    # per-worktree gitdir (e.g. .git/worktrees/<name> → .git/)
    parent = os.path.dirname(gd)
    if os.path.basename(parent) == "worktrees":
        return os.path.dirname(parent)
    return gd


def _scan_file_hook_names(config_path: str, git: str) -> list[str]:
    """Hook names from a git config file, using git to parse it.

    Uses ``git config --file <path> --includes -z --name-only --get-regexp '^hook[.]'``
    so that git handles case-insensitive section names and ``include.path`` directives.
    Returns names only. Raises ``ConfigHookScanError`` when the scan fails.
    """
    argv = [
        git,
        "config",
        "--file",
        config_path,
        "--includes",
        "-z",
        "--name-only",
        "--get-regexp",
        r"^hook\.",
    ]
    try:
        proc = _run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=_SCAN_TIMEOUT_SECS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigHookScanError(f"could not scan submodule config {config_path}: {exc}") from exc
    if proc.returncode not in (0, 1):
        raise ConfigHookScanError(
            f"could not scan submodule config {config_path} (rc {proc.returncode})"
        )
    names: list[str] = []
    for raw in proc.stdout.split(b"\0"):
        key = raw.decode("utf-8", "surrogateescape")
        if not key.startswith("hook."):
            continue
        rest = key[len("hook.") :]
        if "." not in rest:
            continue
        name = rest[: rest.rindex(".")]
        # Keep the empty name "": git honors a `[hook ""]` section, and the child git
        # spawned in a submodule runs it, so it must be disabled like any other name.
        if name not in names:
            names.append(name)
    return names


def config_hook_names(
    cwd: str | os.PathLike[str],
    *,
    git: str = "git",
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Every ``hook.<name>.*`` name git would read in ``cwd``, from all scopes.

    Also scans submodule gitdirs (``.git/modules/*/config``) under the common
    gitdir, because git spawns a child process in each submodule it checks (e.g.
    during ``status`` when a submodule is dirty), and that child reads the
    submodule's own config independently. The submodule hook names are returned
    alongside the superproject's, so the caller disables them all. Note: the
    child process inherits ``-c`` flags from the parent only via env (not argv),
    so callers that cannot set env must also set ``-c diff.ignoreSubmodules=dirty``
    to prevent git from spawning submodule children at all.

    ``git`` and ``env`` should be what the real call uses, so both find the same
    binary and see the same config files. A ``cwd`` that is not a directory, or a
    ``git`` that cannot be found in a trusted location, returns ``[]``: the real
    call fails on its own there.

    Raises :class:`ConfigHookScanError` when the listing fails, when a name
    contains ``=`` (``-c`` splits on the first ``=``, so it could not be
    disabled), when any name exceeds :data:`_MAX_HOOK_NAME_BYTES`, or when there
    are more than :data:`MAX_HOOK_NAMES` names.
    """
    if not os.path.isdir(cwd):
        return []
    resolved = _resolve_git(git)
    if resolved is None:
        # No git in a trusted location. Returning [] would leave config hooks ENABLED
        # while the caller's real git call still runs (git resolved from PATH), so a
        # planted hook would fire. Fail CLOSED: raise, so the caller refuses to run git
        # at all rather than run it with hooks live. Matches update_governance, which
        # also refuses when trusted_git_bin() is None.
        raise ConfigHookScanError(
            "no git in a trusted system location; refusing host-side git without being "
            "able to disable config-defined hooks"
        )
    argv = [
        resolved,
        "-C",
        os.fspath(cwd),
        "-c",
        "core.fsmonitor=false",
        "config",
        "-z",
        "--name-only",
        "--get-regexp",
        r"^hook\.",
    ]
    try:
        proc = _run(
            argv,
            env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=_SCAN_TIMEOUT_SECS,
            check=False,
        )
    except FileNotFoundError:
        # No such git under this name and PATH: the real call, which spawns the same
        # name with the same environment, cannot run either, so there is nothing to
        # disable.
        return []
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigHookScanError(f"could not list git hook config: {exc}") from exc
    # 0 = keys found, 1 = no matching key. Anything else is an unreadable config,
    # which the real call would also choke on; refuse rather than guess.
    if proc.returncode not in (0, 1):
        tail = proc.stderr.decode("utf-8", "replace").strip()[-200:]
        raise ConfigHookScanError(f"could not list git hook config ({proc.returncode}): {tail}")
    names: list[str] = []
    seen: set[str] = set()
    for raw in proc.stdout.split(b"\0"):
        # surrogateescape so a non-UTF-8 name goes back to git byte-for-byte.
        key = raw.decode("utf-8", "surrogateescape")
        if not key.startswith("hook."):
            continue
        rest = key[len("hook.") :]
        if "." not in rest:
            continue  # `hook.jobs`: a setting, not a named hook
        name = rest[: rest.rindex(".")]
        if name in seen:
            continue
        if "=" in name:
            raise ConfigHookScanError(
                f"git hook name {name[:80]!r} contains '=' and cannot be disabled"
            )
        name_bytes = name.encode("utf-8", "surrogateescape")
        if len(name_bytes) > _MAX_HOOK_NAME_BYTES:
            raise ConfigHookScanError(
                f"git hook name is {len(name_bytes)} bytes (limit {_MAX_HOOK_NAME_BYTES})"
            )
        seen.add(name)
        names.append(name)
    if len(names) > MAX_HOOK_NAMES:
        raise ConfigHookScanError(
            f"git config defines {len(names)} hook names (limit {MAX_HOOK_NAMES})"
        )
    # Also scan submodule gitdirs: a child git spawned in a submodule reads
    # the submodule's own .git/modules/<sub>/config, not the superproject's. We
    # need to disable those names too. Silently skip unreadable submodule configs
    # since they add no new names we need to disable.
    common_gitdir = _find_common_gitdir(cwd)
    if common_gitdir is not None:
        modules_dir = os.path.join(common_gitdir, "modules")
        for dirpath, _dirs, filenames in os.walk(modules_dir):
            if "config" not in filenames:
                continue
            sub_config = os.path.join(dirpath, "config")
            try:
                sub_names = _scan_file_hook_names(sub_config, git=resolved)
            except ConfigHookScanError:
                continue  # unreadable submodule config: skip, not fail
            for name in sub_names:
                if name not in seen:
                    if "=" in name:
                        raise ConfigHookScanError(
                            f"git hook name {name[:80]!r} contains '=' and cannot be disabled"
                        )
                    name_bytes = name.encode("utf-8", "surrogateescape")
                    if len(name_bytes) > _MAX_HOOK_NAME_BYTES:
                        raise ConfigHookScanError(
                            f"git hook name is {len(name_bytes)} bytes (limit {_MAX_HOOK_NAME_BYTES})"
                        )
                    seen.add(name)
                    names.append(name)
            if len(names) > MAX_HOOK_NAMES:
                raise ConfigHookScanError(
                    f"git config defines {len(names)} hook names (limit {MAX_HOOK_NAMES})"
                )
    return names


def config_hook_disable_args(
    cwd: str | os.PathLike[str],
    *,
    git: str = "git",
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """``-c hook.<name>.enabled=false`` argv entries; place them before the subcommand.

    Empty when no hook is configured. Raises like :func:`config_hook_names`.
    """
    args: list[str] = []
    for name in config_hook_names(cwd, git=git, env=env):
        args += ["-c", f"hook.{name}.enabled=false"]
    return args
