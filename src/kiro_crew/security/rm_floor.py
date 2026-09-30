"""Argv-structural floor for recursive-force ``rm`` deletion of root / home.

Split out of ``argv_floor.py`` as a cohesive sibling: this module owns the
recursive-force ``rm`` deny floor and nothing else. ``argv_floor.is_denied``'s
caller reaches it through :func:`_recursive_force_rm_targets` (and the
fail-closed fallback), which read only the ``rm`` command's OWN argv and return
the catastrophic target set ``{"root", "home"}`` a command deletes.

This floor is a UNION with the two ``rm`` catalog regexes, which stay LIVE in
the ``re`` deny tier as a fail-closed net: the regex catches a quoted payload
this floor's own-argv model cannot reach (``su -c "rm -rf /"``, ``eval``), while
this floor adds the structural flag/target-spelling coverage. The regex's one
false positive — a ``grep``-family search that merely names the literal — is
narrowed by the ``_DENY_EXCEPTIONS`` grep inert-search carve-out.
"""

from __future__ import annotations

import os as _os
import posixpath as _posixpath
import re

from . import shell_normalizer as _shell_normalizer
from .shell_normalizer import (
    _DATA_CONSUMER_PROGRAMS,
    _argv_programs,
    _data_consumer_command_disqualified,
    _data_consumer_exempt,
    _decode_shell_quoted_literals,
    _ends_argv,
    _iter_shell_chars,
    _program_basename,
    _shell_payload_walk,
    _split_shell_words,
    _substitution_bodies,
    _substitution_depth_delta,
)

# ── Recursive-force ``rm`` deletion floor ──
# ``rm`` recursively force-deleting ROOT or HOME is catastrophic; a path UNDER
# either stays allowed. Catalog literals matched one flag spelling; a REGEX
# widening fails (can't see flags after the operand; fires on a SUBSTRING). The
# sound closure is argv-STRUCTURAL and EXACT: read the ``rm``'s OWN argv, deny only
# when a resolved operand IS root or home itself. UNION with the two catalog
# regexes (kept LIVE). Tokens RAW/ENV-UNEXPANDED, so home is by spelling (expanding
# reads ``$HOME`` as ROOT — GPT + Opus). PROGRAM ``rm`` only.


#: ``rm``'s long options, so an abbreviation can be tested for ambiguity. GNU
#: ``getopt_long`` accepts any UNAMBIGUOUS prefix, so ``rm --rec …`` / ``rm --for
#: …`` run the identical recursive/force delete a fixed string compare would miss
#: (GPT). A prefix is honoured only when it matches exactly ONE option — ``--r`` ->
#: ``--recursive``, ``--f`` -> ``--force`` — never a prefix shared by two.
_RM_LONG_OPTIONS: tuple[str, ...] = (
    "--recursive",
    "--force",
    "--dir",
    "--interactive",
    "--no-preserve-root",
    "--one-file-system",
    "--preserve-root",
    "--verbose",
    "--help",
    "--version",
)


def _rm_long_option_resolves_to(tok: str, target: str) -> bool:
    """Whether *tok* is an unambiguous long-option abbreviation of *target*.

    *tok* must be ``--`` followed by a NON-EMPTY prefix (``--`` alone is the
    end-of-options marker, handled elsewhere), and among ``rm``'s long options
    exactly one must start with that prefix, and it must be *target*. An exact
    spelling is trivially unambiguous. GNU stops at the first ``=`` (``--rec=…``),
    so the option name is taken up to it.
    """
    if not tok.startswith("--") or tok == "--":
        return False
    name = tok[: tok.index("=")] if "=" in tok else tok
    matches = [opt for opt in _RM_LONG_OPTIONS if opt.startswith(name)]
    return matches == [target] or (target in matches and name == target)


#: Whether an ``rm`` argument token carries the recursive flag: the long option
#: ``--recursive`` (or an unambiguous prefix of it), or a single-dash short
#: cluster containing ``r`` (``-r`` / ``-rf`` / ``-fr`` / ``-rfv`` …). A ``--``
#: long option is never read as a short cluster, so ``--force`` is not recursive.
#: The cluster must consist ONLY of rm's real short-option letters (``r f i v d``;
#: ``R``/``I`` fold to ``r``/``i`` in the lowercased view) -- otherwise a FOREIGN
#: single-dash predicate that merely contains ``r`` (find's ``-newer``, ``-regex``,
#: a flattened substitution body) was misread as recursive and failed a legit
#: ``rm -f $(find ~ -newer …)`` closed (Security Scope).
def _rm_is_recursive_flag(tok: str) -> bool:
    if tok.startswith("--"):
        return _rm_long_option_resolves_to(tok, "--recursive")
    return bool(re.fullmatch(r"-[rfivd]*r[rfivd]*", tok))


#: Whether an ``rm`` argument token carries the force flag (``--force`` or an
#: unambiguous prefix of it, or a single-dash short cluster containing ``f``).
def _rm_is_force_flag(tok: str) -> bool:
    if tok.startswith("--"):
        return _rm_long_option_resolves_to(tok, "--force")
    return bool(re.fullmatch(r"-[rfivd]*f[rfivd]*", tok))


def _rm_span_is_recursive_force(tokens: "list[str]", rm_index: int) -> bool:
    """Cheap pre-check: does the ``rm`` span starting after *rm_index* carry a
    RECURSIVE and a FORCE flag (any spelling/order), or ``--no-preserve-root``?

    Only such a span can be a catastrophic wipe AND is the shape whose per-span
    suffix re-scan is expensive, so the per-argv span cap (GPT 6.1 F2) counts only
    these — a long chain of benign ``rm <file>`` commands (no ``-rf``) neither
    charges the budget nor is failed-closed past it (Security Scope false
    positive). Scans only this one span's flag words (until the next command
    boundary); flags are tested on the de-quoted spelling bash acts on, matching
    the structural parse below. Does not resolve brace expansion — a brace-grouped
    flag word is a catastrophic candidate, so an unparsed brace token conservatively
    counts as recursive-force to stay fail-closed on it.
    """
    has_rec = has_force = False
    j = rm_index + 1
    n = len(tokens)
    while j < n and not _ends_argv(tokens[j]):
        tok = _rm_strip_all_quotes(tokens[j])
        if tok == "--":
            break
        if tok == "--no-preserve-root":
            return True
        if "{" in tok and "," in tok:
            return True  # a brace-grouped flag word — classify it (fail-closed)
        if _rm_is_recursive_flag(tok):
            has_rec = True
            if _rm_is_force_flag(tok):
                has_force = True
        elif _rm_is_force_flag(tok):
            has_force = True
        if has_rec and has_force:
            return True
        j += 1
    return has_rec and has_force


#: The filesystem ROOT ITSELF — ``/`` (a run of slashes) or ``/*``, optional
#: trailing slash, NOTHING under it. For an ``rm`` reached through an EXEC WRAPPER
#: (``setsid rm -rf /``, ``sudo …``): base caught a wrapper-reached descendant only
#: incidentally, so denying those newly refuses benign work (``docker exec kc-ci rm
#: -fr /tmp/build-cache`` — base ALLOWED it; Security Scope). Wrapper denies root
#: ITSELF only.
_RM_ROOT_ITSELF_RE = re.compile(r"/+(?:\*/*)?")
#: The HOME dir ITSELF — ``~`` / ``$HOME`` / ``${HOME}``, bare or with trailing
#: slashes (``~//``) or the ``~/*`` glob. The ``${home}`` form also admits a
#: slash-only suffix removal (``${HOME%/}``), the ``:?`` check (``${HOME:?msg}``,
#: GPT 5.6 F1 UPHOLD-FENCED), and the identity substring ``${HOME:0}`` (GPT 6.1).
#: VALUE-CHANGING operators (``:-`` ``:+`` ``:=`` / non-zero substring) are NOT
#: admitted. Wrapper only.
_RM_HOME_ITSELF_RE = re.compile(
    r"(?:~|\$\{home(?:%%?/*|:\?[^}]*|:[ \t]*0+[ \t]*)?\}|\$home(?![a-z0-9_]))(?:/+(?:\*/*)?)?",
    re.IGNORECASE,
)
#: Escape / quote / substitution characters that can reconstruct the ``rm``
#: program name from text that does not contain the literal ``rm`` (a folded
#: ``"r\<nl>m"``, an octal ``$'r\555'``). The cheap pre-filter admits a command
#: carrying any of these so the walk gets a chance to decode it.
_RM_OBFUSCATION_MACHINERY_RE = re.compile(r"[\\$`'\"]")
#: A brace group ``{…}`` (one level, no nested ``{``/``}``). Strips groups from a
#: word so the surviving literal frame can be tested for a root/home prefix.
_RM_BRACE_GROUP_RE = re.compile(r"\{[^{}]*\}")
#: A numeric / single-char brace RANGE body (``000..511``, ``a..z``, ``1..9..2``):
#: it expands only to digits/letters, never a ``/`` / ``~`` / empty member.
_RM_BRACE_RANGE_RE = re.compile(
    r"\A(-?[0-9]+|[A-Za-z])\.\.(-?[0-9]+|[A-Za-z])(?:\.\.(-?[0-9]+))?\Z"
)

#: Ceiling on nested-frame descents per classification. Each ``find -exec`` /
#: ``sh -c`` / interpreter span recurses into :func:`_rm_targets_in_argv`, so a
#: crafted nest would fan out and hang the gate (Opus). A mutable cell decremented
#: per descent; at zero no span opens, so work is linear. Fails SAFE: a real
#: ``rm`` at any reachable depth is classified before the cap bites.
_RM_DESCENT_BUDGET = 64

#: How many ``rm`` command spans one argv classifies before it stops. Each
#: leading ``rm`` re-scans its operand suffix, so an argv padded with thousands of
#: ``rm`` words is quadratic (measured 44 s, past the 25 s gate deadline; GPT 6.1
#: F2). A real command has a handful, so this never trims a legitimate one; past
#: it the scan FAILS CLOSED (returns both targets) because the whole-text net
#: catches only the contiguous spelling.
_RM_CLASSIFY_SPAN_CAP = 64

#: Max substitution openers (``$(`` / backtick) the structural walk runs on. Each
#: seeds a frame, so a chain (``"$( " * 1000``) makes the walk O(openers²) and runs
#: for minutes (Opus perf). Beyond this the expensive descent is skipped but the
#: top-level per-command argv is still classified, so a wipe outside the openers is
#: caught — fail CLOSED, never open (GPT 6.1 F2).
_RM_SUBSTITUTION_OPENER_CAP = 200

# Innermost ``$(...)`` or backtick body -- a span containing NO further opener, so
# a flat regex sees it without the quote-aware paren walk (which a dense
# ``"$(true)"`` run defeats, leaving the real ``$(rm -fr ~)`` unparsed and a home
# wipe failing open -- GPT 6.1 security-class). Peeling innermost spans repeatedly
# reaches nested ones too, under a bounded budget.
_RM_INNERMOST_SUBST_RE = re.compile(r"\$\(([^()`]*)\)|`([^`]*)`")

# How many innermost substitution bodies the heavy path classifies. Unlike the
# recursive frame walk (whose cost is O(openers²), hence the small
# ``_RM_DESCENT_BUDGET``), this scan is a single linear ``finditer`` + a cheap argv
# check per body, so the cap can be generous: the real wipe can sit past hundreds
# of decoy ``"$(true)"`` spans (GPT 6.1 put it at index 201). The cap only bounds a
# truly pathological input; a wipe past it is still caught by the fail-closed
# whole-text regex.
_RM_SUBST_BODY_SCAN_CAP = 20000


def _rm_operand_before_boundary(operand: str) -> "tuple[str, bool]":
    """The operand text up to its first unquoted control-operator boundary.

    Returns ``(head, ended)``: *head* drops everything from the first ``;`` / ``&``
    / ``|`` / newline onward; *ended* is True when one was present. Quotes are
    already resolved by the time tokens reach here, so a remaining operator is a
    real separator — ``rm -rf /;reboot`` is one operand ``/;reboot`` whose target
    is ``/``; splitting classifies ``/`` and ends the argv so a glued command
    cannot hide it.
    """
    match = _rm_unescaped_boundary(operand)
    if match is None:
        return operand, False
    return operand[:match], True


def _rm_unescaped_boundary(operand: str) -> "int | None":
    """Index of the first NOT-backslash-escaped control-operator (``;`` / ``&`` /
    ``|`` / newline), or ``None``.

    ``_split_shell_words`` keeps a source backslash, so ``rm -rf a\\;b /*`` reaches
    here as one operand ``a\\;b`` whose ``;`` is an ESCAPED literal (file ``a;b``),
    not a separator — splitting there would end the argv before ``/*`` and fail
    open (Opus security-class). A boundary preceded by an odd run of backslashes is
    literal and skipped.
    """
    k = 0
    n = len(operand)
    while k < n:
        ch = operand[k]
        if ch == "\\":
            k += 2  # the backslash escapes the next char; neither is a boundary
            continue
        if ch in ";&|\n":
            return k
        k += 1
    return None


def _rm_strip_surrounding_quotes(token: str) -> str:
    """Peel balanced surrounding quote pairs from a raw operand token.

    ``_split_shell_words`` leaves a quoted operand quoted (``"$home"``), so an
    exact operand match needs the wrapper removed. Only a matching leading and
    trailing quote of the same kind is peeled, to a fixed point, so an operand
    that merely CONTAINS a quote is left alone.
    """
    return _rm_strip_surrounding_quotes_reporting(token)[0]


def _rm_strip_surrounding_quotes_reporting(token: str) -> "tuple[str, bool]":
    """``(peeled_token, did_peel)`` — like :func:`_rm_strip_surrounding_quotes`
    but reports whether ANY surrounding quote pair was removed.

    A control-operator character that only becomes bare BECAUSE a quote was
    peeled was QUOTED in the source (``';'`` is a literal filename argument, not
    a command separator), so the operand-boundary split must NOT fire on it:
    ``rm -rf ';' /`` has operands ``;`` and ``/`` and really deletes root, but
    treating the peeled ``;`` as a boundary ends the argv before ``/`` and fails
    open (Opus security-class).
    """
    previous = None
    peeled = False
    while token != previous:
        previous = token
        if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
            token = token[1:-1]
            peeled = True
    return token, peeled


def _rm_strip_all_quotes(token: str) -> str:
    """Remove every unescaped shell quote character from an operand.

    A shell removes quoting during word expansion, so ``"$HOME"/`` and
    ``$HOME/`` are the SAME path, as are ``"${HOME}"/x`` and ``${HOME}/x`` and a
    split ``"$HO"ME``. ``_rm_strip_surrounding_quotes`` only peels a BALANCED
    surrounding pair, so a PARTIALLY quoted operand keeps a leading ``"`` that
    defeats the ``~`` / ``$HOME`` anchor of the home/root matchers (GPT
    security-class: ``setsid rm -fr "$HOME"/`` bypassed the enabled home rule).
    This yields the de-quoted spelling the matchers are anchored on; a backslash
    escape keeps the quote it escapes (``\\"`` is a literal quote char in the
    filename, not a quoting delimiter).
    """
    out: list[str] = []
    i = 0
    n = len(token)
    while i < n:
        ch = token[i]
        if ch == "\\" and i + 1 < n:
            out.append(token[i + 1])
            i += 2
            continue
        if ch in "\"'":
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _rm_operand_is_single_quoted(token: str) -> bool:
    """True if *token* is wholly wrapped in one balanced single-quote pair.

    Bash passes a single-quoted word verbatim with no expansion, so a single-quoted
    ``'~'`` / ``'$HOME'`` names a literal cwd file, never the home dir — unlike a
    double-quoted ``"$HOME"`` which DOES expand. The whole token must be one
    balanced single-quoted span (leading-and-trailing ``'`` with no interior
    unescaped ``'``), so a partially-quoted or concatenated operand does not qualify.
    """
    if len(token) < 2 or token[0] != "'" or token[-1] != "'":
        return False
    return "'" not in token[1:-1]


def _rm_brace_word_could_be_catastrophic(word: str) -> bool:
    """True if a brace word MIGHT expand to the root/home dir ITSELF, so an overflow
    past the expansion cap must fail CLOSED.

    A member is ``head + <alt_1> + mid + <alt_2> … + tail``. It can be the root/home
    dir itself only when the LITERAL frame (the text left after the brace groups are
    removed) is empty or itself root/home (``/``, ``/*``, ``~`` …) AND some group
    offers an alternative that completes the frame to the target — an EMPTY
    alternative (``/{,bin}`` -> ``/``) or a ``/`` / ``~`` spelling. A numeric or
    single-char RANGE (``{000..511}``, ``{1..99}``) only yields digits/letters, so a
    bare ``rm -rf {000..511}`` (relative dir names, base-allowed) is NOT catastrophic
    and must not fail closed. A non-root literal frame (``/tmp/kc-shard-{000..511}``,
    ``./bench-out/run-{1..500}``) can only expand to descendants either way.
    """
    residual = _RM_BRACE_GROUP_RE.sub("", word)
    stripped = _rm_strip_all_quotes(residual).strip()
    norm = _rm_normalize_dot_segments(stripped)
    frame_is_root_or_empty = (
        stripped == ""
        or residual == ""
        or bool(_RM_ROOT_ITSELF_RE.fullmatch(stripped))
        or bool(_RM_HOME_ITSELF_RE.fullmatch(stripped))
        or bool(_RM_ROOT_ITSELF_RE.fullmatch(norm))
        or bool(_RM_HOME_ITSELF_RE.fullmatch(norm))
    )
    if not frame_is_root_or_empty:
        return False
    # The frame could reach root/home — a group must OFFER a completing member.
    for group in _RM_BRACE_GROUP_RE.finditer(word):
        body = group.group()[1:-1]
        if _RM_BRACE_RANGE_RE.match(body):
            # A numeric / single-char RANGE (``000..511``, ``a..z``) yields only
            # digits/letters — never ``/`` / ``~`` / empty. Not catastrophic.
            continue
        if "," not in body:
            continue  # single-member body: not a brace expansion, no new member
        for alt in body.split(","):
            a = alt.strip()
            if a == "" or a.startswith("/") or a.startswith("~"):
                return True
    return False


def _rm_normalize_dot_segments(operand: str) -> str:
    """Collapse ``.`` / ``..`` path segments in an rm operand, LEXICALLY.

    The kernel resolves dot segments, so ``/./`` / ``/tmp/../`` are ROOT and
    ``~/./`` is home — yet the exact matchers see a non-``/`` string and miss it
    (GPT: ``setsid rm -fr /./`` bypassed the wrapped-root guard). Resolves like
    ``os.path.normpath`` WITHOUT filesystem access, preserving a leading ``~`` /
    ``$HOME`` marker and a trailing ``*`` glob so the matchers still fire.
    """
    if "." not in operand:
        return operand
    # Preserve a leading home marker and a trailing ``*`` glob across normpath,
    # which would otherwise mangle ``~`` or drop the glob.
    prefix = ""
    for marker in ("~", "${home}", "$home"):
        if operand[: len(marker)].lower() == marker:
            prefix = operand[: len(marker)]
            operand = operand[len(marker) :] or "/"
            break
    glob_tail = ""
    if operand.endswith("/*"):
        operand, glob_tail = operand[:-1], "*"
    if prefix:
        # A ``..`` after the home marker collapses against HOME, not ``/``:
        # ``$HOME/../alice`` with ``HOME=/home/alice`` IS home (GPT). Resolve against
        # the REAL expanded home, normalize the joined path (lexical), map back:
        # exactly home -> home; under -> descendant; above -> bare absolute. Fold
        # separators + lowercase (Windows CI); cannot widen POSIX.
        home_real = _posixpath.normpath(_os.path.expanduser("~").replace("\\", "/")).lower()
        joined = home_real + ("" if operand == "/" else operand)
        try:
            collapsed_full = _posixpath.normpath(joined)
        except (TypeError, ValueError):
            return prefix + operand + glob_tail
        # The home MATCHER admits a glob only after a ``/`` separator
        # (``_RM_HOME_ITSELF_RE`` is ``~(?:/+(?:\*/*)?)?``), so a bare ``~*`` /
        # ``~/foo*`` with the separator dropped would never fullmatch and the wipe
        # would fail open (Opus security-class: ``rm -fr ~/./*`` collapsed to
        # ``~*``). Re-emit the ``/`` with the glob tail.
        glob_suffix = "/" + glob_tail if glob_tail else ""
        if collapsed_full == home_real:
            return prefix + glob_suffix
        if collapsed_full.startswith(home_real + "/"):
            return prefix + collapsed_full[len(home_real) :] + glob_suffix
        return collapsed_full + glob_suffix
    try:
        collapsed = _posixpath.normpath(operand)
    except (TypeError, ValueError):
        return prefix + operand + glob_tail
    if prefix and collapsed == ".":
        collapsed = ""
    # ``~`` tilde-expands ONLY as a word's first char. ``./~`` is a cwd directory
    # literally named ``~`` (not expanded) — base's ``rm -rf ~.*`` never matched its
    # leading ``./`` (Security Scope). When no home prefix was present yet normpath
    # collapsed a leading ``./`` to a bare ``~`` segment, that ``~`` is a literal
    # filename: restore the dot anchor so it does not re-read as home.
    if not prefix and collapsed[:1] == "~":
        collapsed = "./" + collapsed
    return prefix + collapsed + glob_tail


#: The real expanded home path (``/home/<user>``), computed once. ``expanduser`` is
#: platform-native (a backslash path on Windows), so the separators are folded to
#: ``/`` and the result lowercased to match the lowercased operands the walk
#: produces — the same spelling ``_rm_normalize_dot_segments`` compares against.
_RM_EXPANDED_HOME_CACHE: "list[str] | None" = None


def _rm_expanded_home_path() -> str:
    """The lowercased, ``/``-separated real home directory, cached per process."""
    global _RM_EXPANDED_HOME_CACHE
    if _RM_EXPANDED_HOME_CACHE is None:
        try:
            resolved = _posixpath.normpath(_os.path.expanduser("~").replace("\\", "/")).lower()
        except (TypeError, ValueError):
            resolved = ""
        # A degenerate ``~`` resolving to ``/`` or ``.`` is NOT a usable home anchor
        # (it would misclassify every path), so store empty and the F3 check no-ops.
        _RM_EXPANDED_HOME_CACHE = [resolved if resolved not in ("", "/", ".") else ""]
    return _RM_EXPANDED_HOME_CACHE[0]


#: Mirror of the ``(?:/+(?:\*/*)?)?`` tail ``_RM_HOME_ITSELF_RE`` gives ``~``/
#: ``$HOME``: trailing ``/`` with an OPTIONAL whole-remainder ``*`` glob. Strips
#: that tail so an expanded-home operand carrying it (``/home/<user>/``,
#: ``/home/<user>/*``) compares equal to the bare home, while a real descendant
#: (``/home/<user>/.cache``) keeps a segment and does NOT reduce to home.
_RM_HOME_ITSELF_TAIL_RE = re.compile(r"/+(?:\*/*)?$")


def _rm_strip_home_itself_tail(path: str) -> str:
    """``path`` with a single home-itself tail (trailing slashes / ``/*`` glob) removed."""
    return _RM_HOME_ITSELF_TAIL_RE.sub("", path, count=1)


def _rm_walk_frames(text_lower: str, raw_text: "str | None") -> "list[tuple[str, list[str], bool]]":
    """``(source, norm_tokens, repaired)`` frames for the rm floor to classify.

    Block 1 is ``_shell_payload_walk(text_lower)``. When *raw_text* carries an
    ANSI-C span, block 2 walks that text with its ``$'…'`` spans decoded
    (case-preserved) then lowercased, so the width-sensitive ``\\U`` escape
    resolves (``is_denied`` lowercases first, truncating ``\\U`` at 4 digits).
    ``repaired`` marks block 2; the caller classifies it ONLY via its decoded
    ``norm_tokens`` — a raw split would strip both the shlex-added quotes and the
    LITERAL quotes the decode produced (``$'\\"/\\"'`` -> ``'"/"'`` read as root).
    The block-1 walk is where a raw ``$HOME`` / ``~`` operand is classified.
    """
    frames: "list[tuple[str, list[str], bool]]" = [
        (source, toks, False) for source, toks in _shell_payload_walk(text_lower)
    ]
    if raw_text is not None and "$'" in raw_text:
        repaired = _decode_shell_quoted_literals(raw_text).lower()
        if repaired != text_lower:
            frames.extend((source, toks, True) for source, toks in _shell_payload_walk(repaired))
    # Drop a DESCENDED substitution frame whose opener is SINGLE-QUOTED: single
    # quotes suppress expansion, so a backtick / ``$(`` inside them is literal (``git
    # commit -m 'the `rm -fr /` step'`` is prose; Security Scope). The first frame
    # (whole command) is always kept; a single-quoted ``-c`` payload (``bash -c 'rm
    # -rf /'``) still executes as a ``-c`` descent, so only a bare body is dropped.
    single = _rm_single_quoted_positions(text_lower)
    kept: "list[tuple[str, list[str], bool]]" = []
    for idx, frame in enumerate(frames):
        if idx == 0 or not _rm_frame_is_single_quoted_substitution(text_lower, frame[0], single):
            kept.append(frame)
    return kept


def _rm_frame_is_single_quoted_substitution(
    text_lower: str, src: str, single: "list[bool]"
) -> bool:
    """True if descended frame *src* is a backtick / ``$(`` body inside a
    SINGLE-QUOTED span of *text_lower* — a literal, not an executed command. Finds
    *src* as a substring whose opener char (``\\`` or the ``(`` of ``$(``) is
    single-quoted; conservative, so a genuinely executed payload is never dropped.
    """
    body = src.strip()
    if not body:
        return False
    start = 0
    while True:
        at = text_lower.find(body, start)
        if at < 0:
            return False
        opener = at - 1
        if opener >= 0 and opener < len(single) and single[opener]:
            ch = text_lower[opener]
            if ch == "`" or (ch == "(" and opener > 0 and text_lower[opener - 1] == "$"):
                return True
        start = at + 1


#: An UNQUOTED ``~`` at a word boundary — bash tilde-expands it to the home dir.
#: A quoted (``'~'`` / ``"~"``) or escaped (``\~``) tilde is a LITERAL filename.
#: The boundary classes include ``{`` / ``,`` / ``}`` so a brace-expansion member
#: (``rm -fr {~,/tmp/x}`` -> bash expands ``~``) counts as a live tilde too.
_RM_LIVE_TILDE_RE = re.compile(r"(?:^|[\s;&|({,=])~(?=$|[\s;&|),}/])")
#: A ``$HOME`` / ``${HOME}`` reference — expands when unquoted OR double-quoted.
_RM_HOME_REF_RE = re.compile(r"\$\{?home\b\}?", re.IGNORECASE)


def _rm_has_live_home_expansion(text_lower: str) -> bool:
    """True if *text_lower* contains a home expansion the shell actually performs
    — an UNQUOTED, unescaped ``~`` at a word boundary, or a ``$HOME``/``${HOME}``
    that is unquoted or DOUBLE-quoted (single quotes suppress ``$``).

    A QUOTED tilde (``'~'`` / ``"~"``), a backslash-escaped ``\\~``, and a
    SINGLE-quoted ``'$HOME'`` are literal filenames the shell never expands to the
    home dir, so a command whose only home-shaped token is one of those performs
    NO home expansion — base allowed deleting such a cwd file (Security Scope).
    The caller drops a ``home`` verdict the payload walk produces by expanding a
    quoted tilde regardless of its quoting.
    """
    single = _rm_single_quoted_positions(text_lower)
    for m in _RM_LIVE_TILDE_RE.finditer(text_lower):
        pos = m.end() - 1  # index of the ``~``
        if pos < len(single) and single[pos]:
            continue  # single-quoted tilde (``'~'``) — literal
        # A ``"~"`` double-quoted tilde is literal too; a tilde is only live when
        # unquoted. The live-tilde regex already requires a word-boundary before
        # ``~``; reject it when the preceding char is a quote.
        prev = text_lower[m.start()] if m.start() < pos else ""
        if prev in ("'", '"'):
            continue
        return True
    for m in _RM_HOME_REF_RE.finditer(text_lower):
        pos = m.start()
        if pos < len(single) and single[pos]:
            continue  # single-quoted ``'$HOME'`` — literal, no expansion
        return True
    # A PARTIALLY-quoted ``$HOME`` (``"$HO"ME`` / ``$HO"ME"``) expands to the home
    # dir — the double quotes only group text and bash removes them during word
    # expansion. Scan a view with the DOUBLE quotes removed (single-quoted spans,
    # where ``$`` does not expand, replaced with a sentinel) and re-test for a live
    # ``$HOME`` the raw scan split across a quote.
    joined: list[str] = []
    in_single = in_double = False
    i = 0
    n = len(text_lower)
    while i < n:
        ch = text_lower[i]
        if ch == "\\" and not in_single:
            if i + 1 < n:
                joined.append(text_lower[i + 1])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double  # drop the double quote, joining the spans
            i += 1
            continue
        joined.append("\x00" if in_single and ch == "$" else ch)
        i += 1
    if _RM_HOME_REF_RE.search("".join(joined)):
        return True
    return False


def _rm_split_unquoted_newlines(source: str) -> "list[str]":
    """Split *source* into command lines at UNQUOTED, unescaped newlines.

    A shell runs each line of a multi-line command as its own command, but
    ``_split_shell_words`` treats a newline as ordinary whitespace, so a frame
    like ``rm -f x\\nls -ltr ~`` would otherwise fuse ``ls -ltr ~`` into ``rm``'s
    argv — ``ls``'s packed ``-ltr`` donates a spurious ``-r`` and ``~`` becomes
    the operand, misreading a non-recursive ``rm -f`` as a recursive-force home
    wipe (Security Scope false positive). Splitting on the unquoted newline first
    keeps each line its own argv. A newline inside quotes or escaped is literal
    and does not split. Returns the single source unchanged when it has no
    unquoted newline (the common case), so a one-line command is untouched.
    """
    if "\n" not in source and "\r" not in source:
        return [source]
    lines: list[str] = []
    buf: list[str] = []
    for step in _iter_shell_chars(source):
        if step.active and step.char in ("\n", "\r"):
            lines.append("".join(buf))
            buf = []
            continue
        buf.append(step.text)
    lines.append("".join(buf))
    return [ln for ln in lines if ln.strip()] or [source]


def _rm_split_top_level_semicolons(source: str) -> "list[str]":
    """Split *source* at TOP-LEVEL, unquoted command separators (``;`` / ``&`` /
    ``|``), used only by the heavy-substitution fast path: each segment is
    classified as its own argv so a real ``…; rm -fr ~`` after a flood of
    ``"$(true)"`` operands is still seen (GPT 6.1 F2). A separator inside quotes,
    an escape, or a ``$(…)`` / backtick / ``${…}`` body does not split.
    """
    depth = _rm_substitution_depth(source)
    single = _rm_single_quoted_positions(source)
    both = _rm_quoted_positions(source)
    segs: list[str] = []
    buf: list[str] = []
    for idx, ch in enumerate(source):
        boundary = (
            ch in ";&|"
            and not single[idx]
            and not (idx < len(both) and both[idx])
            and (idx >= len(depth) or depth[idx] <= 0)
        )
        if boundary:
            if buf:
                segs.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        segs.append("".join(buf))
    return [s for s in segs if s.strip()] or [source]


def _rm_absolute_home_operand(text_lower: str) -> bool:
    """True if the DE-QUOTED command names a LITERAL absolute path EQUAL to the
    real home dir (``rm -fr /home/alice`` where ``$HOME`` is ``/home/alice``).

    Such an equality carries NO ``$HOME`` / ``~`` token, so the tilde-liveness
    suppression would wrongly discard it and allow an irreversible home wipe (GPT
    6.1 F3, security-class). Uses the SAME separator-folding + home-itself-tail
    stripping the operand classifier uses, so ``/home/alice/`` and ``/home/alice/*``
    count while a DESCENDANT (``/home/alice/.cache``) does not.
    """
    home_real = _rm_expanded_home_path()
    if not home_real:
        return False
    for tok in _split_shell_words(text_lower):
        op = _rm_strip_all_quotes(tok)
        for spelled in (op, _rm_normalize_dot_segments(op)):
            if _rm_strip_home_itself_tail(spelled.replace("\\", "/").lower()) == home_real:
                return True
    return False


#: A heredoc opener: ``<<`` or ``<<-`` followed by its delimiter word, which may
#: be quoted (``<<'EOF'`` / ``<<"EOF"``) or bare (``<<EOF``). The captured name is
#: the delimiter; a leading ``-`` (``<<-``) lets the terminator be indented with
#: tabs. A ``<<<`` here-string (not a heredoc — its single operand IS the data,
#: inline) is excluded by the negative lookahead so it is left for the ordinary
#: argv walk. Only the FIRST opener on a line is handled per pass.
_RM_HEREDOC_OPEN_RE = re.compile(r"<<-?(?!<)\s*(\S+)")


def _rm_strip_heredoc_bodies(source: str) -> str:
    """Drop heredoc BODIES from *source* — stdin DATA, never argv.

    ``cat > notes.md <<'EOF'`` feeds the following lines to the command on STDIN,
    never parsed as commands. Yet ``_split_shell_words`` flattens a newline to
    whitespace, so a body line ``rm -fr /`` (prose) reads as an ``rm`` command and
    the floor refuses what base allowed (Security Scope FP). An EVALUATOR heredoc
    (``bash <<'EOF'``) that runs its stdin is still caught by the whole-text regex.
    An UNQUOTED delimiter (``<<EOF``) runs ``$(…)`` / backticks in its body, so those
    executed substitutions are kept for classification (GPT 6.1 F2). The opener must
    be a REAL ``<<`` — unquoted, unescaped, not ``<<<``, not ``$((… << …))`` (Opus).
    """
    if "<<" not in source:
        return source
    lines = source.split("\n")
    out: "list[str]" = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        out.append(line)
        # Find a REAL heredoc opener. Quote mask computed ONCE per line (per-match
        # rescan was O(N**2), froze the gate on a ``'<<a'`` flood; Opus). An opener
        # single-quoted, backslash-escaped, or in ``$((… << …))`` arithmetic is
        # literal and opens no heredoc.
        delim = None
        single = _rm_single_quoted_positions(line)
        quoted = _rm_quoted_positions(line)
        # Open-cmdsub state as a per-index mask, computed ONCE per line: a ``<<``
        # inside an open ``$(…)`` is a real operator, elsewhere in double quotes it
        # is literal. Reading the mask at ``s`` is O(1); calling
        # ``_rm_cmdsub_open_before`` per opener rescanned from 0, O(openers x N),
        # and stalled the gateway on a ``<<``-dense command (Opus 5.5 security).
        cmdsub_open = _rm_cmdsub_open_mask(line)
        # First UNQUOTED ``#`` starting a comment — a ``<<`` after it is commented
        # out, not an opener (Opus 5.5 F3).
        comment_at = None
        for ci, cch in enumerate(line):
            if (
                cch == "#"
                and not (ci < len(quoted) and quoted[ci])
                and (ci == 0 or line[ci - 1] in " \t")
            ):
                comment_at = ci
                break
        for m in _RM_HEREDOC_OPEN_RE.finditer(line):
            s = m.start()
            if s < len(single) and single[s]:
                continue  # single-quoted → literal
            if s > 0 and line[s - 1] == "\\":
                continue  # backslash-escaped → literal
            # A DOUBLE-quoted ``<<`` is literal UNLESS inside an open ``$(…)`` /
            # backtick (``--body "$(cat <<EOF …)"``); only this branch needs the
            # O(N) cmdsub scan, so the common case stays O(N).
            if s < len(quoted) and quoted[s] and not (s < len(cmdsub_open) and cmdsub_open[s]):
                continue
            # Arithmetic shift ``$(( a << b ))``: a ``((`` opened before with no
            # closing ``))`` yet means ``<<`` is an operator, not a heredoc.
            if line[:s].count("((") > line[:s].count("))"):
                continue
            # A ``<<`` after an unquoted ``#`` is a COMMENT — opens no heredoc, so a
            # following ``rm`` line is a REAL command (Opus 5.5 F3).
            if comment_at is not None and s > comment_at:
                continue
            # Take the WHOLE delimiter word and strip surrounding quotes, so
            # ``<<'EOF'`` / ``<<EOF'X'`` delimit on the dequoted word and a partial
            # ``EOF`` is not mistaken for the terminator (Opus 5.5 F3).
            raw_delim = m.group(1)
            delim = _rm_strip_all_quotes(raw_delim)
            # A QUOTED delimiter (``<<'EOF'`` / ``<<"EOF"``) suppresses ALL expansion
            # in the body — it is pure data. An UNQUOTED delimiter (``<<EOF``) lets
            # the shell RUN ``$(…)`` / backticks in the body before feeding stdin to
            # the command (GPT 6.1 F2), so those executed substitutions must still be
            # classified rather than silently stripped.
            delim_quoted = raw_delim != delim
            break
        if delim is None:
            i += 1
            continue
        # Drop the body up to the terminator (line == dequoted delimiter; ``<<-``
        # allows leading tabs). If NO terminator exists before EOF the ``<<`` was
        # not a real heredoc, so keep every line — stripping to EOF would hide a
        # real command (Opus 5.5 F3). Scan ahead; drop only on a confirmed match.
        j = i + 1
        term = -1
        while j < n:
            body = lines[j]
            if body.strip() == delim or body.lstrip("\t").rstrip() == delim:
                term = j
                break
            j += 1
        if term < 0:
            i += 1  # no terminator → not a heredoc; keep scanning normally
            continue
        # An UNQUOTED heredoc runs ``$(…)`` / backticks in its body before the
        # command reads stdin, so KEEP those executed substitutions (drop only the
        # literal prose around them); a QUOTED delimiter suppresses expansion, so
        # its whole body is pure data and is dropped (GPT 6.1 F2).
        if not delim_quoted:
            body_text = "\n".join(lines[i + 1 : term])
            kept = _substitution_bodies(body_text)
            if kept:
                out.append(" ; ".join(kept))
        out.append(lines[term])  # keep the terminator word, drop the body between
        i = term + 1
    return "\n".join(out)


def _recursive_force_rm_targets(
    text_lower: str, *, raw_text: "str | None" = None
) -> "frozenset[str]":
    """Which catastrophic target(s) a top-level ``rm`` recursively force-deletes.

    Returns a subset of ``{"root", "home"}`` — ``root`` when a resolved operand IS
    the filesystem root, ``home`` when one IS the home dir (``~`` or ``$HOME``).
    Empty when it is not a recursive-force ``rm`` against such an EXACT target; a
    descendant (``/tmp/x``, ``$HOME/.cache``) and a mere mention both return empty.

    ``--no-preserve-root`` is a trigger on its own; otherwise BOTH a recursive and a
    force flag must be present, in any position. A ``--`` stops flag parsing.

    Every command FRAME is inspected — the top-level argv and every nested shell
    payload (``bash -c '…'``, ``$(…)``, here-string, chained segment) — re-split
    from its RAW source (quote-resolved but ENV-UNEXPANDED), so ``$HOME`` is read by
    spelling, not the expanded path. Frame scoping keeps a string that is merely an
    argument to another program (a ``git commit -m`` message) from reading as ``rm``.

    *raw_text* is the ORIGINAL-case command when the caller has it. Bash's ANSI-C
    unicode escapes are width-case-sensitive (``\\u`` 4 digits, ``\\U`` 8), so a
    ``$'\\U…'`` spelling decodes correctly only from case-preserved text; when
    supplied, its ANSI-C spans are decoded then lowercased and walked as an extra
    frame. It also carries the uppercase ``HOME=`` the reassignment check needs.
    """
    # Cheap necessary condition. A plain ``rm`` invocation contains the literal
    # ``rm``; an OBFUSCATED one (``"r\<nl>m"``, ``$'r\555'``) does not — its ``rm``
    # is built by escape/quote/substitution machinery whose decoded output can be
    # any character, so the only sound cheap gate is "contains ``rm`` OR contains
    # such machinery". When neither is present the walk cannot yield an ``rm``.
    if "rm" not in text_lower and not _RM_OBFUSCATION_MACHINERY_RE.search(text_lower):
        return frozenset()
    # A pathological opener chain (``"$( " * 1000``) makes the walk emit a frame
    # per opener and reprocess O(openers²) (Opus perf). Far past any real command
    # we must NOT skip classification — that fails OPEN: ``: `` + 201×``"$(true)"``
    # + ``; rm -fr ~`` has its wipe OUTSIDE every substitution, invisible to the
    # whole-text ``-rf`` regex (GPT 6.1 F2). Disable only the expensive descent;
    # the top-level per-command argv classification below still runs.
    heavy_substitution = (
        text_lower.count("$(") + text_lower.count("`") > _RM_SUBSTITUTION_OPENER_CAP
    )
    # A heredoc body is stdin DATA, never parsed as commands — strip it from BOTH
    # views BEFORE the walk, so the walk never descends a ``$(…)``/backtick that is
    # really a markdown span in a commit/PR/doc heredoc naming ``rm -fr /`` as prose
    # (Security Scope FP). An evaluator heredoc (``bash <<EOF``) that executes its
    # stdin is still caught by the whole-text regex on the contiguous literal.
    text_lower = _rm_strip_heredoc_bodies(text_lower)
    if raw_text is not None:
        raw_text = _rm_strip_heredoc_bodies(raw_text)
    # A ``bash -c '<payload>'`` whose shell is an operand of a data consumer
    # (``echo bash -c '…'`` / ``cat sh -c '…'``) PRINTS the payload — it is never
    # executed, so the frame the walk descends from it must not be classified
    # (Design Review: base allowed these mentions). Collect those payload strings
    # from the top-level argv so the matching descended frame can be skipped.
    shell_c_data = _rm_shell_c_data_payloads(_split_shell_words(text_lower))
    found: set[str] = set()
    # Under a pathological opener chain, skip the O(openers²) walk but STILL
    # classify the top-level command: split on unquoted newlines + top-level ``;``
    # and classify each simple command's argv (raw + decoded), so ``…; rm -fr ~``
    # outside the openers is caught — linear, no substitution descent (GPT 6.1 F2:
    # budget exhaustion must not fail open).
    if heavy_substitution:
        for line in _rm_split_unquoted_newlines(text_lower):
            for seg in _rm_split_top_level_semicolons(line):
                toks = _split_shell_words(seg)
                found |= _rm_targets_in_argv(toks, strip_quotes=False)
                found |= _rm_targets_in_argv(toks, strip_quotes=True)
                # The outer ``rm``'s own ``$(…)`` operand resolves to its OUTPUT:
                # ``rm -rf <decoys> $(echo ~)`` keeps the unresolved ``$(echo ~)``
                # in this split and misses home, so a wipe whose home target is the
                # STATIC output of a benign producer escapes the per-segment pass
                # (GPT security-class: budget exhaustion must not fail open). Reuse
                # the narrow ``echo``/``printf`` resolver the non-heavy walk runs; a
                # dynamic generator resolves to a non-matching sentinel, so this
                # only ADDS coverage.
                resolved_seg = _rm_resolve_substitution_operands(toks)
                if resolved_seg is not None:
                    found |= _rm_targets_in_argv(resolved_seg, strip_quotes=True)
            if {"root", "home"} <= found:
                break
        # A wipe can live INSIDE a substitution body (``echo "$(true)"*201
        # "$(rm -fr ~)"``), invisible to the top-level per-command split above and
        # to the whole-text regex (no contiguous ``rm -rf`` run). The expensive
        # part was the recursive FRAME WALK (O(openers²)); classify each INNERMOST
        # substitution body with a flat regex (the quote-aware paren walk is
        # defeated by a dense ``"$(true)"`` run), bounded by ``_RM_DESCENT_BUDGET``
        # bodies -- a wipe past the cap is still caught by the fail-closed
        # whole-text regex (GPT 6.1 security-class fail-open fix).
        if not ({"root", "home"} <= found):
            seen = 0
            for m in _RM_INNERMOST_SUBST_RE.finditer(text_lower):
                if seen >= _RM_SUBST_BODY_SCAN_CAP:
                    break
                seen += 1
                body = m.group(1) if m.group(1) is not None else (m.group(2) or "")
                found |= _rm_targets_in_argv(_split_shell_words(body), strip_quotes=True)
                if {"root", "home"} <= found:
                    break
        if (
            "home" in found
            and not _rm_has_live_home_expansion(text_lower)
            and not _rm_absolute_home_operand(text_lower)
        ):
            found.discard("home")
        return frozenset(found)
    # Cap how many frames are CLASSIFIED. A pathological opener chain
    # (``"$( " * 1000``) makes the shell walk emit a frame per opener; classifying
    # every one is O(frames × span) and ran for minutes on the synchronous gate
    # (Opus, security-class perf). The cap fails CLOSED — base's contiguous
    # ``rm -rf /`` / ``rm -rf ~`` literal still runs on the whole text — so a wipe
    # hidden past the cap is caught by base, never allowed.
    frames_left = _RM_DESCENT_BUDGET
    for source, norm_tokens, repaired in _rm_walk_frames(text_lower, raw_text):
        if frames_left <= 0:
            break
        frames_left -= 1
        # Skip a descended payload frame that is a data-consumer's printed ``-c``
        # mention, not an executed command (Design Review).
        if source.strip() in shell_c_data:
            continue
        # The DECODED view (payload walk's own tokens) is always classified: it
        # resolves ANSI-C / unicode escapes and env expansion, so ``rm -rf $'/'`` /
        # ``$'\u002f'`` is caught, and a ``$'"/"'`` filename's LITERAL quotes stay in
        # the token so it is NOT misread as root. A frame spanning unquoted NEWLINES
        # is classified PER LINE — the shell runs each line separately, so a later
        # line's tokens must not fuse into an earlier ``rm``'s argv (Security Scope).
        source_lines = _rm_split_unquoted_newlines(source)
        decoded_targets: set[str] = set()
        if len(source_lines) == 1:
            decoded_targets |= _rm_targets_in_argv(norm_tokens, strip_quotes=False)
        else:
            for line in source_lines:
                decoded_targets |= _rm_targets_in_argv(_split_shell_words(line), strip_quotes=False)
        # A decoded ``home`` verdict can be SPURIOUS: the payload walk tilde/HOME-
        # expands a SINGLE-QUOTED ``'~'`` / ``'$HOME'`` operand (a literal cwd file
        # bash never expands) to the real home path, which the home matcher then
        # equals (``cd ~/src && rm -fr '~'`` deletes a file named ``~``; base allows
        # it — Security Scope). Re-classify the DECODED view of the source with its
        # single-quoted spans MASKED to spaces: if ``home`` disappears, it came only
        # from a single-quoted literal and must not count. ``root`` is unaffected (a
        # single-quoted ``'/'`` is still the literal root bash deletes), and a frame
        # with no single-quoted span skips the re-check.
        # A decoded ``home`` verdict can be SPURIOUS: the payload walk tilde/HOME-
        # expands an operand whose ``~``/``$HOME`` is QUOTED or ESCAPED and so is a
        # literal cwd file bash never expands (``'~'`` / ``"~"`` / ``\~`` / ``'$HOME'``),
        # to the real home path, which the home matcher then equals — kept alive only
        # by an unrelated live ``~`` elsewhere on the line (``cd ~/src && rm -fr '~'``
        # deletes a file named ``~``; base allows it — Security Scope). Re-classify the
        # DECODED view of the source with its NON-LIVE home spellings neutralised: if
        # ``home`` disappears, it came only from a literal and must not count. ``root``
        # is unaffected (a quoted ``'/'`` is still the literal root bash deletes), and a
        # live ``"$HOME"`` / bare ``~`` is preserved so a genuine wipe still denies.
        if "home" in decoded_targets:
            masked_src = _rm_mask_non_live_home(source)
            if masked_src != source:
                masked_home: set[str] = set()
                for mline in _rm_split_unquoted_newlines(masked_src):
                    for _msrc, mtoks in _shell_payload_walk(mline):
                        masked_home |= _rm_targets_in_argv(mtoks, strip_quotes=False)
                        if {"root", "home"} <= masked_home:
                            break
                if "home" not in masked_home:
                    decoded_targets.discard("home")
        found |= decoded_targets
        # A REPAIRED frame (ANSI-C-decoded copy) is classified ONLY via its decoded
        # tokens above. Its raw source went through ``_decode_shell_quoted_literals``
        # + ``shlex.quote``, so a quote-stripping raw split would peel BOTH the added
        # shell quotes and the LITERAL decode quotes (``$'"/"'`` -> ``/``), reading a
        # filename as root. Its raw ``$HOME``/``~`` is already covered by the
        # ORIGINAL-text frame.
        if repaired:
            if {"root", "home"} <= found:
                break
            continue
        # Non-repaired frame: also classify the RAW split, which keeps ``$HOME`` /
        # ``~`` unexpanded so home is classified by its written spelling. Surrounding
        # SHELL quotes are stripped only here (``"$HOME"`` -> ``$HOME``). Split on
        # unquoted newlines first so a multi-line frame is classified per line.
        for line in source_lines:
            found |= _rm_targets_in_argv(_split_shell_words(line), strip_quotes=True)
        # A command-substitution OPERAND resolves to its OUTPUT: ``rm -rf
        # "$(printf /)"`` keeps the unresolved ``$(printf /)`` and misses the root
        # (GPT security-class). Resolve each ``$(…)`` / backtick operand to the word
        # it STATICALLY expands to (the narrow ``echo``/``printf`` resolver) and
        # re-classify. A dynamic generator resolves to a non-matching sentinel, so
        # this only ADDS coverage.
        resolved_subst = _rm_resolve_substitution_operands(_split_shell_words(source))
        if resolved_subst is not None:
            found |= _rm_targets_in_argv(resolved_subst, strip_quotes=True)
        # Execution-substitution bodies: a ``$(…)`` / backtick / process-sub that
        # EXECUTES its command, so an ``rm`` inside is a real wipe even when the
        # output is consumed as data (``grep -rn "$(rm -rf /)"`` runs the wipe
        # first). The shared ``_substitution_bodies`` walk is quote-aware for its own
        # nesting but still extracts a backtick / ``$(…)`` body sitting inside a
        # SINGLE-quoted span, which bash treats as a literal (``git commit -m 'see
        # `rm -rf /`'`` runs no ``rm`` — Security Scope zero-text FP). So mask the
        # single-quoted spans (via the kept ``_rm_single_quoted_positions``) to
        # spaces before the walk; the surviving ``$(…)`` / backtick bodies execute.
        # A bare ``(…)`` subshell / ``${ …;}`` funsub holding an exact-root wipe
        # stays caught by the fail-closed catalog regex UNION. Each body is
        # classified as its own argv.
        _sq = _rm_single_quoted_positions(source)
        _masked = "".join(" " if (i < len(_sq) and _sq[i]) else c for i, c in enumerate(source))
        for body in _substitution_bodies(_masked):
            found |= _rm_targets_in_argv(_split_shell_words(body), strip_quotes=True)
        # ``<producer> | xargs [opts] rm [flags]`` APPENDS the producer's stdin
        # words to ``rm``'s argv, so the target lives in NO token of the ``rm``
        # command (GPT 5.6 UPHOLD-FENCED: ``echo "$HOME" | xargs rm -rf`` wipes
        # home). ``_xargs_reconstructed_command_with_flags`` rebuilds the effective
        # command line KEEPING rm's own ``-fr``/``-rf`` (the flag-stripping variant
        # dropped them, so a wrapped wipe failed open -- GPT 6.1 security-class).
        # The result is classified by the structural path (which denies only the
        # exact root/home target), so a descendant operand
        # (``echo /tmp/x | xargs rm -rf``) stays allowed at base parity.
        xargs_cmd = _shell_normalizer._xargs_reconstructed_command_with_flags(
            _split_shell_words(source)
        )
        if xargs_cmd:
            found |= _rm_targets_in_argv(_split_shell_words(xargs_cmd), strip_quotes=True)
        if {"root", "home"} <= found:
            break
    # An EXECUTED shell ``-c`` payload (``bash -c 'rm -fr "$HOME"'``) runs in a
    # CHILD shell that expands ``$HOME``/``~`` by SPELLING, so classify the payload
    # tokens directly — the walk's ``$HOME``->login-home expansion is ``/``-rooted
    # only where ``expanduser`` is, so a drive-path home (Windows CI) forms no home
    # verdict (GPT 6.1). ``root`` always counts; ``home`` only on a LIVE home
    # expansion in the payload's OWN quote state (``"$HOME"`` live, ``'$HOME'`` not).
    payload_live_home = False
    for payload in _rm_shell_c_executed_payloads(_split_shell_words(text_lower)):
        p_targets = _rm_targets_in_argv(_split_shell_words(payload), strip_quotes=True)
        found |= p_targets - {"home"}
        if "home" in p_targets and _rm_has_live_home_expansion(payload.lower()):
            found.add("home")
            payload_live_home = True
    # A quoted-literal ``'~'`` / ``'$HOME'`` is a cwd file the shell never expands;
    # drop a ``home`` verdict with NO live home expansion (Security Scope). A real
    # ``$HOME``/``~``, an EXECUTED ``-c`` payload verdict (quote state applied
    # above), or an ABSOLUTE-PATH equality (``rm -fr /home/alice`` = real home, no
    # ``$HOME``/``~`` token) all KEEP it — the last would wrongly drop, a common
    # irreversible-wipe spelling (GPT 6.1 F3).
    if (
        "home" in found
        and not payload_live_home
        and not _rm_has_live_home_expansion(text_lower)
        and not _rm_absolute_home_operand(text_lower)
    ):
        found.discard("home")
    return frozenset(found)


def _rm_mask_non_live_home(source: str) -> str:
    """*source* with every NON-LIVE home spelling blanked to spaces, LIVE ones kept.

    Bash expands ``~`` to the home dir ONLY when it is unquoted and unescaped, and
    expands ``$HOME`` when it is unquoted or DOUBLE-quoted (never single-quoted).
    So a literal ``'~'`` / ``"~"`` / ``\\~`` and a single-quoted ``'$HOME'`` name a
    cwd file, not the home dir. This blanks:

    * every character inside a SINGLE-quoted span (so ``'~'`` / ``'$HOME'`` vanish);
    * a ``~`` that is DOUBLE-quoted or BACKSLASH-escaped (``"~"`` / ``\\~``).

    A bare ``~`` and a double-quoted ``"$HOME"`` are LEFT INTACT, so a genuine home
    wipe still classifies. The result is handed to the decoded re-classification:
    if the decoded ``home`` verdict survives this blanking it was a real live
    expansion; if it disappears it came only from a literal (Security Scope FP).
    """
    out: list[str] = []
    in_single = in_double = False
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch == "\\" and not in_single:
            # Escaped next char: ``\~`` is a literal tilde — drop it; any other
            # escape keeps the escaped char so token boundaries are preserved.
            nxt = source[i + 1] if i + 1 < n else ""
            out.append("" if nxt == "~" else nxt)
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single  # drop the delimiter (join), content blanked below
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double  # drop the delimiter so ``"$HO"ME`` joins to $HOME
            i += 1
            continue
        if in_single:
            i += 1  # single-quoted content is a literal — drop it
            continue
        if ch == "~" and in_double:
            i += 1  # double-quoted tilde is literal, not expanded — drop it
            continue
        out.append(ch)  # bare ~, "$HOME" (its $ kept), and ordinary text
        i += 1
    return "".join(out)


def _rm_single_quoted_positions(source: str) -> "list[bool]":
    """One forward pass marking each index as inside a SINGLE-quoted span.

    A single quote in bash suppresses every expansion, so a ``${`` / ``$(`` /
    backtick inside one is literal text, not a construct. A single quote INSIDE a
    double-quoted span is itself a literal apostrophe and opens no span, so BOTH
    contexts are tracked: a ``'`` toggles single-quote state only when NOT inside
    double quotes, and a ``"`` toggles double-quote state only when NOT inside
    single quotes; a backslash outside single quotes escapes the next character.
    Replaces the per-match ``_index_in_single_quote`` rescan that scanned from 0
    on every regex match — O(N**2) on the synchronous gate (Opus security-class,
    ReDoS). ``mask[i]`` is True when index *i* is inside a single-quoted span.
    """
    mask = [False] * len(source)
    in_single = False
    in_double = False
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch == "\\" and not in_single:
            mask[i] = in_single
            if i + 1 < n:
                mask[i + 1] = in_single
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        mask[i] = in_single
        i += 1
    return mask


def _rm_quoted_positions(source: str) -> "list[bool]":
    """One forward pass marking each index as inside a SINGLE- OR DOUBLE-quoted
    span. Unlike :func:`_rm_single_quoted_positions` (which marks only single
    quotes, because single quotes suppress expansion), this marks either, so a
    heredoc ``<<`` operator that sits inside ``echo "<<EOF"`` is seen as literal
    text and opens no heredoc (Opus security-class). A backslash outside single
    quotes escapes the next character. ``mask[i]`` is True when *i* is quoted."""
    mask = [False] * len(source)
    in_single = in_double = False
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch == "\\" and not in_single:
            mask[i] = in_single or in_double
            if i + 1 < n:
                mask[i + 1] = in_single or in_double
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        mask[i] = in_single or in_double
        i += 1
    return mask


def _rm_cmdsub_open_before(line: str, pos: int) -> bool:
    """True if index *pos* in *line* sits inside an OPEN ``$(…)`` or backtick
    command substitution — quote-aware, so a literal ``(`` in a quoted word
    (``--title 'fix(security)'``) does not count toward the balance.

    A ``$(`` opens a substitution even inside DOUBLE quotes (``--body "$(cat
    …"``); a bare ``(`` outside quotes opens a subshell; a backtick toggles one.
    A ``(`` / ``)`` inside single quotes, inside double quotes without a leading
    ``$``, or backslash-escaped is literal. Used by the heredoc gate so a ``<<``
    inside ``"$(cat <<EOF …)"`` is seen as a REAL operator while a ``<<`` in a
    plain double-quoted ``echo "<<EOF"`` stays literal (Security Scope / Opus).
    """
    depth = 0
    in_single = in_double = in_backtick = False
    i = 0
    while i < pos and i < len(line):
        ch = line[i]
        if ch == "\\" and not in_single:
            i += 2
            continue
        if ch == "'" and not in_double and not in_backtick:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single and not in_backtick:
            in_double = not in_double
            i += 1
            continue
        if not in_single:
            if ch == "`":
                in_backtick = not in_backtick
                i += 1
                continue
            if ch == "(" and i > 0 and line[i - 1] == "$":
                depth += 1  # ``$(`` opens even inside double quotes
                i += 1
                continue
            if not in_double and not in_backtick and ch == "(":
                depth += 1  # bare subshell, only outside quotes
                i += 1
                continue
            if ch == ")" and depth > 0:
                depth -= 1
                i += 1
                continue
        i += 1
    return depth > 0 or in_backtick


def _rm_cmdsub_open_mask(line: str) -> "list[bool]":
    """``mask[i]`` is True iff index *i* in *line* sits inside an OPEN ``$(…)`` /
    backtick / subshell command substitution -- the per-index form of
    :func:`_rm_cmdsub_open_before`, computed in ONE forward pass.

    The heredoc gate asks this question once per ``<<`` opener; calling
    ``_rm_cmdsub_open_before`` per opener rescans the line from 0 each time, which
    is O(openers x N) and stalled the gateway on a ``<<``-dense command past the
    25s watchdog (Opus 5.5 security-class). One pass + an index read keeps it O(N).
    """
    mask = [False] * len(line)
    depth = 0
    in_single = in_double = in_backtick = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        mask[i] = depth > 0 or in_backtick
        if ch == "\\" and not in_single:
            if i + 1 < n:
                mask[i + 1] = depth > 0 or in_backtick
            i += 2
            continue
        if ch == "'" and not in_double and not in_backtick:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single and not in_backtick:
            in_double = not in_double
            i += 1
            continue
        if not in_single:
            if ch == "`":
                in_backtick = not in_backtick
                i += 1
                continue
            if ch == "(" and i > 0 and line[i - 1] == "$":
                depth += 1
                i += 1
                continue
            if not in_double and not in_backtick and ch == "(":
                depth += 1
                i += 1
                continue
            if ch == ")" and depth > 0:
                depth -= 1
                i += 1
                continue
        i += 1
    return mask


def _rm_substitution_depth(source: str) -> "list[int]":
    """Per-index nesting depth of command-substitution / subshell bodies.

    ``depth[i]`` is how many ``$(…)`` / ``${…}`` / backtick / bare ``(…)``
    subshell bodies index *i* sits inside. A ``HOME=`` assignment with depth > 0
    runs in a subshell and does NOT persist to the parent shell, so it cannot
    protect a parent ``rm`` from a home wipe (GPT 6.1 F1). Quote-aware: an opener
    or closer inside a single- or double-quoted span (or backslash-escaped) is
    literal text and does not change the depth, matching the shared quote-aware
    span model. Backticks toggle a span rather than nest, which is sufficient here (a
    nested backtick must be escaped in bash anyway).
    """
    n = len(source)
    depth = [0] * n
    cur = 0
    in_single = in_double = in_backtick = False
    i = 0
    while i < n:
        ch = source[i]
        if ch == "\\" and not in_single:
            depth[i] = cur
            if i + 1 < n:
                depth[i + 1] = cur
            i += 2
            continue
        if ch == "'" and not in_double and not in_backtick:
            in_single = not in_single
            depth[i] = cur
            i += 1
            continue
        if ch == '"' and not in_single and not in_backtick:
            in_double = not in_double
            depth[i] = cur
            i += 1
            continue
        if not in_single and not in_double:
            if ch == "`":
                # A backtick toggles a substitution span.
                if in_backtick:
                    depth[i] = cur
                    cur -= 1
                    in_backtick = False
                    i += 1
                    continue
                cur += 1
                in_backtick = True
                depth[i] = cur
                i += 1
                continue
            if not in_backtick and ch == "(":
                cur += 1
                depth[i] = cur
                i += 1
                continue
            if not in_backtick and ch == "{" and i > 0 and source[i - 1] == "$":
                cur += 1
                depth[i] = cur
                i += 1
                continue
            if not in_backtick and ch in ")}" and cur > 0:
                depth[i] = cur
                cur -= 1
                i += 1
                continue
        depth[i] = cur
        i += 1
    return depth


#: A whole-token command substitution: ``$(…)`` or a backtick pair spanning the
#: entire operand word (after surrounding shell quotes are peeled). The output
#: of such a word becomes the operand ``rm`` receives.
_RM_WHOLE_SUBSTITUTION_RE = re.compile(r"\A\$\((?P<body>.*)\)\Z|\A`(?P<btck>.*)`\Z", re.DOTALL)


def _rm_resolve_substitution_operands(tokens: "list[str]") -> "list[str] | None":
    """``tokens`` with each command-substitution OPERAND replaced by its STATIC
    output, or ``None`` when none resolves (caller skips a redundant re-classify).

    ``rm -rf --no-preserve-root "$(printf /)"`` reaches ``rm`` with operand ``/``,
    but the raw split keeps the unresolved ``$(printf /)`` so the matchers never see
    ``/`` (GPT). Resolve a whole-token ``$(…)`` / backtick operand to its static
    expansion via the sibling argv floor's ``echo``/``printf`` resolver (literal
    first operand only). A dynamic generator resolves to the ``"\\x00"`` sentinel no
    matcher accepts, so this only ADDS coverage. Flags/non-subs left untouched.
    """
    from .argv_floor import _static_substitution_output

    resolved: list[str] = []
    changed = False
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        peeled = _rm_strip_surrounding_quotes(tok)
        m = _RM_WHOLE_SUBSTITUTION_RE.match(peeled)
        if m is not None:
            body = m.group("body")
            if body is None:
                body = m.group("btck") or ""
            output = _static_substitution_output(body)
            if output and output != "\x00":
                resolved.append(output)
                changed = True
                i += 1
                continue
        # An UNQUOTED ``$(…)`` whose body has internal spaces splits across
        # several shlex tokens (``$(echo`` … ``/)``); reassemble from the ``$(``
        # opener to the token closing the balanced ``)`` and resolve the joined
        # body, so ``rm -rf $(echo /)`` resolves its operand too.
        if peeled.startswith("$(") and ")" not in peeled[2:]:
            depth = peeled.count("(") - peeled.count(")")
            j = i + 1
            while j < n and depth > 0:
                depth += tokens[j].count("(") - tokens[j].count(")")
                j += 1
            if depth == 0 and j <= n:
                joined = " ".join(tokens[i:j])
                inner = _rm_strip_surrounding_quotes(joined)
                mm = _RM_WHOLE_SUBSTITUTION_RE.match(inner)
                if mm is not None:
                    body = mm.group("body") or ""
                    output = _static_substitution_output(body)
                    if output and output != "\x00":
                        resolved.append(output)
                        changed = True
                        i = j
                        continue
            # The opener did not balance. Advance PAST the scanned span (appending
            # those tokens verbatim) not by one — a chain of unclosed ``$(`` (``"$( "
            # * 1000``) would otherwise re-scan to the end per opener, O(openers²) and
            # minutes on the gate (Opus perf). Scanned tokens keep their raw spelling.
            resolved.extend(tokens[i:j])
            i = j
            continue
        resolved.append(tok)
        i += 1
    return resolved if changed else None


#: Multi-call binaries that DISPATCH to the applet named by their first non-flag
#: argument: ``busybox rm -rf /`` runs the ``rm`` applet (``toybox`` too). Here
#: ``rm`` is the dispatcher's first ARGUMENT, not the program word and not behind
#: an exec wrapper, so the plain scan + wrapper set both miss it (GPT). Matched
#: positionally — ``busybox echo rm -rf /`` runs ``echo``, not ``rm``.
_RM_APPLET_DISPATCHERS: frozenset[str] = frozenset({"busybox", "toybox"})

#: Filesystem-MOVER programs: every non-flag argument is a PATH, never a program
#: to run. A ``rm`` among a mover's operands (``env rm -fr rm rm …``, ``cp rm rm
#: dst``) is a file named ``rm``, not a command, so it is skipped before the
#: per-``rm`` span cap and suffix scan (GPT 6.1 F2). A data-PRINTER
#: (``echo``/``printf``) is already covered by ``_data_consumer_exempt``.
_RM_MOVER_PROGRAMS: frozenset[str] = frozenset(
    {"rm", "cp", "mv", "ln", "mkdir", "rmdir", "touch", "chmod", "chown"}
)

#: One-word exec wrappers whose FIRST argument is the command they run, so a later
#: ``rm`` in the span is an operand of THAT command (``_argv_programs`` attributes
#: it to the wrapper; resolving one layer recovers the real mover).
#: ``sudo``/``ssh``/``docker``/``setsid`` are absent — their ``rm`` executes.
_RM_SPAN_EXEC_WRAPPERS: frozenset[str] = frozenset({"env", "nice", "stdbuf", "time"})


def _rm_effective_span_program(programs: "list[str]", tokens: "list[str]", index: int) -> str:
    """Program of the command owning ``tokens[index]``, resolving ONE leading
    one-word exec wrapper. When ``env`` leads the span (``env rm -fr rm rm``) every
    token is attributed to ``env``; the real command is its first post-option
    argument. A non-first token returns the wrapped basename (``rm``); the first
    wrapped argument (the executed ``rm``) stays the wrapper so it is classified.
    """
    base = programs[index] if 0 <= index < len(programs) else ""
    if base not in _RM_SPAN_EXEC_WRAPPERS:
        return base
    # Find this span's start, then its first post-option argument — the command.
    start = index
    while start > 0 and programs[start - 1] == base:
        start -= 1
    arg = start + 1
    # Skip the wrapper's OWN options AND assignments, not just ``VAR=val``: ``env
    # -i`` / ``env -u NAME`` / ``nice -n 5`` / ``env --`` precede the wrapped
    # command, so stopping at the first option mis-reads it as the mover and lets a
    # 2000-operand flood reach the per-operand suffix scan (GPT 6.1 F3).
    while arg < len(tokens):
        tok = tokens[arg]
        if tok == "--":
            arg += 1  # end-of-options; next word is the command
            break
        if _shell_normalizer.ENV_ASSIGNMENT_RE.match(tok):
            arg += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            arg += 1
            # ``env -u NAME`` / ``nice -n 5`` take a separate value word (unless
            # glued, ``-uNAME``).
            if base in ("env", "nice") and tok in ("-u", "-n", "--unset"):
                arg += 1
            continue
        break
    if arg >= len(tokens) or arg == index:
        # No wrapped command, or this token IS the wrapped command word: not an
        # operand — leave it to the executable path.
        return base
    return _program_basename(tokens[arg])


def _rm_deescape_unquoted_backslashes(text: str) -> str:
    """Remove backslash escapes as an UNQUOTED inner shell would, so an escaped
    program name reforms.

    A ``bash -c $"\\r\\m -rf /"`` payload reaches the inner shell as the script
    ``\\r\\m -rf /``; unquoted, bash drops each backslash before an ordinary
    character, so ``\\r\\m`` becomes the word ``rm``. The outer walk's
    ``_decode_printf_escapes`` instead maps ``\\r`` to whitespace and drops the
    ``r``, so the ``rm`` never reforms and the wipe was missed (Item 4).

    Backslashes INSIDE single quotes are literal and are left untouched; a
    backslash outside single quotes removes itself and keeps the next character
    (``\\n`` -> ``n``, matching the inner shell's own unquoted lexing rather than
    the C-escape meaning — the shell does not turn an unquoted ``\\n`` into a
    newline). A trailing backslash is dropped.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_single = False
    while i < n:
        ch = text[i]
        if ch == "'":
            in_single = not in_single
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and not in_single and i + 1 < n:
            out.append(text[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


#: Shell programs whose ``-c`` argument is a command STRING they execute. When a
#: nested payload's escaped quoting defeats the walk's own descent, the walk can
#: still hand this frame a FLATTENED argv (``['sh', '-c', 'rm', '-rf', '/']``);
#: the tokens after ``-c`` are then the executed command, read here as their own
#: argv so the ``rm`` leads its own command instead of sitting behind ``sh``.
_RM_SHELL_C_PROGRAMS: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"}
)


def _rm_shell_c_data_payloads(tokens: "list[str]") -> "frozenset[str]":
    """The ``-c`` payload strings that are DATA, not executed, in *tokens*.

    ``echo bash -c 'rm -rf "/"'`` / ``cat sh -c '…'`` PRINT the shell command —
    ``bash``/``sh`` is an ARGUMENT of the data consumer (``echo``/``cat``), so the
    ``-c`` string is never run (Design Review: base allowed this as a mention; the
    payload walk otherwise descends it into a frame and refuses it as a wipe).
    Returns the raw ``-c`` argument of every such mention so the caller can skip
    the descended frame it would produce. An EXECUTED shell (``bash -c '…'`` at
    program position, ``sudo bash -c '…'``) is NOT a data consumer's operand and
    is not listed, so a real wipe still denies.
    """
    programs = _argv_programs(tokens)
    disqualified = _data_consumer_command_disqualified(tokens)
    data: set[str] = set()
    n = len(tokens)
    for i, tok in enumerate(tokens):
        if _program_basename(tok) not in _RM_SHELL_C_PROGRAMS:
            continue
        # The shell is DATA only when it is itself an argument of a data consumer
        # (``echo``/``cat`` …), not when it is the command being run.
        if not _data_consumer_exempt(i, tok, programs, tokens, command_disqualified=disqualified):
            continue
        j = i + 1
        while j < n and not _ends_argv(tokens[j]):
            if tokens[j] == "-c" and j + 1 < n:
                data.add(_rm_strip_surrounding_quotes_reporting(tokens[j + 1])[0])
                break
            j += 1
    return frozenset(data)


def _rm_shell_c_executed_payloads(tokens: "list[str]") -> "frozenset[str]":
    """The ``-c`` payload strings of EXECUTED shells in *tokens* (the inverse of
    :func:`_rm_shell_c_data_payloads`).

    ``bash -c 'rm -fr "$HOME"'`` at program position, ``sudo bash -c '…'`` — the
    shell RUNS the payload, so ``$HOME``/``~`` inside it is expanded by that child
    shell regardless of the OUTER quotes that merely delimit the payload. The home
    liveness check must read the payload's OWN quote state, not the enclosing
    command's (GPT 6.1 F2, security-class): ``"$HOME"`` inside the payload is live
    even though the whole payload sits in the outer ``'…'``. A shell that is a data
    consumer's operand (``echo bash -c '…'``) is NOT executed and is excluded.

    Recurses through NESTED payloads to a bounded depth: ``bash -c 'bash -c "rm
    -fr ~"'`` runs the inner ``rm -fr ~`` two levels down, so the inner payload
    must be surfaced for the liveness check too (GPT 6.1 F2). Recursion is capped
    at ``_RM_DESCENT_BUDGET`` payloads so a pathological nest cannot spin.
    """
    out: set[str] = set()
    worklist = [tokens]
    seen: set[str] = set()
    budget = _RM_DESCENT_BUDGET
    while worklist and budget > 0:
        cur = worklist.pop()
        budget -= 1
        programs = _argv_programs(cur)
        disqualified = _data_consumer_command_disqualified(cur)
        n = len(cur)
        # Precompute the next ``-c`` reachable from each position without crossing
        # an argv-end, so the per-token search is O(1). A repeated non-``-c`` shell
        # operand (``'sh rm ' + 'sh ' * 6600``) otherwise rescans the same suffix
        # per token -- O(tokens²), ~19s on the synchronous gate, past the 25s
        # watchdog (GPT 6.1 security-class crash/data-loss fix, same shape as
        # ``_rm_targets_in_shell_c``).
        next_c = [-1] * (n + 1)
        for p in range(n - 1, -1, -1):
            if _ends_argv(cur[p]):
                next_c[p] = -1
            elif cur[p] == "-c":
                next_c[p] = p
            else:
                next_c[p] = next_c[p + 1]
        for i, tok in enumerate(cur):
            if _program_basename(tok) not in _RM_SHELL_C_PROGRAMS:
                continue
            # Skip the DATA case (printed mention); keep only an executed shell.
            if _data_consumer_exempt(i, tok, programs, cur, command_disqualified=disqualified):
                continue
            j = next_c[i + 1] if i + 1 <= n else -1
            if j != -1 and j + 1 < n:
                payload = _rm_strip_surrounding_quotes_reporting(cur[j + 1])[0]
                out.add(payload)
                if payload not in seen:
                    seen.add(payload)
                    worklist.append(_split_shell_words(payload))
    return frozenset(out)


def _rm_targets_in_shell_c(
    tokens: "list[str]", programs: "list[str]", *, strip_quotes: bool, _budget: "list[int]"
) -> "frozenset[str]":
    """Catastrophic ``rm`` targets in a ``sh -c <cmd>`` argv flattened into a frame.

    The payload walk normally descends ``bash -c '<script>'`` into a frame of its
    own, but a two-level nest with ESCAPED inner quotes
    (``bash -c 'sh -c "rm -rf \\"/\\""'``) can defeat the inner extraction and
    leave the ``sh -c`` frame's argv flattened to ``['sh', '-c', 'rm', '-rf',
    '/']``. There ``rm`` is not at program position (``sh`` is) and ``sh`` is not
    an exec wrapper, so the plain scan misses it. When a nested-shell program is
    followed by a ``-c`` flag, the tokens after ``-c`` are the command string it
    runs, so they are classified as their own argv — the same treatment
    ``find -exec`` gets. Scoped to a frame whose PROGRAM is the shell
    (``_argv_programs``), so a ``-c`` that is data to another command is untouched.
    """
    found: set[str] = set()
    i = 0
    n = len(tokens)
    # Precompute, in ONE right-to-left pass, the index of the next ``-c`` reachable
    # from each position WITHOUT crossing an argv-end (``;`` / ``|`` / newline). A
    # command-boundary token resets the lookahead to "none". This turns the inner
    # ``-c`` search into an O(1) read, so a repeated non-``-c`` shell operand
    # (``'sh rm ' + 'sh ' * 6600``) does not rescan the same suffix per token —
    # which would be O(tokens²), ~19s on the synchronous gate and past the 25s
    # watchdog (GPT 6.1 security-class crash/data-loss).
    next_c = [-1] * (n + 1)
    for p in range(n - 1, -1, -1):
        if _ends_argv(tokens[p]):
            next_c[p] = -1
        elif tokens[p] == "-c":
            next_c[p] = p
        else:
            next_c[p] = next_c[p + 1]
    while i < n:
        advance = 1
        if (
            _program_basename(tokens[i]) in _RM_SHELL_C_PROGRAMS
            and _program_basename(programs[i]) in _RM_SHELL_C_PROGRAMS
        ):
            # The shell's own ``-c`` (if any) before its argv ends, read in O(1)
            # from the precomputed table; the rest of the argv is the command
            # string it executes.
            j = next_c[i + 1] if i + 1 <= n else -1
            if j != -1 and j + 1 < n:
                span = []
                k = j + 1
                while k < n and not _ends_argv(tokens[k]):
                    span.append(tokens[k])
                    k += 1
                if span:
                    # ONLY ``span[0]`` is the command STRING; tokens AFTER it
                    # are positional args bound to ``$0``/``$1``/… (``sh -c
                    # '…rm -rf .cache' sh "$HOME"`` — ``$HOME`` is ``$1``, not an
                    # ``rm`` operand), so joining them wrongly refused a legit
                    # cache clean (Security Scope). ONE descent per span (Opus).
                    if _budget[0] > 0:
                        _budget[0] -= 1
                        payload = _rm_deescape_unquoted_backslashes(span[0])
                        found |= _rm_targets_in_argv(
                            _split_shell_words(payload),
                            strip_quotes=strip_quotes,
                            _budget=_budget,
                        )
                # Advance PAST the consumed ``-c`` span, not by one — a chain of
                # ``sh -c`` tokens (``"sh -c " * 1000``) would otherwise re-scan
                # the span to the end for every ``sh``, O(spans²) and minutes on
                # the synchronous gate (Opus, security-class perf).
                advance = max(advance, k - i)
        i += advance
    return frozenset(found)


def _rm_overflow_span_targets(tokens: "list[str]", start: int) -> "frozenset[str]":
    """A CHEAP root/home-shape test for one recursive-force ``rm`` span, used only
    past the per-span classification cap.

    The full structural classifier is capped so a pathological flood of ``rm``
    spans cannot cost O(spans x operand). Past the cap we must still not fail OPEN
    on a real wipe, yet a long bulk cleanup of DESCENDANTS (``rm -fr build0 ; … ;
    rm -fr build69``) is legit and base allowed it -- so a blanket root+home deny
    newly refused it. Instead scan THIS span's operand tokens once (raw, no brace or
    dot-segment expansion) and report only the class whose exact root/home target
    appears: a ``/``- or ``~``/``$HOME``-rooted operand that the itself-matchers
    accept. Each token is visited once across spans, so the whole walk stays linear.
    """
    out: set[str] = set()
    j = start + 1
    n = len(tokens)
    while j < n and not _ends_argv(tokens[j]):
        tok = tokens[j]
        j += 1
        if tok.startswith("-"):
            continue
        stripped = _rm_strip_all_quotes(tok)
        for cand in (
            tok,
            stripped,
            _rm_normalize_dot_segments(tok),
            _rm_normalize_dot_segments(stripped),
        ):
            if _RM_ROOT_ITSELF_RE.fullmatch(cand):
                out.add("root")
            if _RM_HOME_ITSELF_RE.fullmatch(cand):
                out.add("home")
        if {"root", "home"} <= out:
            break
    return frozenset(out)


def _rm_targets_in_argv(
    tokens: "list[str]",
    *,
    strip_quotes: bool,
    _budget: "list[int] | None" = None,
) -> "frozenset[str]":
    """The catastrophic ``rm`` targets deleted within ONE frame's raw argv.

    Fires for each token whose basename is ``rm`` and that is EXECUTED — ``rm`` at
    program position, the first argument of a multi-call dispatcher (``busybox
    rm``), or ``rm`` whose parent does NOT treat its args as data. That last is a
    DENYLIST: an ``rm`` behind ANY parent executes UNLESS the parent is in
    ``_DATA_CONSUMER_PROGRAMS`` (``echo``/``cat``/``cp``/``mv``), so an unknown exec
    wrapper (``setsid``/``nohup``/…) is executable rather than slipping an
    allowlist; an ``rm`` that is a data consumer's argument (``echo rm -rf /``) is
    skipped.

    From each executed ``rm`` its OWN argv is read forward until the command ends.
    A resolved operand is denied when it IS the root (``/``, ``/*``) or home (``~``
    / ``$HOME`` / their ``/*``) dir ITSELF, in ANY flag spelling. A DESCENDANT
    (``rm -rf /etc``, ``rm -rf ~/.ssh``) is NOT denied by this structural pass;
    base's descendant coverage is reproduced by the frame-text pin (``rm -rf /.*``
    / ``rm -rf ~.*``), so only a descendant base's contiguous ``rm -rf `` text
    matched is denied while a widened spelling (``rm -fr /tmp/x``) stays allowed
    (Security Scope).

    ``strip_quotes`` peels surrounding SHELL quotes — True for the raw split
    (``"$HOME"`` -> ``$HOME``), False for the decoded view where a surrounding
    quote is a literal the decode produced (``$'"/"'`` -> ``"/"``).
    """
    if not tokens:
        return frozenset()
    # Shared brace expander (argv_floor) rather than a private rm-local copy.
    from .argv_floor import _brace_expansions

    # One shared descent budget per top-level classification. The public entry
    # (and every non-recursive caller) passes None, so a fresh cell is created
    # here; the sub-helpers thread the SAME cell into their recursive
    # ``_rm_targets_in_argv`` calls, so nested spans draw down one common budget.
    if _budget is None:
        _budget = [_RM_DESCENT_BUDGET]
    programs = _argv_programs(tokens)
    found: set[str] = set()
    found |= _rm_targets_in_shell_c(tokens, programs, strip_quotes=strip_quotes, _budget=_budget)
    # Computed once per argv (not per ``rm`` token): the pipe-into-shell / trailing
    # operator guards ``_data_consumer_exempt`` consults, whose sweep is quadratic
    # per token. ``None`` until the first ``rm`` needs it.
    disqualified: "bool | None" = None
    expect_program = True
    #: Index of the most recent command's program word, so a dispatcher's FIRST
    #: argument (its applet) can be recognised: ``busybox rm -rf /`` runs ``rm``.
    program_word_at = -1
    #: How many ``rm`` spans this argv has structurally classified. Bounds the
    #: per-``rm`` suffix re-scan to keep a ``rm``-padded argv linear (GPT 6.1 F2);
    #: a wipe past the cap is still caught by the whole-text deny-net regex.
    rm_spans_classified = 0
    #: Per-SPAN cache of the recursive-force verdict, keyed on the span's
    #: program-word index, so a flagless ``rm`` flood costs O(1) per token (GPT 6.1
    #: F3).
    span_start_at = -2
    span_is_rf = False
    #: Per-SPAN cache of the overflow root/home-shape verdict (GPT 6.1 F1), keyed on
    #: the same span program-word index. The overflow scan reads the WHOLE span's
    #: operands, so it is a property of the span, not of the operand index it is
    #: called at — computing it once per span keeps a bare-``rm`` flood past the cap
    #: (``sudo rm -fr rm rm …``) at O(1) per operand instead of rescanning the span
    #: suffix for every operand named ``rm`` (O(n²), past the gateway watchdog).
    span_overflow_targets: frozenset[str] = frozenset()
    for i, token in enumerate(tokens):
        is_program_word = (
            expect_program and bool(token) and not _shell_normalizer.ENV_ASSIGNMENT_RE.match(token)
        )
        starts_command = is_program_word
        if is_program_word:
            expect_program = False
            program_word_at = i
        # A glued ``&`` / ``&&`` ENDS the command (backgrounds or chains it), so the
        # next token starts a NEW command that runs — ``echo hi& rm -rf /`` is two
        # commands, the ``rm`` executed. ``_ends_argv`` catches glued ``|``/``;`` but
        # not ``&``, and a standalone ``&`` is already covered; a ``2>&1`` ends in
        # ``1`` not ``&``, so it is not mistaken for a boundary.
        if _ends_argv(token) or token.endswith("&"):
            expect_program = True
        if _program_basename(token) != "rm":
            continue
        # Executed iff ``rm`` leads its own command, is the FIRST argument of a
        # multi-call dispatcher (``busybox rm``), or its parent does NOT treat args
        # as data. A DENYLIST: an UNKNOWN parent defaults to EXECUTABLE; only a
        # ``_DATA_CONSUMER_PROGRAMS`` parent makes ``rm`` a mention (and ``echo rm
        # -rf / | sh`` still executes — ``_data_consumer_exempt`` refuses a pipe).
        dispatched_applet = (
            i == program_word_at + 1
            and program_word_at >= 0
            and _program_basename(tokens[program_word_at]) in _RM_APPLET_DISPATCHERS
        )
        # When the program is a multi-call dispatcher, its FIRST argument is the
        # applet that runs, so THAT — not ``busybox`` — is the effective parent of a
        # later ``rm``. ``busybox echo rm -rf /`` runs ``echo``, which prints it: a
        # mention. Resolve to the applet before the data-consumer test so the
        # dispatcher itself does not make its applet's arguments look executed.
        dispatcher_applet_is_consumer = (
            not dispatched_applet
            and program_word_at >= 0
            and program_word_at + 1 < len(tokens)
            and _program_basename(tokens[program_word_at]) in _RM_APPLET_DISPATCHERS
            and _program_basename(tokens[program_word_at + 1]) in _DATA_CONSUMER_PROGRAMS
        )
        if not (starts_command or dispatched_applet):
            if dispatcher_applet_is_consumer:
                continue
            if disqualified is None:
                disqualified = _shell_normalizer._data_consumer_command_disqualified(tokens)
            if _data_consumer_exempt(i, token, programs, tokens, command_disqualified=disqualified):
                continue
        # A ``rm`` that is a trailing OPERAND of a filesystem-MOVER (``env rm -fr rm
        # rm`` runs ``rm -fr`` on operands ``rm rm``) is a path. A mover under an
        # exec wrapper is attributed to the wrapper, so skip the operand when it is
        # NOT the span's program word and the effective command is a mover (GPT 6.1
        # F2/F3). A wrapper-reached EXECUTED ``rm`` (``ssh host rm -rf /tmp/x``) still
        # classifies.
        if not (starts_command or dispatched_applet):
            effective_program = _rm_effective_span_program(programs, tokens, i)
            if effective_program in _RM_MOVER_PROGRAMS:
                continue
        # Bound the per-``rm`` suffix scans (GPT 6.1 F3): a flagless ``rm`` flood
        # (``setsid true`` + 2,500 bare ``rm`` args) otherwise pays an O(span) scan
        # per token, O(n²), past the gateway watchdog. The recursive-force verdict is
        # a property of the SPAN, so compute it ONCE per span and reuse it; and a
        # NON-recursive-force span can never be a catastrophic wipe (base's ``rm -rf``
        # literal never matched it either), so skip its whole operand classification.
        if span_start_at != program_word_at:
            span_start_at = program_word_at
            span_is_rf = _rm_span_is_recursive_force(tokens, i)
            # Compute the overflow root/home-shape verdict ONCE per span, here at the
            # span's program word (GPT 6.1 F1). It reads the whole span's operands, so
            # it does not depend on which operand ``i`` reached the overflow branch;
            # caching it stops the quadratic rescan a bare-``rm`` flood would cause.
            span_overflow_targets = _rm_overflow_span_targets(tokens, i)
        if not span_is_rf:
            continue
        if rm_spans_classified >= _RM_CLASSIFY_SPAN_CAP:
            # Past the per-span classification cap, do NOT blanket-deny: a long bulk
            # cleanup of recursive-force rm on DESCENDANTS (``rm -fr build0 ; … ;
            # rm -fr build69``) is legit and base allowed it, so failing closed to
            # root+home newly refused it (Security Scope / Opus 5.5). Instead run a
            # CHEAP, bounded root/home-SHAPE test on this overflow span's operands
            # (raw regex + prefix, no brace/dot machinery): fail closed only for the
            # class actually targeted. The verdict is a per-SPAN property computed
            # once at the span's program word (``span_overflow_targets``), so each
            # operand past the cap costs O(1) here, not an O(span) rescan (GPT 6.1
            # F1 — a bare-``rm`` flood ``sudo rm -fr rm rm …`` was otherwise O(n²),
            # 38s past the gateway watchdog).
            found |= span_overflow_targets
            if {"root", "home"} <= found:
                break
            continue
        rm_spans_classified += 1
        # STRUCTURAL classification (below) denies the EXACT root/home target for
        # ANY ``rm`` — direct, dispatcher applet, or EXEC-WRAPPER reached. base's
        # DESCENDANT coverage (``rm -rf /etc``, ``rm -rf ~/.ssh``) is reproduced by
        # the base-contiguous-literal pin, so a descendant base matched is denied
        # while a WIDENED spelling (``rm -fr /tmp/x``) stays allowed (Security Scope).
        has_rec = has_force = has_npr = False
        end_of_options = False
        depth = 0
        operands: list[str] = []
        #: Bare home spellings contributed ONLY by a fully single-quoted operand
        #: (``'~'`` / ``'$HOME'`` / ``'${HOME}'``), which bash passes verbatim as a
        #: literal cwd file — never the home dir. Collected from the RAW arg before
        #: quote-peeling so the home matcher can ignore the de-quoted spelling, and
        #: ``span_has_live_home`` keeps a co-present live ``~`` (``rm -fr '~' ~``)
        #: denying. A single-quoted ``'/'`` root is unaffected (home-only).
        home_single_quote_literals: set[str] = set()
        span_has_live_home = False
        # Base ran its whole-line literal against the QUOTE-NORMALIZED re-join, so
        # ``rm -rf "/etc"`` / ``rm "-rf" /etc`` denied on base; the raw pin misses
        # them (Opus). Reproduce STRUCTURALLY, raw view only: ``$HOME`` stays literal
        # so base's contiguity still excludes ``$HOME``-descendants.
        # ``rm {--recursive,--force,--no-preserve-root} {/,/tmp}`` reaches the floor
        # with brace GROUPS as single tokens matching no flag/operand, yet bash
        # expands each word and wipes ``/`` (GPT F1). Expand every token's
        # statically-decidable alternation members BEFORE flag/operand parsing;
        # non-brace expands to itself. Bounded by ``_RM_BRACE_EXPANSION_CAP``.
        expanded_args: list[str] = []
        for raw_arg in tokens[i + 1 :]:
            # An unquoted word starting with ``#`` opens a shell COMMENT — discarded
            # with the rest of the line, never an ``rm`` operand (``rm -rf dist #
            # remove /`` deletes ``dist``; Opus). A quoted/glued ``#`` is literal.
            if strip_quotes and raw_arg.startswith("#"):
                break
            # Expand this word's brace members via the shared ``_brace_expansions``.
            # It returns ``[word]`` for a non-brace / single-member word and ``None``
            # on a product past the shared cap; on overflow keep the raw word (the
            # per-span ``brace_overflow`` fail-closed below, plus the deny-net regex,
            # still catch a catastrophic member).
            members = _brace_expansions(raw_arg)
            expanded_args.extend(members if members else [raw_arg])
            # Stop at THIS ``rm``'s command boundary — an unescaped ``;``/``&``/
            # ``|``/newline ends the command, so a later command's operands are not
            # brace-expanded (``rm a ;`` + brace blobs is O(commands × operands); GPT
            # 6.1 perf). A separator bare only from a peeled quote (``';'``) is a
            # literal — gate on ``not did_peel`` (``rm -rf ';' /`` deletes root).
            if strip_quotes:
                _boundary_arg, _boundary_did_peel = _rm_strip_surrounding_quotes_reporting(raw_arg)
                if not _boundary_did_peel and _rm_unescaped_boundary(_boundary_arg) is not None:
                    break
        for arg in expanded_args:
            operand, quote_peeled = (
                _rm_strip_surrounding_quotes_reporting(arg) if strip_quotes else (arg, False)
            )
            # Quoting a flag does NOT stop GNU ``rm`` option parsing — bash strips
            # the quotes, so ``rm '-rf' ~`` / ``rm "-rf" ~`` / ``rm -r''f ~`` / ``rm
            # \-rf ~`` all reach ``rm`` as ``-rf`` (Opus). Test the flag predicates
            # on the FULLY de-quoted spelling; the raw ``arg`` keeps its quotes and
            # would be mis-read as an operand, failing open on the wipe.
            flag_tok = _rm_strip_all_quotes(arg) if strip_quotes else arg
            # A glued operator (``/;reboot``) leaves the real operand before it;
            # classify that head and end the argv at the boundary. A separator bare
            # only from a peeled quote (``';'``) is a literal, not a boundary, so the
            # split is suppressed (Opus: ``rm -rf ';' /``), as for a backslash-escaped
            # operator. Raw view only.
            glued_boundary = False
            if strip_quotes and not quote_peeled and depth + _substitution_depth_delta(arg) <= 0:
                operand, glued_boundary = _rm_operand_before_boundary(operand)
            if flag_tok == "--" and not end_of_options:
                end_of_options = True
            elif not end_of_options and flag_tok == "--no-preserve-root":
                has_npr = True
            elif not end_of_options and _rm_is_recursive_flag(flag_tok):
                has_rec = True
                if _rm_is_force_flag(flag_tok):
                    has_force = True
            elif not end_of_options and _rm_is_force_flag(flag_tok):
                has_force = True
            elif operand:
                if strip_quotes and _RM_HOME_ITSELF_RE.fullmatch(_rm_strip_all_quotes(arg)):
                    # Live only when the ``~``/``$HOME`` is unquoted/unescaped (or a
                    # double-quoted ``$HOME``); a ``'~'`` / ``"~"`` / ``\~`` / ``'$HOME'``
                    # is a literal cwd file. Mask the non-live spellings: if nothing
                    # home-shaped survives, this operand is a literal.
                    if not _RM_HOME_REF_RE.search(_rm_mask_non_live_home(arg)) and not any(
                        c == "~" for c in _rm_mask_non_live_home(arg)
                    ):
                        bare = _rm_strip_all_quotes(arg)
                        home_single_quote_literals.add(bare)
                        home_single_quote_literals.add(_rm_normalize_dot_segments(bare))
                    else:
                        span_has_live_home = True
                operands.append(operand)
            # A shell-ELIDED empty word (``rm "" -rf /``) contributes no flag/
            # operand — bash expands ``""`` to nothing, so base never saw it and the
            # ``rm -rf /`` stayed contiguous.
            depth += _substitution_depth_delta(arg)
            # The rm span started at depth 0 (relative to its own program word). A
            # token whose delta drops depth BELOW 0 is the ``)`` / closer of the
            # substitution that HOLDS this rm (``ls $(rm -rf ./build) ~``): the rm
            # argv ends there, so the OUTER command's operands (the trailing ``~``)
            # are not miscounted as rm targets (Opus 5.5 FP; base allowed both).
            if depth < 0:
                break
            # A quoted-``;`` (``';'``) or backslash-ESCAPED operator (``a\;b``) is a
            # literal filename, not a terminator — ``_ends_argv`` on the raw ``arg``
            # would stop the argv before a later ``/`` (Opus: ``rm -rf ';' /``). The
            # raw-view terminator fires only on an UNESCAPED, unpeeled operator; the
            # decoded view ends on its own bare terminator.
            if strip_quotes:
                raw_terminates = (
                    not quote_peeled and _ends_argv(arg) and _rm_unescaped_boundary(arg) is not None
                )
            else:
                raw_terminates = _ends_argv(arg)
            if depth <= 0 and (glued_boundary or raw_terminates):
                break
        # STRUCTURAL classification denies the EXACT root/home target ITSELF in ANY
        # flag spelling. A DESCENDANT in a WIDENED spelling (``rm -fr /tmp/x``) is
        # NOT denied here (base's whole-line literal never matched it; Security
        # Scope). base's OWN ``rm -rf /``/``~`` descendant coverage is the LIVE
        # whole-line deny-net regex, which already scans the raw command text.
        root_re, home_re = _RM_ROOT_ITSELF_RE, _RM_HOME_ITSELF_RE
        # Classify each operand AND its dot-normalized form (``/./``, ``/tmp/../``,
        # ``~/.`` resolve to root/home). On the RAW split also classify the fully
        # de-quoted spelling so a PARTIALLY quoted ``"$HOME"/`` keeps its anchor
        # (GPT security-class); NOT on the decoded view, where a decode-produced
        # quote is a literal filename char (``$'"/"'`` is a file ``/``, not root).
        candidates = list(operands) + [_rm_normalize_dot_segments(op) for op in operands]
        if strip_quotes:
            dequoted = [_rm_strip_all_quotes(op) for op in operands]
            candidates += dequoted + [_rm_normalize_dot_segments(op) for op in dequoted]
        # A brace word (``{~,/x}``, ``/{,bin}``, ``$HOME/{,.cache}``) expands to
        # several operands and the exact matchers must see each, else the root/home
        # member hides behind the un-expandable brace word (GPT). Expand every
        # candidate via the shared ``_brace_expansions`` and classify each member +
        # its dot-normalized form; a non-brace / single-member word contributes
        # nothing extra. A product past the shared cap returns ``None`` — fail CLOSED
        # (treat the span as reaching root/home) rather than drop a catastrophic
        # member past the bound.
        brace_members: list[str] = []
        brace_overflow = False
        for op in list(candidates):
            expanded = _brace_expansions(op)
            if expanded is None:
                # Overflow past the shared cap. Fail CLOSED only when a member COULD
                # be root/home — i.e. the word, with its brace groups stripped, is
                # empty or still root/home-rooted. A word with a non-root LITERAL
                # prefix (``./bench-out/run-{1..500}``, ``/tmp/kc-shard-{000..511}``,
                # ``out/{a,b}{1..99}``) can only expand to descendants, so a huge
                # relative/descendant brace is NOT a catastrophic wipe (Security Scope).
                if _rm_brace_word_could_be_catastrophic(op):
                    brace_overflow = True
                continue
            brace_members.extend(expanded)
        if brace_members:
            candidates += brace_members + [_rm_normalize_dot_segments(m) for m in brace_members]
        root_target = any(root_re.fullmatch(op) for op in candidates)
        home_excluded = home_single_quote_literals if not span_has_live_home else set()
        home_target = any(home_re.fullmatch(op) and op not in home_excluded for op in candidates)
        # ``x=$HOME; rm -rf "$x"`` — the decoded view substitutes ``$x`` to the
        # EXPANDED home (no ``~``/``$HOME`` marker), matching neither matcher (GPT
        # 5.6 F3). Classify an operand that IS the expanded home as ``home``, decoded
        # view only, on EQUALITY. Fold separators + lowercase + ``/``+``*`` tail strip
        # (``expanduser`` native-case on Windows), else ``/*`` slip (Opus 5.5).
        if not strip_quotes and not home_target:
            home_real = _rm_expanded_home_path()
            if home_real and any(
                _rm_strip_home_itself_tail(op.replace("\\", "/").lower()) == home_real
                or _rm_strip_home_itself_tail(
                    _rm_normalize_dot_segments(op).replace("\\", "/").lower()
                )
                == home_real
                for op in candidates
            ):
                home_target = True

        # base's own ``rm -rf /.*`` / ``rm -rf ~.*`` descendant coverage is the LIVE
        # whole-line deny-net regex, which scans the raw command text; the structural
        # path below denies the exact root/home target ITSELF in any flag spelling,
        # and a brace-overflow fails closed. A separate ``base_rf_descendant`` pin
        # here only re-spelled the regex's descendant denial (First Principles:
        # one mechanism, not two) -- the full suite stays green without it, so the
        # descendant case is left to the regex.
        if has_npr or (has_rec and has_force):
            if root_target or brace_overflow:
                found.add("root")
            if home_target or brace_overflow:
                found.add("home")
    return frozenset(found)
