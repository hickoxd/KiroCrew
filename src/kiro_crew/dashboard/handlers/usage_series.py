"""Stacked spend-over-time series for the Usage tab's area chart.

``GET /api/usage/series`` answers one question the per-day totals cannot:
*what is today's spend made of, and how did that composition drift?* The
reply is a dense day axis plus one zero-filled series per bucket of a chosen
dimension, shaped so the browser can stack the series directly (and, for the
cumulative view, run a prefix sum over each one). Rows come from the same
per-turn shards every other usage reader scans
(``<data home>/usage/tokens/YYYY-MM-DD.jsonl``), admitted by the same row
guard: a ``tokens`` row with a parseable local day.

Dimensions (``by``): ``surface`` (the dispatch origin: ``dashboard``,
``cron``, ``bg:*`` …), ``agent``, ``model``, and ``cohort`` — the ISO week in
which the row's session was first seen inside the window, keyed by that week's
Monday. Cohort is the one dimension that is a property of the session rather
than of the row, so it is assigned in a second pass once every row's session
is known. A session that started before the window looks like it started on
the window's first day; the shards it started in have been retired, so there
is nothing to read a truer answer from.

Metrics: ``credits`` (what the kiro-cli backend bills, present on every acp
row) and ``tokens`` (input + output + cache create + cache read, which that
backend reports as zero — kept for providers that do report them).

Bucketing is top-N by total over the window, with the remainder folded into
one ``other`` series so a dimension with hundreds of distinct values (agents,
session cohorts on a busy install) still renders as a legible stack. A row
whose dimension value is empty or absent — every row predates ``surface`` /
``agent``, and several surfaces never set a model — lands in an explicit
``unattributed`` series rather than being guessed at or dropped: dropping it
would make the stack's top edge disagree with the Daily History credits for
the same day. Series are returned in stack order, bottom first: value
dimensions largest-first, cohorts oldest-first, then ``other``, then
``unattributed``.

The parsed rows are cached on the shard fingerprint the other readers use
(``(path, mtime, size)`` per shard in the window, plus a TTL), so a dashboard
switching dimension or metric re-aggregates a few thousand small tuples
instead of re-reading the shards.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from aiohttp import web

from kiro_crew import model_registry
from kiro_crew.dashboard.handlers import usage as _usage
from kiro_crew.jsonl_util import bounded_records

logger = logging.getLogger(__name__)

#: Dimensions a caller may stack by. Everything but ``cohort`` is a row field.
SERIES_DIMENSIONS: tuple[str, ...] = ("surface", "agent", "model", "cohort")
SERIES_METRICS: tuple[str, ...] = ("credits", "tokens")
DEFAULT_DIMENSION = "surface"
DEFAULT_METRIC = "credits"
#: Buckets kept apart before the rest folds into ``other``. Matches the number
#: of distinguishable hues the dashboard's session palette generates, so a
#: default request never needs more colours than the theme can give it.
DEFAULT_TOP = 7
MAX_TOP = 20
#: The series window ceiling is the shard retention window: a longer axis
#: would only add empty days.
MAX_DAYS = _usage._TOKEN_HISTORY_DAYS

#: Reserved series keys. Chosen so no real surface, agent, model or week date
#: can collide with them (dimension values are free text but a user-facing
#: name wrapped in double underscores is not one anyone writes).
OTHER_KEY = "__other__"
UNATTRIBUTED_KEY = "__unattributed__"

_ROW_FIELDS = {"surface": "surface", "agent": "agent", "model": "model"}

# Parsed-row cache: keyed on the shard fingerprint plus a TTL safety net for
# clock skew and in-place edits, the same posture as usage._parse_token_history.
_ROWS_CACHE: list[_Row] = []
_ROWS_CACHE_KEY: tuple[tuple[str, float, int], ...] | None = None
_ROWS_CACHE_TS: float = 0.0
_ROWS_CACHE_TTL = 120.0


@dataclass(frozen=True, slots=True)
class _Row:
    """One admitted per-turn row, reduced to what the series needs."""

    day: str
    ts: float
    slot: str
    surface: str
    agent: str
    model: str
    tokens: int
    credits: float


def _str_field(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    return value if isinstance(value, str) else ""


def _tokens_of(obj: dict[str, Any]) -> int:
    """The row's token total; a field that is not a usable number counts 0.

    A total wider than a double cannot be served (``float`` of it raises rather
    than answers), so such a row counts 0, like a non-finite credits value does.
    """
    total = 0
    for key in ("input", "output", "cache_create", "cache_read"):
        number = _usage._usage_number(obj.get(key))
        if number is not None:
            total += int(number)
    try:
        float(total)
    except OverflowError:
        return 0
    return total


def _credits_of(obj: dict[str, Any]) -> float:
    """The row's credits as a finite float; anything else counts 0.

    ``float`` of an int wider than a double raises rather than answers, and a
    non-finite value would reach the client as ``Infinity``, which is not JSON.
    """
    number = _usage._usage_number(obj.get("credits"))
    if number is None:
        return 0.0
    try:
        value = float(number)
    except OverflowError:
        return 0.0
    return value if math.isfinite(value) else 0.0


def _row_from(obj: dict[str, Any]) -> _Row | None:
    if obj.get("_type") != "tokens":
        return None
    ts_raw = obj.get("ts")
    ts_epoch = _usage._parse_row_ts(str(ts_raw or ""))
    day = _usage._parse_row_day(ts_raw)
    if ts_epoch is None or day is None:
        return None
    return _Row(
        day=day,
        ts=ts_epoch,
        slot=_str_field(obj, "slot"),
        # Same canonicalisation the daily chart applies, so a renamed surface
        # or a model that crossed a provider id migration never splits into
        # two buckets.
        surface=_usage._canonical_telemetry_surface(_str_field(obj, "surface")),
        agent=_str_field(obj, "agent"),
        model=model_registry.canonicalize_for_provider(
            _str_field(obj, "model"), _str_field(obj, "provider")
        ),
        tokens=_tokens_of(obj),
        credits=_credits_of(obj),
    )


def _scan_rows(days: int) -> list[_Row]:
    rows: list[_Row] = []
    for path in _usage._shards_in_window(days):
        try:
            with path.open("rb") as fh:
                for line in bounded_records(fh, path, label="usage"):
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    row = _row_from(obj)
                    if row is not None:
                        rows.append(row)
        except (OSError, UnicodeDecodeError):
            # A corrupt or unreadable shard costs its own rows, not the window.
            continue
    return rows


def load_rows() -> list[_Row]:
    """Every admitted row in the retention window, cached on the shard fingerprint."""
    global _ROWS_CACHE, _ROWS_CACHE_KEY, _ROWS_CACHE_TS

    shard_paths = _usage._shards_in_window(MAX_DAYS)
    cache_key: tuple[tuple[str, float, int], ...] | None
    try:
        cache_key = tuple(
            sorted((str(p), p.stat().st_mtime, p.stat().st_size) for p in shard_paths)
        )
    except OSError:
        cache_key = None
    now = time.time()
    if (
        cache_key is not None
        and _ROWS_CACHE_KEY == cache_key
        and (now - _ROWS_CACHE_TS) < _ROWS_CACHE_TTL
    ):
        return _ROWS_CACHE
    rows = _scan_rows(MAX_DAYS)
    _ROWS_CACHE = rows
    _ROWS_CACHE_KEY = cache_key
    _ROWS_CACHE_TS = now
    return rows


def _week_monday(ts: float) -> str:
    """The Monday of the ISO week containing the LOCAL day of ``ts``."""
    local = datetime.fromtimestamp(ts).astimezone()
    monday = local.date() - timedelta(days=local.isoweekday() - 1)
    return monday.isoformat()


def _cohort_of_slot(rows: list[_Row]) -> dict[str, str]:
    """Each session's cohort: the ISO week of its first row inside the window."""
    first_seen: dict[str, float] = {}
    for row in rows:
        if not row.slot:
            continue
        seen = first_seen.get(row.slot)
        if seen is None or row.ts < seen:
            first_seen[row.slot] = row.ts
    return {slot: _week_monday(ts) for slot, ts in first_seen.items()}


def _bucket_key(row: _Row, by: str, cohorts: dict[str, str]) -> str:
    if by == "cohort":
        return cohorts.get(row.slot, "") if row.slot else ""
    return getattr(row, _ROW_FIELDS[by])


def _metric_of(row: _Row, metric: str) -> float:
    return row.credits if metric == "credits" else float(row.tokens)


def _day_axis(days: int, today: date) -> list[str]:
    start = today - timedelta(days=days - 1)
    return [(start + timedelta(days=i)).isoformat() for i in range(days)]


def _round(value: float) -> float:
    return round(value, 6)


def _add(total: float, value: float) -> float:
    """``total + value``, or ``total`` unchanged when the sum leaves the finite range.

    Every operand is finite, but a sum of finite floats can still overflow to
    ``Infinity``, which is not JSON. Same rule as the Daily History credits: the
    contribution that would push a figure past the finite range is dropped.
    """
    candidate = total + value
    return candidate if math.isfinite(candidate) else total


def _sum(values: Iterable[float]) -> float:
    total = 0.0
    for value in values:
        total = _add(total, value)
    return total


def build_series(
    rows: list[_Row],
    *,
    by: str = DEFAULT_DIMENSION,
    metric: str = DEFAULT_METRIC,
    days: int = MAX_DAYS,
    top: int = DEFAULT_TOP,
    today: date | None = None,
) -> dict[str, Any]:
    """Aggregate ``rows`` into the stacked-series payload. Pure; see the module doc."""
    today = today or datetime.now().astimezone().date()
    dates = _day_axis(days, today)
    index = {d: i for i, d in enumerate(dates)}
    window_rows = [r for r in rows if r.day in index]
    cohorts = _cohort_of_slot(window_rows) if by == "cohort" else {}

    per_bucket: dict[str, list[float]] = {}
    unattributed = [0.0] * days
    for row in window_rows:
        value = _metric_of(row, metric)
        if value == 0.0:
            continue
        key = _bucket_key(row, by, cohorts)
        target = unattributed if not key else per_bucket.setdefault(key, [0.0] * days)
        target[index[row.day]] = _add(target[index[row.day]], value)

    ranked = sorted(per_bucket.items(), key=lambda kv: (-_sum(kv[1]), kv[0]))
    kept, folded = ranked[:top], ranked[top:]
    if by == "cohort":
        kept.sort(key=lambda kv: kv[0])

    series: list[dict[str, Any]] = [
        {
            "key": key,
            "kind": "bucket",
            "values": [_round(v) for v in values],
            "total": _round(_sum(values)),
        }
        for key, values in kept
    ]
    if folded:
        other = [0.0] * days
        for _key, values in folded:
            for i, v in enumerate(values):
                other[i] = _add(other[i], v)
        series.append(
            {
                "key": OTHER_KEY,
                "kind": "other",
                "values": [_round(v) for v in other],
                "total": _round(_sum(other)),
                "members": len(folded),
            }
        )
    if any(unattributed):
        series.append(
            {
                "key": UNATTRIBUTED_KEY,
                "kind": "unattributed",
                "values": [_round(v) for v in unattributed],
                "total": _round(_sum(unattributed)),
            }
        )
    return {
        "by": by,
        "metric": metric,
        "days": days,
        "dates": dates,
        "series": series,
        "total": _round(_sum(s["total"] for s in series)),
        "rows": len(window_rows),
    }


def _query_choice(
    request: web.Request, name: str, allowed: tuple[str, ...], default: str
) -> str | None:
    """The query value when it is one of ``allowed``; the default when absent; ``None`` otherwise."""
    raw = (request.query.get(name) or "").strip()
    if not raw:
        return default
    return raw if raw in allowed else None


def _query_int(request: web.Request, name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(request.query.get(name) or default)
    except ValueError:
        value = default
    return max(lo, min(value, hi))


async def api_usage_series(request: web.Request) -> web.Response:
    """GET /api/usage/series?by=surface|agent|model|cohort&metric=credits|tokens&days=N&top=N.

    Dashboard-only: the payload is the whole install's spend with no slot
    filter, so an app token — scoped to its own rows on ``/api/usage/turns`` —
    is answered 404 here, indistinguishable from a route it was never granted.
    ``days`` and ``top`` clamp to their ceilings rather than refusing; an
    unknown ``by`` or ``metric`` is a 400, because silently substituting the
    default would render a chart of something other than what was asked for.
    """
    if str(request.get("app", "") or ""):
        return web.json_response({"error": "not found", "code": "not_found"}, status=404)
    by = _query_choice(request, "by", SERIES_DIMENSIONS, DEFAULT_DIMENSION)
    if by is None:
        return web.json_response(
            {
                "error": f"by must be one of {', '.join(SERIES_DIMENSIONS)}",
                "code": "invalid_dimension",
            },
            status=400,
        )
    metric = _query_choice(request, "metric", SERIES_METRICS, DEFAULT_METRIC)
    if metric is None:
        return web.json_response(
            {
                "error": f"metric must be one of {', '.join(SERIES_METRICS)}",
                "code": "invalid_metric",
            },
            status=400,
        )
    days = _query_int(request, "days", MAX_DAYS, 1, MAX_DAYS)
    top = _query_int(request, "top", DEFAULT_TOP, 1, MAX_TOP)
    rows = await asyncio.to_thread(load_rows)
    return web.json_response(build_series(rows, by=by, metric=metric, days=days, top=top))
