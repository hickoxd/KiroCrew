"""Tests for kiro_crew.dashboard.handlers.usage_series (the Usage tab's stacked series)."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import kiro_crew.dashboard.handlers.usage as usage_mod
import kiro_crew.dashboard.handlers.usage_series as series_mod
from kiro_crew.dashboard.handlers.usage_series import (
    OTHER_KEY,
    UNATTRIBUTED_KEY,
    _Row,
    api_usage_series,
    build_series,
    load_rows,
)

TODAY = date(2026, 10, 2)  # a Friday; its ISO week starts Monday 2026-09-28


def _row(
    day: str,
    credits: float = 1.0,
    *,
    slot: str = "s1",
    surface: str = "dashboard",
    agent: str = "kirocrew",
    model: str = "m",
    tokens: int = 0,
    hour: int = 12,
) -> _Row:
    ts = datetime.fromisoformat(f"{day}T{hour:02d}:00:00").astimezone().timestamp()
    return _Row(
        day=day,
        ts=ts,
        slot=slot,
        surface=surface,
        agent=agent,
        model=model,
        tokens=tokens,
        credits=credits,
    )


def _by_key(payload: dict) -> dict[str, dict]:
    return {s["key"]: s for s in payload["series"]}


class TestBuildSeries:
    def test_dense_day_axis_is_zero_filled(self):
        rows = [_row("2026-10-01", 2.5), _row("2026-10-02", 1.5)]

        out = build_series(rows, by="surface", days=5, today=TODAY)

        assert out["dates"] == [
            "2026-09-28",
            "2026-09-29",
            "2026-09-30",
            "2026-10-01",
            "2026-10-02",
        ]
        assert out["series"] == [
            {"key": "dashboard", "kind": "bucket", "values": [0, 0, 0, 2.5, 1.5], "total": 4.0}
        ]
        assert out["total"] == 4.0
        assert out["rows"] == 2

    def test_rows_outside_the_window_are_ignored(self):
        rows = [_row("2026-09-01", 99.0), _row("2026-10-02", 1.0)]

        out = build_series(rows, by="surface", days=7, today=TODAY)

        assert out["total"] == 1.0
        assert out["rows"] == 1

    def test_value_dimensions_stack_largest_first(self):
        rows = [
            _row("2026-10-02", 1.0, surface="bg:consolidation"),
            _row("2026-10-02", 5.0, surface="cron"),
            _row("2026-10-01", 3.0, surface="dashboard"),
        ]

        out = build_series(rows, by="surface", days=2, today=TODAY)

        assert [s["key"] for s in out["series"]] == ["cron", "dashboard", "bg:consolidation"]

    def test_top_n_folds_the_remainder_into_other(self):
        rows = [_row("2026-10-02", float(n), agent=f"agent-{n}") for n in range(1, 6)]

        out = build_series(rows, by="agent", days=1, top=2, today=TODAY)

        keys = [s["key"] for s in out["series"]]
        assert keys == ["agent-5", "agent-4", OTHER_KEY]
        other = _by_key(out)[OTHER_KEY]
        assert other == {
            "key": OTHER_KEY,
            "kind": "other",
            "values": [6.0],
            "total": 6.0,
            "members": 3,
        }
        # Folding loses nothing: the stack's top edge is still the day's spend.
        assert out["total"] == 15.0

    def test_empty_dimension_value_is_an_explicit_unattributed_series(self):
        rows = [_row("2026-10-02", 2.0, model=""), _row("2026-10-02", 3.0, model="opus")]

        out = build_series(rows, by="model", days=1, today=TODAY)

        assert [s["key"] for s in out["series"]] == ["opus", UNATTRIBUTED_KEY]
        assert _by_key(out)[UNATTRIBUTED_KEY]["total"] == 2.0
        assert out["total"] == 5.0

    def test_unattributed_and_other_are_omitted_when_empty(self):
        out = build_series([_row("2026-10-02", 1.0)], by="surface", days=1, today=TODAY)

        assert [s["kind"] for s in out["series"]] == ["bucket"]

    def test_tokens_metric_sums_the_four_token_fields_and_ignores_credits(self):
        rows = [_row("2026-10-02", 50.0, tokens=120), _row("2026-10-02", 50.0, tokens=0)]

        out = build_series(rows, by="surface", metric="tokens", days=1, today=TODAY)

        assert out["metric"] == "tokens"
        assert out["total"] == 120.0

    def test_zero_valued_rows_do_not_create_buckets(self):
        rows = [
            _row("2026-10-02", 0.0, surface="cron"),
            _row("2026-10-02", 1.0, surface="dashboard"),
        ]

        out = build_series(rows, by="surface", days=1, today=TODAY)

        assert [s["key"] for s in out["series"]] == ["dashboard"]

    def test_a_row_that_would_overflow_a_day_is_dropped_not_served_as_infinity(self):
        rows = [_row("2026-10-02", 1.0), _row("2026-10-02", 1.7e308), _row("2026-10-02", 1.7e308)]

        out = build_series(rows, by="surface", days=1, today=TODAY)

        assert out["total"] == 1.0 + 1.7e308
        assert json.dumps(out, allow_nan=False)

    def test_folded_and_total_sums_cannot_overflow_to_infinity_either(self):
        rows = [
            _row("2026-10-01", 1.7e308, surface="kept"),
            _row("2026-10-02", 1.0e308, surface="folded-a"),
            _row("2026-10-02", 1.0e308, surface="folded-b"),
        ]

        out = build_series(rows, by="surface", days=2, top=1, today=TODAY)

        assert _by_key(out)["kept"]["total"] == 1.7e308
        assert _by_key(out)["__other__"]["values"] == [0.0, 1.0e308]
        assert out["total"] == 1.7e308
        assert json.dumps(out, allow_nan=False)

    def test_cohort_is_the_sessions_first_seen_iso_week_in_stack_order_oldest_first(self):
        rows = [
            # s-old starts Tue 09-15 (week of Mon 09-14) and keeps spending into October:
            # every one of its rows belongs to the 09-14 cohort, not the week it was spent.
            _row("2026-09-15", 1.0, slot="s-old"),
            _row("2026-10-02", 4.0, slot="s-old"),
            # s-new starts Thu 10-01 (week of Mon 09-28).
            _row("2026-10-01", 2.0, slot="s-new"),
            _row("2026-10-02", 8.0, slot="s-new"),
        ]

        out = build_series(rows, by="cohort", days=30, today=TODAY)

        assert [s["key"] for s in out["series"]] == ["2026-09-14", "2026-09-28"]
        cohorts = _by_key(out)
        assert cohorts["2026-09-14"]["total"] == 5.0
        assert cohorts["2026-09-28"]["total"] == 10.0
        # Oldest first even though the newer cohort is the bigger one.
        assert cohorts["2026-09-14"]["total"] < cohorts["2026-09-28"]["total"]

    def test_cohort_first_seen_is_judged_inside_the_window_only(self):
        rows = [_row("2026-09-01", 1.0, slot="s"), _row("2026-10-02", 1.0, slot="s")]

        out = build_series(rows, by="cohort", days=7, today=TODAY)

        # The September row is outside a 7-day window, so the session's first
        # appearance inside the window is the October row: week of Mon 09-28.
        assert [s["key"] for s in out["series"]] == ["2026-09-28"]

    def test_cohort_row_without_a_slot_is_unattributed(self):
        rows = [_row("2026-10-02", 1.0, slot=""), _row("2026-10-02", 2.0, slot="s")]

        out = build_series(rows, by="cohort", days=1, today=TODAY)

        assert [s["key"] for s in out["series"]] == ["2026-09-28", UNATTRIBUTED_KEY]


def _patch_shards(monkeypatch, tmp_path):
    shard_dir = tmp_path / "tokens"
    shard_dir.mkdir()
    monkeypatch.setattr(usage_mod, "_TOKEN_USAGE_DIR", shard_dir)
    monkeypatch.setattr(series_mod, "_ROWS_CACHE", [])
    monkeypatch.setattr(series_mod, "_ROWS_CACHE_KEY", None)
    monkeypatch.setattr(series_mod, "_ROWS_CACHE_TS", 0.0)
    return shard_dir


def _write_shard(shard_dir, day: str, records: list[dict]) -> None:
    (shard_dir / f"{day}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )


def _today_local() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d")


def _record(ts: str, **fields) -> dict:
    base = {
        "_type": "tokens",
        "ts": ts,
        "slot": "chat-1",
        "provider": "acp",
        "model": "m",
        "surface": "dashboard",
        "agent": "kirocrew",
        "input": 0,
        "output": 0,
        "cache_create": 0,
        "cache_read": 0,
        "credits": 1.0,
    }
    base.update(fields)
    return base


class TestLoadRows:
    def test_reads_tokens_rows_and_skips_the_rest(self, tmp_path, monkeypatch):
        shard_dir = _patch_shards(monkeypatch, tmp_path)
        day = _today_local()
        now = datetime.now().astimezone().replace(minute=0, second=0, microsecond=0)
        _write_shard(
            shard_dir,
            day,
            [
                _record(
                    now.isoformat(), credits=2.5, input=10, output=5, cache_create=1, cache_read=4
                ),
                {"_type": "context", "ts": now.isoformat(), "slot": "chat-1"},
                {"_type": "tokens", "ts": "not a timestamp", "credits": 99},
                {"_type": "tokens", "ts": now.isoformat(), "credits": "nan", "slot": "chat-2"},
            ],
        )
        (shard_dir / f"{day}.jsonl").open("a", encoding="utf-8").write("{not json\n")

        rows = load_rows()

        assert [(r.slot, r.credits, r.tokens) for r in rows] == [
            ("chat-1", 2.5, 20),
            ("chat-2", 0.0, 0),
        ]

    def test_legacy_surface_spelling_is_canonicalised_like_daily_history(
        self, tmp_path, monkeypatch
    ):
        shard_dir = _patch_shards(monkeypatch, tmp_path)
        now = datetime.now().astimezone().replace(minute=0, second=0, microsecond=0)
        _write_shard(
            shard_dir,
            _today_local(),
            [
                _record(now.isoformat(), slot="old", surface="task_runner"),
                _record(now.isoformat(), slot="new", surface="taskrunner"),
            ],
        )

        rows = load_rows()

        assert [r.surface for r in rows] == ["taskrunner", "taskrunner"]

    def test_a_token_count_wider_than_a_double_counts_zero_instead_of_failing_the_read(
        self, tmp_path, monkeypatch
    ):
        shard_dir = _patch_shards(monkeypatch, tmp_path)
        now = datetime.now().astimezone().replace(minute=0, second=0, microsecond=0)
        _write_shard(
            shard_dir,
            _today_local(),
            [_record(now.isoformat(), input=10**400, output=7, credits=2.0)],
        )

        rows = load_rows()
        out = build_series(rows, by="surface", metric="tokens", days=1)

        assert [(r.tokens, r.credits) for r in rows] == [(0, 2.0)]
        assert out["total"] == 0.0
        assert json.dumps(out, allow_nan=False)

    def test_rows_are_cached_until_a_shard_changes(self, tmp_path, monkeypatch):
        shard_dir = _patch_shards(monkeypatch, tmp_path)
        day = _today_local()
        now = datetime.now().astimezone()
        _write_shard(shard_dir, day, [_record(now.isoformat(), credits=1.0)])

        first = load_rows()
        assert len(first) == 1
        # An append changes the shard's size, so the fingerprint misses.
        with (shard_dir / f"{day}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(_record(now.isoformat(), credits=2.0)) + "\n")
        second = load_rows()

        assert len(second) == 2
        assert load_rows() is second

    def test_missing_directory_yields_no_rows(self, tmp_path, monkeypatch):
        _patch_shards(monkeypatch, tmp_path)
        monkeypatch.setattr(usage_mod, "_TOKEN_USAGE_DIR", tmp_path / "absent")

        assert load_rows() == []


class TestApiUsageSeries:
    async def _get(self, query: str, app_name: str = ""):
        app = web.Application()

        @web.middleware
        async def stamp_app(request, handler):
            request["app"] = app_name
            return await handler(request)

        app.middlewares.append(stamp_app)
        app.router.add_get("/api/usage/series", api_usage_series)
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/api/usage/series" + query)
            return resp.status, await resp.json()

    @pytest.mark.asyncio
    async def test_defaults_and_clamps(self, tmp_path, monkeypatch):
        shard_dir = _patch_shards(monkeypatch, tmp_path)
        now = datetime.now().astimezone()
        _write_shard(
            shard_dir, _today_local(), [_record(now.isoformat(), credits=3.0, surface="cron")]
        )

        status, body = await self._get("?days=9999&top=0")

        assert status == 200
        assert (body["by"], body["metric"], body["days"]) == (
            "surface",
            "credits",
            series_mod.MAX_DAYS,
        )
        assert body["dates"][-1] == _today_local()
        assert [s["key"] for s in body["series"]] == ["cron"]
        assert body["total"] == 3.0

    @pytest.mark.asyncio
    async def test_unknown_dimension_or_metric_is_a_400(self, tmp_path, monkeypatch):
        _patch_shards(monkeypatch, tmp_path)

        status, body = await self._get("?by=slot")
        assert (status, body["code"]) == (400, "invalid_dimension")

        status, body = await self._get("?metric=dollars")
        assert (status, body["code"]) == (400, "invalid_metric")

    @pytest.mark.asyncio
    async def test_cohort_dimension_over_the_wire(self, tmp_path, monkeypatch):
        shard_dir = _patch_shards(monkeypatch, tmp_path)
        now = datetime.now().astimezone()
        _write_shard(shard_dir, _today_local(), [_record(now.isoformat(), credits=1.0)])
        monday = (now.date() - timedelta(days=now.isoweekday() - 1)).isoformat()

        status, body = await self._get("?by=cohort&metric=credits&days=7")

        assert status == 200
        assert [s["key"] for s in body["series"]] == [monday]

    @pytest.mark.asyncio
    async def test_app_token_is_refused_as_not_found(self, tmp_path, monkeypatch):
        _patch_shards(monkeypatch, tmp_path)

        status, body = await self._get("", app_name="some-app")

        assert (status, body["code"]) == (404, "not_found")
