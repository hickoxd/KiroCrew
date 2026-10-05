"""PoolKey.from_register security-boundary validation.

``trust_all_tools`` and ``os_uid`` are part of the security partition of the
PoolKey. They must be type-checked, not coerced: ``bool("false")`` is ``True``
and ``int`` on a bool silently passes, so a stub sending a JSON string/number
for these could land in the wrong trust/uid partition and share a backend it
should not.
"""

from __future__ import annotations

import pytest

from kiro_crew.mcp_gateway.pool import PoolKey

_VALID = {
    "server_name": "slack-mcp",
    "agent_name": "agent-a",
    "command_args_hash": "h1",
    "effective_env_hash": "h2",
    "work_dir": "/tmp/wd",
    "binary_version": "1.0",
    "os_uid": 1000,
    "sandbox_mode": "auto",
    "autoapprove_set_hash": "h3",
    "approval_mode": "interactive",
    "trust_all_tools": False,
    "channel_id": None,
    "config_snapshot_hash": "h4",
}


def test_pool_key_field_set_is_exactly_the_ten_dimensions() -> None:
    """The key's field set is asserted EXPLICITLY so adding or removing a
    pool dimension has to be a deliberate test change, never a silent one.

    Three fields are intentionally absent. ``user_identity``: nothing populates
    its ``KIROCREW_PRINCIPAL`` source, so it always collapsed to the OS user and
    never isolated anything. ``agent_name``: the agent never reaches the backend
    process, so two agents declaring one server identically asked for the same
    process. ``config_snapshot_hash``: the stub always sent 64 zeros, so it
    partitioned nothing at all.
    """
    assert set(PoolKey.__dataclass_fields__) == {
        # identity
        "server_name",
        # execution shape
        "command_args_hash",
        "effective_env_hash",
        "work_dir",
        "binary_version",
        # security boundary
        "os_uid",
        "sandbox_mode",
        "autoapprove_set_hash",
        "approval_mode",
        "trust_all_tools",
    }


def test_valid_register_roundtrips() -> None:
    key = PoolKey.from_register(dict(_VALID))
    assert key.os_uid == 1000
    assert key.trust_all_tools is False


def test_string_trust_all_tools_is_rejected_not_coerced() -> None:
    # bool("false") == True — coercion would wrongly key this as trusted.
    with pytest.raises(ValueError, match="trust_all_tools must be bool"):
        PoolKey.from_register({**_VALID, "trust_all_tools": "false"})


def test_bool_os_uid_is_rejected() -> None:
    # isinstance(True, int) is True; a bool must not pass as a uid.
    with pytest.raises(ValueError, match="os_uid must be int"):
        PoolKey.from_register({**_VALID, "os_uid": True})


def test_string_os_uid_is_rejected_not_coerced() -> None:
    with pytest.raises(ValueError, match="os_uid must be int"):
        PoolKey.from_register({**_VALID, "os_uid": "1000"})


class TestChannelIsNotAPoolDimension:
    """A channel does not partition the pool.

    It was never a usable trust boundary: on Slack a channel is a room shared
    by several people (so two humans in one channel shared a backend anyway),
    while on Telegram the same field carried a per-user id. The channel is
    delivered to backends PER CALL via ``_meta.kirocrew.caller`` instead, so a
    channel-aware server does not need a process to itself.
    """

    def test_two_channels_share_one_backend(self) -> None:
        a = PoolKey.from_register({**_VALID, "channel_id": "C_AAA"})
        b = PoolKey.from_register({**_VALID, "channel_id": "C_BBB"})
        assert a.stable_hash() == b.stable_hash()
        assert a == b

    def test_channel_and_no_channel_share_one_backend(self) -> None:
        with_chan = PoolKey.from_register({**_VALID, "channel_id": "C_AAA"})
        without = PoolKey.from_register({**_VALID, "channel_id": None})
        assert with_chan.stable_hash() == without.stable_hash()

    def test_payload_without_channel_id_is_accepted(self) -> None:
        """It is not a field at all — not a special-cased optional one — so a
        payload omitting it is complete rather than tolerated."""
        payload = {k: v for k, v in _VALID.items() if k != "channel_id"}
        key = PoolKey.from_register(payload)
        assert key.stable_hash() == PoolKey.from_register(dict(_VALID)).stable_hash()

    def test_unknown_channel_id_shape_does_not_break_register(self) -> None:
        """Forward/backward compat: an older stub still reports ``channel_id``
        (gatewayd threads it into caller identity), and a malformed value must
        not fail a register that does not depend on it."""
        for bogus in (123, {"a": 1}, ["x"], ""):
            key = PoolKey.from_register({**_VALID, "channel_id": bogus})
            assert key.stable_hash() == PoolKey.from_register(dict(_VALID)).stable_hash()

    def test_channel_absent_from_repr(self) -> None:
        assert "chan=" not in str(PoolKey.from_register({**_VALID, "channel_id": "C_X"}))

    def test_legacy_user_identity_is_not_a_pool_dimension(self) -> None:
        """An older stub still sends ``user_identity`` in its register
        payload. The field was deleted from the key (it never isolated
        anything — nothing populated ``KIROCREW_PRINCIPAL``, so it always
        collapsed to the OS user), so the payload key must be ignored, not
        rejected, and must not partition the pool."""
        base = PoolKey.from_register(dict(_VALID))
        for legacy in ("someone-else", "", "unknown"):
            variant = PoolKey.from_register({**_VALID, "user_identity": legacy})
            assert variant.stable_hash() == base.stable_hash()
            assert variant == base

    def test_security_dimensions_still_partition(self) -> None:
        """Negative control: dropping the channel dimension must not have made
        the key permissive — the real boundaries still split."""
        base = PoolKey.from_register(dict(_VALID))
        for field, other in (
            ("os_uid", 1001),
            ("sandbox_mode", "none"),
            ("effective_env_hash", "different"),
            ("work_dir", "/tmp/other"),
        ):
            variant = PoolKey.from_register({**_VALID, field: other})
            assert variant.stable_hash() != base.stable_hash(), field


class TestAgentIsNotAPoolDimension:
    """Two agents with identical server config share ONE backend.

    The agent name never reaches the backend process. Every input that does --
    command, env, work dir, binary -- is its own dimension and already differs
    whenever two agents declare a server differently, so an agent dimension only
    ever duplicated processes: on a host running several agents a common server
    ran up to five indistinguishable backends.
    """

    def test_two_agents_with_identical_config_share_one_backend(self) -> None:
        a = PoolKey.from_register({**_VALID, "agent_name": "gpu-dev"})
        b = PoolKey.from_register({**_VALID, "agent_name": "kirocrew"})
        assert a.stable_hash() == b.stable_hash()
        assert a == b

    def test_payload_without_agent_name_is_accepted(self) -> None:
        """Not a field at all, so a payload omitting it is complete."""
        payload = {k: v for k, v in _VALID.items() if k != "agent_name"}
        assert (
            PoolKey.from_register(payload).stable_hash()
            == PoolKey.from_register(dict(_VALID)).stable_hash()
        )

    def test_agent_absent_from_the_log_label(self) -> None:
        """``human_readable`` labels a POOL IDENTITY. Keeping the agent in it
        would read as though the agent still split the pool -- on the very line
        an operator uses to check that."""
        assert "agent-a" not in PoolKey.from_register(dict(_VALID)).human_readable()

    def test_a_declared_difference_still_partitions(self) -> None:
        """Negative control: agents whose declarations DIFFER must still get
        their own backends. That is the whole basis for sharing when they agree,
        so it is the same test read from the other side."""
        base = PoolKey.from_register({**_VALID, "agent_name": "gpu-dev"})
        for field, other in (
            ("command_args_hash", "other-cmd"),
            ("effective_env_hash", "other-env"),
            ("work_dir", "/tmp/other"),
            ("binary_version", "2.0"),
            ("autoapprove_set_hash", "other-approve"),
        ):
            variant = PoolKey.from_register({**_VALID, "agent_name": "kirocrew", field: other})
            assert variant.stable_hash() != base.stable_hash(), field


class TestConfigSnapshotIsNotAPoolDimension:
    """``config_snapshot_hash`` was inert from the start.

    The stub always sent a constant run of 64 zeros for it, so it never
    partitioned anything. Real config drift is carried by the execution-shape
    fields, which are recomputed from the spec the stub was launched with.
    """

    def test_differing_snapshot_hashes_share_one_backend(self) -> None:
        a = PoolKey.from_register({**_VALID, "config_snapshot_hash": "0" * 64})
        b = PoolKey.from_register({**_VALID, "config_snapshot_hash": "f" * 64})
        assert a.stable_hash() == b.stable_hash()
        assert a == b

    def test_payload_without_config_snapshot_hash_is_accepted(self) -> None:
        payload = {k: v for k, v in _VALID.items() if k != "config_snapshot_hash"}
        assert (
            PoolKey.from_register(payload).stable_hash()
            == PoolKey.from_register(dict(_VALID)).stable_hash()
        )


def test_an_old_stubs_full_payload_still_registers() -> None:
    """Wire compat. A stub predating these removals sends every legacy key at
    once; the daemon must ignore them rather than reject the register, or an
    upgraded daemon would un-pool every stub still on the old build."""
    legacy = {
        **_VALID,
        "user_identity": "mingweic",
        "agent_name": "gpu-dev",
        "config_snapshot_hash": "0" * 64,
        "channel_id": "C_AAA",
        "poolable": True,
    }
    assert (
        PoolKey.from_register(legacy).stable_hash()
        == PoolKey.from_register(dict(_VALID)).stable_hash()
    )
