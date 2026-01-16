"""Tests for SNARK asset resolver fallbacks."""

from __future__ import annotations

import pytest

from privacy_protocol.snark import assets


def test_membership_v1_fixtures_resolve() -> None:
    instance_path, public_inputs_path, proof_path = assets.resolve_fixture_paths(
        "membership",
        1,
        depth=16,
    )
    assert instance_path.exists()
    assert public_inputs_path.exists()
    assert proof_path.exists()


def test_continuity_v1_fixtures_resolve() -> None:
    instance_path, public_inputs_path, proof_path = assets.resolve_fixture_paths(
        "continuity",
        1,
    )
    assert instance_path.exists()
    assert public_inputs_path.exists()
    assert proof_path.exists()


def test_membership_v2_vk_resolves_if_present() -> None:
    try:
        vk_path = assets.resolve_vk("membership", 2, depth=16)
    except FileNotFoundError:
        pytest.skip("membership v2 vk not available")
    assert vk_path.exists()


def test_continuity_v2_vk_resolves_if_present() -> None:
    try:
        vk_path = assets.resolve_vk("continuity", 2)
    except FileNotFoundError:
        pytest.skip("continuity v2 vk not available")
    assert vk_path.exists()
