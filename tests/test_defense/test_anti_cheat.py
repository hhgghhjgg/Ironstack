#!/usr/bin/env python3
"""
Unit tests for IronStack Anti‑Cheat module.
Covers:
  - AntiCheat main class
  - AimbotDetector
  - WallhackDetector
  - ScriptDetector
  - BaseAntiCheat (via a minimal implementation)
  - Utility functions
"""

import sys
import os
import pytest
import time
import math
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ironstack.defense.anti_cheat import (
    AntiCheat,
    AVAILABLE_DETECTORS,
)
from ironstack.defense.anti_cheat.base import (
    BaseAntiCheat,
    DetectionResult,
    PlayerState,
    AimState,
    calculate_distance,
    calculate_angle,
    calculate_aim_angle,
    moving_average,
    standard_deviation,
)
from ironstack.defense.anti_cheat.aimbot import AimbotDetector
from ironstack.defense.anti_cheat.wallhack import WallhackDetector
from ironstack.defense.anti_cheat.scripts import ScriptDetector
from ironstack.exceptions import AntiCheatError, CheatDetectedError


# ============================================================
# Helper: minimal detector for testing BaseAntiCheat
# ============================================================
class _ConcreteDetector(BaseAntiCheat):
    """A concrete subclass of BaseAntiCheat used for testing the base class."""
    def detect(self, player_id, action_data):
        self._stats["checks_performed"] += 1
        return DetectionResult(cheat_detected=False)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def base_detector():
    return _ConcreteDetector(sensitivity="medium")


@pytest.fixture
def ac_fps():
    return AntiCheat(game_type="fps", sensitivity="medium", auto_ban=False)


@pytest.fixture
def ac_auto():
    return AntiCheat(game_type="auto", auto_ban=True)


@pytest.fixture
def aimbot():
    return AimbotDetector(sensitivity="medium")


@pytest.fixture
def wallhack():
    return WallhackDetector(sensitivity="medium")


@pytest.fixture
def script():
    return ScriptDetector(sensitivity="medium")


# ============================================================
# BaseAntiCheat Tests
# ============================================================

class TestBaseAntiCheat:
    def test_initialization(self, base_detector):
        assert base_detector.sensitivity == "medium"
        assert base_detector.history_size == 100
        assert len(base_detector.player_states) == 0

    def test_update_player_state(self, base_detector):
        base_detector.update_player_state("p1", position=(1.0, 2.0, 3.0), rotation=(0, 90, 0))
        assert "p1" in base_detector.player_states
        assert base_detector.get_player_state("p1").position == (1.0, 2.0, 3.0)

    def test_record_action(self, base_detector):
        base_detector.record_action("p1", {"action": "jump"})
        history = base_detector.get_player_history("p1")
        assert len(history) == 1

    def test_remove_player(self, base_detector):
        base_detector.update_player_state("p1")
        base_detector.remove_player("p1")
        assert base_detector.get_player_state("p1") is None

    def test_detect_updates_stats(self, base_detector):
        base_detector.detect("p1", {})
        stats = base_detector.get_stats()
        assert stats["checks_performed"] == 1

    def test_sensitivity_threshold(self):
        low = _ConcreteDetector(sensitivity="low")
        high = _ConcreteDetector(sensitivity="high")
        assert low.threshold == 0.9
        assert high.threshold == 0.5


# ============================================================
# Utility Function Tests
# ============================================================

class TestUtilities:
    def test_calculate_distance(self):
        d = calculate_distance((0, 0, 0), (3, 4, 0))
        assert abs(d - 5.0) < 1e-6

    def test_calculate_angle(self):
        angle = calculate_angle((0, 0, 0), (1, 0, 1))
        # 45 degrees expected (dx=1, dz=1, horizontal=1 → atan2(1,1))
        assert abs(angle - 45.0) < 1e-1

    def test_calculate_aim_angle(self):
        pitch, yaw = calculate_aim_angle(
            from_pos=(0, 0, 0), from_rot=(0, 0, 0), to_pos=(0, 10, 0)
        )
        # aim at (0,10,0) → required yaw 90°, pitch 0°
        assert abs(yaw - 90.0) < 1e-1

    def test_moving_average(self):
        assert moving_average([1, 2, 3], 3) == 2.0

    def test_standard_deviation(self):
        assert standard_deviation([2, 2, 2]) == 0.0
        assert standard_deviation([0, 10]) > 0


# ============================================================
# AntiCheat Main Class Tests
# ============================================================

class TestAntiCheatInit:
    def test_valid_game_type(self, ac_fps):
        assert ac_fps.game_type == "fps"
        assert ac_fps.sensitivity == "medium"

    def test_invalid_game_type_raises(self):
        with pytest.raises(AntiCheatError):
            AntiCheat