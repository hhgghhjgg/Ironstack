#!/usr/bin/env python3
"""
Base Anti-Cheat module for IronStack.
Provides the foundation for all cheat detectors.
"""

import time
import math
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from collections import deque

from ...logging_config import get_logger

logger = get_logger(__name__)


# ==========================================
# Data Classes
# ==========================================

@dataclass
class PlayerState:
    """Represents a player's current state."""
    player_id: str
    position: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    rotation: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    velocity: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    health: float = 100.0
    is_alive: bool = True
    team: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class AimState:
    """Represents aim-related data for a player."""
    player_id: str
    aim_angle_x: float = 0.0
    aim_angle_y: float = 0.0
    aim_speed: float = 0.0
    aim_acceleration: float = 0.0
    target_id: Optional[str] = None
    target_position: Optional[Tuple[float, float, float]] = None
    shot_fired: bool = False
    hit_target: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class DetectionResult:
    """Result of a cheat detection check."""
    cheat_detected: bool = False
    cheat_type: str = "none"
    confidence: float = 0.0  # 0-100
    risk_increase: float = 0.0  # How much to increase risk score
    reason: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


# ==========================================
# Utility Functions
# ==========================================

def calculate_distance(
    pos1: Tuple[float, float, float],
    pos2: Tuple[float, float, float],
) -> float:
    """Calculate Euclidean distance between two 3D points."""
    return math.sqrt(
        (pos1[0] - pos2[0]) ** 2 +
        (pos1[1] - pos2[1]) ** 2 +
        (pos1[2] - pos2[2]) ** 2
    )


def calculate_angle(
    pos1: Tuple[float, float, float],
    pos2: Tuple[float, float, float],
) -> float:
    """Calculate angle between two points in degrees."""
    dx = pos2[0] - pos1[0]
    dy = pos2[1] - pos1[1]
    dz = pos2[2] - pos1[2]
    
    horizontal_dist = math.sqrt(dx * dx + dy * dy)
    angle = math.atan2(dz, horizontal_dist)
    
    return math.degrees(angle)


def calculate_aim_angle(
    from_pos: Tuple[float, float, float],
    from_rot: Tuple[float, float, float],
    to_pos: Tuple[float, float, float],
) -> Tuple[float, float]:
    """
    Calculate the difference between current aim and required aim to hit target.
    
    Args:
        from_pos: Shooter position
        from_rot: Shooter rotation (pitch, yaw, roll)
        to_pos: Target position
        
    Returns:
        Tuple of (pitch_difference, yaw_difference) in degrees
    """
    # Calculate required rotation to aim at target
    dx = to_pos[0] - from_pos[0]
    dy = to_pos[1] - from_pos[1]
    dz = to_pos[2] - from_pos[2]
    
    # Required yaw (horizontal angle)
    required_yaw = math.degrees(math.atan2(dy, dx))
    
    # Required pitch (vertical angle)
    horizontal_dist = math.sqrt(dx * dx + dy * dy)
    required_pitch = -math.degrees(math.atan2(dz, horizontal_dist))
    
    # Normalize angles
    def normalize_angle(angle: float) -> float:
        while angle > 180:
            angle -= 360
        while angle < -180:
            angle += 360
        return angle
    
    pitch_diff = normalize_angle(required_pitch - from_rot[0])
    yaw_diff = normalize_angle(required_yaw - from_rot[1])
    
    return pitch_diff, yaw_diff


def moving_average(values: List[float], window: int = 5) -> float:
    """Calculate moving average of values."""
    if not values:
        return 0.0
    return sum(values[-window:]) / min(len(values), window)


def standard_deviation(values: List[float]) -> float:
    """Calculate standard deviation of values."""
    if len(values) < 2:
        return 0.0
    
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


# ==========================================
# Base Anti-Cheat Class
# ==========================================

class BaseAntiCheat(ABC):
    """
    Abstract base class for all anti-cheat detectors.
    
    Provides common functionality for player tracking,
    action history, and detection thresholds.
    
    Attributes:
        sensitivity: Detection sensitivity (low, medium, high)
        threshold: Detection threshold value
        history_size: Maximum actions to keep per player
        player_states: Dictionary of player states
        action_history: Dictionary of player action histories
    """
    
    def __init__(
        self,
        sensitivity: str = "medium",
        history_size: int = 100,
    ):
        """
        Initialize base anti-cheat detector.
        
        Args:
            sensitivity: Detection sensitivity (low, medium, high)
            history_size: Maximum actions to keep per player
        """
        self.sensitivity = sensitivity
        self.history_size = history_size
        
        # Set thresholds based on sensitivity
        self.threshold = self._get_sensitivity_threshold()
        
        # Player tracking
        self.player_states: Dict[str, PlayerState] = {}
        self.action_history: Dict[str, deque] = {}
        
        # Detection statistics
        self._stats = {
            "checks_performed": 0,
            "cheats_detected": 0,
            "false_positives": 0,
        }
        
        logger.info(
            f"BaseAntiCheat initialized (sensitivity: {sensitivity}, "
            f"threshold: {self.threshold})"
        )
    
    def _get_sensitivity_threshold(self) -> float:
        """
        Get threshold based on sensitivity level.
        
        Lower threshold = more sensitive (catches more, but more false positives)
        Higher threshold = less sensitive (catches fewer, but more accurate)
        
        Returns:
            Threshold value
        """
        thresholds = {
            "low": 0.9,     # Less sensitive, fewer false positives
            "medium": 0.7,  # Balanced
            "high": 0.5,    # More sensitive, more detections
            "max": 0.3,     # Maximum sensitivity
        }
        return thresholds.get(self.sensitivity, 0.7)
    
    # ==========================================
    # Player State Management
    # ==========================================
    
    def update_player_state(
        self,
        player_id: str,
        position: Optional[Tuple[float, float, float]] = None,
        rotation: Optional[Tuple[float, float, float]] = None,
        velocity: Optional[Tuple[float, float, float]] = None,
        **kwargs,
    ):
        """
        Update a player's state.
        
        Args:
            player_id: Player identifier
            position: Player position (x, y, z)
            rotation: Player rotation (pitch, yaw, roll)
            velocity: Player velocity (vx, vy, vz)
            **kwargs: Additional state data
        """
        if player_id not in self.player_states:
            self.player_states[player_id] = PlayerState(
                player_id=player_id,
            )
            self.action_history[player_id] = deque(maxlen=self.history_size)
        
        state = self.player_states[player_id]
        
        if position is not None:
            state.position = position
        if rotation is not None:
            state.rotation = rotation
        if velocity is not None:
            state.velocity = velocity
        
        state.timestamp = time.time()
        
        # Update additional attributes
        for key, value in kwargs.items():
            if hasattr(state, key):
                setattr(state, key, value)
    
    def get_player_state(self, player_id: str) -> Optional[PlayerState]:
        """Get a player's current state."""
        return self.player_states.get(player_id)
    
    def remove_player(self, player_id: str):
        """Remove a player from tracking."""
        self.player_states.pop(player_id, None)
        self.action_history.pop(player_id, None)
    
    # ==========================================
    # Action History
    # ==========================================
    
    def record_action(
        self,
        player_id: str,
        action_data: Dict[str, Any],
    ):
        """
        Record a player action.
        
        Args:
            player_id: Player identifier
            action_data: Action data
        """
        if player_id not in self.action_history:
            self.action_history[player_id] = deque(maxlen=self.history_size)
        
        action_data["_recorded_at"] = time.time()
        self.action_history[player_id].append(action_data)
    
    def get_player_history(self, player_id: str) -> List[Dict[str, Any]]:
        """Get a player's action history."""
        return list(self.action_history.get(player_id, []))
    
    def get_recent_actions(
        self,
        player_id: str,
        count: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get a player's most recent actions."""
        history = self.action_history.get(player_id, deque())
        return list(history)[-count:]
    
    # ==========================================
    # Statistical Analysis
    # ==========================================
    
    def analyze_pattern(
        self,
        player_id: str,
        key: str,
        window: int = 20,
    ) -> Dict[str, float]:
        """
        Analyze a pattern in player's action history.
        
        Args:
            player_id: Player identifier
            key: Key to analyze in action data
            window: Number of recent actions to analyze
            
        Returns:
            Dictionary with mean, std_dev, min, max
        """
        history = self.get_recent_actions(player_id, window)
        values = [h.get(key, 0) for h in history if key in h]
        
        if not values:
            return {"mean": 0, "std_dev": 0, "min": 0, "max": 0}
        
        return {
            "mean": sum(values) / len(values),
            "std_dev": standard_deviation(values),
            "min": min(values),
            "max": max(values),
        }
    
    def detect_anomaly(
        self,
        value: float,
        history_values: List[float],
        std_dev_threshold: float = 3.0,
    ) -> bool:
        """
        Detect if a value is anomalous compared to history.
        
        Args:
            value: Current value
            history_values: Historical values
            std_dev_threshold: Number of standard deviations for anomaly
            
        Returns:
            True if value is anomalous
        """
        if len(history_values) < 5:
            return False
        
        mean = sum(history_values) / len(history_values)
        std = standard_deviation(history_values)
        
        if std == 0:
            return False
        
        z_score = abs(value - mean) / std
        return z_score > std_dev_threshold
    
    # ==========================================
    # Abstract Methods
    # ==========================================
    
    @abstractmethod
    def detect(
        self,
        player_id: str,
        action_data: Dict[str, Any],
    ) -> DetectionResult:
        """
        Detect cheating based on player action.
        
        Must be implemented by all detector subclasses.
        
        Args:
            player_id: Player identifier
            action_data: Action data to analyze
            
        Returns:
            DetectionResult with detection details
        """
        pass
    
    # ==========================================
    # Statistics
    # ==========================================
    
    def get_stats(self) -> dict:
        """Get detector statistics."""
        return {
            **self._stats,
            "players_tracked": len(self.player_states),
            "sensitivity": self.sensitivity,
            "threshold": self.threshold,
        }
    
    def reset_stats(self):
        """Reset detector statistics."""
        self._stats = {
            "checks_performed": 0,
            "cheats_detected": 0,
            "false_positives": 0,
        }
    
    # ==========================================
    # Utility
    # ==========================================
    
    def _clamp_confidence(self, confidence: float) -> float:
        """Clamp confidence value between 0 and 100."""
        return max(0.0, min(100.0, confidence))
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(sensitivity='{self.sensitivity}')"
