#!/usr/bin/env python3
"""
Aimbot Detector for IronStack Anti-Cheat.
Detects various aimbot patterns in FPS/TPS games.
"""

import math
import time
from typing import Dict, Any, Optional, List, Tuple
from collections import deque

from .base import (
    BaseAntiCheat,
    DetectionResult,
    PlayerState,
    AimState,
    calculate_distance,
    calculate_aim_angle,
    moving_average,
    standard_deviation,
)

from ...logging_config import get_logger

logger = get_logger(__name__)


class AimbotDetector(BaseAntiCheat):
    """
    Detects aimbot cheats by analyzing player aiming patterns.
    
    Detection Methods:
    1. Snap Aiming - Instantaneous aim changes to target
    2. Perfect Tracking - Unnaturally smooth target tracking
    3. Aim Locking - Aim stays locked on target through walls/obstacles
    4. Angle Snapping - Aim snaps to specific angles (common in simple aimbots)
    5. Reaction Time - Unnaturally fast target acquisition
    6. FOV Analysis - Aims outside normal field of view
    7. Recoil Compensation - Perfect recoil control patterns
    
    Attributes:
        sensitivity: Detection sensitivity level
        aim_states: Dictionary of player aim states
        snap_detection_threshold: Minimum angle change for snap detection
        tracking_smoothness_threshold: Maximum smoothness for tracking detection
    """
    
    def __init__(
        self,
        sensitivity: str = "medium",
        history_size: int = 100,
        snap_threshold: float = 15.0,  # Degrees
        tracking_window: int = 30,
        reaction_time_min: float = 0.05,  # Seconds (too fast = suspicious)
        fov_max: float = 180.0,  # Degrees
    ):
        """
        Initialize Aimbot Detector.
        
        Args:
            sensitivity: Detection sensitivity
            history_size: Maximum actions to keep per player
            snap_threshold: Minimum angle change to flag as snap
            tracking_window: Window size for tracking analysis
            reaction_time_min: Minimum human reaction time
            fov_max: Maximum field of view
        """
        super().__init__(sensitivity=sensitivity, history_size=history_size)
        
        self.snap_threshold = snap_threshold
        self.tracking_window = tracking_window
        self.reaction_time_min = reaction_time_min
        self.fov_max = fov_max
        
        # Aim state tracking
        self.aim_states: Dict[str, deque] = {}  # player_id -> deque of AimState
        
        # Detection parameters
        self.params = {
            "snap_angle_threshold": snap_threshold,
            "max_tracking_smoothness": 0.95,  # Correlation coefficient threshold
            "max_reaction_time": reaction_time_min,
            "max_fov": fov_max,
            "recoil_pattern_variance": 0.1,
        }
        
        logger.info(f"AimbotDetector initialized (snap_threshold={snap_threshold}°)")
    
    # ==========================================
    # Main Detection Method
    # ==========================================
    
    def detect(
        self,
        player_id: str,
        action_data: Dict[str, Any],
    ) -> DetectionResult:
        """
        Detect aimbot usage based on player action.
        
        Args:
            player_id: Player identifier
            action_data: Action data containing:
                - aim_angle_x: Current aim X angle
                - aim_angle_y: Current aim Y angle
                - aim_speed: Aim movement speed
                - target_position: Target position (x, y, z)
                - player_position: Player position (x, y, z)
                - shot_fired: Whether shot was fired
                - hit_target: Whether shot hit target
                - target_id: Target player ID
                - timestamp: Action timestamp
                
        Returns:
            DetectionResult
        """
        self._stats["checks_performed"] += 1
        
        # Initialize tracking if needed
        if player_id not in self.aim_states:
            self.aim_states[player_id] = deque(maxlen=self.history_size)
        
        # Create aim state from action data
        aim_state = AimState(
            player_id=player_id,
            aim_angle_x=action_data.get("aim_angle_x", 0),
            aim_angle_y=action_data.get("aim_angle_y", 0),
            aim_speed=action_data.get("aim_speed", 0),
            aim_acceleration=action_data.get("aim_acceleration", 0),
            target_id=action_data.get("target_id"),
            target_position=action_data.get("target_position"),
            shot_fired=action_data.get("shot_fired", False),
            hit_target=action_data.get("hit_target", False),
        )
        
        self.aim_states[player_id].append(aim_state)
        
        # Record action for history
        self.record_action(player_id, action_data)
        
        # Run all detection methods
        detections = []
        
        # 1. Snap aim detection
        snap_result = self._detect_snap_aim(player_id, aim_state)
        if snap_result.cheat_detected:
            detections.append(snap_result)
        
        # 2. Perfect tracking detection
        tracking_result = self._detect_perfect_tracking(player_id)
        if tracking_result.cheat_detected:
            detections.append(tracking_result)
        
        # 3. Aim lock detection
        lock_result = self._detect_aim_lock(player_id, aim_state)
        if lock_result.cheat_detected:
            detections.append(lock_result)
        
        # 4. Reaction time detection
        reaction_result = self._detect_unnatural_reaction(player_id, aim_state)
        if reaction_result.cheat_detected:
            detections.append(reaction_result)
        
        # 5. FOV violation detection
        fov_result = self._detect_fov_violation(player_id, aim_state, action_data)
        if fov_result.cheat_detected:
            detections.append(fov_result)
        
        # 6. Recoil pattern detection
        recoil_result = self._detect_recoil_pattern(player_id)
        if recoil_result.cheat_detected:
            detections.append(recoil_result)
        
        # Combine results
        if detections:
            self._stats["cheats_detected"] += 1
            
            # Use the highest confidence detection
            best_detection = max(detections, key=lambda d: d.confidence)
            
            # Increase confidence if multiple detectors triggered
            if len(detections) > 1:
                best_detection.confidence = min(100, best_detection.confidence + 10 * len(detections))
                best_detection.reason += f" (+{len(detections)-1} other detectors)"
            
            return best_detection
        
        return DetectionResult(cheat_detected=False)
    
    # ==========================================
    # Detection Methods
    # ==========================================
    
    def _detect_snap_aim(
        self,
        player_id: str,
        current_aim: AimState,
    ) -> DetectionResult:
        """
        Detect snap aiming - instantaneous large angle changes.
        
        Real players move their aim smoothly. Aimbots often snap
        directly to targets in a single frame.
        """
        aim_history = self.aim_states.get(player_id, deque())
        
        if len(aim_history) < 2:
            return DetectionResult()
        
        previous_aim = aim_history[-2]
        
        # Calculate angle change
        angle_change_x = abs(current_aim.aim_angle_x - previous_aim.aim_angle_x)
        angle_change_y = abs(current_aim.aim_angle_y - previous_aim.aim_angle_y)
        total_change = math.sqrt(angle_change_x**2 + angle_change_y**2)
        
        # Calculate time delta
        time_delta = current_aim.timestamp - previous_aim.timestamp
        if time_delta <= 0:
            return DetectionResult()
        
        # Calculate angular velocity
        angular_velocity = total_change / time_delta
        
        # Human limits
        # Pro players can achieve ~200-300 degrees/sec in flicks
        # Aimbots can achieve 1000+ degrees/sec
        human_max_velocity = 400  # degrees per second
        
        # Check for snap
        if total_change > self.snap_threshold:
            if angular_velocity > human_max_velocity * 2:
                confidence = min(100, (angular_velocity / human_max_velocity) * 50)
                
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="snap_aim",
                    confidence=confidence,
                    risk_increase=30,
                    reason=f"Snap aim detected: {total_change:.1f}° in {time_delta*1000:.0f}ms ({angular_velocity:.0f}°/s)",
                    evidence={
                        "angle_change": total_change,
                        "time_delta": time_delta,
                        "angular_velocity": angular_velocity,
                        "human_max": human_max_velocity,
                    },
                )
            
            # Check for suspicious speed
            if angular_velocity > human_max_velocity:
                confidence = min(100, (angular_velocity / human_max_velocity) * 30)
                
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="suspicious_aim_speed",
                    confidence=confidence,
                    risk_increase=15,
                    reason=f"Suspicious aim speed: {angular_velocity:.0f}°/s",
                    evidence={"angular_velocity": angular_velocity},
                )
        
        return DetectionResult()
    
    def _detect_perfect_tracking(
        self,
        player_id: str,
    ) -> DetectionResult:
        """
        Detect perfect target tracking.
        
        Aimbots can track targets with unnatural smoothness.
        Human aim has natural micro-jitters and variations.
        """
        aim_history = self.aim_states.get(player_id, deque())
        
        if len(aim_history) < self.tracking_window:
            return DetectionResult()
        
        recent = list(aim_history)[-self.tracking_window:]
        
        # Analyze aim speed consistency
        speeds = [a.aim_speed for a in recent if a.aim_speed > 0]
        
        if len(speeds) < 10:
            return DetectionResult()
        
        # Calculate coefficient of variation (CV)
        mean_speed = sum(speeds) / len(speeds)
        if mean_speed == 0:
            return DetectionResult()
        
        std_speed = standard_deviation(speeds)
        cv = std_speed / mean_speed  # Lower CV = more consistent
        
        # Human aim has CV of 0.3-0.8
        # Aimbot tracking has CV < 0.1
        
        if cv < 0.08:
            confidence = (1 - cv / 0.3) * 100
            confidence = min(100, max(0, confidence))
            
            return DetectionResult(
                cheat_detected=True,
                cheat_type="perfect_tracking",
                confidence=confidence,
                risk_increase=25,
                reason=f"Unnaturally smooth tracking (CV: {cv:.4f})",
                evidence={
                    "coefficient_of_variation": cv,
                    "sample_size": len(speeds),
                    "mean_speed": mean_speed,
                },
            )
        
        if cv < 0.15:
            confidence = (1 - cv / 0.3) * 60
            confidence = min(100, max(0, confidence))
            
            return DetectionResult(
                cheat_detected=True,
                cheat_type="suspicious_tracking",
                confidence=confidence,
                risk_increase=10,
                reason=f"Very smooth tracking (CV: {cv:.4f})",
                evidence={"coefficient_of_variation": cv},
            )
        
        return DetectionResult()
    
    def _detect_aim_lock(
        self,
        player_id: str,
        current_aim: AimState,
    ) -> DetectionResult:
        """
        Detect aim locking - aim stays on target regardless of obstacles.
        
        Checks if player maintains perfect aim on target through walls
        or after target position changes rapidly.
        """
        aim_history = self.aim_states.get(player_id, deque())
        
        if len(aim_history) < 5:
            return DetectionResult()
        
        if not current_aim.target_position:
            return DetectionResult()
        
        # Check if aim is perfectly on target
        recent = list(aim_history)[-5:]
        
        perfect_aims = 0
        for aim in recent:
            if aim.target_position:
                # Calculate angle to target
                # Perfect aim means angle difference is nearly 0
                if abs(aim.aim_angle_x) < 0.1 and abs(aim.aim_angle_y) < 0.1:
                    perfect_aims += 1
        
        if perfect_aims >= 4:  # 4 out of 5 perfect aims
            return DetectionResult(
                cheat_detected=True,
                cheat_type="aim_lock",
                confidence=80,
                risk_increase=35,
                reason=f"Aim locked on target ({perfect_aims}/5 perfect aims)",
                evidence={
                    "perfect_aims": perfect_aims,
                    "total_checked": 5,
                },
            )
        
        return DetectionResult()
    
    def _detect_unnatural_reaction(
        self,
        player_id: str,
        current_aim: AimState,
    ) -> DetectionResult:
        """
        Detect unnaturally fast reaction times.
        
        Human reaction time is typically 150-250ms.
        Aimbots can react in <10ms.
        """
        aim_history = self.aim_states.get(player_id, deque())
        
        if len(aim_history) < 3:
            return DetectionResult()
        
        # Find when target changed and when aim adjusted
        for i in range(len(aim_history) - 1, 0, -1):
            current = aim_history[i]
            previous = aim_history[i - 1]
            
            # Target ID changed (new target appeared)
            if (current.target_id and previous.target_id and
                    current.target_id != previous.target_id):
                
                # Time to acquire new target
                acquisition_time = current.timestamp - previous.timestamp
                
                # Check if unrealistically fast
                if acquisition_time < self.reaction_time_min:
                    confidence = (1 - acquisition_time / self.reaction_time_min) * 80
                    
                    return DetectionResult(
                        cheat_detected=True,
                        cheat_type="unnatural_reaction",
                        confidence=confidence,
                        risk_increase=20,
                        reason=f"Reaction time too fast: {acquisition_time*1000:.1f}ms",
                        evidence={
                            "reaction_time_ms": acquisition_time * 1000,
                            "human_min_ms": self.reaction_time_min * 1000,
                        },
                    )
        
        return DetectionResult()
    
    def _detect_fov_violation(
        self,
        player_id: str,
        current_aim: AimState,
        action_data: Dict[str, Any],
    ) -> DetectionResult:
        """
        Detect aiming outside normal field of view.
        
        Some aimbots can aim at targets behind the player
        or outside the normal FOV range.
        """
        player_state = self.get_player_state(player_id)
        
        if not player_state:
            return DetectionResult()
        
        if not current_aim.target_position:
            return DetectionResult()
        
        # Calculate angle between player's forward vector and target
        player_pos = player_state.position
        player_rot = player_state.rotation
        target_pos = current_aim.target_position
        
        # Simplified FOV check
        # In a real implementation, this would use proper vector math
        dx = target_pos[0] - player_pos[0]
        dy = target_pos[1] - player_pos[1]
        
        # Calculate horizontal angle to target
        angle_to_target = math.degrees(math.atan2(dy, dx))
        
        # Calculate player's facing direction from rotation
        player_yaw = player_rot[1]  # Horizontal rotation
        
        # Normalize angle difference
        angle_diff = abs(angle_to_target - player_yaw)
        while angle_diff > 180:
            angle_diff = 360 - angle_diff
        
        # Check if target is outside normal FOV
        if angle_diff > 120:  # Beyond 120 degrees (normal FOV is ~90)
            return DetectionResult(
                cheat_detected=True,
                cheat_type="fov_violation",
                confidence=min(100, angle_diff),
                risk_increase=25,
                reason=f"Aiming outside FOV: {angle_diff:.1f}°",
                evidence={
                    "angle_diff": angle_diff,
                    "fov_max": self.fov_max,
                },
            )
        
        return DetectionResult()
    
    def _detect_recoil_pattern(
        self,
        player_id: str,
    ) -> DetectionResult:
        """
        Detect perfect recoil compensation.
        
        Recoil patterns have randomness. Aimbots often
        compensate perfectly without variation.
        """
        aim_history = self.aim_states.get(player_id, deque())
        
        if len(aim_history) < 10:
            return DetectionResult()
        
        # Get aim movements during shooting
        shooting_aims = [
            a for a in aim_history
            if a.shot_fired and a.aim_speed > 0
        ]
        
        if len(shooting_aims) < 8:
            return DetectionResult()
        
        # Analyze vertical recoil compensation
        # Real players have varying compensation
        # Aimbots have near-perfect compensation
        
        y_movements = [a.aim_angle_y for a in shooting_aims]
        y_variance = standard_deviation(y_movements)
        
        if y_variance < 0.05:  # Very consistent recoil control
            confidence = (1 - y_variance / 0.5) * 90
            
            return DetectionResult(
                cheat_detected=True,
                cheat_type="perfect_recoil_control",
                confidence=confidence,
                risk_increase=20,
                reason=f"Perfect recoil compensation (variance: {y_variance:.4f})",
                evidence={
                    "recoil_variance": y_variance,
                    "shots_analyzed": len(shooting_aims),
                },
            )
        
        return DetectionResult()
    
    # ==========================================
    # Player-Specific Analysis
    # ==========================================
    
    def get_aim_profile(self, player_id: str) -> Dict[str, Any]:
        """
        Get aim profile for a player.
        
        Args:
            player_id: Player identifier
            
        Returns:
            Dictionary with aim statistics
        """
        aim_history = self.aim_states.get(player_id, deque())
        
        if not aim_history:
            return {"error": "No data for player"}
        
        recent = list(aim_history)
        
        speeds = [a.aim_speed for a in recent if a.aim_speed > 0]
        shots = [a for a in recent if a.shot_fired]
        hits = [a for a in shots if a.hit_target]
        
        return {
            "total_actions": len(recent),
            "average_aim_speed": sum(speeds) / len(speeds) if speeds else 0,
            "max_aim_speed": max(speeds) if speeds else 0,
            "total_shots": len(shots),
            "total_hits": len(hits),
            "accuracy": (len(hits) / len(shots) * 100) if shots else 0,
        }
    
    # ==========================================
    # Reset
    # ==========================================
    
    def reset_player(self, player_id: str):
        """Reset tracking for a player."""
        super().remove_player(player_id)
        self.aim_states.pop(player_id, None)
    
    def reset_all(self):
        """Reset all tracking data."""
        super().reset_stats()
        self.aim_states.clear()
        logger.info("AimbotDetector reset")
