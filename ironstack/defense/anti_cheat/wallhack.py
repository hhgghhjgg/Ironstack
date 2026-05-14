#!/usr/bin/env python3
"""
Wallhack Detector for IronStack Anti-Cheat.
Detects wallhack/ESP cheats by analyzing player vision and behavior through walls.
"""

import math
import time
from typing import Dict, Any, Optional, List, Tuple, Set
from collections import deque

from .base import (
    BaseAntiCheat,
    DetectionResult,
    PlayerState,
    calculate_distance,
    calculate_angle,
    moving_average,
    standard_deviation,
)

from ...logging_config import get_logger

logger = get_logger(__name__)


class WallhackDetector(BaseAntiCheat):
    """
    Detects wallhack and ESP (Extra Sensory Perception) cheats.
    
    Detection Methods:
    1. Wall Tracking - Tracking enemies through walls/obstacles
    2. Pre-aiming - Aiming at enemies before they become visible
    3. Pre-firing - Shooting before enemy is visible
    4. Vision Analysis - Analyzing if player can actually see target
    5. Behavior Patterns - Unnatural awareness of enemy positions
    6. Sound ESP - Tracking without line of sight or sound cues
    7. Radar Hack Detection - Detecting minimap/reveal hacks
    
    Attributes:
        sensitivity: Detection sensitivity level
        map_data: Optional map data for line-of-sight calculations
        vision_history: Player vision tracking history
        wall_bang_threshold: Maximum wall thickness for legit wallbangs
    """
    
    def __init__(
        self,
        sensitivity: str = "medium",
        history_size: int = 100,
        wall_bang_threshold: float = 2.0,  # Units (wall thickness)
        tracking_window: int = 50,
        pre_aim_window: float = 2.0,  # Seconds before visible
        suspicious_tracking_time: float = 5.0,  # Seconds of tracking through walls
    ):
        """
        Initialize Wallhack Detector.
        
        Args:
            sensitivity: Detection sensitivity
            history_size: Maximum actions to keep per player
            wall_bang_threshold: Max wall thickness for legitimate wallbangs
            tracking_window: Number of actions for tracking analysis
            pre_aim_window: Time window to detect pre-aiming
            suspicious_tracking_time: Time threshold for suspicious tracking
        """
        super().__init__(sensitivity=sensitivity, history_size=history_size)
        
        self.wall_bang_threshold = wall_bang_threshold
        self.tracking_window = tracking_window
        self.pre_aim_window = pre_aim_window
        self.suspicious_tracking_time = suspicious_tracking_time
        
        # Vision tracking
        self.vision_history: Dict[str, deque] = {}  # player_id -> deque of vision data
        self.visibility_events: Dict[str, List[Dict]] = {}  # player_id -> visibility change events
        
        # Map data (walls, obstacles)
        self.map_data: Optional[Dict[str, Any]] = None
        
        # Detection parameters
        self.params = {
            "max_wall_thickness": wall_bang_threshold,
            "max_tracking_through_wall_time": suspicious_tracking_time,
            "min_pre_aim_time": 0.5,  # Minimum pre-aim time to flag
            "suspicious_accuracy_through_wall": 0.3,  # 30% accuracy through walls
        }
        
        logger.info(f"WallhackDetector initialized (sensitivity: {sensitivity})")
    
    # ==========================================
    # Map Data Management
    # ==========================================
    
    def load_map_data(self, map_data: Dict[str, Any]):
        """
        Load map data for line-of-sight calculations.
        
        Args:
            map_data: Map geometry data with walls and obstacles
        """
        self.map_data = map_data
        logger.info("Map data loaded for wallhack detection")
    
    # ==========================================
    # Main Detection Method
    # ==========================================
    
    def detect(
        self,
        player_id: str,
        action_data: Dict[str, Any],
    ) -> DetectionResult:
        """
        Detect wallhack usage based on player action.
        
        Args:
            player_id: Player identifier
            action_data: Action data containing:
                - player_position: Player position (x, y, z)
                - player_rotation: Player rotation (pitch, yaw, roll)
                - target_id: Target player ID
                - target_position: Target position (x, y, z)
                - target_visible: Whether target is visible to player
                - shot_fired: Whether shot was fired
                - hit_target: Whether shot hit target
                - line_of_sight: Whether there's line of sight to target
                - obstacles: List of obstacles between player and target
                - timestamp: Action timestamp
                
        Returns:
            DetectionResult
        """
        self._stats["checks_performed"] += 1
        
        # Initialize tracking if needed
        if player_id not in self.vision_history:
            self.vision_history[player_id] = deque(maxlen=self.history_size)
            self.visibility_events[player_id] = []
        
        # Record vision data
        vision_data = {
            "player_position": action_data.get("player_position"),
            "player_rotation": action_data.get("player_rotation"),
            "target_id": action_data.get("target_id"),
            "target_position": action_data.get("target_position"),
            "target_visible": action_data.get("target_visible", True),
            "line_of_sight": action_data.get("line_of_sight", True),
            "obstacles": action_data.get("obstacles", []),
            "shot_fired": action_data.get("shot_fired", False),
            "hit_target": action_data.get("hit_target", False),
            "timestamp": time.time(),
        }
        
        self.vision_history[player_id].append(vision_data)
        self.record_action(player_id, action_data)
        
        # Track visibility changes
        if len(self.vision_history[player_id]) >= 2:
            previous = self.vision_history[player_id][-2]
            if previous["target_visible"] != vision_data["target_visible"]:
                self.visibility_events[player_id].append({
                    "became_visible": vision_data["target_visible"],
                    "timestamp": vision_data["timestamp"],
                    "target_id": vision_data["target_id"],
                })
        
        # Run all detection methods
        detections = []
        
        # 1. Wall tracking detection
        wall_track = self._detect_wall_tracking(player_id)
        if wall_track.cheat_detected:
            detections.append(wall_track)
        
        # 2. Pre-aim detection
        pre_aim = self._detect_pre_aim(player_id)
        if pre_aim.cheat_detected:
            detections.append(pre_aim)
        
        # 3. Pre-fire detection
        pre_fire = self._detect_pre_fire(player_id, vision_data)
        if pre_fire.cheat_detected:
            detections.append(pre_fire)
        
        # 4. Suspicious awareness detection
        awareness = self._detect_suspicious_awareness(player_id)
        if awareness.cheat_detected:
            detections.append(awareness)
        
        # 5. Wall bang analysis
        wall_bang = self._detect_wall_bang(player_id, vision_data)
        if wall_bang.cheat_detected:
            detections.append(wall_bang)
        
        # 6. Pattern analysis
        pattern = self._detect_esp_pattern(player_id)
        if pattern.cheat_detected:
            detections.append(pattern)
        
        # Combine results
        if detections:
            self._stats["cheats_detected"] += 1
            best_detection = max(detections, key=lambda d: d.confidence)
            
            if len(detections) > 1:
                best_detection.confidence = min(100, best_detection.confidence + 10 * len(detections))
                best_detection.reason += f" (+{len(detections)-1} other indicators)"
            
            return best_detection
        
        return DetectionResult(cheat_detected=False)
    
    # ==========================================
    # Detection Methods
    # ==========================================
    
    def _detect_wall_tracking(self, player_id: str) -> DetectionResult:
        """
        Detect tracking enemies through walls.
        
        Players with wallhack often track enemies through walls
        for extended periods without legitimate visual contact.
        """
        vision_history = self.vision_history.get(player_id, deque())
        
        if len(vision_history) < self.tracking_window:
            return DetectionResult()
        
        recent = list(vision_history)[-self.tracking_window:]
        
        # Count time spent tracking while target not visible
        tracking_through_wall_time = 0
        last_time = None
        
        for data in recent:
            if not data["target_visible"] and not data["line_of_sight"]:
                if data["target_id"] and data["target_position"]:
                    if last_time:
                        tracking_through_wall_time += data["timestamp"] - last_time
                    last_time = data["timestamp"]
        
        if tracking_through_wall_time > self.suspicious_tracking_time:
            confidence = min(100, (tracking_through_wall_time / 10) * 100)
            
            return DetectionResult(
                cheat_detected=True,
                cheat_type="wall_tracking",
                confidence=confidence,
                risk_increase=30,
                reason=f"Tracking through walls for {tracking_through_wall_time:.1f}s",
                evidence={
                    "tracking_time": tracking_through_wall_time,
                    "window": self.tracking_window,
                },
            )
        
        return DetectionResult()
    
    def _detect_pre_aim(self, player_id: str) -> DetectionResult:
        """
        Detect pre-aiming at enemies before they become visible.
        
        Wallhack users often aim at enemy positions before
        the enemy rounds a corner or becomes visible.
        """
        vision_history = self.vision_history.get(player_id, deque())
        
        if len(vision_history) < 10:
            return DetectionResult()
        
        recent = list(vision_history)
        
        pre_aim_events = 0
        total_visibility_changes = 0
        
        for i in range(1, len(recent)):
            current = recent[i]
            previous = recent[i - 1]
            
            # Target became visible
            if (not previous["target_visible"] and current["target_visible"]):
                total_visibility_changes += 1
                
                # Check if player was already aiming at target position
                if current["player_position"] and current["target_position"]:
                    # Check if aim was near target before visibility
                    aim_difference = self._calculate_aim_difference(current)
                    
                    if aim_difference < 5.0:  # Within 5 degrees
                        pre_aim_events += 1
        
        if total_visibility_changes > 0:
            pre_aim_ratio = pre_aim_events / total_visibility_changes
            
            if pre_aim_ratio > 0.7:  # 70% of visibility changes preceded by aim
                confidence = pre_aim_ratio * 100
                
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="pre_aiming",
                    confidence=confidence,
                    risk_increase=25,
                    reason=f"Pre-aiming detected ({pre_aim_events}/{total_visibility_changes} events)",
                    evidence={
                        "pre_aim_events": pre_aim_events,
                        "total_events": total_visibility_changes,
                        "ratio": pre_aim_ratio,
                    },
                )
        
        return DetectionResult()
    
    def _detect_pre_fire(
        self,
        player_id: str,
        current_data: Dict[str, Any],
    ) -> DetectionResult:
        """
        Detect firing before enemy is visible.
        
        Players with wallhack often start shooting before
        the enemy becomes visible, especially with sniper rifles.
        """
        if not current_data["shot_fired"]:
            return DetectionResult()
        
        # Shot fired while target not visible
        if not current_data["target_visible"] and current_data["hit_target"]:
            # Check obstacles
            obstacles = current_data.get("obstacles", [])
            
            if len(obstacles) > 0:
                total_thickness = sum(
                    obs.get("thickness", 0) for obs in obstacles
                )
                
                if total_thickness > self.wall_bang_threshold:
                    return DetectionResult(
                        cheat_detected=True,
                        cheat_type="pre_fire",
                        confidence=85,
                        risk_increase=30,
                        reason=f"Hit through {total_thickness:.1f}u wall without visibility",
                        evidence={
                            "wall_thickness": total_thickness,
                            "threshold": self.wall_bang_threshold,
                            "obstacles": obstacles,
                        },
                    )
                else:
                    # Legitimate wallbang
                    return DetectionResult()
            else:
                # Hit without visibility and no obstacles
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="pre_fire",
                    confidence=90,
                    risk_increase=35,
                    reason="Hit target without line of sight",
                    evidence={},
                )
        
        return DetectionResult()
    
    def _detect_suspicious_awareness(self, player_id: str) -> DetectionResult:
        """
        Detect suspicious awareness of enemy positions.
        
        Wallhack users show unnatural awareness:
        - Always facing nearest threat
        - Reacting to enemies they can't see/hear
        - Checking corners where enemies are hiding
        """
        vision_history = self.vision_history.get(player_id, deque())
        
        if len(vision_history) < 20:
            return DetectionResult()
        
        recent = list(vision_history)[-20:]
        
        # Count times player faces non-visible enemies
        suspicious_faces = 0
        total_non_visible = 0
        
        for data in recent:
            if not data["target_visible"] and data["target_position"] and data["player_position"]:
                total_non_visible += 1
                
                # Calculate if player is facing the enemy
                aim_diff = self._calculate_aim_difference(data)
                
                if aim_diff < 15.0:  # Within 15 degrees
                    suspicious_faces += 1
        
        if total_non_visible > 5:
            face_ratio = suspicious_faces / total_non_visible
            
            if face_ratio > 0.8:  # 80% of time facing non-visible enemies
                confidence = face_ratio * 80
                
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="suspicious_awareness",
                    confidence=confidence,
                    risk_increase=20,
                    reason=f"Unnatural awareness of non-visible enemies ({suspicious_faces}/{total_non_visible})",
                    evidence={
                        "suspicious_faces": suspicious_faces,
                        "total_non_visible": total_non_visible,
                        "ratio": face_ratio,
                    },
                )
        
        return DetectionResult()
    
    def _detect_wall_bang(
        self,
        player_id: str,
        current_data: Dict[str, Any],
    ) -> DetectionResult:
        """
        Analyze wall bang patterns.
        
        Legitimate wallbangs are occasional and through thin walls.
        Wallhack users have unnatural wallbang accuracy.
        """
        vision_history = self.vision_history.get(player_id, deque())
        
        if not current_data["shot_fired"] or not current_data["target_visible"]:
            return DetectionResult()
        
        # Count wallbangs in recent history
        recent = list(vision_history)[-50:]
        
        wall_bangs = []
        for data in recent:
            if (data["shot_fired"] and
                    not data["target_visible"] and
                    data["obstacles"]):
                wall_bangs.append(data)
        
        if len(wall_bangs) > 10:
            # Check accuracy of wallbangs
            hits = sum(1 for wb in wall_bangs if wb["hit_target"])
            accuracy = hits / len(wall_bangs)
            
            if accuracy > 0.5:  # 50% accuracy through walls is suspicious
                confidence = accuracy * 100
                
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="suspicious_wallbangs",
                    confidence=confidence,
                    risk_increase=20,
                    reason=f"High wallbang accuracy: {accuracy:.0%} ({hits}/{len(wall_bangs)})",
                    evidence={
                        "wallbangs": len(wall_bangs),
                        "hits": hits,
                        "accuracy": accuracy,
                    },
                )
        
        return DetectionResult()
    
    def _detect_esp_pattern(self, player_id: str) -> DetectionResult:
        """
        Detect ESP/reveal patterns.
        
        Analyzes overall behavior patterns that indicate
        the use of ESP or radar hacks.
        """
        vision_history = self.vision_history.get(player_id, deque())
        
        if len(vision_history) < 30:
            return DetectionResult()
        
        recent = list(vision_history)[-30:]
        
        # Pattern 1: Always knows where enemies are
        # (changes target direction instantly when new enemy appears)
        target_switches = 0
        instant_switches = 0
        
        for i in range(1, len(recent)):
            current = recent[i]
            previous = recent[i - 1]
            
            if (current["target_id"] and previous["target_id"] and
                    current["target_id"] != previous["target_id"]):
                target_switches += 1
                
                # Check if switch was instant (no scanning)
                time_diff = current["timestamp"] - previous["timestamp"]
                if time_diff < 0.1:  # 100ms
                    instant_switches += 1
        
        if target_switches > 5:
            instant_ratio = instant_switches / target_switches
            
            if instant_ratio > 0.7:
                confidence = instant_ratio * 90
                
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="esp_pattern",
                    confidence=confidence,
                    risk_increase=25,
                    reason=f"Instant target switching pattern ({instant_switches}/{target_switches})",
                    evidence={
                        "target_switches": target_switches,
                        "instant_switches": instant_switches,
                        "ratio": instant_ratio,
                    },
                )
        
        return DetectionResult()
    
    # ==========================================
    # Helper Methods
    # ==========================================
    
    def _calculate_aim_difference(self, data: Dict[str, Any]) -> float:
        """
        Calculate angle between player aim and target.
        
        Args:
            data: Vision data with player and target positions
            
        Returns:
            Angle difference in degrees
        """
        player_pos = data.get("player_position")
        target_pos = data.get("target_position")
        player_rot = data.get("player_rotation")
        
        if not all([player_pos, target_pos, player_rot]):
            return 180.0  # Maximum difference if data missing
        
        # Calculate required aim angle to target
        dx = target_pos[0] - player_pos[0]
        dy = target_pos[1] - player_pos[1]
        dz = target_pos[2] - player_pos[2]
        
        # Horizontal angle
        required_yaw = math.degrees(math.atan2(dy, dx))
        player_yaw = player_rot[1]
        
        # Vertical angle
        horizontal_dist = math.sqrt(dx*dx + dy*dy)
        required_pitch = -math.degrees(math.atan2(dz, horizontal_dist))
        player_pitch = player_rot[0]
        
        # Normalize angles
        def normalize(a):
            while a > 180: a -= 360
            while a < -180: a += 360
            return a
        
        yaw_diff = abs(normalize(required_yaw - player_yaw))
        pitch_diff = abs(normalize(required_pitch - player_pitch))
        
        return math.sqrt(yaw_diff**2 + pitch_diff**2)
    
    def _check_line_of_sight(
        self,
        pos1: Tuple[float, float, float],
        pos2: Tuple[float, float, float],
    ) -> Tuple[bool, List[Dict]]:
        """
        Check if there's line of sight between two positions.
        
        Args:
            pos1: First position
            pos2: Second position
            
        Returns:
            Tuple of (has_line_of_sight, obstacles_list)
        """
        if not self.map_data:
            return True, []
        
        # In a real implementation, this would do raycasting
        # through the map data to check for walls between positions
        obstacles = []
        
        # Placeholder: Simple distance-based check
        distance = calculate_distance(pos1, pos2)
        if distance > 100:
            obstacles.append({"type": "distance", "thickness": 0})
        
        has_los = len(obstacles) == 0
        return has_los, obstacles
    
    # ==========================================
    # Player Analysis
    # ==========================================
    
    def get_player_vision_profile(self, player_id: str) -> Dict[str, Any]:
        """
        Get vision analysis profile for a player.
        
        Args:
            player_id: Player identifier
            
        Returns:
            Dictionary with vision statistics
        """
        vision_history = self.vision_history.get(player_id, deque())
        
        if not vision_history:
            return {"error": "No data for player"}
        
        recent = list(vision_history)
        
        visible_time = sum(1 for v in recent if v["target_visible"])
        wall_bangs = sum(1 for v in recent if v["shot_fired"] and not v["target_visible"])
        
        return {
            "total_checks": len(recent),
            "visible_percentage": (visible_time / len(recent) * 100) if recent else 0,
            "wall_bangs": wall_bangs,
            "visibility_changes": len(self.visibility_events.get(player_id, [])),
        }
    
    # ==========================================
    # Reset
    # ==========================================
    
    def reset_player(self, player_id: str):
        """Reset tracking for a player."""
        super().remove_player(player_id)
        self.vision_history.pop(player_id, None)
        self.visibility_events.pop(player_id, None)
    
    def reset_all(self):
        """Reset all tracking data."""
        super().reset_stats()
        self.vision_history.clear()
        self.visibility_events.clear()
        logger.info("WallhackDetector reset")
