#!/usr/bin/env python3
"""
Script Detector for IronStack Anti-Cheat.
Detects unauthorized scripts, macros, and automation in games.
"""

import math
import time
import re
from typing import Dict, Any, Optional, List, Tuple, Set
from collections import deque

from .base import (
    BaseAntiCheat,
    DetectionResult,
    PlayerState,
    moving_average,
    standard_deviation,
)

from ...logging_config import get_logger

logger = get_logger(__name__)


class ScriptDetector(BaseAntiCheat):
    """
    Detects unauthorized scripts, macros, and automation.
    
    Detection Methods:
    1. Macro Detection - Detects automated input patterns
    2. Script Pattern Detection - Identifies known script behaviors
    3. Input Timing Analysis - Analyzes input timing for automation
    4. Repetitive Action Detection - Detects bot-like repetitive actions
    5. Pixel Bot Detection - Identifies color-based aimbots
    6. AFK Bot Detection - Detects automated farming/grinding bots
    7. Chat Spam Detection - Identifies spam bots
    8. Trading Bot Detection - Detects automated trading
    
    Attributes:
        sensitivity: Detection sensitivity level
        input_history: Player input timing history
        action_patterns: Known script patterns database
        macro_signatures: Known macro signatures
    """
    
    def __init__(
        self,
        sensitivity: str = "medium",
        history_size: int = 200,
        macro_threshold: float = 0.95,  # Pattern similarity threshold
        input_timing_window: int = 100,
        repetitive_action_threshold: int = 50,
        afk_timeout: float = 300.0,  # 5 minutes
    ):
        """
        Initialize Script Detector.
        
        Args:
            sensitivity: Detection sensitivity
            history_size: Maximum actions to keep per player
            macro_threshold: Similarity threshold for macro detection
            input_timing_window: Number of inputs to analyze
            repetitive_action_threshold: Max similar actions before flag
            afk_timeout: Time before considering player AFK
        """
        super().__init__(sensitivity=sensitivity, history_size=history_size)
        
        self.macro_threshold = macro_threshold
        self.input_timing_window = input_timing_window
        self.repetitive_action_threshold = repetitive_action_threshold
        self.afk_timeout = afk_timeout
        
        # Input tracking
        self.input_history: Dict[str, deque] = {}  # player_id -> deque of input data
        self.action_sequences: Dict[str, deque] = {}  # player_id -> action sequences
        
        # Known script patterns
        self.script_patterns = self._load_script_patterns()
        
        # Known macro signatures
        self.macro_signatures = self._load_macro_signatures()
        
        # Pixel bot tracking
        self.pixel_bot_data: Dict[str, Dict] = {}
        
        # AFK tracking
        self.afk_tracking: Dict[str, Dict] = {}
        
        logger.info(f"ScriptDetector initialized (macro_threshold={macro_threshold})")
    
    # ==========================================
    # Pattern Database
    # ==========================================
    
    def _load_script_patterns(self) -> List[Dict]:
        """Load known script behavior patterns."""
        return [
            {
                "name": "perfect_recoil_control",
                "description": "Perfect recoil compensation pattern",
                "indicators": [
                    "consistent_vertical_pull",
                    "no_horizontal_deviation",
                    "exact_timing_between_bursts",
                ],
                "weight": 0.8,
            },
            {
                "name": "auto_bunny_hop",
                "description": "Automated bunny hopping",
                "indicators": [
                    "perfect_jump_timing",
                    "consistent_air_strafe",
                    "no_missed_jumps",
                ],
                "weight": 0.7,
            },
            {
                "name": "auto_clicker",
                "description": "Automated clicking",
                "indicators": [
                    "exact_click_intervals",
                    "no_click_variation",
                    "consistent_click_duration",
                ],
                "weight": 0.9,
            },
            {
                "name": "auto_farming",
                "description": "Automated resource farming",
                "indicators": [
                    "repetitive_path",
                    "exact_timing",
                    "no_breaks",
                    "24_7_activity",
                ],
                "weight": 0.85,
            },
            {
                "name": "pixel_bot",
                "description": "Color-based aimbot",
                "indicators": [
                    "snap_to_colors",
                    "ignore_invisible",
                    "perfect_tracking_colored",
                    "no_reaction_to_non_colored",
                ],
                "weight": 0.75,
            },
        ]
    
    def _load_macro_signatures(self) -> List[Dict]:
        """Load known macro timing signatures."""
        return [
            {
                "name": "perfect_timing",
                "description": "Actions with exactly equal intervals",
                "variance_threshold": 0.001,  # Almost zero variance
                "confidence": 95,
            },
            {
                "name": "looped_pattern",
                "description": "Repeating sequence of timed actions",
                "min_repetitions": 5,
                "confidence": 85,
            },
            {
                "name": "synchronized_actions",
                "description": "Multiple actions with synchronized timing",
                "sync_threshold": 0.01,
                "confidence": 80,
            },
        ]
    
    # ==========================================
    # Main Detection Method
    # ==========================================
    
    def detect(
        self,
        player_id: str,
        action_data: Dict[str, Any],
    ) -> DetectionResult:
        """
        Detect scripts/macros based on player action.
        
        Args:
            player_id: Player identifier
            action_data: Action data containing:
                - action_type: Type of action (click, keypress, move, etc.)
                - action_value: Action value/data
                - timestamp: Action timestamp
                - position: Player position (for movement analysis)
                - input_device: Input device used
                - action_duration: Duration of action
                
        Returns:
            DetectionResult
        """
        self._stats["checks_performed"] += 1
        
        # Initialize tracking
        if player_id not in self.input_history:
            self.input_history[player_id] = deque(maxlen=self.history_size)
            self.action_sequences[player_id] = deque(maxlen=self.history_size)
        
        # Record input
        input_data = {
            "action_type": action_data.get("action_type", "unknown"),
            "action_value": action_data.get("action_value"),
            "timestamp": time.time(),
            "position": action_data.get("position"),
            "input_device": action_data.get("input_device", "unknown"),
            "action_duration": action_data.get("action_duration", 0),
        }
        
        self.input_history[player_id].append(input_data)
        self.action_sequences[player_id].append(action_data)
        self.record_action(player_id, action_data)
        
        # Run detection methods
        detections = []
        
        # 1. Macro detection
        macro = self._detect_macro(player_id)
        if macro.cheat_detected:
            detections.append(macro)
        
        # 2. Script pattern detection
        script = self._detect_script_patterns(player_id)
        if script.cheat_detected:
            detections.append(script)
        
        # 3. Input timing analysis
        timing = self._detect_input_timing_anomaly(player_id)
        if timing.cheat_detected:
            detections.append(timing)
        
        # 4. Repetitive action detection
        repetitive = self._detect_repetitive_actions(player_id)
        if repetitive.cheat_detected:
            detections.append(repetitive)
        
        # 5. Auto-clicker detection
        autoclicker = self._detect_auto_clicker(player_id)
        if autoclicker.cheat_detected:
            detections.append(autoclicker)
        
        # 6. AFK bot detection
        afk_bot = self._detect_afk_bot(player_id)
        if afk_bot.cheat_detected:
            detections.append(afk_bot)
        
        # 7. Chat spam detection
        spam = self._detect_chat_spam(player_id, action_data)
        if spam.cheat_detected:
            detections.append(spam)
        
        # Combine results
        if detections:
            self._stats["cheats_detected"] += 1
            best_detection = max(detections, key=lambda d: d.confidence)
            
            if len(detections) > 1:
                best_detection.confidence = min(100, best_detection.confidence + 5 * len(detections))
                best_detection.reason += f" (+{len(detections)-1} other indicators)"
            
            return best_detection
        
        return DetectionResult(cheat_detected=False)
    
    # ==========================================
    # Detection Methods
    # ==========================================
    
    def _detect_macro(self, player_id: str) -> DetectionResult:
        """
        Detect macro usage by analyzing input timing patterns.
        
        Macros produce unnaturally consistent timing between actions.
        Humans have natural variation in timing.
        """
        input_history = self.input_history.get(player_id, deque())
        
        if len(input_history) < self.input_timing_window:
            return DetectionResult()
        
        recent = list(input_history)[-self.input_timing_window:]
        
        # Calculate time intervals between consecutive actions
        intervals = []
        for i in range(1, len(recent)):
            interval = recent[i]["timestamp"] - recent[i - 1]["timestamp"]
            if interval > 0 and interval < 10:  # Ignore long pauses and zero intervals
                intervals.append(interval)
        
        if len(intervals) < 20:
            return DetectionResult()
        
        # Calculate statistics
        mean_interval = sum(intervals) / len(intervals)
        std_interval = standard_deviation(intervals)
        
        # Coefficient of variation
        if mean_interval > 0:
            cv = std_interval / mean_interval
            
            # Macro detection thresholds
            if cv < 0.01:  # Extremely consistent (almost certainly a macro)
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="macro_detected",
                    confidence=95,
                    risk_increase=40,
                    reason=f"Perfect timing consistency (CV: {cv:.6f})",
                    evidence={
                        "coefficient_of_variation": cv,
                        "mean_interval_ms": mean_interval * 1000,
                        "sample_size": len(intervals),
                    },
                )
            
            if cv < 0.05:  # Very consistent (suspicious)
                confidence = (1 - cv / 0.1) * 80
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="suspicious_macro",
                    confidence=confidence,
                    risk_increase=25,
                    reason=f"Very consistent timing (CV: {cv:.4f})",
                    evidence={"coefficient_of_variation": cv},
                )
            
            # Check for exact interval patterns
            unique_intervals = len(set(round(i, 3) for i in intervals))
            if unique_intervals < len(intervals) * 0.1:  # Less than 10% unique intervals
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="looped_macro",
                    confidence=85,
                    risk_increase=30,
                    reason=f"Looped timing pattern ({unique_intervals} unique / {len(intervals)} total)",
                    evidence={
                        "unique_intervals": unique_intervals,
                        "total_intervals": len(intervals),
                    },
                )
        
        return DetectionResult()
    
    def _detect_script_patterns(self, player_id: str) -> DetectionResult:
        """
        Detect known script behavior patterns.
        
        Analyzes action sequences for patterns matching
        known cheat scripts.
        """
        action_history = self.action_sequences.get(player_id, deque())
        
        if len(action_history) < 30:
            return DetectionResult()
        
        recent = list(action_history)[-50:]
        
        matched_patterns = []
        
        for pattern in self.script_patterns:
            pattern_score = self._match_pattern(pattern, recent)
            if pattern_score > 0.6:
                matched_patterns.append({
                    "pattern": pattern["name"],
                    "score": pattern_score,
                    "weight": pattern["weight"],
                })
        
        if matched_patterns:
            # Calculate combined confidence
            best_match = max(matched_patterns, key=lambda m: m["score"] * m["weight"])
            confidence = best_match["score"] * best_match["weight"] * 100
            
            return DetectionResult(
                cheat_detected=True,
                cheat_type=f"script_pattern_{best_match['pattern']}",
                confidence=min(100, confidence),
                risk_increase=30,
                reason=f"Detected script pattern: {best_match['pattern']}",
                evidence={
                    "matched_patterns": matched_patterns,
                    "best_match": best_match,
                },
            )
        
        return DetectionResult()
    
    def _match_pattern(self, pattern: Dict, actions: List[Dict]) -> float:
        """
        Match actions against a known script pattern.
        
        Args:
            pattern: Pattern definition
            actions: Recent actions
            
        Returns:
            Match score (0-1)
        """
        indicators_matched = 0
        
        for indicator in pattern["indicators"]:
            if self._check_indicator(indicator, actions):
                indicators_matched += 1
        
        return indicators_matched / len(pattern["indicators"])
    
    def _check_indicator(self, indicator: str, actions: List[Dict]) -> bool:
        """
        Check if a specific indicator is present in actions.
        
        Args:
            indicator: Indicator name
            actions: Recent actions
            
        Returns:
            True if indicator is detected
        """
        if indicator == "consistent_vertical_pull":
            # Check for consistent downward mouse movement
            y_moves = [a.get("position", (0, 0))[1] for a in actions if a.get("position")]
            if len(y_moves) > 10:
                changes = [y_moves[i] - y_moves[i - 1] for i in range(1, len(y_moves))]
                positive_changes = sum(1 for c in changes if c > 0)
                return positive_changes / len(changes) > 0.8
        
        elif indicator == "exact_timing_between_bursts":
            # Check for exact timing between action bursts
            timestamps = [a.get("timestamp", 0) for a in actions]
            if len(timestamps) > 20:
                intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
                return standard_deviation(intervals) < 0.01
        
        elif indicator == "exact_click_intervals":
            clicks = [a for a in actions if a.get("action_type") == "click"]
            if len(clicks) > 10:
                click_times = [c["timestamp"] for c in clicks]
                intervals = [click_times[i] - click_times[i - 1] for i in range(1, len(click_times))]
                return standard_deviation(intervals) < 0.005
        
        elif indicator == "repetitive_path":
            positions = [a.get("position") for a in actions if a.get("position")]
            if len(positions) > 20:
                unique_positions = len(set(str(p) for p in positions))
                return unique_positions < len(positions) * 0.2
        
        elif indicator == "no_breaks":
            timestamps = [a.get("timestamp", 0) for a in actions]
            if len(timestamps) > 30:
                max_gap = max(
                    timestamps[i] - timestamps[i - 1]
                    for i in range(1, len(timestamps))
                )
                return max_gap < 5  # No gap longer than 5 seconds
        
        return False
    
    def _detect_input_timing_anomaly(self, player_id: str) -> DetectionResult:
        """
        Detect anomalous input timing.
        
        Analyzes input timing distribution for non-human patterns.
        """
        input_history = self.input_history.get(player_id, deque())
        
        if len(input_history) < 50:
            return DetectionResult()
        
        recent = list(input_history)[-50:]
        
        # Analyze per action type
        action_types = set(a["action_type"] for a in recent)
        
        for action_type in action_types:
            type_actions = [a for a in recent if a["action_type"] == action_type]
            
            if len(type_actions) < 15:
                continue
            
            # Check for exact timing
            timestamps = [a["timestamp"] for a in type_actions]
            intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            
            # Round intervals to 3 decimal places
            rounded = [round(i, 3) for i in intervals]
            
            # Check for exact duplicates
            from collections import Counter
            counts = Counter(rounded)
            most_common_count = counts.most_common(1)[0][1]
            
            if most_common_count > len(intervals) * 0.5:
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="exact_timing_pattern",
                    confidence=90,
                    risk_increase=35,
                    reason=f"Exact timing pattern in {action_type} actions",
                    evidence={
                        "action_type": action_type,
                        "most_common_count": most_common_count,
                        "total_intervals": len(intervals),
                    },
                )
        
        return DetectionResult()
    
    def _detect_repetitive_actions(self, player_id: str) -> DetectionResult:
        """
        Detect bot-like repetitive actions.
        
        Bots often repeat the exact same sequence of actions
        many times without variation.
        """
        action_history = self.action_sequences.get(player_id, deque())
        
        if len(action_history) < self.repetitive_action_threshold:
            return DetectionResult()
        
        recent = list(action_history)[-self.repetitive_action_threshold:]
        
        # Extract action sequence (simplified)
        action_sequence = []
        for action in recent:
            action_sequence.append({
                "type": action.get("action_type"),
                "value_hash": hash(str(action.get("action_value", ""))),
            })
        
        # Look for repeating sequences
        sequence_length = 5  # Look for 5-action sequences
        if len(action_sequence) < sequence_length * 3:
            return DetectionResult()
        
        sequences = []
        for i in range(len(action_sequence) - sequence_length + 1):
            seq = tuple(
                (a["type"], a["value_hash"])
                for a in action_sequence[i:i + sequence_length]
            )
            sequences.append(seq)
        
        # Count repetitions
        from collections import Counter
        seq_counts = Counter(sequences)
        most_common = seq_counts.most_common(1)[0]
        
        if most_common[1] > self.repetitive_action_threshold / 5:
            return DetectionResult(
                cheat_detected=True,
                cheat_type="repetitive_actions",
                confidence=min(100, most_common[1] * 5),
                risk_increase=25,
                reason=f"Repetitive action sequence ({most_common[1]} repetitions)",
                evidence={
                    "repetitions": most_common[1],
                    "sequence_length": sequence_length,
                },
            )
        
        return DetectionResult()
    
    def _detect_auto_clicker(self, player_id: str) -> DetectionResult:
        """
        Detect auto-clicker usage.
        
        Auto-clickers produce clicks with exact intervals
        and identical click durations.
        """
        input_history = self.input_history.get(player_id, deque())
        
        clicks = [
            a for a in input_history
            if a["action_type"] in ("click", "mouse_down", "mouse_up")
        ]
        
        if len(clicks) < 30:
            return DetectionResult()
        
        recent_clicks = list(clicks)[-30:]
        
        # Check click intervals
        click_times = [c["timestamp"] for c in recent_clicks]
        intervals = [click_times[i] - click_times[i - 1] for i in range(1, len(click_times))]
        
        if len(intervals) < 10:
            return DetectionResult()
        
        mean_interval = sum(intervals) / len(intervals)
        
        # Auto-clickers typically have intervals between 10ms and 100ms
        if 0.01 <= mean_interval <= 0.1:  # 10-100ms
            std_interval = standard_deviation(intervals)
            
            if std_interval < 0.001:  # Less than 1ms variation
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="auto_clicker",
                    confidence=95,
                    risk_increase=40,
                    reason=f"Auto-clicker detected ({mean_interval*1000:.0f}ms intervals, {std_interval*1000:.2f}ms std)",
                    evidence={
                        "mean_interval_ms": mean_interval * 1000,
                        "std_interval_ms": std_interval * 1000,
                        "click_count": len(intervals),
                    },
                )
        
        # Check click durations
        durations = [c.get("action_duration", 0) for c in recent_clicks if c.get("action_duration")]
        if len(durations) > 10:
            mean_duration = sum(durations) / len(durations)
            std_duration = standard_deviation(durations)
            
            if std_duration < 0.001 and mean_duration < 0.05:
                return DetectionResult(
                    cheat_detected=True,
                    cheat_type="auto_clicker",
                    confidence=85,
                    risk_increase=30,
                    reason="Identical click durations detected",
                    evidence={"mean_duration_ms": mean_duration * 1000},
                )
        
        return DetectionResult()
    
    def _detect_afk_bot(self, player_id: str) -> DetectionResult:
        """
        Detect AFK farming/grinding bots.
        
        AFK bots run for extended periods with repetitive actions
        and no breaks.
        """
        action_history = self.action_sequences.get(player_id, deque())
        
        if len(action_history) < 100:
            return DetectionResult()
        
        recent = list(action_history)
        
        # Check total active time
        if len(recent) > 0:
            first_time = recent[0].get("timestamp", 0)
            last_time = recent[-1].get("timestamp", 0)
            active_duration = last_time - first_time
            
            # If active for very long with no significant breaks
            if active_duration > self.afk_timeout * 2:  # 10+ minutes
                # Check for breaks
                breaks = 0
                for i in range(1, len(recent)):
                    gap = recent[i].get("timestamp", 0) - recent[i - 1].get("timestamp", 0)
                    if gap > 30:  # 30 second break
                        breaks += 1
                
                if breaks < active_duration / 600:  # Less than 1 break per 10 minutes
                    # Check action variety
                    action_types = set(a.get("action_type") for a in recent)
                    
                    if len(action_types) < 5:  # Very limited action variety
                        return DetectionResult(
                            cheat_detected=True,
                            cheat_type="afk_bot",
                            confidence=80,
                            risk_increase=25,
                            reason=f"AFK bot pattern (active: {active_duration/60:.0f}min, breaks: {breaks})",
                            evidence={
                                "active_minutes": active_duration / 60,
                                "breaks": breaks,
                                "action_variety": len(action_types),
                            },
                        )
        
        return DetectionResult()
    
    def _detect_chat_spam(
        self,
        player_id: str,
        action_data: Dict[str, Any],
    ) -> DetectionResult:
        """
        Detect chat spam bots.
        
        Spam bots send repeated messages at high frequency
        with identical or template-based content.
        """
        if action_data.get("action_type") != "chat_message":
            return DetectionResult()
        
        chat_history = [
            a for a in self.action_sequences.get(player_id, deque())
            if a.get("action_type") == "chat_message"
        ]
        
        if len(chat_history) < 10:
            return DetectionResult()
        
        recent_chat = list(chat_history)[-20:]
        
        # Check message frequency
        if len(recent_chat) > 0:
            first_time = recent_chat[0].get("timestamp", 0)
            last_time = recent_chat[-1].get("timestamp", 0)
            duration = last_time - first_time
            
            if duration > 0:
                messages_per_second = len(recent_chat) / duration
                
                if messages_per_second > 2:  # More than 2 messages per second
                    # Check for duplicate messages
                    messages = [c.get("action_value", "") for c in recent_chat]
                    unique_messages = len(set(messages))
                    
                    if unique_messages < len(messages) * 0.3:  # 70%+ duplicates
                        return DetectionResult(
                            cheat_detected=True,
                            cheat_type="chat_spam_bot",
                            confidence=90,
                            risk_increase=20,
                            reason=f"Chat spam detected ({messages_per_second:.1f} msg/s, {unique_messages} unique)",
                            evidence={
                                "messages_per_second": messages_per_second,
                                "unique_messages": unique_messages,
                                "total_messages": len(recent_chat),
                            },
                        )
        
        return DetectionResult()
    
    # ==========================================
    # Script Pattern Management
    # ==========================================
    
    def add_script_pattern(self, pattern: Dict):
        """Add a custom script pattern."""
        self.script_patterns.append(pattern)
        logger.info(f"Added script pattern: {pattern.get('name', 'unnamed')}")
    
    def add_macro_signature(self, signature: Dict):
        """Add a custom macro signature."""
        self.macro_signatures.append(signature)
        logger.info(f"Added macro signature: {signature.get('name', 'unnamed')}")
    
    # ==========================================
    # Player Analysis
    # ==========================================
    
    def get_player_input_profile(self, player_id: str) -> Dict[str, Any]:
        """
        Get input analysis profile for a player.
        
        Args:
            player_id: Player identifier
            
        Returns:
            Dictionary with input statistics
        """
        input_history = self.input_history.get(player_id, deque())
        
        if not input_history:
            return {"error": "No data for player"}
        
        recent = list(input_history)
        
        action_counts = {}
        for action in recent:
            action_type = action["action_type"]
            action_counts[action_type] = action_counts.get(action_type, 0) + 1
        
        # Calculate timing stats
        timestamps = [a["timestamp"] for a in recent]
        if len(timestamps) > 1:
            intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            mean_interval = sum(intervals) / len(intervals)
            std_interval = standard_deviation(intervals)
        else:
            mean_interval = 0
            std_interval = 0
        
        return {
            "total_actions": len(recent),
            "action_types": action_counts,
            "mean_interval_ms": mean_interval * 1000,
            "std_interval_ms": std_interval * 1000,
            "coefficient_of_variation": std_interval / mean_interval if mean_interval > 0 else 0,
        }
    
    # ==========================================
    # Reset
    # ==========================================
    
    def reset_player(self, player_id: str):
        """Reset tracking for a player."""
        super().remove_player(player_id)
        self.input_history.pop(player_id, None)
        self.action_sequences.pop(player_id, None)
        self.pixel_bot_data.pop(player_id, None)
        self.afk_tracking.pop(player_id, None)
    
    def reset_all(self):
        """Reset all tracking data."""
        super().reset_stats()
        self.input_history.clear()
        self.action_sequences.clear()
        self.pixel_bot_data.clear()
        self.afk_tracking.clear()
        logger.info("ScriptDetector reset")
