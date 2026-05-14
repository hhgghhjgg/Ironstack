#!/usr/bin/env python3
"""
IronStack Anti-Cheat Module
============================
Game anti-cheat system for detecting and preventing cheating in games.

This module provides multiple detection engines for various types of cheats:
- Aimbot detection
- Wallhack detection
- Unauthorized scripts/macros detection
- Speedhack detection
- Memory manipulation detection

Usage:
    from ironstack.defense.anti_cheat import AntiCheat
    
    # Initialize for FPS game
    ac = AntiCheat(game_type="fps")
    ac.enable_detector("aimbot")
    ac.enable_detector("wallhack")
    
    # Check player action
    result = ac.check_player_action(player_id="player123", action_data={...})
    
    # Get report
    report = ac.get_report()
"""

# ==========================================
# Public API - Classes
# ==========================================

from .base import BaseAntiCheat
from .aimbot import AimbotDetector
from .wallhack import WallhackDetector
from .scripts import ScriptDetector

# ==========================================
# Public API - Exceptions
# ==========================================

from ..exceptions import (
    AntiCheatError,
    CheatDetectedError,
)

# ==========================================
# Detector Registry
# ==========================================

AVAILABLE_DETECTORS = {
    "aimbot": {
        "class": "AimbotDetector",
        "description": "Detects aimbot patterns including snap aiming, tracking, and aim locking",
        "game_types": ["fps", "tps", "shooter"],
    },
    "wallhack": {
        "class": "WallhackDetector",
        "description": "Detects wallhack/ESP by analyzing player vision through walls",
        "game_types": ["fps", "tps", "shooter", "battle_royale"],
    },
    "scripts": {
        "class": "ScriptDetector",
        "description": "Detects unauthorized scripts, macros, and automation",
        "game_types": ["all"],
    },
}

# ==========================================
# Main AntiCheat Class
# ==========================================

class AntiCheat:
    """
    Main Anti-Cheat system for IronStack.
    
    Manages multiple cheat detectors and provides a unified interface
    for cheat detection in games.
    
    Attributes:
        game_type: Type of game (fps, rts, chess, etc.)
        detectors: Dictionary of active detectors
        config: Anti-cheat configuration
    
    Basic Usage:
        >>> from ironstack.defense import AntiCheat
        >>> ac = AntiCheat(game_type="fps")
        >>> ac.enable_all()
        >>> result = ac.check_player("player1", action_data)
        >>> print(result["cheat_detected"])
        False
    
    Advanced Usage:
        >>> ac = AntiCheat(
        ...     game_type="fps",
        ...     sensitivity="high",
        ...     auto_ban=True,
        ... )
        >>> ac.enable_detector("aimbot", sensitivity="max")
        >>> ac.enable_detector("wallhack")
        >>> report = ac.get_report()
    """
    
    def __init__(
        self,
        game_type: str = "fps",
        sensitivity: str = "medium",
        auto_ban: bool = False,
        ban_duration: int = 86400,  # 24 hours
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize Anti-Cheat system.
        
        Args:
            game_type: Type of game (fps, rts, chess, auto)
            sensitivity: Detection sensitivity (low, medium, high)
            auto_ban: Automatically ban detected cheaters
            ban_duration: Ban duration in seconds
            config: Additional configuration
        
        Raises:
            AntiCheatError: If game_type is not supported
        """
        # Validate game type
        valid_types = ["fps", "tps", "shooter", "rts", "chess", "battle_royale", "auto", "all"]
        if game_type not in valid_types:
            raise AntiCheatError(
                f"Invalid game type: {game_type}. Must be one of: {', '.join(valid_types)}"
            )
        
        self.game_type = game_type
        self.sensitivity = sensitivity
        self.auto_ban = auto_ban
        self.ban_duration = ban_duration
        
        # Configuration
        self.config = {
            "log_suspicious": True,
            "report_path": None,
            "max_reports_before_ban": 5,
            "evidence_collection": True,
        }
        
        if config:
            self._deep_merge(self.config, config)
        
        # Initialize detectors
        self.detectors = {}
        
        # Player tracking
        self._players = {}  # player_id -> {reports, actions, risk_score}
        self._banned_players = {}  # player_id -> {ban_time, reason, evidence}
        self._suspicious_actions = []  # List of suspicious actions
        
        # Statistics
        self._stats = {
            "players_tracked": 0,
            "actions_checked": 0,
            "cheats_detected": 0,
            "players_banned": 0,
            "false_positives": 0,
        }
        
        logger.info(f"🎮 AntiCheat initialized for {game_type} (sensitivity: {sensitivity})")
    
    def _deep_merge(self, base: dict, override: dict):
        """Deep merge two dictionaries."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    # ==========================================
    # Detector Management
    # ==========================================
    
    def enable_detector(self, detector_name: str, **kwargs) -> bool:
        """
        Enable a specific cheat detector.
        
        Args:
            detector_name: Name of detector (aimbot, wallhack, scripts)
            **kwargs: Additional detector configuration
            
        Returns:
            True if detector was enabled
            
        Raises:
            AntiCheatError: If detector is not available
        """
        if detector_name not in AVAILABLE_DETECTORS:
            raise AntiCheatError(
                f"Unknown detector: {detector_name}. "
                f"Available: {', '.join(AVAILABLE_DETECTORS.keys())}"
            )
        
        detector_info = AVAILABLE_DETECTORS[detector_name]
        
        # Check game type compatibility
        if self.game_type not in detector_info["game_types"] and "all" not in detector_info["game_types"]:
            logger.warning(
                f"Detector '{detector_name}' may not be optimal for game type '{self.game_type}'"
            )
        
        # Create detector instance
        if detector_name == "aimbot":
            self.detectors["aimbot"] = AimbotDetector(
                sensitivity=self.sensitivity,
                **kwargs,
            )
        elif detector_name == "wallhack":
            self.detectors["wallhack"] = WallhackDetector(
                sensitivity=self.sensitivity,
                **kwargs,
            )
        elif detector_name == "scripts":
            self.detectors["scripts"] = ScriptDetector(
                sensitivity=self.sensitivity,
                **kwargs,
            )
        
        logger.info(f"✅ Detector enabled: {detector_name}")
        return True
    
    def enable_all(self):
        """Enable all compatible detectors."""
        for detector_name, info in AVAILABLE_DETECTORS.items():
            if self.game_type in info["game_types"] or "all" in info["game_types"]:
                try:
                    self.enable_detector(detector_name)
                except Exception as e:
                    logger.error(f"Failed to enable {detector_name}: {e}")
        
        logger.info(f"All compatible detectors enabled ({len(self.detectors)} total)")
    
    def disable_detector(self, detector_name: str):
        """Disable a specific detector."""
        if detector_name in self.detectors:
            del self.detectors[detector_name]
            logger.info(f"Detector disabled: {detector_name}")
    
    def get_active_detectors(self) -> list:
        """Get list of active detector names."""
        return list(self.detectors.keys())
    
    # ==========================================
    # Player Management
    # ==========================================
    
    def register_player(self, player_id: str, player_data: Optional[Dict[str, Any]] = None):
        """
        Register a player for tracking.
        
        Args:
            player_id: Unique player identifier
            player_data: Optional player metadata
        """
        if player_id not in self._players:
            self._players[player_id] = {
                "registered_at": datetime.now(),
                "reports": [],
                "actions": [],
                "risk_score": 0,
                "data": player_data or {},
            }
            self._stats["players_tracked"] += 1
    
    def unregister_player(self, player_id: str):
        """Remove a player from tracking."""
        self._players.pop(player_id, None)
    
    # ==========================================
    # Cheat Detection
    # ==========================================
    
    def check_player(
        self,
        player_id: str,
        action_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Check a player action for cheating.
        
        Args:
            player_id: Player identifier
            action_data: Action data to analyze
            
        Returns:
            Result dictionary with:
                - cheat_detected: Whether cheating was detected
                - cheat_type: Type of cheat detected (if any)
                - confidence: Detection confidence (0-100)
                - detectors_triggered: Which detectors triggered
                - risk_score: Player's current risk score
                - action_taken: Action taken (allow, warn, ban)
                
        Examples:
            >>> ac = AntiCheat(game_type="fps")
            >>> ac.enable_detector("aimbot")
            >>> result = ac.check_player("player1", {
            ...     "aim_angle": 0.5,
            ...     "aim_speed": 999,
            ...     "target_position": {"x": 100, "y": 200, "z": 50},
            ...     "player_position": {"x": 50, "y": 100, "z": 25},
            ... })
            >>> if result["cheat_detected"]:
            ...     print(f"Cheat detected: {result['cheat_type']}")
        """
        self._stats["actions_checked"] += 1
        
        # Ensure player is registered
        if player_id not in self._players:
            self.register_player(player_id)
        
        # Check if player is already banned
        if player_id in self._banned_players:
            return {
                "cheat_detected": True,
                "cheat_type": "previously_banned",
                "confidence": 100,
                "detectors_triggered": [],
                "risk_score": 100,
                "action_taken": "ban",
                "message": "Player is banned",
            }
        
        result = {
            "cheat_detected": False,
            "cheat_type": None,
            "confidence": 0,
            "detectors_triggered": [],
            "risk_score": self._players[player_id]["risk_score"],
            "action_taken": "allow",
            "message": "No cheating detected",
        }
        
        # Run all active detectors
        for detector_name, detector in self.detectors.items():
            try:
                detection = detector.detect(player_id, action_data)
                
                if detection["cheat_detected"]:
                    result["cheat_detected"] = True
                    result["cheat_type"] = detection["cheat_type"]
                    result["confidence"] = max(result["confidence"], detection["confidence"])
                    result["detectors_triggered"].append(detector_name)
                    
                    # Update risk score
                    self._players[player_id]["risk_score"] += detection.get("risk_increase", 20)
                    result["risk_score"] = self._players[player_id]["risk_score"]
                    
                    # Record suspicious action
                    if self.config["log_suspicious"]:
                        self._suspicious_actions.append({
                            "player_id": player_id,
                            "detector": detector_name,
                            "cheat_type": detection["cheat_type"],
                            "confidence": detection["confidence"],
                            "timestamp": datetime.now().isoformat(),
                            "action_data": action_data,
                        })
                    
                    self._stats["cheats_detected"] += 1
                    
            except Exception as e:
                logger.error(f"Detector {detector_name} error: {e}")
        
        # Determine action
        if result["cheat_detected"]:
            if result["confidence"] >= 90:
                result["action_taken"] = "ban"
                result["message"] = f"Cheat detected: {result['cheat_type']} (confidence: {result['confidence']}%)"
                
                if self.auto_ban:
                    self.ban_player(
                        player_id=player_id,
                        reason=f"Cheat detected: {result['cheat_type']}",
                        evidence=action_data,
                    )
            elif result["confidence"] >= 70:
                result["action_taken"] = "warn"
                result["message"] = f"Suspicious behavior: {result['cheat_type']}"
            else:
                result["action_taken"] = "log"
                result["message"] = f"Low confidence detection: {result['cheat_type']}"
        
        # Store action in player history
        self._players[player_id]["actions"].append({
            "timestamp": datetime.now().isoformat(),
            "result": result,
        })
        
        # Keep only last 1000 actions
        if len(self._players[player_id]["actions"]) > 1000:
            self._players[player_id]["actions"] = self._players[player_id]["actions"][-1000:]
        
        return result
    
    # ==========================================
    # Ban Management
    # ==========================================
    
    def ban_player(
        self,
        player_id: str,
        reason: str = "Cheating detected",
        duration: Optional[int] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ):
        """
        Ban a player.
        
        Args:
            player_id: Player to ban
            reason: Ban reason
            duration: Ban duration in seconds
            evidence: Evidence of cheating
        """
        ban_duration = duration or self.ban_duration
        
        self._banned_players[player_id] = {
            "banned_at": datetime.now(),
            "banned_until": datetime.now() + timedelta(seconds=ban_duration),
            "reason": reason,
            "evidence": evidence or {},
            "duration": ban_duration,
        }
        
        self._stats["players_banned"] += 1
        logger.warning(f"🚫 Player banned: {player_id} - {reason}")
    
    def unban_player(self, player_id: str):
        """Remove a player's ban."""
        if player_id in self._banned_players:
            del self._banned_players[player_id]
            logger.info(f"✅ Player unbanned: {player_id}")
    
    def is_player_banned(self, player_id: str) -> bool:
        """Check if a player is banned."""
        if player_id in self._banned_players:
            ban_info = self._banned_players[player_id]
            if datetime.now() < ban_info["banned_until"]:
                return True
            else:
                # Ban expired
                del self._banned_players[player_id]
        return False
    
    def get_ban_info(self, player_id: str) -> Optional[dict]:
        """Get ban information for a player."""
        if player_id in self._banned_players:
            info = self._banned_players[player_id].copy()
            info["banned_at"] = info["banned_at"].isoformat()
            info["banned_until"] = info["banned_until"].isoformat()
            info["remaining_seconds"] = (
                self._banned_players[player_id]["banned_until"] - datetime.now()
            ).total_seconds()
            return info
        return None
    
    # ==========================================
    # Reports & Statistics
    # ==========================================
    
    def get_player_report(self, player_id: str) -> Dict[str, Any]:
        """
        Get a detailed report for a specific player.
        
        Args:
            player_id: Player identifier
            
        Returns:
            Player report dictionary
        """
        if player_id not in self._players:
            return {"error": "Player not found"}
        
        player = self._players[player_id]
        
        return {
            "player_id": player_id,
            "risk_score": player["risk_score"],
            "total_actions": len(player["actions"]),
            "cheat_detections": len([
                a for a in player["actions"]
                if a["result"].get("cheat_detected")
            ]),
            "is_banned": self.is_player_banned(player_id),
            "ban_info": self.get_ban_info(player_id),
            "registered_at": player["registered_at"].isoformat(),
        }
    
    def get_report(self) -> Dict[str, Any]:
        """
        Get comprehensive anti-cheat report.
        
        Returns:
            Report dictionary
        """
        return {
            "stats": self._stats,
            "active_detectors": self.get_active_detectors(),
            "players_tracked": len(self._players),
            "players_banned": len(self._banned_players),
            "suspicious_actions_count": len(self._suspicious_actions),
            "config": {
                "game_type": self.game_type,
                "sensitivity": self.sensitivity,
                "auto_ban": self.auto_ban,
            },
        }
    
    def get_suspicious_actions(self, limit: int = 100) -> list:
        """Get recent suspicious actions."""
        return self._suspicious_actions[-limit:]
    
    def export_report(self, filepath: Optional[str] = None) -> str:
        """
        Export report to JSON file.
        
        Args:
            filepath: Output file path
            
        Returns:
            JSON string
        """
        report = self.get_report()
        report["suspicious_actions"] = self.get_suspicious_actions()
        report["banned_players"] = {
            pid: self.get_ban_info(pid)
            for pid in self._banned_players
        }
        
        json_str = json.dumps(report, indent=2, default=str)
        
        if filepath:
            with open(filepath, "w") as f:
                f.write(json_str)
            logger.info(f"Report exported to {filepath}")
        
        return json_str
    
    # ==========================================
    # Reset & Cleanup
    # ==========================================
    
    def reset_stats(self):
        """Reset all statistics."""
        self._stats = {
            "players_tracked": len(self._players),
            "actions_checked": 0,
            "cheats_detected": 0,
            "players_banned": 0,
            "false_positives": 0,
        }
        logger.info("Statistics reset")
    
    def clear_suspicious_actions(self):
        """Clear suspicious actions log."""
        self._suspicious_actions.clear()
    
    def reset_player(self, player_id: str):
        """Reset a player's tracking data."""
        if player_id in self._players:
            self._players[player_id]["risk_score"] = 0
            self._players[player_id]["actions"].clear()
            self._players[player_id]["reports"].clear()
    
    # ==========================================
    # Magic Methods
    # ==========================================
    
    def __repr__(self) -> str:
        return (
            f"AntiCheat(game_type='{self.game_type}', "
            f"detectors={len(self.detectors)}, "
            f"players={len(self._players)})"
        )
    
    def __str__(self) -> str:
        return (
            f"🎮 AntiCheat [{self.game_type.upper()}] | "
            f"Detectors: {len(self.detectors)} | "
            f"Players: {len(self._players)} | "
            f"Banned: {len(self._banned_players)}"
        )


# ==========================================
# What gets exported
# ==========================================

__all__ = [
    # Main class
    "AntiCheat",
    
    # Base classes
    "BaseAntiCheat",
    
    # Detectors
    "AimbotDetector",
    "WallhackDetector",
    "ScriptDetector",
    
    # Constants
    "AVAILABLE_DETECTORS",
    
    # Exceptions
    "AntiCheatError",
    "CheatDetectedError",
]
