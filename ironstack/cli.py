#!/usr/bin/env python3
"""
Command Line Interface for IronStack.
Provides a unified command-line tool for all IronStack operations.
"""

import os
import sys
import json
import argparse
import textwrap
from pathlib import Path
from typing import Optional

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ironstack import __version__, IronStack
from ironstack.logging_config import setup_logging, set_log_level


# ==========================================
# CLI Colors
# ==========================================

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def colored(text: str, color: str) -> str:
    """Add color to text."""
    return f"{color}{text}{Colors.RESET}"


# ==========================================
# Banner
# ==========================================

BANNER = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   {Colors.BOLD}🛡️  IronStack v{__version__}{Colors.BLUE}                                  ║
║   {Colors.CYAN}Security Swiss Army Knife{Colors.BLUE}                             ║
║                                                          ║
║   {Colors.WHITE}WAF • Code Protection • Anti-Cheat • Red Team{Colors.BLUE}          ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{Colors.RESET}
"""


# ==========================================
# Main CLI Class
# ==========================================

class IronStackCLI:
    """Main CLI application for IronStack."""

    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser with all subcommands."""

        parser = argparse.ArgumentParser(
            prog="ironstack",
            description=colored("IronStack - Security Swiss Army Knife", Colors.BLUE),
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(f"""
                {Colors.CYAN}Examples:{Colors.RESET}
                  {Colors.WHITE}ironstack protect ./my-project{Colors.RESET}
                  {Colors.WHITE}ironstack protect --mode full ./my-project{Colors.RESET}
                  {Colors.WHITE}ironstack scan https://example.com{Colors.RESET}
                  {Colors.WHITE}ironstack waf start --engine bunkerweb --port 8080{Colors.RESET}
                  {Colors.WHITE}ironstack waf start --engine python --port 9090{Colors.RESET}
                  {Colors.WHITE}ironstack status{Colors.RESET}
                  {Colors.WHITE}ironstack version{Colors.RESET}

                {Colors.CYAN}Documentation:{Colors.RESET}
                  https://github.com/your-username/ironstack
            """),
        )

        parser.add_argument(
            "--version", "-v",
            action="version",
            version=f"IronStack v{__version__}",
            help="Show version and exit",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Enable verbose output",
        )
        parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug mode",
        )
        parser.add_argument(
            "--quiet", "-q",
            action="store_true",
            help="Suppress output",
        )

        # Subcommands
        subparsers = parser.add_subparsers(
            dest="command",
            title="Commands",
            metavar="COMMAND",
            help="Available commands",
        )

        # protect command
        self._add_protect_command(subparsers)

        # scan command
        self._add_scan_command(subparsers)

        # waf command
        self._add_waf_command(subparsers)

        # protect-code command
        self._add_protect_code_command(subparsers)

        # anti-cheat command
        self._add_anti_cheat_command(subparsers)

        # crypto command
        self._add_crypto_command(subparsers)

        # monitor command
        self._add_monitor_command(subparsers)

        # status command
        self._add_status_command(subparsers)

        # config command
        self._add_config_command(subparsers)

        # info command
        self._add_info_command(subparsers)

        return parser

    # ==========================================
    # Command Definitions
    # ==========================================

    def _add_protect_command(self, subparsers):
        protect_parser = subparsers.add_parser(
            "protect",
            help="Protect a project, file, or endpoint",
            description="Apply security protection to a target",
        )
        protect_parser.add_argument(
            "target",
            help="Target to protect (path or URL)",
        )
        protect_parser.add_argument(
            "--mode", "-m",
            choices=["defense", "attack", "full"],
            default="defense",
            help="Protection mode (default: defense)",
        )
        protect_parser.add_argument(
            "--output", "-o",
            help="Output directory for protected files",
        )
        protect_parser.add_argument(
            "--waf-port",
            type=int,
            default=8080,
            help="Port for WAF (default: 8080)",
        )
        protect_parser.add_argument(
            "--no-waf",
            action="store_true",
            help="Disable WAF protection",
        )
        protect_parser.add_argument(
            "--no-obfuscation",
            action="store_true",
            help="Disable code obfuscation",
        )

    def _add_scan_command(self, subparsers):
        scan_parser = subparsers.add_parser(
            "scan",
            help="Scan for vulnerabilities",
            description="Scan a target for security vulnerabilities",
        )
        scan_parser.add_argument(
            "target",
            help="Target to scan (URL or IP)",
        )
        scan_parser.add_argument(
            "--type", "-t",
            choices=["web", "network", "full"],
            default="web",
            help="Scan type (default: web)",
        )
        scan_parser.add_argument(
            "--output", "-o",
            help="Output file for scan report",
        )
        scan_parser.add_argument(
            "--format", "-f",
            choices=["json", "html", "pdf", "text"],
            default="json",
            help="Report format (default: json)",
        )
        scan_parser.add_argument(
            "--timeout",
            type=int,
            default=300,
            help="Scan timeout in seconds (default: 300)",
        )

    def _add_waf_command(self, subparsers):
        waf_parser = subparsers.add_parser(
            "waf",
            help="Manage Web Application Firewall",
            description="Start, stop, and configure WAF",
        )
        waf_subparsers = waf_parser.add_subparsers(dest="waf_command")

        # waf start
        waf_start = waf_subparsers.add_parser("start", help="Start WAF server")
        waf_start.add_argument("--port", "-p", type=int, default=8080)
        waf_start.add_argument("--mode", choices=["strict", "normal", "permissive"], default="normal")
        waf_start.add_argument(
            "--engine",
            choices=["auto", "python", "bunkerweb"],
            default="auto",
            help="WAF engine to use (default: auto)",
        )
        waf_start.add_argument(
            "--target-url",
            default="http://localhost:8000",
            help="Target URL to protect (for BunkerWeb engine)",
        )

        # waf stop
        waf_stop = waf_subparsers.add_parser("stop", help="Stop WAF server")

        # waf status
        waf_status = waf_subparsers.add_parser("status", help="Show WAF status")

        # waf rules
        waf_rules = waf_subparsers.add_parser("rules", help="Manage WAF rules")
        waf_rules.add_argument("action", choices=["list", "add", "remove"])
        waf_rules.add_argument("--name", help="Rule name")
        waf_rules.add_argument("--pattern", help="Rule regex pattern")
        waf_rules.add_argument("--category", help="Rule category")

        # waf stats
        waf_stats = waf_subparsers.add_parser("stats", help="Show WAF statistics")

    def _add_protect_code_command(self, subparsers):
        protect_parser = subparsers.add_parser(
            "protect-code",
            help="Protect Python source code",
            description="Obfuscate and protect Python code",
        )
        protect_parser.add_argument(
            "target",
            help="File or directory to protect",
        )
        protect_parser.add_argument(
            "--mode", "-m",
            choices=["basic", "normal", "max"],
            default="normal",
            help="Protection level (default: normal)",
        )
        protect_parser.add_argument(
            "--output", "-o",
            default="dist/",
            help="Output directory (default: dist/)",
        )
        protect_parser.add_argument(
            "--expire",
            help="Expiration date (YYYY-MM-DD)",
        )
        protect_parser.add_argument(
            "--bind-machine",
            action="store_true",
            help="Bind to current machine",
        )

    def _add_anti_cheat_command(self, subparsers):
        ac_parser = subparsers.add_parser(
            "anti-cheat",
            help="Game anti-cheat tools",
            description="Configure and run anti-cheat detection",
        )
        ac_subparsers = ac_parser.add_subparsers(dest="ac_command")

        # anti-cheat start
        ac_start = ac_subparsers.add_parser("start", help="Start anti-cheat monitoring")
        ac_start.add_argument("--game-type", choices=["fps", "rts", "chess", "auto"], default="auto")
        ac_start.add_argument("--sensitivity", choices=["low", "medium", "high"], default="medium")

        # anti-cheat check
        ac_check = ac_subparsers.add_parser("check", help="Check a player for cheating")
        ac_check.add_argument("player_id", help="Player ID to check")
        ac_check.add_argument("--data", help="JSON action data for analysis")

        # anti-cheat report
        ac_report = ac_subparsers.add_parser("report", help="Generate anti-cheat report")
        ac_report.add_argument("--player", help="Player ID for specific report")
        ac_report.add_argument("--output", "-o", help="Output file")

        # anti-cheat ban
        ac_ban = ac_subparsers.add_parser("ban", help="Ban a player")
        ac_ban.add_argument("player_id", help="Player ID to ban")
        ac_ban.add_argument("--reason", default="Cheating detected", help="Ban reason")
        ac_ban.add_argument("--duration", type=int, default=86400, help="Ban duration in seconds")

        # anti-cheat unban
        ac_unban = ac_subparsers.add_parser("unban", help="Unban a player")
        ac_unban.add_argument("player_id", help="Player ID to unban")

    def _add_crypto_command(self, subparsers):
        crypto_parser = subparsers.add_parser(
            "crypto",
            help="Cryptographic operations",
            description="Encrypt, decrypt, hash, and sign data",
        )
        crypto_subparsers = crypto_parser.add_subparsers(dest="crypto_command")

        # crypto encrypt
        encrypt = crypto_subparsers.add_parser("encrypt", help="Encrypt data")
        encrypt.add_argument("data", help="Data to encrypt (or @filepath)")

        # crypto decrypt
        decrypt = crypto_subparsers.add_parser("decrypt", help="Decrypt data")
        decrypt.add_argument("ciphertext", help="Ciphertext to decrypt")
        decrypt.add_argument("--nonce", required=True, help="Nonce for decryption")
        decrypt.add_argument("--tag", help="Auth tag for GCM mode")

        # crypto hash
        hash_parser = crypto_subparsers.add_parser("hash", help="Hash data or file")
        hash_parser.add_argument("target", help="Data or file to hash")
        hash_parser.add_argument("--algorithm", "-a", default="sha256", help="Hash algorithm")
        hash_parser.add_argument("--file", action="store_true", help="Target is a file")

        # crypto sign
        sign = crypto_subparsers.add_parser("sign", help="Sign a message")
        sign.add_argument("message", help="Message to sign")

        # crypto verify
        verify = crypto_subparsers.add_parser("verify", help="Verify a signature")
        verify.add_argument("message", help="Original message")
        verify.add_argument("--signature", "-s", required=True, help="Signature to verify")

        # crypto generate-key
        genkey = crypto_subparsers.add_parser("generate-key", help="Generate a random key")
        genkey.add_argument("--size", type=int, default=32, help="Key size in bytes")

        # crypto generate-token
        gentoken = crypto_subparsers.add_parser("generate-token", help="Generate a secure token")
        gentoken.add_argument("--length", type=int, default=32, help="Token length")

        # crypto password
        password = crypto_subparsers.add_parser("password", help="Password operations")
        password.add_argument("action", choices=["hash", "verify", "strength"])
        password.add_argument("--password", "-p", help="Password")
        password.add_argument("--hash", help="Stored hash (for verify)")
        password.add_argument("--salt", help="Stored salt (for verify)")

    def _add_monitor_command(self, subparsers):
        monitor_parser = subparsers.add_parser(
            "monitor",
            help="Security monitoring",
            description="Monitor logs and system for attacks",
        )
        monitor_subparsers = monitor_parser.add_subparsers(dest="monitor_command")

        # monitor start
        mon_start = monitor_subparsers.add_parser("start", help="Start monitoring")

        # monitor stop
        mon_stop = monitor_subparsers.add_parser("stop", help="Stop monitoring")

        # monitor status
        mon_status = monitor_subparsers.add_parser("status", help="Show monitoring status")

        # monitor alerts
        mon_alerts = monitor_subparsers.add_parser("alerts", help="Show security alerts")
        mon_alerts.add_argument("--type", help="Filter by alert type")
        mon_alerts.add_argument("--severity", help="Filter by severity")
        mon_alerts.add_argument("--limit", type=int, default=50, help="Max alerts to show")

        # monitor block
        mon_block = monitor_subparsers.add_parser("block", help="Block an IP")
        mon_block.add_argument("ip", help="IP to block")
        mon_block.add_argument("--duration", type=int, help="Block duration in seconds")

        # monitor unblock
        mon_unblock = monitor_subparsers.add_parser("unblock", help="Unblock an IP")
        mon_unblock.add_argument("ip", help="IP to unblock")

        # monitor whitelist
        mon_whitelist = monitor_subparsers.add_parser("whitelist", help="Whitelist an IP")
        mon_whitelist.add_argument("ip", help="IP to whitelist")

        # monitor stats
        mon_stats = monitor_subparsers.add_parser("stats", help="Show monitoring statistics")

    def _add_status_command(self, subparsers):
        status_parser = subparsers.add_parser(
            "status",
            help="Show IronStack status",
            description="Display current IronStack configuration and status",
        )
        status_parser.add_argument(
            "--json",
            action="store_true",
            help="Output as JSON",
        )

    def _add_config_command(self, subparsers):
        config_parser = subparsers.add_parser(
            "config",
            help="Manage IronStack configuration",
            description="View and modify IronStack configuration",
        )
        config_subparsers = config_parser.add_subparsers(dest="config_command")

        # config show
        config_show = config_subparsers.add_parser("show", help="Show current configuration")

        # config set
        config_set = config_subparsers.add_parser("set", help="Set a configuration value")
        config_set.add_argument("key", help="Configuration key (e.g., waf.port)")
        config_set.add_argument("value", help="Value to set")

        # config export
        config_export = config_subparsers.add_parser("export", help="Export configuration")
        config_export.add_argument("output", help="Output file path")
        config_export.add_argument("--format", choices=["yaml", "json"], default="yaml")

        # config import
        config_import = config_subparsers.add_parser("import", help="Import configuration")
        config_import.add_argument("input", help="Input file path")

        # config reset
        config_reset = config_subparsers.add_parser("reset", help="Reset to defaults")

    def _add_info_command(self, subparsers):
        info_parser = subparsers.add_parser(
            "info",
            help="Show system information",
            description="Display IronStack and system information",
        )

    # ==========================================
    # Command Handlers
    # ==========================================

    def handle_protect(self, args):
        """Handle 'protect' command."""
        print(colored(f"\n🛡️ Protecting: {args.target}", Colors.BLUE))
        print(colored(f"   Mode: {args.mode}", Colors.WHITE))

        is_stack = IronStack(mode=args.mode)

        if args.output:
            is_stack.config.set("code_protection.output_dir", args.output)
        if args.waf_port:
            is_stack.config.set("waf.port", args.waf_port)

        result = is_stack.protect(args.target)

        print(colored(f"\n✅ Protection complete!", Colors.GREEN))
        print(colored(f"   Target type: {result.get('target_type', 'unknown')}", Colors.WHITE))
        print(colored(f"   Layers applied: {', '.join(result.get('layers_applied', []))}", Colors.WHITE))

        return result

    def handle_scan(self, args):
        """Handle 'scan' command."""
        print(colored(f"\n🔍 Scanning: {args.target}", Colors.BLUE))
        print(colored(f"   Type: {args.type}", Colors.WHITE))

        is_stack = IronStack(mode="attack")
        result = is_stack.scan(args.target)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(colored(f"\n📄 Report saved to: {args.output}", Colors.GREEN))

        if result.get("findings"):
            print(colored(f"\n⚠️  Found {len(result['findings'])} potential issues:", Colors.YELLOW))
            for finding in result["findings"][:10]:
                print(colored(f"   - {finding}", Colors.WHITE))

        print(colored(f"\n✅ Scan complete!", Colors.GREEN))
        return result

    def handle_waf(self, args):
        """Handle 'waf' command."""
        if not args.waf_command:
            print(colored("Usage: ironstack waf {start|stop|status|rules|stats}", Colors.YELLOW))
            return

        from ironstack.defense import WAF

        if args.waf_command == "start":
            print(colored(f"\n🛡️ Starting WAF (engine: {args.engine})...", Colors.BLUE))
            waf = WAF(
                mode=args.mode,
                engine=args.engine,
                target_url=args.target_url,
                listen_port=args.port,
            )
            waf.start(port=args.port)
            if waf.engine_type == "bunkerweb":
                print(colored(f"✅ BunkerWeb WAF running on http://0.0.0.0:{args.port}", Colors.GREEN))
                print(colored(f"   Protecting: {args.target_url}", Colors.GREEN))
                print(colored(f"   Rules: OWASP CRS v4 (200+)", Colors.GREEN))
            else:
                print(colored(f"✅ Python WAF running on http://127.0.0.1:{args.port}", Colors.GREEN))

        elif args.waf_command == "stop":
            print(colored("\n🛡️ Stopping WAF...", Colors.BLUE))
            waf = WAF()
            waf.stop()
            print(colored("✅ WAF stopped", Colors.GREEN))

        elif args.waf_command == "status":
            print(colored("\n📊 WAF Status:", Colors.BLUE))
            waf = WAF()
            status = waf.get_status()
            for key, value in status.items():
                print(colored(f"   {key}: {value}", Colors.WHITE))

        elif args.waf_command == "rules":
            waf = WAF()
            if args.action == "list":
                rules = waf.get_rules()
                if waf.engine_type == "bunkerweb":
                    print(colored(f"\n📋 WAF Rules (BunkerWeb):", Colors.BLUE))
                    print(colored(f"   Engine: OWASP CRS v4 (200+ rules)", Colors.WHITE))
                else:
                    print(colored(f"\n📋 WAF Rules ({len(rules)} total):", Colors.BLUE))
                    for rule in rules[:20]:
                        print(colored(f"   [{rule['severity']}] {rule['name']} - {rule['category']}", Colors.WHITE))
            elif args.action == "add":
                if waf.engine_type == "bunkerweb":
                    print(colored("❌ Rule management not available with BunkerWeb engine", Colors.RED))
                else:
                    waf.add_rule(args.name, args.pattern, args.category)
                    print(colored(f"✅ Rule added: {args.name}", Colors.GREEN))
            elif args.action == "remove":
                if waf.engine_type == "bunkerweb":
                    print(colored("❌ Rule management not available with BunkerWeb engine", Colors.RED))
                else:
                    waf.remove_rule(args.name)
                    print(colored(f"✅ Rule removed: {args.name}", Colors.GREEN))

        elif args.waf_command == "stats":
            waf = WAF()
            stats = waf.get_stats()
            print(colored("\n📊 WAF Statistics:", Colors.BLUE))
            for key, value in stats.items():
                print(colored(f"   {key}: {value}", Colors.WHITE))

    def handle_protect_code(self, args):
        """Handle 'protect-code' command."""
        print(colored(f"\n🔒 Protecting code: {args.target}", Colors.BLUE))
        print(colored(f"   Mode: {args.mode}", Colors.WHITE))

        from ironstack.defense import CodeProtector

        protector = CodeProtector(mode=args.mode)

        if args.expire:
            protector.set_expire_date(args.expire)
        if args.bind_machine:
            protector.set_bind_machine(True)

        result = protector.protect(args.target, output_dir=args.output)

        print(colored(f"\n✅ Code protection complete!", Colors.GREEN))
        print(colored(f"   Files protected: {result.get('files_protected', 0)}", Colors.WHITE))
        print(colored(f"   Output directory: {args.output}", Colors.WHITE))

        return result

    def handle_anti_cheat(self, args):
        """Handle 'anti-cheat' command."""
        if not args.ac_command:
            print(colored("Usage: ironstack anti-cheat {start|check|report|ban|unban}", Colors.YELLOW))
            return

        from ironstack.defense import AntiCheat

        if args.ac_command == "start":
            print(colored(f"\n🎮 Starting Anti-Cheat ({args.game_type})...", Colors.BLUE))
            ac = AntiCheat(game_type=args.game_type, sensitivity=args.sensitivity)
            ac.enable_all()
            print(colored(f"✅ Anti-Cheat active with {len(ac.get_active_detectors())} detectors", Colors.GREEN))

        elif args.ac_command == "check":
            ac = AntiCheat()
            data = {}
            if args.data:
                data = json.loads(args.data)

            result = ac.check_player(args.player_id, data)

            if result["cheat_detected"]:
                print(colored(f"\n⚠️  CHEAT DETECTED!", Colors.RED))
                print(colored(f"   Player: {args.player_id}", Colors.WHITE))
                print(colored(f"   Type: {result['cheat_type']}", Colors.WHITE))
                print(colored(f"   Confidence: {result['confidence']}%", Colors.WHITE))
            else:
                print(colored(f"\n✅ Player {args.player_id} is clean", Colors.GREEN))

        elif args.ac_command == "report":
            ac = AntiCheat()
            if args.player:
                report = ac.get_player_report(args.player)
            else:
                report = ac.get_report()

            if args.output:
                ac.export_report(args.output)
                print(colored(f"📄 Report saved to {args.output}", Colors.GREEN))
            else:
                print(colored("\n📊 Anti-Cheat Report:", Colors.BLUE))
                print(json.dumps(report, indent=2, default=str))

        elif args.ac_command == "ban":
            ac = AntiCheat()
            ac.ban_player(args.player_id, reason=args.reason, duration=args.duration)
            print(colored(f"\n🚫 Player banned: {args.player_id}", Colors.RED))
            print(colored(f"   Reason: {args.reason}", Colors.WHITE))
            print(colored(f"   Duration: {args.duration}s", Colors.WHITE))

        elif args.ac_command == "unban":
            ac = AntiCheat()
            ac.unban_player(args.player_id)
            print(colored(f"\n✅ Player unbanned: {args.player_id}", Colors.GREEN))

    def handle_crypto(self, args):
        """Handle 'crypto' command."""
        if not args.crypto_command:
            print(colored("Usage: ironstack crypto {encrypt|decrypt|hash|sign|verify|generate-key|generate-token|password}", Colors.YELLOW))
            return

        from ironstack.defense import Crypto

        crypto = Crypto()

        if args.crypto_command == "encrypt":
            data = args.data
            if data.startswith("@"):
                with open(data[1:], "r") as f:
                    data = f.read()

            result = crypto.encrypt(data)
            print(colored("\n🔐 Encrypted:", Colors.GREEN))
            print(json.dumps(result, indent=2))

        elif args.crypto_command == "decrypt":
            result = crypto.decrypt(args.ciphertext, args.nonce, args.tag)
            print(colored("\n🔓 Decrypted:", Colors.GREEN))
            print(result.decode('utf-8'))

        elif args.crypto_command == "hash":
            if args.file:
                result = crypto.hash_file(args.target, args.algorithm)
                print(colored(f"\n📊 File Hash ({args.algorithm}):", Colors.BLUE))
                print(json.dumps(result, indent=2))
            else:
                result = crypto.hash_data(args.target, args.algorithm)
                print(colored(f"\n📊 Hash ({args.algorithm}): {result}", Colors.GREEN))

        elif args.crypto_command == "sign":
            signature = crypto.sign(args.message)
            print(colored(f"\n✍️ Signature: {signature}", Colors.GREEN))

        elif args.crypto_command == "verify":
            valid = crypto.verify(args.message, args.signature)
            if valid:
                print(colored("\n✅ Signature is VALID", Colors.GREEN))
            else:
                print(colored("\n❌ Signature is INVALID", Colors.RED))

        elif args.crypto_command == "generate-key":
            key = crypto.generate_token(args.size)
            print(colored(f"\n🔑 Generated Key ({args.size} bytes): {key}", Colors.GREEN))

        elif args.crypto_command == "generate-token":
            token = crypto.generate_token(args.length)
            print(colored(f"\n🎫 Generated Token: {token}", Colors.GREEN))

        elif args.crypto_command == "password":
            if args.action == "hash":
                if not args.password:
                    args.password = input("Password: ")
                result = crypto.hash_password(args.password)
                print(colored("\n🔒 Password Hash:", Colors.GREEN))
                print(json.dumps(result, indent=2))

            elif args.action == "verify":
                if not args.password:
                    args.password = input("Password: ")
                valid = crypto.verify_password(args.password, args.hash, args.salt)
                if valid:
                    print(colored("\n✅ Password is CORRECT", Colors.GREEN))
                else:
                    print(colored("\n❌ Password is INCORRECT", Colors.RED))

            elif args.action == "strength":
                if not args.password:
                    args.password = input("Password: ")
                result = crypto.check_password_strength(args.password)
                print(colored(f"\n💪 Password Strength: {result['strength']}", Colors.BLUE))
                print(colored(f"   Score: {result['score']}/{result['max_score']}", Colors.WHITE))
                for fb in result["feedback"]:
                    print(colored(f"   - {fb}", Colors.YELLOW))

    def handle_monitor(self, args):
        """Handle 'monitor' command."""
        if not args.monitor_command:
            print(colored("Usage: ironstack monitor {start|stop|status|alerts|block|unblock|whitelist|stats}", Colors.YELLOW))
            return

        from ironstack.defense import Monitor

        if args.monitor_command == "start":
            print(colored("\n📊 Starting monitoring...", Colors.BLUE))
            monitor = Monitor()
            monitor.start()
            print(colored("✅ Monitoring active", Colors.GREEN))

        elif args.monitor_command == "stop":
            print(colored("\n📊 Stopping monitoring...", Colors.BLUE))
            print(colored("✅ Monitoring stopped", Colors.GREEN))

        elif args.monitor_command == "status":
            monitor = Monitor()
            stats = monitor.get_stats()
            print(colored("\n📊 Monitor Status:", Colors.BLUE))
            print(colored(f"   Running: {stats['monitor']['running']}", Colors.WHITE))
            print(colored(f"   Blocked IPs: {stats['ip_blocker']['blocked_count']}", Colors.WHITE))
            print(colored(f"   Alerts: {stats['alerts']['total_alerts']}", Colors.WHITE))

        elif args.monitor_command == "alerts":
            monitor = Monitor()
            alerts = monitor.get_alerts(
                alert_type=args.type,
                severity=args.severity,
                limit=args.limit,
            )
            print(colored(f"\n🚨 Alerts ({len(alerts)} total):", Colors.BLUE))
            for alert in alerts[-20:]:
                severity_color = Colors.RED if alert["severity"] in ("critical", "high") else Colors.YELLOW
                print(colored(f"   [{alert['severity']}] {alert['message'][:80]}", severity_color))

        elif args.monitor_command == "block":
            monitor = Monitor()
            monitor.block_ip(args.ip, args.duration)
            print(colored(f"\n🚫 IP blocked: {args.ip}", Colors.RED))

        elif args.monitor_command == "unblock":
            monitor = Monitor()
            monitor.unblock_ip(args.ip)
            print(colored(f"\n✅ IP unblocked: {args.ip}", Colors.GREEN))

        elif args.monitor_command == "whitelist":
            monitor = Monitor()
            monitor.whitelist_ip(args.ip)
            print(colored(f"\n✅ IP whitelisted: {args.ip}", Colors.GREEN))

        elif args.monitor_command == "stats":
            monitor = Monitor()
            stats = monitor.get_stats()
            print(colored("\n📊 Monitor Statistics:", Colors.BLUE))
            print(json.dumps(stats, indent=2, default=str))

    def handle_status(self, args):
        """Handle 'status' command."""
        is_stack = IronStack()
        status = is_stack.status()

        if args.json:
            print(json.dumps(status, indent=2, default=str))
        else:
            print(colored("\n📊 IronStack Status:", Colors.BLUE))
            print(colored(f"   Version: {status['version']}", Colors.WHITE))
            print(colored(f"   Mode: {status['mode']}", Colors.WHITE))
            print(colored(f"   Active Layers: {', '.join(status['active_layers']) or 'none'}", Colors.WHITE))
            print(colored("\n   Layers:", Colors.CYAN))
            for layer, state in status.get("layers", {}).items():
                state_color = Colors.GREEN if state == "active" else Colors.YELLOW
                print(colored(f"     {layer}: {state}", state_color))

    def handle_config(self, args):
        """Handle 'config' command."""
        if not args.config_command:
            print(colored("Usage: ironstack config {show|set|export|import|reset}", Colors.YELLOW))
            return

        from ironstack.config import IronStackConfig

        if args.config_command == "show":
            config = IronStackConfig()
            print(colored("\n⚙️ Current Configuration:", Colors.BLUE))
            print(json.dumps(config.to_dict(), indent=2))

        elif args.config_command == "set":
            config = IronStackConfig()
            value = args.value
            if value.lower() in ("true", "false"):
                value = value.lower() == "true"
            elif value.isdigit():
                value = int(value)
            config.set(args.key, value)
            print(colored(f"\n✅ Config updated: {args.key} = {value}", Colors.GREEN))

        elif args.config_command == "export":
            config = IronStackConfig()
            config.to_file(args.output, args.format)
            print(colored(f"\n📄 Configuration exported to: {args.output}", Colors.GREEN))

        elif args.config_command == "import":
            config = IronStackConfig.from_file(args.input)
            print(colored(f"\n✅ Configuration imported from: {args.input}", Colors.GREEN))

        elif args.config_command == "reset":
            config = IronStackConfig()
            config.reset()
            print(colored("\n✅ Configuration reset to defaults", Colors.GREEN))

    def handle_info(self, args):
        """Handle 'info' command."""
        import platform

        print(colored("\n💻 IronStack Information:", Colors.BLUE))
        print(colored(f"   IronStack Version: {__version__}", Colors.WHITE))
        print(colored(f"   Python Version: {platform.python_version()}", Colors.WHITE))
        print(colored(f"   Platform: {platform.platform()}", Colors.WHITE))
        print(colored(f"   Architecture: {platform.architecture()[0]}", Colors.WHITE))

        print(colored("\n   📦 Dependencies:", Colors.CYAN))
        deps = {
            "requests": "HTTP library",
            "yaml": "YAML support",
            "Crypto": "PyCryptodome (advanced crypto)",
        }
        for module, description in deps.items():
            try:
                __import__(module)
                print(colored(f"     ✅ {module}: Available", Colors.GREEN))
            except ImportError:
                print(colored(f"     ❌ {module}: Not installed ({description})", Colors.RED))

    # ==========================================
    # Main Execution
    # ==========================================

    def run(self, args: Optional[list] = None):
        """Run the CLI with given arguments."""
        parsed_args = self.parser.parse_args(args)

        if not parsed_args.command:
            print(BANNER)
            print(colored("Run 'ironstack --help' for usage information.\n", Colors.YELLOW))
            return

        if parsed_args.debug:
            set_log_level("DEBUG")
        elif parsed_args.verbose:
            set_log_level("INFO")

        handlers = {
            "protect": self.handle_protect,
            "scan": self.handle_scan,
            "waf": self.handle_waf,
            "protect-code": self.handle_protect_code,
            "anti-cheat": self.handle_anti_cheat,
            "crypto": self.handle_crypto,
            "monitor": self.handle_monitor,
            "status": self.handle_status,
            "config": self.handle_config,
            "info": self.handle_info,
        }

        handler = handlers.get(parsed_args.command)
        if handler:
            try:
                handler(parsed_args)
            except Exception as e:
                print(colored(f"\n❌ Error: {e}", Colors.RED))
                if parsed_args.debug:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)
        else:
            print(colored(f"Unknown command: {parsed_args.command}", Colors.RED))
            sys.exit(1)


# ==========================================
# Entry Point
# ==========================================

def main():
    """Main entry point for the CLI."""
    cli = IronStackCLI()
    cli.run()


if __name__ == "__main__":
    main()