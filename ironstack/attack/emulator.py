#!/usr/bin/env python3
"""
CPU Emulator module for IronStack.
Integrates with Unicorn for code emulation and sandboxed execution.
"""

import os
import sys
import struct
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum

from ..logging_config import get_logger
from ..exceptions import (
    IronStackError,
    DependencyNotFoundError,
)

logger = get_logger(__name__)

# Try to import Unicorn
try:
    import unicorn
    from unicorn import (
        Uc, UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64,
        UC_ARCH_MIPS, UC_ARCH_PPC, UC_ARCH_SPARC,
        UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_MODE_THUMB,
        UC_MODE_LITTLE_ENDIAN, UC_MODE_BIG_ENDIAN,
        UC_MODE_MICRO, UC_MODE_MIPS32R6,
        UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL,
        UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_INTR, UC_HOOK_INSN,
        UC_ERR_OK, UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED,
        UC_ERR_FETCH_UNMAPPED, UC_ERR_HOOK,
        UcError,
    )
    UNICORN_AVAILABLE = True
    logger.info("Unicorn loaded successfully")
except ImportError:
    UNICORN_AVAILABLE = False
    logger.warning("Unicorn not available. Install with: pip install unicorn")


# ==========================================
# Enums
# ==========================================

class EmuArchitecture(Enum):
    """Supported CPU architectures for emulation."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    PPC = "ppc"
    SPARC = "sparc"


class HookType(Enum):
    """Types of emulation hooks."""
    CODE = "code"
    MEM_READ = "mem_read"
    MEM_WRITE = "mem_write"
    MEM_UNMAPPED = "mem_unmapped"
    INTERRUPT = "interrupt"
    INSTRUCTION = "instruction"


# ==========================================
# Data Classes
# ==========================================

@dataclass
class MemoryRegion:
    """Represents a mapped memory region."""
    address: int
    size: int
    permissions: int
    data: Optional[bytes] = None
    name: str = ""


@dataclass
class RegisterState:
    """Snapshot of CPU register values."""
    registers: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {k: hex(v) for k, v in self.registers.items()}


@dataclass
class EmulationResult:
    """Result of code emulation."""
    success: bool
    instructions_executed: int = 0
    start_address: int = 0
    end_address: int = 0
    duration_ms: float = 0.0
    error_message: str = ""
    final_registers: Optional[RegisterState] = None
    memory_writes: List[Dict[str, Any]] = field(default_factory=list)
    memory_reads: List[Dict[str, Any]] = field(default_factory=list)
    syscalls: List[Dict[str, Any]] = field(default_factory=list)
    accessed_addresses: set = field(default_factory=set)
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "instructions_executed": self.instructions_executed,
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
            "final_registers": self.final_registers.to_dict() if self.final_registers else {},
            "memory_writes": self.memory_writes[-50:],  # Last 50
            "memory_reads": self.memory_reads[-50:],    # Last 50
            "syscalls": self.syscalls,
            "unique_addresses_accessed": len(self.accessed_addresses),
        }


# ==========================================
# Unicorn Engine Wrapper
# ==========================================

class UnicornEngine:
    """
    Wrapper around Unicorn CPU emulator.
    """
    
    def __init__(self):
        if not UNICORN_AVAILABLE:
            raise DependencyNotFoundError(
                "unicorn",
                install_hint="pip install unicorn",
            )
        
        self._uc: Optional[Uc] = None
        self._arch = None
        self._mode = None
        self._memory_regions: List[MemoryRegion] = []
        self._hooks: Dict[HookType, Any] = {}
        
        # Tracking
        self._instruction_count = 0
        self._memory_writes: List[Dict[str, Any]] = []
        self._memory_reads: List[Dict[str, Any]] = []
        self._syscalls: List[Dict[str, Any]] = []
        self._accessed_addresses: set = set()
        
        # Limits
        self._max_instructions = 1_000_000
        self._timeout_ms = 60_000  # 60 seconds
    
    def setup(
        self,
        arch: EmuArchitecture = EmuArchitecture.X64,
    ):
        """
        Configure the emulator.
        
        Args:
            arch: Target architecture
        """
        arch_map = {
            EmuArchitecture.X86: (UC_ARCH_X86, UC_MODE_32),
            EmuArchitecture.X64: (UC_ARCH_X86, UC_MODE_64),
            EmuArchitecture.ARM: (UC_ARCH_ARM, UC_MODE_ARM),
            EmuArchitecture.ARM64: (UC_ARCH_ARM64, UC_MODE_ARM),
            EmuArchitecture.MIPS: (UC_ARCH_MIPS, UC_MODE_32),
            EmuArchitecture.PPC: (UC_ARCH_PPC, UC_MODE_32),
            EmuArchitecture.SPARC: (UC_ARCH_SPARC, UC_MODE_32),
        }
        
        if arch not in arch_map:
            raise IronStackError(f"Unsupported architecture: {arch.value}")
        
        uc_arch, uc_mode = arch_map[arch]
        self._uc = Uc(uc_arch, uc_mode)
        self._arch = arch
        self._mode = uc_mode
        
        logger.info(f"Emulator setup: {arch.value}")
    
    def map_memory(
        self,
        address: int,
        size: int,
        permissions: int = UC_PROT_ALL,
        data: Optional[bytes] = None,
        name: str = "",
    ):
        """
        Map a memory region.
        
        Args:
            address: Base address
            size: Region size
            permissions: Memory permissions
            data: Initial data to write
            name: Region name
        """
        if not self._uc:
            raise IronStackError("Emulator not configured. Call setup() first.")
        
        # Align to page boundary
        page_size = 0x1000  # 4KB
        aligned_address = address & ~(page_size - 1)
        aligned_size = ((address + size - aligned_address + page_size - 1) // page_size) * page_size
        
        try:
            self._uc.mem_map(aligned_address, aligned_size, permissions)
            
            if data:
                self._uc.mem_write(address, data)
            
            region = MemoryRegion(
                address=aligned_address,
                size=aligned_size,
                permissions=permissions,
                data=data,
                name=name,
            )
            self._memory_regions.append(region)
            
            logger.debug(f"Mapped {aligned_size} bytes at {hex(aligned_address)} ({name})")
            
        except UcError as e:
            raise IronStackError(f"Memory map failed at {hex(address)}: {e}")
    
    def write_memory(self, address: int, data: bytes):
        """Write data to emulated memory."""
        if not self._uc:
            raise IronStackError("Emulator not configured.")
        
        self._uc.mem_write(address, data)
    
    def read_memory(self, address: int, size: int) -> bytes:
        """Read data from emulated memory."""
        if not self._uc:
            raise IronStackError("Emulator not configured.")
        
        return self._uc.mem_read(address, size)
    
    def set_register(self, reg: int, value: int):
        """Set a CPU register value."""
        if not self._uc:
            raise IronStackError("Emulator not configured.")
        
        self._uc.reg_write(reg, value)
    
    def get_register(self, reg: int) -> int:
        """Get a CPU register value."""
        if not self._uc:
            raise IronStackError("Emulator not configured.")
        
        return self._uc.reg_read(reg)
    
    def set_registers(self, registers: Dict[int, int]):
        """Set multiple CPU registers."""
        for reg, value in registers.items():
            self.set_register(reg, value)
    
    def get_registers(self, register_ids: List[int]) -> RegisterState:
        """Get multiple CPU registers."""
        state = RegisterState()
        for reg_id in register_ids:
            try:
                value = self.get_register(reg_id)
                state.registers[unicorn.reg_name(reg_id)] = value
            except Exception:
                pass
        return state
    
    # ==========================================
    # Hooks
    # ==========================================
    
    def add_hook(
        self,
        hook_type: HookType,
        callback: Callable,
        begin: int = 1,
        end: int = 0,
    ):
        """
        Add an emulation hook.
        
        Args:
            hook_type: Type of hook
            callback: Callback function
            begin: Start address (1 = everywhere)
            end: End address (0 = everywhere)
        """
        if not self._uc:
            raise IronStackError("Emulator not configured.")
        
        hook_map = {
            HookType.CODE: UC_HOOK_CODE,
            HookType.MEM_READ: UC_HOOK_MEM_READ,
            HookType.MEM_WRITE: UC_HOOK_MEM_WRITE,
            HookType.MEM_UNMAPPED: UC_HOOK_MEM_READ_UNMAPPED,
            HookType.INTERRUPT: UC_HOOK_INTR,
        }
        
        uc_hook_type = hook_map.get(hook_type)
        if uc_hook_type is None:
            raise IronStackError(f"Unsupported hook type: {hook_type.value}")
        
        self._hooks[hook_type] = self._uc.hook_add(uc_hook_type, callback, begin=begin, end=end)
        logger.debug(f"Hook added: {hook_type.value}")
    
    def add_code_hook(self, callback: Callable):
        """Add a code execution hook (fires for every instruction)."""
        self.add_hook(HookType.CODE, callback)
    
    def add_memory_hook(self, callback: Callable):
        """Add memory access hooks."""
        self.add_hook(HookType.MEM_READ, self._on_mem_read)
        self.add_hook(HookType.MEM_WRITE, self._on_mem_write)
        self.add_hook(HookType.MEM_UNMAPPED, self._on_mem_unmapped)
    
    def add_syscall_hook(self, callback: Optional[Callable] = None):
        """Add interrupt/syscall hook."""
        def default_syscall_handler(uc, intno, user_data):
            self._syscalls.append({
                "interrupt": intno,
                "address": hex(uc.reg_read(self._get_ip_register())),
            })
        
        self.add_hook(HookType.INTERRUPT, callback or default_syscall_handler)
    
    def _get_ip_register(self) -> int:
        """Get instruction pointer register ID."""
        if self._arch in (EmuArchitecture.X86,):
            return unicorn.x86_const.UC_X86_REG_EIP
        elif self._arch in (EmuArchitecture.X64,):
            return unicorn.x86_const.UC_X86_REG_RIP
        elif self._arch in (EmuArchitecture.ARM,):
            return unicorn.arm_const.UC_ARM_REG_PC
        elif self._arch in (EmuArchitecture.ARM64,):
            return unicorn.arm64_const.UC_ARM64_REG_PC
        return 0
    
    def _on_mem_read(self, uc, access, address, size, value, user_data):
        """Memory read callback."""
        self._accessed_addresses.add(address)
        self._memory_reads.append({
            "address": hex(address),
            "size": size,
        })
    
    def _on_mem_write(self, uc, access, address, size, value, user_data):
        """Memory write callback."""
        self._accessed_addresses.add(address)
        self._memory_writes.append({
            "address": hex(address),
            "size": size,
            "value": hex(value) if size <= 8 else f"bytes[{size}]",
        })
    
    def _on_mem_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory access."""
        logger.warning(f"Unmapped memory access at {hex(address)} (size: {size})")
        return False  # Stop emulation
    
    # ==========================================
    # Emulation
    # ==========================================
    
    def emulate(
        self,
        start_address: int,
        end_address: Optional[int] = None,
        max_instructions: Optional[int] = None,
        timeout_ms: Optional[int] = None,
        count_instructions: bool = True,
    ) -> EmulationResult:
        """
        Emulate code execution.
        
        Args:
            start_address: Address to start emulation
            end_address: Address to stop emulation
            max_instructions: Maximum instructions to execute
            timeout_ms: Timeout in milliseconds
            count_instructions: Track instruction count via hook
            
        Returns:
            EmulationResult
        """
        if not self._uc:
            raise IronStackError("Emulator not configured.")
        
        import time
        
        max_insns = max_instructions or self._max_instructions
        timeout = timeout_ms or self._timeout_ms
        
        result = EmulationResult(
            success=False,
            start_address=start_address,
        )
        
        # Reset tracking
        self._instruction_count = 0
        self._memory_writes.clear()
        self._memory_reads.clear()
        self._syscalls.clear()
        self._accessed_addresses.clear()
        
        # Add instruction counter hook
        if count_instructions:
            def instruction_counter(uc, address, size, user_data):
                self._instruction_count += 1
                if self._instruction_count > max_insns:
                    uc.emu_stop()
                    result.error_message = f"Max instructions exceeded ({max_insns})"
            
            self.add_code_hook(instruction_counter)
        
        start_time = time.perf_counter()
        
        try:
            if end_address:
                self._uc.emu_start(start_address, end_address, timeout=timeout * 1000)
            else:
                # Emulate with timeout only
                self._uc.emu_start(start_address, 0, timeout=timeout * 1000)
            
            result.success = True
            result.end_address = self._uc.reg_read(self._get_ip_register())
            
        except UcError as e:
            result.success = False
            result.error_message = str(e)
            result.end_address = self._uc.reg_read(self._get_ip_register())
        
        result.duration_ms = (time.perf_counter() - start_time) * 1000
        result.instructions_executed = self._instruction_count
        result.memory_writes = self._memory_writes.copy()
        result.memory_reads = self._memory_reads.copy()
        result.syscalls = self._syscalls.copy()
        result.accessed_addresses = self._accessed_addresses.copy()
        
        # Save final register state
        if self._arch in (EmuArchitecture.X86, EmuArchitecture.X64):
            reg_ids = [
                unicorn.x86_const.UC_X86_REG_RAX,
                unicorn.x86_const.UC_X86_REG_RBX,
                unicorn.x86_const.UC_X86_REG_RCX,
                unicorn.x86_const.UC_X86_REG_RDX,
                unicorn.x86_const.UC_X86_REG_RSI,
                unicorn.x86_const.UC_X86_REG_RDI,
                unicorn.x86_const.UC_X86_REG_RSP,
                unicorn.x86_const.UC_X86_REG_RBP,
                unicorn.x86_const.UC_X86_REG_RIP,
            ]
            result.final_registers = self.get_registers(reg_ids)
        
        logger.info(
            f"Emulation {'succeeded' if result.success else 'failed'}: "
            f"{result.instructions_executed} instructions in {result.duration_ms:.2f}ms"
        )
        
        return result
    
    def reset(self):
        """Reset emulator state."""
        if self._uc:
            # Remove hooks
            for hook in self._hooks.values():
                self._uc.hook_del(hook)
            self._hooks.clear()
            
            self._uc = None
        
        self._memory_regions.clear()
        self._instruction_count = 0
        self._memory_writes.clear()
        self._memory_reads.clear()
        self._syscalls.clear()
        self._accessed_addresses.clear()
        
        logger.info("Emulator reset")
    
    # ==========================================
    # Stack Operations
    # ==========================================
    
    def setup_stack(self, stack_addr: int, stack_size: int = 0x10000):
        """
        Set up a stack for emulation.
        
        Args:
            stack_addr: Stack base address
            stack_size: Stack size
        """
        self.map_memory(
            stack_addr,
            stack_size,
            UC_PROT_READ | UC_PROT_WRITE,
            name="stack",
        )
        
        if self._arch in (EmuArchitecture.X86,):
            self.set_register(unicorn.x86_const.UC_X86_REG_ESP, stack_addr + stack_size // 2)
        elif self._arch in (EmuArchitecture.X64,):
            self.set_register(unicorn.x86_const.UC_X86_REG_RSP, stack_addr + stack_size // 2)
    
    def push_value(self, value: int) -> int:
        """Push a value onto the stack."""
        if self._arch in (EmuArchitecture.X86,):
            sp = self.get_register(unicorn.x86_const.UC_X86_REG_ESP)
            sp -= 4
            self.write_memory(sp, struct.pack("<I", value))
            self.set_register(unicorn.x86_const.UC_X86_REG_ESP, sp)
        elif self._arch in (EmuArchitecture.X64,):
            sp = self.get_register(unicorn.x86_const.UC_X86_REG_RSP)
            sp -= 8
            self.write_memory(sp, struct.pack("<Q", value))
            self.set_register(unicorn.x86_const.UC_X86_REG_RSP, sp)
        return sp
    
    def pop_value(self) -> int:
        """Pop a value from the stack."""
        if self._arch in (EmuArchitecture.X86,):
            sp = self.get_register(unicorn.x86_const.UC_X86_REG_ESP)
            data = self.read_memory(sp, 4)
            self.set_register(unicorn.x86_const.UC_X86_REG_ESP, sp + 4)
            return struct.unpack("<I", data)[0]
        elif self._arch in (EmuArchitecture.X64,):
            sp = self.get_register(unicorn.x86_const.UC_X86_REG_RSP)
            data = self.read_memory(sp, 8)
            self.set_register(unicorn.x86_const.UC_X86_REG_RSP, sp + 8)
            return struct.unpack("<Q", data)[0]
        return 0
    
    # ==========================================
    # Shellcode Helpers
    # ==========================================
    
    def run_shellcode(
        self,
        shellcode: bytes,
        base_address: int = 0x100000,
        stack_address: int = 0x200000,
        arch: EmuArchitecture = EmuArchitecture.X64,
    ) -> EmulationResult:
        """
        Run shellcode in a sandboxed environment.
        
        Args:
            shellcode: Shellcode bytes
            base_address: Base address for code
            stack_address: Stack address
            arch: Target architecture
            
        Returns:
            EmulationResult
        """
        self.setup(arch)
        
        # Map code memory
        self.map_memory(
            base_address,
            len(shellcode) + 0x1000,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
            data=shellcode,
            name="code",
        )
        
        # Setup stack
        self.setup_stack(stack_address)
        
        # Add hooks
        self.add_memory_hook(None)
        self.add_syscall_hook()
        
        # Start emulation
        result = self.emulate(base_address)
        
        return result
    
    def analyze_shellcode(self, shellcode: bytes, arch: Optional[EmuArchitecture] = None) -> Dict[str, Any]:
        """
        Analyze shellcode behavior.
        
        Args:
            shellcode: Shellcode to analyze
            arch: Target architecture (auto-detect if None)
            
        Returns:
            Analysis results
        """
        if arch is None:
            # Try to detect architecture from shellcode
            arch = EmuArchitecture.X64  # Default
        
        result = self.run_shellcode(shellcode, arch=arch)
        
        analysis = result.to_dict()
        analysis["shellcode_size"] = len(shellcode)
        analysis["shellcode_hex"] = shellcode[:64].hex()  # First 64 bytes
        analysis["unique_addresses"] = len(result.accessed_addresses)
        
        # Check for suspicious patterns
        suspicious = []
        
        if "syscall" in str(result.syscalls).lower():
            suspicious.append("Uses syscalls")
        
        if len(result.memory_writes) > 50:
            suspicious.append("Excessive memory writes")
        
        analysis["suspicious_patterns"] = suspicious
        analysis["risk_level"] = "high" if len(suspicious) > 2 else "medium" if suspicious else "low"
        
        return analysis


# ==========================================
# Main Emulator Class
# ==========================================

class Emulator:
    """
    CPU emulator for IronStack.
    
    Provides code emulation, shellcode analysis,
    and sandboxed execution capabilities.
    
    Usage:
        >>> from ironstack.attack import Emulator
        >>> emulator = Emulator()
        
        # Run shellcode
        >>> result = emulator.run_shellcode(b"\\x90\\x90\\xcc")
        >>> print(result.success)
        
        # Analyze shellcode
        >>> analysis = emulator.analyze_shellcode(b"\\x31\\xc0\\x40\\xcd\\x80")
        >>> print(analysis["risk_level"])
    """
    
    def __init__(self):
        """
        Initialize Emulator.
        
        Raises:
            DependencyNotFoundError: If Unicorn is not installed
        """
        if not UNICORN_AVAILABLE:
            raise DependencyNotFoundError(
                "unicorn",
                install_hint="pip install unicorn",
            )
        
        self.engine = UnicornEngine()
        self._results: List[EmulationResult] = []
        self._analysis_cache: Dict[str, Dict[str, Any]] = {}
        
        logger.info("🧪 Emulator initialized")
    
    # ==========================================
    # Emulation Methods
    # ==========================================
    
    def run_shellcode(
        self,
        shellcode: Union[bytes, str],
        base_address: int = 0x100000,
        stack_address: int = 0x200000,
        arch: EmuArchitecture = EmuArchitecture.X64,
    ) -> EmulationResult:
        """
        Run shellcode in a sandboxed environment.
        
        Args:
            shellcode: Shellcode bytes or hex string
            base_address: Base address for code
            stack_address: Stack address
            arch: Target architecture
            
        Returns:
            EmulationResult
        """
        if isinstance(shellcode, str):
            shellcode = bytes.fromhex(shellcode.replace(" ", ""))
        
        result = self.engine.run_shellcode(
            shellcode=shellcode,
            base_address=base_address,
            stack_address=stack_address,
            arch=arch,
        )
        
        self._results.append(result)
        return result
    
    def emulate_code(
        self,
        code: bytes,
        start_address: int = 0x1000,
        end_address: Optional[int] = None,
        arch: EmuArchitecture = EmuArchitecture.X64,
        registers: Optional[Dict[int, int]] = None,
        memory_regions: Optional[List[Dict[str, Any]]] = None,
    ) -> EmulationResult:
        """
        Emulate arbitrary code with custom setup.
        
        Args:
            code: Code bytes to emulate
            start_address: Start address
            end_address: End address
            arch: Architecture
            registers: Initial register values
            memory_regions: Memory regions to map
            
        Returns:
            EmulationResult
        """
        self.engine.setup(arch)
        
        # Map code
        self.engine.map_memory(
            start_address,
            len(code) + 0x1000,
            UC_PROT_ALL,
            data=code,
            name="code",
        )
        
        # Map additional memory regions
        if memory_regions:
            for region in memory_regions:
                self.engine.map_memory(
                    address=region.get("address", 0),
                    size=region.get("size", 0x1000),
                    permissions=region.get("permissions", UC_PROT_ALL),
                    data=region.get("data"),
                    name=region.get("name", "custom"),
                )
        
        # Setup stack
        self.engine.setup_stack(0x200000)
        
        # Set registers
        if registers:
            self.engine.set_registers(registers)
        
        # Add hooks
        self.engine.add_memory_hook(None)
        self.engine.add_syscall_hook()
        
        # Emulate
        result = self.engine.emulate(start_address, end_address)
        self._results.append(result)
        
        return result
    
    # ==========================================
    # Analysis Methods
    # ==========================================
    
    def analyze_shellcode(
        self,
        shellcode: Union[bytes, str],
        arch: Optional[EmuArchitecture] = None,
    ) -> Dict[str, Any]:
        """
        Analyze shellcode behavior.
        
        Args:
            shellcode: Shellcode to analyze
            arch: Target architecture
            
        Returns:
            Analysis dictionary
        """
        if isinstance(shellcode, str):
            shellcode = bytes.fromhex(shellcode.replace(" ", ""))
        
        # Check cache
        cache_key = shellcode.hex()[:32]
        if cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]
        
        analysis = self.engine.analyze_shellcode(shellcode, arch)
        
        # Store in cache
        self._analysis_cache[cache_key] = analysis
        
        return analysis
    
    def analyze_file(
        self,
        filepath: Union[str, Path],
        section: str = ".text",
    ) -> Dict[str, Any]:
        """
        Analyze code from a binary file.
        
        Args:
            filepath: Path to binary file
            section: Section to analyze
            
        Returns:
            Analysis results
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        # Parse file to extract code section
        from .disassembler import BinaryParser
        
        file_info = BinaryParser.parse_file(filepath)
        
        # Find requested section
        code_data = None
        for s in file_info.get("sections", []):
            if s.get("name") == section or ".text" in s.get("name", ""):
                code_data = s.get("data", b"")
                break
        
        if not code_data and file_info.get("sections"):
            code_data = file_info["sections"][0].get("data", b"")
        
        if not code_data:
            return {"error": "No code section found"}
        
        # Analyze the code
        return self.analyze_shellcode(code_data[:0x1000])  # First 4KB
    
    # ==========================================
    # Results & History
    # ==========================================
    
    def get_last_result(self) -> Optional[EmulationResult]:
        """Get the last emulation result."""
        return self._results[-1] if self._results else None
    
    def get_all_results(self) -> List[Dict[str, Any]]:
        """Get all emulation results."""
        return [r.to_dict() for r in self._results]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get emulator statistics."""
        total_instructions = sum(r.instructions_executed for r in self._results)
        successful = sum(1 for r in self._results if r.success)
        
        return {
            "total_emulations": len(self._results),
            "successful": successful,
            "failed": len(self._results) - successful,
            "total_instructions_executed": total_instructions,
            "analyses_cached": len(self._analysis_cache),
        }
    
    def clear_history(self):
        """Clear emulation history."""
        self._results.clear()
        self._analysis_cache.clear()
        logger.info("Emulation history cleared")
    
    # ==========================================
    # Shellcode Database
    # ==========================================
    
    def detect_shellcode_type(self, shellcode: bytes) -> str:
        """
        Attempt to identify shellcode type.
        
        Args:
            shellcode: Shellcode bytes
            
        Returns:
            Shellcode type description
        """
        # Common shellcode signatures
        signatures = {
            b"\x31\xc0\x50\x68": "Linux x86 execve /bin/sh",
            b"\x31\xc0\x48\xbb": "Linux x64 execve /bin/sh",
            b"\x31\xc9\x64\x8b": "Windows x86 reverse shell",
            b"\x48\x31\xc9\x48\x81": "Windows x64 reverse shell",
            b"\x6a\x3b\x58\x99": "Linux x86 setuid execve",
            b"\x90\x90\x90\x90": "NOP sled",
            b"\xcc\xcc\xcc\xcc": "INT3 breakpoints",
        }
        
        for sig, desc in signatures.items():
            if sig in shellcode[:len(sig)]:
                return desc
        
        return "Unknown shellcode"
    
    # ==========================================
    # Utility
    # ==========================================
    
    def hex_to_bytes(self, hex_str: str) -> bytes:
        """Convert hex string to bytes."""
        return bytes.fromhex(hex_str.replace(" ", "").replace("\\x", ""))
    
    def bytes_to_hex(self, data: bytes) -> str:
        """Convert bytes to hex string."""
        return data.hex()
    
    def test_shellcode(
        self,
        shellcode: Union[bytes, str],
        arch: Optional[EmuArchitecture] = None,
    ) -> Dict[str, Any]:
        """
        Quick test of shellcode.
        
        Args:
            shellcode: Shellcode to test
            arch: Architecture
            
        Returns:
            Test results summary
        """
        if isinstance(shellcode, str):
            shellcode = self.hex_to_bytes(shellcode)
        
        result = self.run_shellcode(shellcode, arch=arch or EmuArchitecture.X64)
        
        return {
            "shellcode_size": len(shellcode),
            "shellcode_type": self.detect_shellcode_type(shellcode),
            "execution_success": result.success,
            "instructions_executed": result.instructions_executed,
            "duration_ms": result.duration_ms,
            "error": result.error_message if not result.success else None,
            "syscalls_used": len(result.syscalls),
            "memory_operations": len(result.memory_writes) + len(result.memory_reads),
        }
    
    def reset(self):
        """Reset emulator state."""
        self.engine.reset()
        self._results.clear()
        self._analysis_cache.clear()
        logger.info("Emulator reset")
    
    def __repr__(self) -> str:
        return f"Emulator(emulations={len(self._results)})"
    
    def __str__(self) -> str:
        stats = self.get_stats()
        return (
            f"🧪 Emulator | "
            f"Emulations: {stats['total_emulations']} | "
            f"Success: {stats['successful']} | "
            f"Instructions: {stats['total_instructions_executed']}"
        )
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.reset()
        return False
