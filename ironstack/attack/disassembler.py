#!/usr/bin/env python3
"""
Disassembler module for IronStack.
Integrates with Capstone for binary code disassembly and analysis.
"""

import os
import struct
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..logging_config import get_logger
from ..exceptions import (
    IronStackError,
    DependencyNotFoundError,
    FileNotFoundError,
    FileFormatError,
)

logger = get_logger(__name__)

# Try to import Capstone
try:
    import capstone
    from capstone import (
        Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64,
        CS_ARCH_MIPS, CS_ARCH_PPC, CS_ARCH_SPARC,
        CS_ARCH_SYSZ, CS_ARCH_XCORE,
        CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB,
        CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN,
        CS_MODE_MICRO, CS_MODE_MIPS32R6, CS_MODE_V8,
    )
    CAPSTONE_AVAILABLE = True
    logger.info("Capstone loaded successfully")
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning("Capstone not available. Install with: pip install capstone")


# ==========================================
# Enums
# ==========================================

class Architecture(Enum):
    """Supported CPU architectures."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    PPC = "ppc"
    SPARC = "sparc"
    SYSZ = "sysz"
    XCORE = "xcore"
    UNKNOWN = "unknown"


class Syntax(Enum):
    """Disassembly syntax styles."""
    INTEL = "intel"
    ATT = "att"
    DEFAULT = "default"


class FileType(Enum):
    """Supported binary file types."""
    RAW = "raw"
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    UNKNOWN = "unknown"


# ==========================================
# Data Classes
# ==========================================

@dataclass
class Instruction:
    """Represents a disassembled instruction."""
    address: int
    mnemonic: str
    op_str: str
    size: int
    bytes_hex: str
    group_names: List[str] = field(default_factory=list)
    regs_read: List[str] = field(default_factory=list)
    regs_write: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "address": hex(self.address),
            "mnemonic": self.mnemonic,
            "op_str": self.op_str,
            "size": self.size,
            "bytes": self.bytes_hex,
            "groups": self.group_names,
            "regs_read": self.regs_read,
            "regs_write": self.regs_write,
        }
    
    def __str__(self) -> str:
        return f"{hex(self.address).ljust(10)} {self.bytes_hex.ljust(20)} {self.mnemonic.ljust(8)} {self.op_str}"


@dataclass
class BasicBlock:
    """Represents a basic block of instructions."""
    start_address: int
    end_address: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    
    @property
    def size(self) -> int:
        return self.end_address - self.start_address
    
    @property
    def instruction_count(self) -> int:
        return len(self.instructions)
    
    def to_dict(self) -> dict:
        return {
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "size": self.size,
            "instruction_count": self.instruction_count,
            "successors": [hex(s) for s in self.successors],
            "instructions": [i.to_dict() for i in self.instructions[:10]],  # First 10
        }


@dataclass
class Function:
    """Represents a function in the disassembled code."""
    name: str
    start_address: int
    end_address: int
    basic_blocks: List[BasicBlock] = field(default_factory=list)
    call_count: int = 0
    xrefs_from: List[int] = field(default_factory=list)
    xrefs_to: List[int] = field(default_factory=list)
    
    @property
    def instruction_count(self) -> int:
        return sum(bb.instruction_count for bb in self.basic_blocks)
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "size": self.end_address - self.start_address,
            "instruction_count": self.instruction_count,
            "basic_blocks": len(self.basic_blocks),
            "call_count": self.call_count,
            "xrefs_from": [hex(x) for x in self.xrefs_from],
            "xrefs_to": [hex(x) for x in self.xrefs_to],
        }


# ==========================================
# Binary File Parser
# ==========================================

class BinaryParser:
    """
    Parser for various binary file formats.
    Extracts code sections for disassembly.
    """
    
    @staticmethod
    def detect_file_type(filepath: Union[str, Path]) -> FileType:
        """Detect the type of a binary file."""
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(str(filepath))
        
        with open(filepath, "rb") as f:
            magic = f.read(4)
        
        if magic[:4] == b'\x7fELF':
            return FileType.ELF
        elif magic[:2] == b'MZ':
            return FileType.PE
        elif magic[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                           b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
            return FileType.MACHO
        else:
            return FileType.RAW
    
    @staticmethod
    def parse_elf(filepath: Union[str, Path]) -> Dict[str, Any]:
        """Parse an ELF file and extract code sections."""
        filepath = Path(filepath)
        
        with open(filepath, "rb") as f:
            data = f.read()
        
        # Parse ELF header
        if data[:4] != b'\x7fELF':
            raise FileFormatError("Not a valid ELF file", path=str(filepath))
        
        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = little endian, 2 = big endian
        
        is_64bit = ei_class == 2
        is_little = ei_data == 1
        
        # Parse sections
        sections = []
        entry_point = None
        
        try:
            if is_64bit:
                # 64-bit ELF
                entry_point = struct.unpack_from("<Q" if is_little else ">Q", data, 24)[0]
                e_phoff = struct.unpack_from("<Q" if is_little else ">Q", data, 32)[0]
                e_shoff = struct.unpack_from("<Q" if is_little else ">Q", data, 40)[0]
                e_phentsize = struct.unpack_from("<H" if is_little else ">H", data, 54)[0]
                e_phnum = struct.unpack_from("<H" if is_little else ">H", data, 56)[0]
                e_shentsize = struct.unpack_from("<H" if is_little else ">H", data, 58)[0]
                e_shnum = struct.unpack_from("<H" if is_little else ">H", data, 60)[0]
                e_shstrndx = struct.unpack_from("<H" if is_little else ">H", data, 62)[0]
            else:
                # 32-bit ELF
                entry_point = struct.unpack_from("<I" if is_little else ">I", data, 24)[0]
                e_phoff = struct.unpack_from("<I" if is_little else ">I", data, 28)[0]
                e_shoff = struct.unpack_from("<I" if is_little else ">I", data, 32)[0]
                e_phentsize = struct.unpack_from("<H" if is_little else ">H", data, 42)[0]
                e_phnum = struct.unpack_from("<H" if is_little else ">H", data, 44)[0]
                e_shentsize = struct.unpack_from("<H" if is_little else ">H", data, 46)[0]
                e_shnum = struct.unpack_from("<H" if is_little else ">H", data, 48)[0]
                e_shstrndx = struct.unpack_from("<H" if is_little else ">H", data, 50)[0]
            
            # Extract section headers
            for i in range(e_shnum):
                offset = e_shoff + i * e_shentsize
                
                if is_64bit:
                    sh_name = struct.unpack_from("<I" if is_little else ">I", data, offset)[0]
                    sh_type = struct.unpack_from("<I" if is_little else ">I", data, offset + 4)[0]
                    sh_addr = struct.unpack_from("<Q" if is_little else ">Q", data, offset + 16)[0]
                    sh_offset = struct.unpack_from("<Q" if is_little else ">Q", data, offset + 24)[0]
                    sh_size = struct.unpack_from("<Q" if is_little else ">Q", data, offset + 32)[0]
                else:
                    sh_name = struct.unpack_from("<I" if is_little else ">I", data, offset)[0]
                    sh_type = struct.unpack_from("<I" if is_little else ">I", data, offset + 4)[0]
                    sh_addr = struct.unpack_from("<I" if is_little else ">I", data, offset + 12)[0]
                    sh_offset = struct.unpack_from("<I" if is_little else ">I", data, offset + 16)[0]
                    sh_size = struct.unpack_from("<I" if is_little else ">I", data, offset + 20)[0]
                
                if sh_type == 1 and sh_size > 0:  # PROGBITS with content
                    sections.append({
                        "name": f".section_{i}",
                        "address": sh_addr,
                        "offset": sh_offset,
                        "size": sh_size,
                        "data": data[sh_offset:sh_offset + sh_size],
                    })
        
        except Exception as e:
            logger.warning(f"ELF parsing incomplete: {e}")
        
        return {
            "file_type": "ELF",
            "is_64bit": is_64bit,
            "is_little_endian": is_little,
            "entry_point": entry_point,
            "sections": sections,
        }
    
    @staticmethod
    def parse_pe(filepath: Union[str, Path]) -> Dict[str, Any]:
        """Parse a PE file and extract code sections."""
        filepath = Path(filepath)
        
        with open(filepath, "rb") as f:
            data = f.read()
        
        if data[:2] != b'MZ':
            raise FileFormatError("Not a valid PE file", path=str(filepath))
        
        # Find PE signature
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        
        if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
            raise FileFormatError("Invalid PE signature", path=str(filepath))
        
        # COFF header
        coff_offset = pe_offset + 4
        machine = struct.unpack_from("<H", data, coff_offset)[0]
        number_of_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
        
        # Optional header
        opt_offset = coff_offset + 20
        magic = struct.unpack_from("<H", data, opt_offset)[0]
        is_64bit = magic == 0x020b
        
        if is_64bit:
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
        else:
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
        
        # Section headers
        sections = []
        section_offset = opt_offset + (112 if is_64bit else 96) + struct.unpack_from("<I", data, opt_offset + (68 if is_64bit else 60))[0]
        
        for i in range(number_of_sections):
            sec_offset = section_offset + i * 40
            
            name = data[sec_offset:sec_offset + 8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virtual_size = struct.unpack_from("<I", data, sec_offset + 8)[0]
            virtual_address = struct.unpack_from("<I", data, sec_offset + 12)[0]
            raw_size = struct.unpack_from("<I", data, sec_offset + 16)[0]
            raw_offset = struct.unpack_from("<I", data, sec_offset + 20)[0]
            characteristics = struct.unpack_from("<I", data, sec_offset + 36)[0]
            
            # Check if section contains executable code
            if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                sections.append({
                    "name": name,
                    "address": image_base + virtual_address,
                    "offset": raw_offset,
                    "size": raw_size,
                    "data": data[raw_offset:raw_offset + raw_size],
                })
        
        return {
            "file_type": "PE",
            "is_64bit": is_64bit,
            "entry_point": image_base + entry_point,
            "image_base": image_base,
            "sections": sections,
        }
    
    @staticmethod
    def parse_file(filepath: Union[str, Path]) -> Dict[str, Any]:
        """Auto-detect and parse a binary file."""
        file_type = BinaryParser.detect_file_type(filepath)
        
        if file_type == FileType.ELF:
            return BinaryParser.parse_elf(filepath)
        elif file_type == FileType.PE:
            return BinaryParser.parse_pe(filepath)
        else:
            # Treat as raw binary
            with open(filepath, "rb") as f:
                data = f.read()
            
            return {
                "file_type": "RAW",
                "sections": [{
                    "name": ".raw",
                    "address": 0,
                    "offset": 0,
                    "size": len(data),
                    "data": data,
                }],
            }


# ==========================================
# Disassembler Engine
# ==========================================

class DisassemblerEngine:
    """
    Low-level disassembly engine using Capstone.
    """
    
    def __init__(self):
        if not CAPSTONE_AVAILABLE:
            raise DependencyNotFoundError(
                "capstone",
                install_hint="pip install capstone",
            )
        
        self._cs: Optional[Cs] = None
        self._arch = None
        self._mode = None
    
    def setup(
        self,
        arch: Architecture = Architecture.X64,
        syntax: Syntax = Syntax.INTEL,
    ):
        """
        Configure the disassembler.
        
        Args:
            arch: Target architecture
            syntax: Disassembly syntax
        """
        arch_map = {
            Architecture.X86: (CS_ARCH_X86, CS_MODE_32),
            Architecture.X64: (CS_ARCH_X86, CS_MODE_64),
            Architecture.ARM: (CS_ARCH_ARM, CS_MODE_ARM),
            Architecture.ARM64: (CS_ARCH_ARM64, CS_MODE_ARM),
            Architecture.MIPS: (CS_ARCH_MIPS, CS_MODE_32),
            Architecture.PPC: (CS_ARCH_PPC, CS_MODE_32),
            Architecture.SPARC: (CS_ARCH_SPARC, CS_MODE_32),
            Architecture.SYSZ: (CS_ARCH_SYSZ, CS_MODE_32),
            Architecture.XCORE: (CS_ARCH_XCORE, CS_MODE_32),
        }
        
        if arch not in arch_map:
            raise IronStackError(f"Unsupported architecture: {arch.value}")
        
        cs_arch, cs_mode = arch_map[arch]
        
        # Apply syntax
        if arch in (Architecture.X86, Architecture.X64):
            if syntax == Syntax.INTEL:
                self._cs = Cs(cs_arch, cs_mode)
                self._cs.syntax = capstone.CS_OPT_SYNTAX_INTEL
            elif syntax == Syntax.ATT:
                self._cs = Cs(cs_arch, cs_mode)
                self._cs.syntax = capstone.CS_OPT_SYNTAX_ATT
            else:
                self._cs = Cs(cs_arch, cs_mode)
        else:
            self._cs = Cs(cs_arch, cs_mode)
        
        # Enable detail mode
        self._cs.detail = True
        
        self._arch = arch
        self._mode = cs_mode
        
        logger.info(f"Disassembler setup: {arch.value}, {syntax.value}")
    
    def disassemble(
        self,
        code: bytes,
        base_address: int = 0x1000,
        count: int = 0,
    ) -> List[Instruction]:
        """
        Disassemble binary code.
        
        Args:
            code: Binary code bytes
            base_address: Base address for code
            count: Maximum instructions (0 = all)
            
        Returns:
            List of Instruction objects
        """
        if not self._cs:
            self.setup()
        
        instructions = []
        
        try:
            for insn in self._cs.disasm(code, base_address, count):
                # Get instruction bytes
                bytes_hex = ' '.join(f'{b:02x}' for b in insn.bytes)
                
                # Get group names
                group_names = []
                for group in insn.groups:
                    group_names.append(insn.group_name(group))
                
                # Get registers
                regs_read = [insn.reg_name(r) for r in insn.regs_read]
                regs_write = [insn.reg_name(r) for r in insn.regs_write]
                
                instruction = Instruction(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    size=insn.size,
                    bytes_hex=bytes_hex,
                    group_names=group_names,
                    regs_read=regs_read,
                    regs_write=regs_write,
                )
                instructions.append(instruction)
        except Exception as e:
            logger.error(f"Disassembly error: {e}")
        
        return instructions
    
    def disassemble_single(self, code: bytes, address: int = 0) -> Optional[Instruction]:
        """Disassemble a single instruction."""
        instructions = self.disassemble(code, address, count=1)
        return instructions[0] if instructions else None


# ==========================================
# Code Analyzer
# ==========================================

class CodeAnalyzer:
    """
    Analyzes disassembled code for patterns and functions.
    """
    
    def __init__(self, engine: DisassemblerEngine):
        self.engine = engine
    
    def find_functions(self, instructions: List[Instruction]) -> List[Function]:
        """
        Identify functions in disassembled code.
        
        Args:
            instructions: List of disassembled instructions
            
        Returns:
            List of Function objects
        """
        functions = []
        
        # Find function prologues
        current_func = None
        
        for i, insn in enumerate(instructions):
            # x86/x64 function prologue: push rbp; mov rbp, rsp
            if insn.mnemonic in ("push", "pushq"):
                if any(r in ("rbp", "ebp") for r in insn.regs_read):
                    if i + 1 < len(instructions):
                        next_insn = instructions[i + 1]
                        if next_insn.mnemonic == "mov":
                            if any(r in ("rbp", "ebp") for r in next_insn.regs_write):
                                if any(r in ("rsp", "esp") for r in next_insn.regs_read):
                                    # Found function start
                                    if current_func:
                                        current_func.end_address = insn.address
                                        functions.append(current_func)
                                    
                                    current_func = Function(
                                        name=f"sub_{hex(insn.address)}",
                                        start_address=insn.address,
                                        end_address=0,
                                    )
            
            # Function epilogue: leave; ret or pop rbp; ret
            if current_func and insn.mnemonic == "ret":
                current_func.end_address = insn.address + insn.size
                functions.append(current_func)
                current_func = None
        
        # Add remaining function
        if current_func:
            current_func.end_address = instructions[-1].address + instructions[-1].size
            functions.append(current_func)
        
        return functions
    
    def find_basic_blocks(
        self,
        instructions: List[Instruction],
        start_address: int,
        end_address: int,
    ) -> List[BasicBlock]:
        """
        Identify basic blocks in a range of instructions.
        
        Args:
            instructions: List of instructions
            start_address: Start of range
            end_address: End of range
            
        Returns:
            List of BasicBlock objects
        """
        # Filter instructions in range
        range_insns = [
            i for i in instructions
            if start_address <= i.address < end_address
        ]
        
        if not range_insns:
            return []
        
        # Find block leaders
        leaders = {range_insns[0].address}  # First instruction is a leader
        
        for insn in range_insns:
            # Jump targets are leaders
            if insn.mnemonic.startswith("j"):
                # Parse jump target from op_str
                target = self._parse_jump_target(insn.op_str)
                if target is not None:
                    leaders.add(target)
            
            # Instructions after jumps are leaders
            if insn.mnemonic in ("jmp", "ret", "call"):
                idx = range_insns.index(insn)
                if idx + 1 < len(range_insns):
                    leaders.add(range_insns[idx + 1].address)
        
        # Create basic blocks
        sorted_leaders = sorted(leaders)
        blocks = []
        
        for i, leader in enumerate(sorted_leaders):
            if leader < start_address:
                continue
            
            # Find end of block
            if i + 1 < len(sorted_leaders):
                block_end = sorted_leaders[i + 1]
            else:
                block_end = end_address
            
            # Get instructions in block
            block_insns = [
                insn for insn in range_insns
                if leader <= insn.address < block_end
            ]
            
            if block_insns:
                # Find successors
                successors = []
                last_insn = block_insns[-1]
                
                if last_insn.mnemonic.startswith("j"):
                    target = self._parse_jump_target(last_insn.op_str)
                    if target:
                        successors.append(target)
                
                if last_insn.mnemonic not in ("jmp", "ret"):
                    next_addr = last_insn.address + last_insn.size
                    if next_addr < end_address:
                        successors.append(next_addr)
                
                block = BasicBlock(
                    start_address=leader,
                    end_address=block_end,
                    instructions=block_insns,
                    successors=successors,
                )
                blocks.append(block)
        
        return blocks
    
    def _parse_jump_target(self, op_str: str) -> Optional[int]:
        """Parse jump target address from operand string."""
        # Try hex address
        match = None
        
        import re
        hex_match = re.search(r'0x([0-9a-fA-F]+)', op_str)
        if hex_match:
            return int(hex_match.group(1), 16)
        
        return None
    
    def find_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """
        Extract readable strings from binary data.
        
        Args:
            data: Binary data
            min_length: Minimum string length
            
        Returns:
            List of found strings with offsets
        """
        strings = []
        current_string = b""
        current_offset = 0
        
        for i, byte in enumerate(data):
            if 32 <= byte < 127:  # Printable ASCII
                if not current_string:
                    current_offset = i
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    strings.append({
                        "offset": current_offset,
                        "address": current_offset,  # Will be adjusted for base
                        "string": current_string.decode("ascii", errors="ignore"),
                        "length": len(current_string),
                    })
                current_string = b""
        
        # Check last string
        if len(current_string) >= min_length:
            strings.append({
                "offset": current_offset,
                "address": current_offset,
                "string": current_string.decode("ascii", errors="ignore"),
                "length": len(current_string),
            })
        
        return strings
    
    def find_patterns(self, instructions: List[Instruction]) -> Dict[str, List[int]]:
        """
        Find common patterns in disassembled code.
        
        Args:
            instructions: List of instructions
            
        Returns:
            Dictionary of pattern -> addresses
        """
        patterns = {
            "syscall": [],
            "int3": [],
            "nop_sled": [],
            "call_rax": [],
            "xor_eax_eax": [],
            "pushad_popad": [],
        }
        
        for insn in instructions:
            if insn.mnemonic == "syscall":
                patterns["syscall"].append(insn.address)
            elif insn.mnemonic == "int3":
                patterns["int3"].append(insn.address)
            elif insn.mnemonic == "nop":
                patterns["nop_sled"].append(insn.address)
            elif insn.mnemonic == "call" and "rax" in insn.op_str:
                patterns["call_rax"].append(insn.address)
            elif insn.mnemonic == "xor" and "eax" in insn.op_str and "eax" in insn.regs_write:
                patterns["xor_eax_eax"].append(insn.address)
        
        return patterns


# ==========================================
# Main Disassembler Class
# ==========================================

class Disassembler:
    """
    Binary disassembler for IronStack.
    
    Provides disassembly, analysis, and pattern detection
    for binary code and executable files.
    
    Usage:
        >>> from ironstack.attack import Disassembler
        >>> disasm = Disassembler()
        >>> disasm.load_file("target.exe")
        >>> functions = disasm.analyze()
        >>> print(disasm.get_report())
    """
    
    def __init__(self):
        """
        Initialize Disassembler.
        
        Raises:
            DependencyNotFoundError: If Capstone is not installed
        """
        if not CAPSTONE_AVAILABLE:
            raise DependencyNotFoundError(
                "capstone",
                install_hint="pip install capstone",
            )
        
        self.engine = DisassemblerEngine()
        self.analyzer = CodeAnalyzer(self.engine)
        
        # State
        self._file_path: Optional[Path] = None
        self._file_info: Optional[Dict[str, Any]] = None
        self._instructions: List[Instruction] = []
        self._functions: List[Function] = []
        self._basic_blocks: List[BasicBlock] = []
        self._strings: List[Dict[str, Any]] = []
        self._patterns: Dict[str, List[int]] = {}
        
        # Default configuration
        self.arch = Architecture.X64
        self.syntax = Syntax.INTEL
        
        logger.info("🔬 Disassembler initialized")
    
    # ==========================================
    # File Loading
    # ==========================================
    
    def load_file(
        self,
        filepath: Union[str, Path],
        arch: Optional[Architecture] = None,
        syntax: Optional[Syntax] = None,
    ):
        """
        Load a binary file for disassembly.
        
        Args:
            filepath: Path to binary file
            arch: Target architecture (auto-detect if None)
            syntax: Disassembly syntax
        """
        filepath = Path(filepath)
        self._file_path = filepath
        
        # Parse file
        self._file_info = BinaryParser.parse_file(filepath)
        
        # Auto-detect architecture
        if arch is None:
            arch = self._detect_arch()
        
        self.arch = arch
        self.syntax = syntax or Syntax.INTEL
        
        # Setup engine
        self.engine.setup(self.arch, self.syntax)
        
        # Disassemble all code sections
        self._instructions = []
        
        for section in self._file_info.get("sections", []):
            code = section.get("data", b"")
            address = section.get("address", 0)
            
            instructions = self.engine.disassemble(code, address)
            self._instructions.extend(instructions)
        
        logger.info(
            f"Loaded {filepath.name}: {len(self._instructions)} instructions, "
            f"{len(self._file_info.get('sections', []))} sections"
        )
    
    def load_bytes(
        self,
        code: bytes,
        base_address: int = 0x1000,
        arch: Architecture = Architecture.X64,
        syntax: Syntax = Syntax.INTEL,
    ):
        """
        Disassemble raw bytes.
        
        Args:
            code: Raw binary code
            base_address: Base address for code
            arch: Target architecture
            syntax: Disassembly syntax
        """
        self.arch = arch
        self.syntax = syntax
        
        self.engine.setup(arch, syntax)
        self._instructions = self.engine.disassemble(code, base_address)
        
        logger.info(f"Disassembled {len(self._instructions)} instructions from bytes")
    
    def _detect_arch(self) -> Architecture:
        """Auto-detect architecture from file info."""
        if not self._file_info:
            return Architecture.X64
        
        file_type = self._file_info.get("file_type", "")
        is_64bit = self._file_info.get("is_64bit", True)
        
        if file_type == "ELF":
            return Architecture.X64 if is_64bit else Architecture.X86
        elif file_type == "PE":
            return Architecture.X64 if is_64bit else Architecture.X86
        
        return Architecture.X64  # Default
    
    # ==========================================
    # Analysis
    # ==========================================
    
    def analyze(self) -> List[Function]:
        """
        Perform full code analysis.
        
        Returns:
            List of identified functions
        """
        if not self._instructions:
            raise IronStackError("No code loaded. Call load_file() or load_bytes() first.")
        
        # Find functions
        self._functions = self.analyzer.find_functions(self._instructions)
        
        # Find basic blocks for each function
        self._basic_blocks = []
        for func in self._functions:
            blocks = self.analyzer.find_basic_blocks(
                self._instructions,
                func.start_address,
                func.end_address,
            )
            func.basic_blocks = blocks
            self._basic_blocks.extend(blocks)
        
        # Find strings (from raw data if available)
        if self._file_info:
            for section in self._file_info.get("sections", []):
                strings = self.analyzer.find_strings(section.get("data", b""))
                for s in strings:
                    s["address"] = section.get("address", 0) + s["offset"]
                self._strings.extend(strings)
        
        # Find patterns
        self._patterns = self.analyzer.find_patterns(self._instructions)
        
        logger.info(
            f"Analysis complete: {len(self._functions)} functions, "
            f"{len(self._basic_blocks)} basic blocks, {len(self._strings)} strings"
        )
        
        return self._functions
    
    # ==========================================
    # Search & Query
    # ==========================================
    
    def find_instruction(self, mnemonic: str) -> List[Instruction]:
        """Find instructions by mnemonic."""
        return [i for i in self._instructions if i.mnemonic == mnemonic]
    
    def find_at_address(self, address: int) -> Optional[Instruction]:
        """Find instruction at a specific address."""
        for i in self._instructions:
            if i.address == address:
                return i
        return None
    
    def find_function(self, name: str) -> Optional[Function]:
        """Find a function by name."""
        for f in self._functions:
            if f.name == name:
                return f
        return None
    
    def find_function_at(self, address: int) -> Optional[Function]:
        """Find function containing an address."""
        for f in self._functions:
            if f.start_address <= address < f.end_address:
                return f
        return None
    
    def get_call_graph(self) -> Dict[str, List[str]]:
        """
        Build a simple call graph.
        
        Returns:
            Dictionary of function -> list of called functions
        """
        call_graph = {}
        
        for func in self._functions:
            calls = []
            for block in func.basic_blocks:
                for insn in block.instructions:
                    if insn.mnemonic == "call":
                        # Try to resolve call target
                        target = self.analyzer._parse_jump_target(insn.op_str)
                        if target:
                            called_func = self.find_function_at(target)
                            if called_func:
                                calls.append(called_func.name)
                            else:
                                calls.append(hex(target))
            
            call_graph[func.name] = calls
        
        return call_graph
    
    def get_xrefs_to(self, address: int) -> List[Instruction]:
        """Find all cross-references to an address."""
        xrefs = []
        for insn in self._instructions:
            if insn.mnemonic.startswith("j") or insn.mnemonic == "call":
                target = self.analyzer._parse_jump_target(insn.op_str)
                if target == address:
                    xrefs.append(insn)
        return xrefs
    
    # ==========================================
    # Export & Report
    # ==========================================
    
    def get_report(self) -> Dict[str, Any]:
        """Generate a comprehensive analysis report."""
        return {
            "file": str(self._file_path) if self._file_path else "raw_bytes",
            "file_info": self._file_info,
            "architecture": self.arch.value,
            "syntax": self.syntax.value,
            "total_instructions": len(self._instructions),
            "functions": {
                "count": len(self._functions),
                "list": [f.to_dict() for f in self._functions[:50]],  # First 50
            },
            "basic_blocks": len(self._basic_blocks),
            "strings": {
                "count": len(self._strings),
                "list": self._strings[:100],  # First 100
            },
            "patterns": {
                k: len(v) for k, v in self._patterns.items()
            },
            "call_graph": self.get_call_graph() if self._functions else {},
        }
    
    def export_disassembly(
        self,
        output_path: Optional[Union[str, Path]] = None,
        format: str = "text",
    ) -> str:
        """
        Export disassembly output.
        
        Args:
            output_path: Output file path
            format: Output format (text, json, html)
            
        Returns:
            Disassembly output string
        """
        if format == "text":
            output = self._export_text()
        elif format == "json":
            output = json.dumps(
                [i.to_dict() for i in self._instructions],
                indent=2,
                default=str,
            )
        elif format == "html":
            output = self._export_html()
        else:
            output = self._export_text()
        
        if output_path:
            with open(output_path, "w") as f:
                f.write(output)
            logger.info(f"Disassembly exported to {output_path}")
        
        return output
    
    def _export_text(self) -> str:
        """Export as text format."""
        lines = [
            "=" * 80,
            f"IRONSTACK DISASSEMBLY REPORT",
            "=" * 80,
        ]
        
        if self._file_path:
            lines.append(f"File: {self._file_path}")
        lines.append(f"Architecture: {self.arch.value}")
        lines.append(f"Syntax: {self.syntax.value}")
        lines.append(f"Total Instructions: {len(self._instructions)}")
        lines.append("")
        
        if self._functions:
            lines.append("-" * 80)
            lines.append("FUNCTIONS")
            lines.append("-" * 80)
            for func in self._functions[:20]:
                lines.append(f"\n{func.name} ({hex(func.start_address)} - {hex(func.end_address)})")
                lines.append(f"  Instructions: {func.instruction_count}")
                lines.append(f"  Basic Blocks: {len(func.basic_blocks)}")
                
                for block in func.basic_blocks[:3]:
                    lines.append(f"\n  Block at {hex(block.start_address)}:")
                    for insn in block.instructions[:5]:
                        lines.append(f"    {insn}")
        
        lines.append("\n" + "-" * 80)
        lines.append("DISASSEMBLY")
        lines.append("-" * 80)
        
        for insn in self._instructions[:500]:  # First 500 instructions
            lines.append(str(insn))
        
        lines.append("\n" + "=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def _export_html(self) -> str:
        """Export as HTML format."""
        rows = ""
        for insn in self._instructions[:200]:
            rows += f"""
            <tr>
                <td><code>{hex(insn.address)}</code></td>
                <td><code>{insn.bytes_hex}</code></td>
                <td><b>{insn.mnemonic}</b></td>
                <td>{insn.op_str}</td>
            </tr>"""
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>IronStack Disassembly</title>
            <style>
                body {{ font-family: monospace; background: #1a1a2e; color: #eee; padding: 20px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; border: 1px solid #333; text-align: left; }}
                th {{ background: #16213e; color: #00d2ff; }}
                tr:hover {{ background: #0f3460; }}
                code {{ color: #00d2ff; }}
                b {{ color: #e94560; }}
            </style>
        </head>
        <body>
            <h1>🛡️ IronStack Disassembly Report</h1>
            <p>Architecture: {self.arch.value} | Instructions: {len(self._instructions)}</p>
            <table>
                <tr><th>Address</th><th>Bytes</th><th>Mnemonic</th><th>Operands</th></tr>
                {rows}
            </table>
        </body>
        </html>
        """
    
    def get_section_summary(self) -> List[Dict[str, Any]]:
        """Get summary of analyzed sections."""
        if not self._file_info:
            return []
        
        summaries = []
        for section in self._file_info.get("sections", []):
            addr = section.get("address", 0)
            size = section.get("size", 0)
            
            # Count instructions in this section
            section_insns = [
                i for i in self._instructions
                if addr <= i.address < addr + size
            ]
            
            summaries.append({
                "name": section.get("name", "unknown"),
                "address": hex(addr),
                "size": size,
                "instruction_count": len(section_insns),
            })
        
        return summaries
    
    # ==========================================
    # Utility
    # ==========================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get disassembler statistics."""
        mnemonics = {}
        for insn in self._instructions:
            mnemonics[insn.mnemonic] = mnemonics.get(insn.mnemonic, 0) + 1
        
        # Top 20 most common instructions
        top_mnemonics = sorted(mnemonics.items(), key=lambda x: x[1], reverse=True)[:20]
        
        return {
            "total_instructions": len(self._instructions),
            "total_functions": len(self._functions),
            "total_basic_blocks": len(self._basic_blocks),
            "total_strings": len(self._strings),
            "unique_mnemonics": len(mnemonics),
            "top_mnemonics": dict(top_mnemonics),
            "architecture": self.arch.value,
        }
    
    def reset(self):
        """Reset all analysis data."""
        self._file_path = None
        self._file_info = None
        self._instructions.clear()
        self._functions.clear()
        self._basic_blocks.clear()
        self._strings.clear()
        self._patterns.clear()
        logger.info("Disassembler reset")
    
    def __repr__(self) -> str:
        return f"Disassembler(arch='{self.arch.value}', instructions={len(self._instructions)})"
    
    def __str__(self) -> str:
        return f"🔬 Disassembler [{self.arch.value}] | {len(self._instructions)} instructions | {len(self._functions)} functions"
