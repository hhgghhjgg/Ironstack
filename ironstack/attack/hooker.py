#!/usr/bin/env python3
"""
Dynamic Instrumentation / Hooking module for IronStack.
Integrates with Frida for runtime analysis and modification.
"""

import os
import sys
import time
import json
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, field

from ..logging_config import get_logger
from ..exceptions import (
    IronStackError,
    DependencyNotFoundError,
    ConnectionError,
    TimeoutError,
)

logger = get_logger(__name__)

# Try to import Frida
try:
    import frida
    FRIDA_AVAILABLE = True
    logger.info("Frida loaded successfully")
except ImportError:
    FRIDA_AVAILABLE = False
    logger.warning("Frida not available. Install with: pip install frida-tools")


# ==========================================
# Data Classes
# ==========================================

@dataclass
class HookInfo:
    """Information about an active hook."""
    hook_id: str
    target: str
    function_name: str
    hook_type: str  # intercept, replace, trace
    created_at: float = field(default_factory=time.time)
    hit_count: int = 0
    enabled: bool = True


@dataclass
class HookResult:
    """Result from a hook trigger."""
    hook_id: str
    function_name: str
    args: List[Any] = field(default_factory=list)
    retval: Any = None
    timestamp: float = field(default_factory=time.time)
    stack_trace: Optional[str] = None


# ==========================================
# Frida Script Templates
# ==========================================

INTERCEPT_TEMPLATE = """
// IronStack Hook: Intercept {function_name}
Interceptor.attach(Module.findExportByName({module_name}, "{function_name}"), {{
    onEnter: function(args) {{
        console.log("[IronStack] " + "{function_name}" + " called");
        
        // Log arguments
        var argInfo = {{
            hook_id: "{hook_id}",
            function_name: "{function_name}",
            args: []
        }};
        
        {arg_logging}
        
        send(JSON.stringify(argInfo));
        
        // Store context
        this.context = argInfo;
    }},
    
    onLeave: function(retval) {{
        console.log("[IronStack] " + "{function_name}" + " returned: " + retval);
        
        var result = {{
            hook_id: "{hook_id}",
            function_name: "{function_name}",
            retval: retval.toString(),
            timestamp: Date.now()
        }};
        
        send(JSON.stringify(result));
    }}
}});
"""

REPLACE_TEMPLATE = """
// IronStack Hook: Replace {function_name}
Interceptor.replace(Module.findExportByName({module_name}, "{function_name}"),
    new NativeCallback(function({arg_list}) {{
        console.log("[IronStack] " + "{function_name}" + " replaced!");
        {replacement_code}
    }}, "{return_type}", [{arg_types}])
);
"""

TRACE_TEMPLATE = """
// IronStack Hook: Trace {function_name}
Interceptor.attach(Module.findExportByName({module_name}, "{function_name}"), {{
    onEnter: function(args) {{
        console.log("[Trace] " + "{function_name}" + " called from:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\\n"));
    }}
}});
"""


# ==========================================
# Frida Manager
# ==========================================

class FridaManager:
    """
    Manages Frida sessions and script execution.
    """
    
    def __init__(self):
        if not FRIDA_AVAILABLE:
            raise DependencyNotFoundError(
                "frida",
                install_hint="pip install frida frida-tools",
            )
        
        self.session: Optional[frida.core.Session] = None
        self.device: Optional[frida.core.Device] = None
        self.scripts: Dict[str, frida.core.Script] = {}
        self.hooks: Dict[str, HookInfo] = {}
        self._on_message_callbacks: List[Callable] = []
        self._lock = threading.Lock()
    
    # ==========================================
    # Device Management
    # ==========================================
    
    def get_local_device(self) -> frida.core.Device:
        """Get the local Frida device."""
        try:
            self.device = frida.get_local_device()
            return self.device
        except Exception as e:
            raise ConnectionError("localhost", message=str(e))
    
    def get_usb_device(self) -> frida.core.Device:
        """Get a USB-connected Frida device."""
        try:
            self.device = frida.get_usb_device()
            return self.device
        except Exception as e:
            raise ConnectionError("usb", message=str(e))
    
    def get_remote_device(self, host: str = "localhost", port: int = 27042) -> frida.core.Device:
        """Get a remote Frida device."""
        try:
            self.device = frida.get_device_manager().add_remote_device(
                f"{host}:{port}"
            )
            return self.device
        except Exception as e:
            raise ConnectionError(host, port, message=str(e))
    
    def list_processes(self) -> List[Dict[str, Any]]:
        """List all processes on the device."""
        if not self.device:
            self.get_local_device()
        
        processes = self.device.enumerate_processes()
        return [
            {
                "pid": p.pid,
                "name": p.name,
            }
            for p in processes
        ]
    
    def list_applications(self) -> List[Dict[str, Any]]:
        """List all applications on the device."""
        if not self.device:
            self.get_local_device()
        
        apps = self.device.enumerate_applications()
        return [
            {
                "identifier": app.identifier,
                "name": app.name,
                "pid": app.pid,
            }
            for app in apps
        ]
    
    # ==========================================
    # Session Management
    # ==========================================
    
    def attach(self, target: Union[int, str]) -> bool:
        """
        Attach to a process.
        
        Args:
            target: Process ID (int) or process name (str)
            
        Returns:
            True if attached successfully
        """
        if not self.device:
            self.get_local_device()
        
        try:
            if isinstance(target, int):
                self.session = self.device.attach(target)
                logger.info(f"Attached to PID: {target}")
            else:
                self.session = self.device.attach(target)
                logger.info(f"Attached to process: {target}")
            
            return True
        except frida.ProcessNotFoundError:
            raise ConnectionError(
                str(target),
                message=f"Process not found: {target}. Is Frida server running?",
            )
        except Exception as e:
            raise ConnectionError(str(target), message=str(e))
    
    def spawn(self, program: str, args: Optional[List[str]] = None) -> int:
        """
        Spawn a program and attach to it.
        
        Args:
            program: Program path
            args: Command line arguments
            
        Returns:
            Process ID
        """
        if not self.device:
            self.get_local_device()
        
        try:
            pid = self.device.spawn([program] + (args or []))
            self.session = self.device.attach(pid)
            self.device.resume(pid)
            logger.info(f"Spawned {program} with PID: {pid}")
            return pid
        except Exception as e:
            raise IronStackError(f"Failed to spawn {program}: {e}")
    
    def detach(self):
        """Detach from current session."""
        if self.session:
            # Unload all scripts
            for hook_id in list(self.scripts.keys()):
                self.unload_script(hook_id)
            
            self.session.detach()
            self.session = None
            logger.info("Detached from session")
    
    def is_attached(self) -> bool:
        """Check if attached to a process."""
        return self.session is not None
    
    # ==========================================
    # Script Management
    # ==========================================
    
    def create_script(
        self,
        script_code: str,
        hook_id: str,
    ) -> frida.core.Script:
        """
        Create and load a Frida script.
        
        Args:
            script_code: JavaScript code for Frida
            hook_id: Unique identifier for this hook
            
        Returns:
            Loaded Frida script
        """
        if not self.session:
            raise IronStackError("Not attached to any process")
        
        with self._lock:
            # Remove existing script with same ID
            if hook_id in self.scripts:
                self.unload_script(hook_id)
            
            script = self.session.create_script(script_code)
            
            script.on("message", self._on_message)
            
            script.load()
            
            self.scripts[hook_id] = script
            logger.info(f"Script loaded: {hook_id}")
            
            return script
    
    def unload_script(self, hook_id: str):
        """Unload a specific script."""
        with self._lock:
            if hook_id in self.scripts:
                try:
                    self.scripts[hook_id].unload()
                except Exception:
                    pass
                del self.scripts[hook_id]
                logger.info(f"Script unloaded: {hook_id}")
    
    def _on_message(self, message: Dict, data: Any):
        """Handle messages from Frida scripts."""
        if message["type"] == "send":
            try:
                payload = json.loads(message["payload"])
                
                for callback in self._on_message_callbacks:
                    try:
                        callback(payload)
                    except Exception as e:
                        logger.error(f"Message callback error: {e}")
                        
            except json.JSONDecodeError:
                logger.debug(f"Non-JSON message: {message['payload']}")
        
        elif message["type"] == "error":
            logger.error(f"Frida error: {message.get('description', 'Unknown')}")
    
    def on_message(self, callback: Callable):
        """Register a callback for script messages."""
        self._on_message_callbacks.append(callback)
    
    # ==========================================
    # Memory Operations
    # ==========================================
    
    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from the target process."""
        if not self.session:
            raise IronStackError("Not attached to any process")
        
        try:
            script = self.session.create_script(f"""
                var bytes = Memory.readByteArray(ptr("{hex(address)}"), {size});
                send(JSON.stringify({{data: Array.from(new Uint8Array(bytes))}}));
            """)
            
            result = {"data": None}
            
            def on_message(message, data):
                if message["type"] == "send":
                    result["data"] = bytes(json.loads(message["payload"])["data"])
            
            script.on("message", on_message)
            script.load()
            
            # Wait for result
            timeout = 5
            start = time.time()
            while result["data"] is None and time.time() - start < timeout:
                time.sleep(0.1)
            
            script.unload()
            
            return result["data"] or b""
        except Exception as e:
            logger.error(f"Memory read error: {e}")
            return b""
    
    def write_memory(self, address: int, data: bytes):
        """Write memory to the target process."""
        if not self.session:
            raise IronStackError("Not attached to any process")
        
        try:
            data_array = list(data)
            script = self.session.create_script(f"""
                var bytes = [{','.join(str(b) for b in data_array)}];
                Memory.writeByteArray(ptr("{hex(address)}"), bytes);
                send(JSON.stringify({{success: true}}));
            """)
            script.load()
            time.sleep(0.5)
            script.unload()
            
            logger.info(f"Wrote {len(data)} bytes to {hex(address)}")
        except Exception as e:
            logger.error(f"Memory write error: {e}")
    
    def enumerate_modules(self) -> List[Dict[str, Any]]:
        """List loaded modules in the target process."""
        if not self.session:
            raise IronStackError("Not attached to any process")
        
        modules = self.session.enumerate_modules()
        return [
            {
                "name": m.name,
                "base_address": hex(m.base_address),
                "size": m.size,
                "path": m.path,
            }
            for m in modules
        ]
    
    def find_module(self, name: str) -> Optional[Dict[str, Any]]:
        """Find a module by name."""
        modules = self.enumerate_modules()
        for m in modules:
            if name.lower() in m["name"].lower():
                return m
        return None
    
    def enumerate_exports(self, module_name: str) -> List[Dict[str, Any]]:
        """List exports from a module."""
        if not self.session:
            raise IronStackError("Not attached to any process")
        
        try:
            script = self.session.create_script(f"""
                var exports = Module.enumerateExports("{module_name}");
                send(JSON.stringify(exports));
            """)
            
            result = {"exports": []}
            
            def on_message(message, data):
                if message["type"] == "send":
                    result["exports"] = json.loads(message["payload"])
            
            script.on("message", on_message)
            script.load()
            
            time.sleep(1)
            script.unload()
            
            return [
                {
                    "name": e["name"],
                    "address": e["address"],
                    "type": e["type"],
                }
                for e in result["exports"]
            ]
        except Exception as e:
            logger.error(f"Export enumeration error: {e}")
            return []
    
    # ==========================================
    # Cleanup
    # ==========================================
    
    def cleanup(self):
        """Clean up all resources."""
        self.detach()
        self.scripts.clear()
        self.hooks.clear()
        self._on_message_callbacks.clear()
        logger.info("FridaManager cleaned up")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False


# ==========================================
# Main Hooker Class
# ==========================================

class Hooker:
    """
    Dynamic instrumentation and hooking for IronStack.
    
    Provides process hooking, function interception,
    memory analysis, and runtime modification capabilities.
    
    Usage:
        >>> from ironstack.attack import Hooker
        >>> hooker = Hooker()
        
        # Attach to a process
        >>> hooker.attach(pid=1234)
        # or
        >>> hooker.attach("firefox")
        
        # Hook a function
        >>> hooker.intercept(
        ...     module="libc.so",
        ...     function="open",
        ...     on_enter=lambda args: print(f"open called: {args}"),
        ... )
        
        # Read memory
        >>> data = hooker.read_memory(0x7fff1234, 256)
    """
    
    def __init__(self):
        """
        Initialize Hooker.
        
        Raises:
            DependencyNotFoundError: If Frida is not installed
        """
        if not FRIDA_AVAILABLE:
            raise DependencyNotFoundError(
                "frida",
                install_hint="pip install frida frida-tools",
            )
        
        self.frida = FridaManager()
        self.hooks: Dict[str, HookInfo] = {}
        self.hook_results: List[HookResult] = []
        self._hook_counter = 0
        
        # Register default message handler
        self.frida.on_message(self._default_message_handler)
        
        logger.info("🪝 Hooker initialized")
    
    def _default_message_handler(self, payload: Dict):
        """Default handler for hook messages."""
        if "hook_id" in payload:
            hook_id = payload["hook_id"]
            
            if hook_id in self.hooks:
                self.hooks[hook_id].hit_count += 1
            
            # Store result
            result = HookResult(
                hook_id=hook_id,
                function_name=payload.get("function_name", "unknown"),
                args=payload.get("args", []),
                retval=payload.get("retval"),
                stack_trace=payload.get("stack_trace"),
            )
            self.hook_results.append(result)
    
    # ==========================================
    # Process Management
    # ==========================================
    
    def attach(self, target: Union[int, str]) -> bool:
        """
        Attach to a process.
        
        Args:
            target: PID (int) or process name (str)
            
        Returns:
            True if attached
            
        Examples:
            >>> hooker.attach(1234)
            >>> hooker.attach("firefox")
        """
        return self.frida.attach(target)
    
    def spawn(self, program: str, args: Optional[List[str]] = None) -> int:
        """Spawn and attach to a program."""
        return self.frida.spawn(program, args)
    
    def detach(self):
        """Detach from the current process."""
        self.frida.detach()
    
    def list_processes(self) -> List[Dict[str, Any]]:
        """List available processes."""
        return self.frida.list_processes()
    
    # ==========================================
    # Function Hooking
    # ==========================================
    
    def intercept(
        self,
        function: str,
        module: Optional[str] = None,
        on_enter: Optional[Callable] = None,
        on_leave: Optional[Callable] = None,
        log_args: bool = True,
        log_retval: bool = True,
        arg_count: int = 4,
    ) -> str:
        """
        Intercept a function call.
        
        Args:
            function: Function name to intercept
            module: Module name (None = all modules)
            on_enter: Callback when function is called
            on_leave: Callback when function returns
            log_args: Log function arguments
            log_retval: Log return value
            arg_count: Number of arguments to log
            
        Returns:
            Hook ID for managing the hook
        """
        if not self.frida.is_attached():
            raise IronStackError("Not attached to any process")
        
        self._hook_counter += 1
        hook_id = f"hook_{self._hook_counter}_{function}"
        
        # Build arg logging code
        arg_logging_lines = []
        for i in range(arg_count):
            arg_logging_lines.append(
                f"argInfo.args.push(ptr(args[{i}]).toString());"
            )
        arg_logging = "\n        ".join(arg_logging_lines)
        
        # Build script
        module_name = f'"{module}"' if module else "null"
        
        script_code = INTERCEPT_TEMPLATE.format(
            hook_id=hook_id,
            function_name=function,
            module_name=module_name,
            arg_logging=arg_logging,
        )
        
        # Create and load script
        self.frida.create_script(script_code, hook_id)
        
        # Register hook info
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            target=function,
            function_name=function,
            hook_type="intercept",
        )
        
        # Register callbacks
        if on_enter or on_leave:
            def callback(payload):
                if "retval" in payload and on_leave:
                    on_leave(payload.get("retval"), payload.get("args", []))
                elif "args" in payload and on_enter:
                    on_enter(payload.get("args", []))
            
            self.frida.on_message(callback)
        
        logger.info(f"Intercept hook set: {function} (id: {hook_id})")
        return hook_id
    
    def replace(
        self,
        function: str,
        replacement_code: str,
        module: Optional[str] = None,
        return_type: str = "void",
        arg_types: Optional[List[str]] = None,
        arg_count: int = 0,
    ) -> str:
        """
        Replace a function implementation.
        
        Args:
            function: Function to replace
            replacement_code: JavaScript code for new implementation
            module: Module containing the function
            return_type: Return type of the function
            arg_types: Argument types
            arg_count: Number of arguments
            
        Returns:
            Hook ID
        """
        if not self.frida.is_attached():
            raise IronStackError("Not attached to any process")
        
        self._hook_counter += 1
        hook_id = f"replace_{self._hook_counter}_{function}"
        
        # Build arg list
        arg_list = ", ".join(f"arg{i}" for i in range(arg_count))
        arg_types_str = ", ".join(arg_types or ["pointer"] * arg_count)
        
        module_name = f'"{module}"' if module else "null"
        
        script_code = REPLACE_TEMPLATE.format(
            hook_id=hook_id,
            function_name=function,
            module_name=module_name,
            arg_list=arg_list,
            return_type=return_type,
            arg_types=arg_types_str,
            replacement_code=replacement_code,
        )
        
        self.frida.create_script(script_code, hook_id)
        
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            target=function,
            function_name=function,
            hook_type="replace",
        )
        
        logger.info(f"Replace hook set: {function} (id: {hook_id})")
        return hook_id
    
    def trace(self, function: str, module: Optional[str] = None) -> str:
        """
        Trace function calls with stack traces.
        
        Args:
            function: Function to trace
            module: Module containing the function
            
        Returns:
            Hook ID
        """
        if not self.frida.is_attached():
            raise IronStackError("Not attached to any process")
        
        self._hook_counter += 1
        hook_id = f"trace_{self._hook_counter}_{function}"
        
        module_name = f'"{module}"' if module else "null"
        
        script_code = TRACE_TEMPLATE.format(
            function_name=function,
            module_name=module_name,
        )
        
        self.frida.create_script(script_code, hook_id)
        
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            target=function,
            function_name=function,
            hook_type="trace",
        )
        
        logger.info(f"Trace hook set: {function} (id: {hook_id})")
        return hook_id
    
    def unhook(self, hook_id: str):
        """Remove a hook."""
        self.frida.unload_script(hook_id)
        self.hooks.pop(hook_id, None)
        logger.info(f"Hook removed: {hook_id}")
    
    def unhook_all(self):
        """Remove all hooks."""
        for hook_id in list(self.hooks.keys()):
            self.unhook(hook_id)
    
    # ==========================================
    # Memory Operations
    # ==========================================
    
    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from target process."""
        return self.frida.read_memory(address, size)
    
    def write_memory(self, address: int, data: bytes):
        """Write memory to target process."""
        self.frida.write_memory(address, data)
    
    def read_string(self, address: int, max_length: int = 256) -> Optional[str]:
        """Read a string from memory."""
        data = self.read_memory(address, max_length)
        try:
            null_pos = data.index(0)
            return data[:null_pos].decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            return data.decode("utf-8", errors="ignore")
    
    def read_int32(self, address: int) -> int:
        """Read a 32-bit integer from memory."""
        data = self.read_memory(address, 4)
        return int.from_bytes(data, "little")
    
    def read_int64(self, address: int) -> int:
        """Read a 64-bit integer from memory."""
        data = self.read_memory(address, 8)
        return int.from_bytes(data, "little")
    
    def read_pointer(self, address: int) -> int:
        """Read a pointer from memory."""
        if sys.maxsize > 2**32:  # 64-bit
            return self.read_int64(address)
        else:  # 32-bit
            return self.read_int32(address)
    
    # ==========================================
    # Module Operations
    # ==========================================
    
    def list_modules(self) -> List[Dict[str, Any]]:
        """List loaded modules."""
        return self.frida.enumerate_modules()
    
    def find_module(self, name: str) -> Optional[Dict[str, Any]]:
        """Find a module by name."""
        return self.frida.find_module(name)
    
    def get_module_base(self, name: str) -> Optional[int]:
        """Get base address of a module."""
        module = self.frida.find_module(name)
        if module:
            return int(module["base_address"], 16)
        return None
    
    def list_exports(self, module: str) -> List[Dict[str, Any]]:
        """List exports from a module."""
        return self.frida.enumerate_exports(module)
    
    def find_export(self, module: str, name: str) -> Optional[Dict[str, Any]]:
        """Find an export by name."""
        exports = self.frida.enumerate_exports(module)
        for exp in exports:
            if exp["name"] == name:
                return exp
        return None
    
    # ==========================================
    # Hook Statistics
    # ==========================================
    
    def get_hook_info(self, hook_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific hook."""
        hook = self.hooks.get(hook_id)
        if hook:
            return {
                "hook_id": hook.hook_id,
                "target": hook.target,
                "function_name": hook.function_name,
                "hook_type": hook.hook_type,
                "hit_count": hook.hit_count,
                "enabled": hook.enabled,
                "created_at": hook.created_at,
            }
        return None
    
    def get_all_hooks(self) -> List[Dict[str, Any]]:
        """Get information about all hooks."""
        return [self.get_hook_info(hid) for hid in self.hooks]
    
    def get_hook_results(self, hook_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get hook trigger results.
        
        Args:
            hook_id: Filter by hook ID
            limit: Maximum results
            
        Returns:
            List of hook results
        """
        results = self.hook_results
        if hook_id:
            results = [r for r in results if r.hook_id == hook_id]
        
        return [
            {
                "hook_id": r.hook_id,
                "function_name": r.function_name,
                "args": r.args,
                "retval": r.retval,
                "timestamp": r.timestamp,
                "stack_trace": r.stack_trace,
            }
            for r in results[-limit:]
        ]
    
    def clear_results(self):
        """Clear all hook results."""
        self.hook_results.clear()
    
    # ==========================================
    # Utility
    # ==========================================
    
    def create_injectable_script(self, script_code: str, hook_id: Optional[str] = None) -> str:
        """
        Create and load a custom Frida script.
        
        Args:
            script_code: JavaScript code
            hook_id: Optional hook identifier
            
        Returns:
            Hook ID
        """
        if not hook_id:
            self._hook_counter += 1
            hook_id = f"custom_{self._hook_counter}"
        
        self.frida.create_script(script_code, hook_id)
        
        self.hooks[hook_id] = HookInfo(
            hook_id=hook_id,
            target="custom",
            function_name="custom_script",
            hook_type="custom",
        )
        
        return hook_id
    
    def enumerate_threads(self) -> List[Dict[str, Any]]:
        """List threads in the target process."""
        if not self.frida.is_attached():
            raise IronStackError("Not attached to any process")
        
        try:
            script = self.frida.session.create_script("""
                var threads = Process.enumerateThreads();
                send(JSON.stringify(threads));
            """)
            
            result = {"threads": []}
            
            def on_message(message, data):
                if message["type"] == "send":
                    result["threads"] = json.loads(message["payload"])
            
            script.on("message", on_message)
            script.load()
            time.sleep(0.5)
            script.unload()
            
            return [
                {
                    "id": t["id"],
                    "state": t["state"],
                }
                for t in result["threads"]
            ]
        except Exception as e:
            logger.error(f"Thread enumeration error: {e}")
            return []
    
    def get_process_info(self) -> Dict[str, Any]:
        """Get information about the target process."""
        if not self.frida.is_attached():
            return {"error": "Not attached"}
        
        try:
            script = self.frida.session.create_script("""
                send(JSON.stringify({
                    arch: Process.arch,
                    platform: Process.platform,
                    pageSize: Process.pageSize,
                    pointerSize: Process.pointerSize,
                    codeSigningPolicy: Process.codeSigningPolicy
                }));
            """)
            
            result = {}
            
            def on_message(message, data):
                if message["type"] == "send":
                    result.update(json.loads(message["payload"]))
            
            script.on("message", on_message)
            script.load()
            time.sleep(0.5)
            script.unload()
            
            return result
        except Exception as e:
            return {"error": str(e)}
    
    # ==========================================
    # Magic Methods
    # ==========================================
    
    def __repr__(self) -> str:
        return f"Hooker(hooks={len(self.hooks)}, attached={self.frida.is_attached()})"
    
    def __str__(self) -> str:
        attached = "ATTACHED" if self.frida.is_attached() else "DETACHED"
        return f"🪝 Hooker [{attached}] | Hooks: {len(self.hooks)} | Results: {len(self.hook_results)}"
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.unhook_all()
        self.frida.cleanup()
        return False
