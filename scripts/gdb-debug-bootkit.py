#!/usr/bin/env python3
"""
GDB Python Script for Live UEFI Bootkit Debugging
Allows real-time observation of UEFI→Kernel handoff
"""

import gdb
import struct
from typing import Dict, List, Optional

class BootkitDebugger:
    """Interactive debugger for UEFI bootkit analysis"""
    
    def __init__(self):
        self.breakpoints: Dict[str, gdb.Breakpoint] = {}
        self.hook_log: List[Dict] = []
        self.memory_regions: Dict[str, tuple] = {}
        
    def setup_breakpoints(self):
        """Set breakpoints on critical UEFI functions"""
        print("[*] Setting up breakpoints...")
        
        # ExitBootServices hook
        try:
            bp = gdb.Breakpoint("ExitBootServices")
            self.breakpoints['ExitBootServices'] = bp
            print(f"[+] Breakpoint set: ExitBootServices")
        except:
            print("[-] Could not set ExitBootServices breakpoint")
        
        # LoadImage hook
        try:
            bp = gdb.Breakpoint("LoadImage")
            self.breakpoints['LoadImage'] = bp
            print(f"[+] Breakpoint set: LoadImage")
        except:
            print("[-] Could not set LoadImage breakpoint")
        
        # StartImage hook
        try:
            bp = gdb.Breakpoint("StartImage")
            self.breakpoints['StartImage'] = bp
            print(f"[+] Breakpoint set: StartImage")
        except:
            print("[-] Could not set StartImage breakpoint")
        
        # SetVariable hook
        try:
            bp = gdb.Breakpoint("SetVariable")
            self.breakpoints['SetVariable'] = bp
            print(f"[+] Breakpoint set: SetVariable")
        except:
            print("[-] Could not set SetVariable breakpoint")
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read memory at specified address"""
        try:
            inferior = gdb.selected_inferior()
            return inferior.read_memory(address, size).tobytes()
        except:
            return None
    
    def read_pointer(self, address: int) -> Optional[int]:
        """Read 64-bit pointer at address"""
        data = self.read_memory(address, 8)
        if data:
            return struct.unpack('<Q', data)[0]
        return None
    
    def dump_registers(self):
        """Dump current register state"""
        print("\n[*] Register State:")
        regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip']
        for reg in regs:
            try:
                val = gdb.parse_and_eval(f"${reg}")
                print(f"  {reg.upper()}: 0x{int(val):016x}")
            except:
                pass
    
    def dump_stack(self, count: int = 16):
        """Dump stack contents"""
        print(f"\n[*] Stack Dump (top {count} entries):")
        try:
            rsp = int(gdb.parse_and_eval("$rsp"))
            for i in range(count):
                addr = rsp + (i * 8)
                val = self.read_pointer(addr)
                if val is not None:
                    print(f"  [RSP+0x{i*8:02x}] 0x{addr:016x}: 0x{val:016x}")
        except:
            print("  [!] Could not read stack")
    
    def analyze_hook(self, function_name: str):
        """Analyze hook when breakpoint is hit"""
        print(f"\n{'='*60}")
        print(f"[!] Hook Hit: {function_name}")
        print(f"{'='*60}")
        
        self.dump_registers()
        self.dump_stack()
        
        # Log hook event
        try:
            rip = int(gdb.parse_and_eval("$rip"))
            self.hook_log.append({
                'function': function_name,
                'rip': rip,
                'timestamp': gdb.execute("info proc", to_string=True)
            })
        except:
            pass
        
        # Check for trampolines
        self.check_trampoline()
    
    def check_trampoline(self):
        """Check if current instruction is a trampoline"""
        try:
            rip = int(gdb.parse_and_eval("$rip"))
            code = self.read_memory(rip, 14)
            
            if code:
                # Check for MOV RAX, imm64; JMP RAX pattern
                if code[0:2] == b'\x48\xb8' and code[10:12] == b'\xff\xe0':
                    target = struct.unpack('<Q', code[2:10])[0]
                    print(f"\n[!] TRAMPOLINE DETECTED!")
                    print(f"    Pattern: MOV RAX, 0x{target:016x}; JMP RAX")
                    print(f"    Target:  0x{target:016x}")
                    
                    # Try to identify target
                    self.identify_target(target)
        except:
            pass
    
    def identify_target(self, address: int):
        """Try to identify what the target address points to"""
        try:
            # Read potential PE header
            data = self.read_memory(address, 64)
            if data and data[0:2] == b'MZ':
                print(f"    [+] Target appears to be PE executable (ntoskrnl.exe?)")
            elif data and data[0:4] == b'\x7fELF':
                print(f"    [+] Target appears to be ELF executable (vmlinuz?)")
            else:
                print(f"    [?] Target type unknown")
        except:
            pass
    
    def trace_msr_writes(self):
        """Monitor MSR writes (IA32_LSTAR)"""
        print("\n[*] Monitoring MSR writes...")
        try:
            # Set watchpoint on WRMSR instruction
            gdb.execute("catch syscall wrmsr")
            print("[+] MSR write monitoring enabled")
        except:
            print("[-] Could not enable MSR monitoring")
    
    def dump_boot_services_table(self):
        """Dump UEFI Boot Services Table"""
        print("\n[*] Dumping Boot Services Table...")
        try:
            # Try to find EFI_BOOT_SERVICES pointer
            # This is typically passed in RCX on x64
            bs_ptr = int(gdb.parse_and_eval("$rcx"))
            
            print(f"  Boot Services Table: 0x{bs_ptr:016x}")
            
            # Read function pointers
            offsets = {
                0x28: "RaiseTPL",
                0x30: "RestoreTPL",
                0x38: "AllocatePages",
                0x40: "FreePages",
                0x48: "GetMemoryMap",
                0x50: "AllocatePool",
                0x58: "FreePool",
                0x60: "CreateEvent",
                0x68: "SetTimer",
                0x70: "WaitForEvent",
                0x78: "SignalEvent",
                0x80: "CloseEvent",
                0x88: "CheckEvent",
                0x90: "InstallProtocolInterface",
                0x98: "ReinstallProtocolInterface",
                0xa0: "UninstallProtocolInterface",
                0xa8: "HandleProtocol",
                0xb8: "RegisterProtocolNotify",
                0xc0: "LocateHandle",
                0xc8: "LocateDevicePath",
                0xd0: "InstallConfigurationTable",
                0xd8: "LoadImage",
                0xe0: "StartImage",
                0xe8: "Exit",
                0xf0: "UnloadImage",
                0xf8: "ExitBootServices",
            }
            
            for offset, name in offsets.items():
                ptr = self.read_pointer(bs_ptr + offset)
                if ptr:
                    print(f"  [+0x{offset:03x}] {name:30s}: 0x{ptr:016x}")
        except:
            print("  [!] Could not read Boot Services Table")
    
    def interactive_mode(self):
        """Enter interactive debugging mode"""
        print("\n" + "="*60)
        print("Barzakh Interactive Debugger")
        print("="*60)
        print("\nCommands:")
        print("  continue (c)  - Continue execution")
        print("  step (s)      - Step one instruction")
        print("  next (n)      - Step over function calls")
        print("  info regs     - Show registers")
        print("  info stack    - Show stack")
        print("  info hooks    - Show hook log")
        print("  dump bs       - Dump Boot Services Table")
        print("  quit (q)      - Exit debugger")
        print("="*60 + "\n")

class ExitBootServicesBreakpoint(gdb.Breakpoint):
    """Custom breakpoint for ExitBootServices"""
    
    def __init__(self, debugger: BootkitDebugger):
        super().__init__("ExitBootServices")
        self.debugger = debugger
    
    def stop(self):
        self.debugger.analyze_hook("ExitBootServices")
        return True  # Stop execution

class LoadImageBreakpoint(gdb.Breakpoint):
    """Custom breakpoint for LoadImage"""
    
    def __init__(self, debugger: BootkitDebugger):
        super().__init__("LoadImage")
        self.debugger = debugger
    
    def stop(self):
        self.debugger.analyze_hook("LoadImage")
        return True

class StartImageBreakpoint(gdb.Breakpoint):
    """Custom breakpoint for StartImage"""
    
    def __init__(self, debugger: BootkitDebugger):
        super().__init__("StartImage")
        self.debugger = debugger
    
    def stop(self):
        self.debugger.analyze_hook("StartImage")
        return True

class SetVariableBreakpoint(gdb.Breakpoint):
    """Custom breakpoint for SetVariable"""
    
    def __init__(self, debugger: BootkitDebugger):
        super().__init__("SetVariable")
        self.debugger = debugger
    
    def stop(self):
        self.debugger.analyze_hook("SetVariable")
        return True

# GDB Commands
class BarzakhCommand(gdb.Command):
    """Barzakh debugging commands"""
    
    def __init__(self, debugger: BootkitDebugger):
        super().__init__("barzakh", gdb.COMMAND_USER)
        self.debugger = debugger
    
    def invoke(self, argument, from_tty):
        args = argument.split()
        
        if not args:
            self.debugger.interactive_mode()
            return
        
        cmd = args[0]
        
        if cmd == "setup":
            self.debugger.setup_breakpoints()
        elif cmd == "hooks":
            print("\n[*] Hook Log:")
            for i, entry in enumerate(self.debugger.hook_log):
                print(f"  [{i}] {entry['function']} @ 0x{entry['rip']:016x}")
        elif cmd == "bs":
            self.debugger.dump_boot_services_table()
        elif cmd == "msr":
            self.debugger.trace_msr_writes()
        else:
            print(f"Unknown command: {cmd}")
            print("Usage: barzakh [setup|hooks|bs|msr]")

# Initialize debugger
debugger = BootkitDebugger()
BarzakhCommand(debugger)

print("\n" + "="*60)
print("Barzakh GDB Debugger Loaded")
print("="*60)
print("\nType 'barzakh setup' to configure breakpoints")
print("Type 'barzakh' for interactive mode")
print("="*60 + "\n")


