"""
Hook Analyzer — Analyzes bootkit hook handlers symbolically.

Determines: what service is hooked, what filtering logic is applied,
what modifications are made, and under what conditions the hook
activates vs passes through.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .engine import ExecutionPath, ExecutionState, MemoryWrite, SymbolicEngine
from .efi_environment import EfiEnvironment, ServiceCall
from .path_explorer import PathExplorer, PathSummary
from .constraint_solver import Constraint, ConstraintSolver


@dataclass
class HookBehavior:
    """Describes the behavior of a single hook handler."""
    hooked_service: str
    hook_address: int
    original_handler: int = 0
    filter_conditions: List[str] = field(default_factory=list)
    modifications: List[Dict] = field(default_factory=list)
    passthrough_paths: int = 0
    intercept_paths: int = 0
    calls_original: bool = False
    persistence_mechanism: str = ""


@dataclass
class HookChain:
    """A chain of hooks (hook A calls hook B calls original)."""
    service: str
    chain: List[HookBehavior] = field(default_factory=list)
    total_depth: int = 0


class HookAnalyzer:
    """
    Analyzes bootkit hook handlers to determine their behavior.

    For each detected hook:
    1. Symbolically execute the hook handler
    2. Identify filtering logic (what inputs cause activation)
    3. Identify modifications (what gets changed)
    4. Determine if original handler is called (passthrough)
    """

    def __init__(self):
        self._hooks: List[HookBehavior] = []
        self._chains: List[HookChain] = []

    @property
    def hooks(self) -> List[HookBehavior]:
        return list(self._hooks)

    @property
    def hook_count(self) -> int:
        return len(self._hooks)

    def analyze_hook(self, hook_code: bytes, hook_address: int,
                     service_name: str, original_handler: int = 0,
                     max_paths: int = 32) -> HookBehavior:
        """
        Analyze a single hook handler.

        Args:
            hook_code: Raw bytes of the hook handler
            hook_address: Address where hook is installed
            service_name: Name of the hooked service
            original_handler: Address of the original handler
            max_paths: Maximum paths to explore
        """
        engine = SymbolicEngine()
        env = EfiEnvironment()

        entry = engine.load_binary(hook_code, hook_address)

        engine._init_emulator(entry)
        env.setup_tables(engine._uc)

        for addr, handler in env.get_service_stubs().items():
            engine.register_service_handler(addr, handler)

        if original_handler:
            def orig_handler(uc, addr):
                return 0
            engine.register_service_handler(original_handler, orig_handler)

        explorer = PathExplorer(engine, env)
        paths = explorer.explore(entry, max_paths)

        behavior = self._analyze_paths(
            paths, service_name, hook_address, original_handler, env
        )
        self._hooks.append(behavior)
        return behavior

    def analyze_from_memory(self, engine: SymbolicEngine,
                            hook_address: int, size: int,
                            service_name: str,
                            original_handler: int = 0) -> HookBehavior:
        """Analyze a hook using code already loaded in the engine."""
        code = engine.get_memory_region(hook_address, size)
        return self.analyze_hook(
            code, hook_address, service_name, original_handler
        )

    def detect_persistence(self, behavior: HookBehavior,
                           paths: List[PathSummary]) -> str:
        """Detect persistence mechanisms from path analysis."""
        for path in paths:
            for call in path.services_called:
                if 'SetVariable' in call:
                    return 'nvram_variable'
                if 'InstallProtocol' in call:
                    return 'protocol_registration'

            for write in path.memory_writes:
                if 0x7C00 <= write.address <= 0x7E00:
                    return 'mbr_modification'
                if write.address >= 0xFF000000:
                    return 'spi_flash_write'

        return 'memory_only'

    def detect_evasion(self, behavior: HookBehavior,
                       paths: List[PathSummary]) -> List[str]:
        """Detect evasion techniques from path behavior."""
        evasions = []

        if behavior.passthrough_paths > 0 and behavior.intercept_paths > 0:
            evasions.append('conditional_activation')

        if behavior.filter_conditions:
            evasions.append('input_filtering')

        for path in paths:
            for call in path.services_called:
                if 'SetTimer' in call:
                    evasions.append('timer_based_delay')
                    break
                if 'Stall' in call:
                    evasions.append('execution_stalling')
                    break

        return evasions

    def build_chain(self, service_name: str) -> HookChain:
        """Build the full hook chain for a service."""
        chain_hooks = [h for h in self._hooks
                       if h.hooked_service == service_name]

        chain = HookChain(
            service=service_name,
            chain=chain_hooks,
            total_depth=len(chain_hooks),
        )
        self._chains.append(chain)
        return chain

    def _analyze_paths(self, paths: List[PathSummary],
                       service_name: str, hook_address: int,
                       original_handler: int,
                       env: EfiEnvironment) -> HookBehavior:
        """Analyze explored paths to determine hook behavior."""
        passthrough = 0
        intercept = 0
        modifications = []
        filters = []

        for path in paths:
            is_passthrough = self._path_calls_original(
                path, original_handler)
            if is_passthrough:
                passthrough += 1
            else:
                intercept += 1

            for write in path.memory_writes:
                modifications.append({
                    'address': write.address,
                    'value': write.value,
                    'size': write.size,
                    'pc': write.pc,
                    'path_id': path.path_id,
                })

        calls_original = passthrough > 0

        if passthrough > 0 and intercept > 0:
            filters.append(
                f"Conditional: {intercept}/{passthrough + intercept} "
                f"paths intercept"
            )

        persistence = self.detect_persistence(
            HookBehavior(hooked_service=service_name,
                         hook_address=hook_address),
            paths
        )

        return HookBehavior(
            hooked_service=service_name,
            hook_address=hook_address,
            original_handler=original_handler,
            filter_conditions=filters,
            modifications=modifications,
            passthrough_paths=passthrough,
            intercept_paths=intercept,
            calls_original=calls_original,
            persistence_mechanism=persistence,
        )

    def _path_calls_original(self, path: PathSummary,
                             original_handler: int) -> bool:
        """Check if a path calls the original service handler."""
        if not original_handler:
            return False
        addr_str = f"0x{original_handler:x}"
        for svc in path.services_called:
            if addr_str in svc:
                return True
        return False

    def summary(self) -> Dict:
        """Analysis summary."""
        services_hooked = set(h.hooked_service for h in self._hooks)
        total_mods = sum(len(h.modifications) for h in self._hooks)

        return {
            'total_hooks_analyzed': len(self._hooks),
            'services_hooked': list(services_hooked),
            'total_modifications': total_mods,
            'hooks_with_filtering': sum(
                1 for h in self._hooks if h.filter_conditions),
            'hooks_calling_original': sum(
                1 for h in self._hooks if h.calls_original),
            'persistence_mechanisms': list(set(
                h.persistence_mechanism for h in self._hooks
                if h.persistence_mechanism)),
        }
