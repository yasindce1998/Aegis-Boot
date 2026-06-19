"""
Path Explorer — Enumerates execution paths through EFI binaries.

Manages path forking at conditional branches and tracks path
constraints for each explored execution path.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .engine import ExecutionPath, ExecutionState, MemoryWrite, SymbolicEngine
from .efi_environment import EfiEnvironment


@dataclass
class PathCondition:
    """A condition that must hold for this path to be taken."""
    pc: int
    condition: str
    taken: bool
    symbolic_var: str = ""


@dataclass
class PathSummary:
    """Summary of an explored execution path."""
    path_id: int
    depth: int
    instructions: int
    state: ExecutionState
    conditions: List[PathCondition] = field(default_factory=list)
    memory_writes: List[MemoryWrite] = field(default_factory=list)
    services_called: List[str] = field(default_factory=list)
    hooks_installed: List[Dict] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict:
        return {
            'path_id': self.path_id,
            'depth': self.depth,
            'instructions': self.instructions,
            'state': self.state.name,
            'num_conditions': len(self.conditions),
            'num_writes': len(self.memory_writes),
            'services_called': self.services_called,
            'hooks_installed': self.hooks_installed,
            'error': self.error,
        }


class PathExplorer:
    """
    Explores all feasible execution paths through a binary.

    Strategy: single-path concrete execution with symbolic return values.
    At each service call that returns a symbolic value, fork the path
    with different concrete instantiations (SUCCESS vs error codes).
    """

    MAX_PATHS = 64
    MAX_DEPTH = 32

    def __init__(self, engine: SymbolicEngine, environment: EfiEnvironment):
        self._engine = engine
        self._env = environment
        self._explored: List[PathSummary] = []
        self._worklist: List[Tuple[int, List[PathCondition]]] = []

    @property
    def explored_paths(self) -> List[PathSummary]:
        return list(self._explored)

    @property
    def path_count(self) -> int:
        return len(self._explored)

    def explore(self, entry_point: int, max_paths: int = 0,
                max_instructions: int = 0) -> List[PathSummary]:
        """Explore paths from entry point."""
        if max_paths == 0:
            max_paths = self.MAX_PATHS

        for addr, handler in self._env.get_service_stubs().items():
            self._engine.register_service_handler(addr, handler)

        paths = self._engine.execute(entry_point, max_instructions)

        for path in paths:
            summary = self._summarize_path(path)
            self._explored.append(summary)
            if len(self._explored) >= max_paths:
                break

        return self._explored

    def explore_from_file(self, binary_path: Path, max_paths: int = 0) -> List[PathSummary]:
        """Load and explore a binary file."""
        entry = self._engine.load_pe(binary_path)
        return self.explore(entry, max_paths)

    def explore_from_bytes(self, data: bytes, max_paths: int = 0) -> List[PathSummary]:
        """Explore raw binary code."""
        entry = self._engine.load_binary(data)
        return self.explore(entry, max_paths)

    def get_hook_paths(self) -> List[PathSummary]:
        """Return paths where hooks were installed."""
        return [p for p in self._explored if p.hooks_installed]

    def get_write_paths(self) -> List[PathSummary]:
        """Return paths that performed memory writes."""
        return [p for p in self._explored if p.memory_writes]

    def get_error_paths(self) -> List[PathSummary]:
        """Return paths that ended in error."""
        return [p for p in self._explored
                if p.state == ExecutionState.ERROR]

    def get_service_coverage(self) -> Dict[str, int]:
        """Return how many paths called each service."""
        coverage = {}
        for path in self._explored:
            for svc in path.services_called:
                coverage[svc] = coverage.get(svc, 0) + 1
        return coverage

    def _summarize_path(self, path: ExecutionPath) -> PathSummary:
        """Summarize an execution path."""
        services = [call.get('address', 0) for call in path.service_calls]
        service_names = []
        for call in path.service_calls:
            if 'result' in call:
                service_names.append(f"svc_0x{call['address']:x}")
            else:
                service_names.append(f"svc_0x{call.get('address', 0):x}")

        hooks = self._detect_hooks(path)

        return PathSummary(
            path_id=path.path_id,
            depth=path.depth,
            instructions=path.instructions_executed,
            state=path.state,
            memory_writes=path.memory_writes,
            services_called=service_names,
            hooks_installed=hooks,
            error=path.error_message,
        )

    def _detect_hooks(self, path: ExecutionPath) -> List[Dict]:
        """Detect BST/RST hook installations from memory writes."""
        hooks = []
        bst_base = self._env.get_bst_address()
        bst_end = bst_base + 0x200

        for write in path.memory_writes:
            if bst_base <= write.address < bst_end:
                offset = write.address - bst_base
                service_info = EfiEnvironment.BST_SERVICES.get(offset)
                service_name = service_info[0] if service_info else f"offset_0x{offset:x}"
                hooks.append({
                    'type': 'bst_hook',
                    'offset': offset,
                    'service': service_name,
                    'new_handler': write.value,
                    'installing_pc': write.pc,
                })

        return hooks

    def summary(self) -> Dict:
        """Overall exploration summary."""
        states = {}
        for p in self._explored:
            name = p.state.name
            states[name] = states.get(name, 0) + 1

        total_hooks = sum(len(p.hooks_installed) for p in self._explored)
        total_writes = sum(len(p.memory_writes) for p in self._explored)

        return {
            'total_paths': len(self._explored),
            'path_states': states,
            'total_hooks_detected': total_hooks,
            'total_memory_writes': total_writes,
            'service_coverage': self.get_service_coverage(),
        }
