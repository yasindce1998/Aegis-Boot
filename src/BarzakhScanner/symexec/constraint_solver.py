"""
Constraint Solver — Z3-based path condition solving.

Determines feasibility of execution paths and synthesizes concrete
inputs that satisfy path conditions.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False


@dataclass
class Constraint:
    """A single constraint on a symbolic variable."""
    variable: str
    operation: str  # eq, neq, lt, gt, le, ge, and, or, bitmask
    value: int = 0
    bits: int = 64

    def __str__(self) -> str:
        return f"{self.variable} {self.operation} 0x{self.value:x}"


@dataclass
class SolverResult:
    """Result from constraint solving."""
    satisfiable: bool
    model: Dict[str, int] = field(default_factory=dict)
    unsat_core: List[str] = field(default_factory=list)


class ConstraintSolver:
    """
    Z3-based constraint solver for path feasibility.

    Determines whether a set of path conditions can be simultaneously
    satisfied, and if so, provides concrete values for all symbolic vars.
    """

    def __init__(self):
        self._variables: Dict[str, Any] = {}
        self._constraints: List[Constraint] = []
        self._solver = None
        if HAS_Z3:
            self._solver = z3.Solver()

    @property
    def has_backend(self) -> bool:
        return HAS_Z3

    @property
    def constraint_count(self) -> int:
        return len(self._constraints)

    def declare_variable(self, name: str, bits: int = 64):
        """Declare a symbolic bitvector variable."""
        if not HAS_Z3:
            self._variables[name] = None
            return

        var = z3.BitVec(name, bits)
        self._variables[name] = var

    def add_constraint(self, constraint: Constraint):
        """Add a constraint to the solver."""
        self._constraints.append(constraint)

        if not HAS_Z3:
            return

        if constraint.variable not in self._variables:
            self.declare_variable(constraint.variable, constraint.bits)

        var = self._variables[constraint.variable]
        value = z3.BitVecVal(constraint.value, constraint.bits)

        if constraint.operation == 'eq':
            self._solver.add(var == value)
        elif constraint.operation == 'neq':
            self._solver.add(var != value)
        elif constraint.operation == 'lt':
            self._solver.add(z3.ULT(var, value))
        elif constraint.operation == 'gt':
            self._solver.add(z3.UGT(var, value))
        elif constraint.operation == 'le':
            self._solver.add(z3.ULE(var, value))
        elif constraint.operation == 'ge':
            self._solver.add(z3.UGE(var, value))
        elif constraint.operation == 'bitmask':
            self._solver.add((var & value) != z3.BitVecVal(0, constraint.bits))

    def add_equality(self, var_name: str, value: int, bits: int = 64):
        """Shorthand: variable == value."""
        self.add_constraint(Constraint(var_name, 'eq', value, bits))

    def add_inequality(self, var_name: str, value: int, bits: int = 64):
        """Shorthand: variable != value."""
        self.add_constraint(Constraint(var_name, 'neq', value, bits))

    def add_range(self, var_name: str, low: int, high: int, bits: int = 64):
        """Constrain variable to [low, high]."""
        self.add_constraint(Constraint(var_name, 'ge', low, bits))
        self.add_constraint(Constraint(var_name, 'le', high, bits))

    def check(self) -> SolverResult:
        """Check satisfiability of all constraints."""
        if not HAS_Z3:
            return SolverResult(
                satisfiable=True,
                model={name: 0 for name in self._variables},
            )

        result = self._solver.check()
        if result == z3.sat:
            model = self._solver.model()
            concrete = {}
            for name, var in self._variables.items():
                val = model.evaluate(var)
                try:
                    concrete[name] = val.as_long()
                except Exception:
                    concrete[name] = 0
            return SolverResult(satisfiable=True, model=concrete)
        else:
            return SolverResult(satisfiable=False)

    def check_with_assumption(self, var_name: str, value: int,
                               bits: int = 64) -> SolverResult:
        """Check if constraints are satisfiable with an additional assumption."""
        if not HAS_Z3:
            return SolverResult(satisfiable=True,
                                model={var_name: value})

        self._solver.push()
        if var_name not in self._variables:
            self.declare_variable(var_name, bits)
        var = self._variables[var_name]
        self._solver.add(var == z3.BitVecVal(value, bits))
        result = self.check()
        self._solver.pop()
        return result

    def find_all_solutions(self, var_name: str, max_solutions: int = 10
                           ) -> List[int]:
        """Find all possible values for a variable."""
        if not HAS_Z3 or var_name not in self._variables:
            return [0]

        solutions = []
        var = self._variables[var_name]
        self._solver.push()

        for _ in range(max_solutions):
            if self._solver.check() != z3.sat:
                break
            model = self._solver.model()
            val = model.evaluate(var)
            try:
                concrete = val.as_long()
            except Exception:
                break
            solutions.append(concrete)
            self._solver.add(var != z3.BitVecVal(concrete, var.size()))

        self._solver.pop()
        return solutions

    def reset(self):
        """Reset solver state."""
        self._variables = {}
        self._constraints = []
        if HAS_Z3:
            self._solver = z3.Solver()

    def get_path_condition_string(self) -> str:
        """Human-readable representation of all constraints."""
        if not self._constraints:
            return "true (unconstrained)"
        parts = [str(c) for c in self._constraints]
        return " && ".join(parts)

    def summary(self) -> Dict:
        """Solver state summary."""
        return {
            'variables': list(self._variables.keys()),
            'constraint_count': len(self._constraints),
            'has_z3_backend': HAS_Z3,
        }
