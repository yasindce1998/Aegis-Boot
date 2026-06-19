"""
Unit tests for the UEFI Symbolic Execution module (Phase 8).

Tests the symbolic engine, EFI environment, path explorer,
constraint solver, hook analyzer, and behavior report components.
"""

import struct
import tempfile
from pathlib import Path
from unittest import TestCase, skipUnless

try:
    import unicorn
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

from src.BarzakhScanner.symexec import (
    SymbolicEngine,
    EfiEnvironment,
    PathExplorer,
    ConstraintSolver,
    BehaviorReportBuilder,
    HookAnalyzer,
)
from src.BarzakhScanner.symexec.engine import (
    ExecutionPath,
    ExecutionState,
    MemoryWrite,
)
from src.BarzakhScanner.symexec.efi_environment import (
    EfiStatus,
    ServiceCall,
    ProtocolInstall,
)
from src.BarzakhScanner.symexec.path_explorer import (
    PathCondition,
    PathSummary,
)
from src.BarzakhScanner.symexec.constraint_solver import (
    Constraint,
    SolverResult,
)
from src.BarzakhScanner.symexec.hook_analyzer import (
    HookBehavior,
    HookChain,
)
from src.BarzakhScanner.symexec.behavior_report import (
    BehaviorFinding,
    BehaviorReport,
)


class TestSymbolicEngineConstants(TestCase):
    """Test engine constants and configuration."""

    def test_code_base(self):
        self.assertEqual(SymbolicEngine.CODE_BASE, 0x10000000)

    def test_stack_base(self):
        self.assertEqual(SymbolicEngine.STACK_BASE, 0x7FFF0000)

    def test_heap_base(self):
        self.assertEqual(SymbolicEngine.HEAP_BASE, 0x80000000)

    def test_max_instructions(self):
        self.assertEqual(SymbolicEngine.MAX_INSTRUCTIONS, 100000)

    def test_max_paths(self):
        self.assertEqual(SymbolicEngine.MAX_PATHS, 64)


@skipUnless(HAS_UNICORN, "unicorn not installed")
class TestSymbolicEngine(TestCase):
    """Test the core symbolic execution engine."""

    def test_engine_creation(self):
        engine = SymbolicEngine()
        self.assertIsNotNone(engine)

    def test_load_binary(self):
        code = b'\xc3'  # RET instruction
        engine = SymbolicEngine()
        entry = engine.load_binary(code)
        self.assertEqual(entry, SymbolicEngine.CODE_BASE)

    def test_load_binary_custom_address(self):
        code = b'\xc3'
        engine = SymbolicEngine()
        entry = engine.load_binary(code, 0x20000000)
        self.assertEqual(entry, 0x20000000)

    def test_register_service_handler(self):
        engine = SymbolicEngine()
        code = b'\xc3'
        engine.load_binary(code)
        handler_called = []

        def my_handler(uc, addr):
            handler_called.append(addr)
            return 0

        engine.register_service_handler(0x50000000, my_handler)
        self.assertIn(0x50000000, engine._service_handlers)


class TestExecutionState(TestCase):
    """Test ExecutionState enum values."""

    def test_states_exist(self):
        self.assertIsNotNone(ExecutionState.RUNNING)
        self.assertIsNotNone(ExecutionState.HALTED)
        self.assertIsNotNone(ExecutionState.ERROR)
        self.assertIsNotNone(ExecutionState.TIMEOUT)


class TestMemoryWrite(TestCase):
    """Test MemoryWrite dataclass."""

    def test_memory_write_creation(self):
        write = MemoryWrite(
            address=0x1000,
            size=8,
            value=0xDEADBEEF,
            pc=0x10000010,
            is_symbolic=False,
        )
        self.assertEqual(write.address, 0x1000)
        self.assertEqual(write.size, 8)
        self.assertEqual(write.value, 0xDEADBEEF)
        self.assertEqual(write.pc, 0x10000010)
        self.assertFalse(write.is_symbolic)

    def test_memory_write_symbolic(self):
        write = MemoryWrite(
            address=0x2000,
            size=4,
            value=0,
            pc=0x10000020,
            is_symbolic=True,
        )
        self.assertTrue(write.is_symbolic)


class TestEfiEnvironment(TestCase):
    """Test EFI environment modeling."""

    def test_environment_creation(self):
        env = EfiEnvironment()
        self.assertIsNotNone(env)
        self.assertEqual(len(env.service_calls), 0)
        self.assertEqual(len(env.allocations), 0)

    def test_bst_base_address(self):
        self.assertEqual(EfiEnvironment.BST_BASE, 0x7EF00000)

    def test_rst_base_address(self):
        self.assertEqual(EfiEnvironment.RST_BASE, 0x7EF10000)

    def test_system_table_base_address(self):
        self.assertEqual(EfiEnvironment.SYSTEM_TABLE_BASE, 0x7EF20000)

    def test_bst_services_populated(self):
        self.assertGreater(len(EfiEnvironment.BST_SERVICES), 0)
        self.assertIn(0x40, EfiEnvironment.BST_SERVICES)
        self.assertEqual(EfiEnvironment.BST_SERVICES[0x40][0], "AllocatePool")

    def test_rst_services_populated(self):
        self.assertGreater(len(EfiEnvironment.RST_SERVICES), 0)
        self.assertIn(0x48, EfiEnvironment.RST_SERVICES)
        self.assertEqual(EfiEnvironment.RST_SERVICES[0x48][0], "GetVariable")

    def test_get_bst_address(self):
        env = EfiEnvironment()
        self.assertEqual(env.get_bst_address(), 0x7EF00000)

    def test_get_rst_address(self):
        env = EfiEnvironment()
        self.assertEqual(env.get_rst_address(), 0x7EF10000)

    def test_get_system_table_address(self):
        env = EfiEnvironment()
        self.assertEqual(env.get_system_table_address(), 0x7EF20000)

    def test_service_stubs(self):
        env = EfiEnvironment()
        stubs = env.get_service_stubs()
        self.assertGreater(len(stubs), 0)
        for addr, handler in stubs.items():
            self.assertTrue(callable(handler))

    def test_summary_empty(self):
        env = EfiEnvironment()
        summary = env.summary()
        self.assertEqual(summary['total_service_calls'], 0)
        self.assertEqual(summary['unique_services_called'], 0)
        self.assertEqual(summary['total_allocations'], 0)


class TestEfiStatus(TestCase):
    """Test EFI status code constants."""

    def test_success(self):
        self.assertEqual(EfiStatus.SUCCESS, 0)

    def test_invalid_parameter(self):
        self.assertEqual(EfiStatus.INVALID_PARAMETER, 0x8000000000000002)

    def test_not_found(self):
        self.assertEqual(EfiStatus.NOT_FOUND, 0x800000000000000E)


class TestServiceCall(TestCase):
    """Test ServiceCall dataclass."""

    def test_service_call_creation(self):
        call = ServiceCall(
            service_name="AllocatePool",
            bst_offset=0x40,
            arguments=[1, 0x100, 0x80000000],
            return_value=0,
            caller_pc=0x10000020,
        )
        self.assertEqual(call.service_name, "AllocatePool")
        self.assertEqual(call.bst_offset, 0x40)
        self.assertEqual(call.return_value, 0)


class TestPathExplorer(TestCase):
    """Test path exploration."""

    def test_path_summary_creation(self):
        summary = PathSummary(
            path_id=0,
            depth=1,
            instructions=10,
            state=ExecutionState.HALTED,
        )
        self.assertEqual(summary.path_id, 0)
        self.assertEqual(summary.depth, 1)
        self.assertEqual(summary.instructions, 10)
        self.assertEqual(summary.state, ExecutionState.HALTED)
        self.assertEqual(summary.hooks_installed, [])
        self.assertEqual(summary.memory_writes, [])

    def test_path_summary_to_dict(self):
        summary = PathSummary(
            path_id=1,
            depth=2,
            instructions=50,
            state=ExecutionState.HALTED,
            services_called=['svc_0x40'],
        )
        d = summary.to_dict()
        self.assertEqual(d['path_id'], 1)
        self.assertEqual(d['depth'], 2)
        self.assertEqual(d['instructions'], 50)
        self.assertEqual(d['state'], 'HALTED')
        self.assertEqual(d['services_called'], ['svc_0x40'])

    def test_path_condition_creation(self):
        cond = PathCondition(
            pc=0x10000050,
            condition="ZF==1",
            taken=True,
            symbolic_var="ret_AllocatePool",
        )
        self.assertEqual(cond.pc, 0x10000050)
        self.assertTrue(cond.taken)


class TestConstraintSolver(TestCase):
    """Test constraint solving."""

    def test_solver_creation(self):
        solver = ConstraintSolver()
        self.assertIsNotNone(solver)
        self.assertEqual(solver.constraint_count, 0)

    def test_declare_variable(self):
        solver = ConstraintSolver()
        solver.declare_variable("x", 64)
        self.assertIn("x", solver._variables)

    def test_add_equality_constraint(self):
        solver = ConstraintSolver()
        solver.add_equality("x", 42)
        self.assertEqual(solver.constraint_count, 1)

    def test_add_inequality_constraint(self):
        solver = ConstraintSolver()
        solver.add_inequality("x", 0)
        self.assertEqual(solver.constraint_count, 1)

    def test_add_range_constraint(self):
        solver = ConstraintSolver()
        solver.add_range("x", 10, 100)
        self.assertEqual(solver.constraint_count, 2)

    @skipUnless(HAS_Z3, "z3 not installed")
    def test_check_satisfiable(self):
        solver = ConstraintSolver()
        solver.add_equality("x", 42)
        result = solver.check()
        self.assertTrue(result.satisfiable)
        self.assertIn("x", result.model)

    def test_check_unsatisfiable(self):
        solver = ConstraintSolver()
        solver.add_equality("x", 42)
        solver.add_equality("x", 99)
        result = solver.check()
        if solver.has_backend:
            self.assertFalse(result.satisfiable)

    def test_constraint_str(self):
        c = Constraint(variable="rax", operation="eq", value=0x100, bits=64)
        s = str(c)
        self.assertIn("rax", s)
        self.assertIn("eq", s)

    def test_solver_result_creation(self):
        result = SolverResult(satisfiable=True, model={"x": 42})
        self.assertTrue(result.satisfiable)
        self.assertEqual(result.model["x"], 42)

    def test_reset(self):
        solver = ConstraintSolver()
        solver.add_equality("x", 1)
        solver.reset()
        self.assertEqual(solver.constraint_count, 0)

    def test_path_condition_string_empty(self):
        solver = ConstraintSolver()
        s = solver.get_path_condition_string()
        self.assertIn("unconstrained", s)

    def test_path_condition_string_with_constraints(self):
        solver = ConstraintSolver()
        solver.add_equality("x", 42)
        s = solver.get_path_condition_string()
        self.assertIn("x", s)

    def test_summary(self):
        solver = ConstraintSolver()
        solver.declare_variable("a")
        solver.declare_variable("b")
        summary = solver.summary()
        self.assertEqual(summary['constraint_count'], 0)
        self.assertIn('a', summary['variables'])
        self.assertIn('b', summary['variables'])


class TestHookAnalyzer(TestCase):
    """Test hook analysis."""

    def test_analyzer_creation(self):
        analyzer = HookAnalyzer()
        self.assertEqual(analyzer.hook_count, 0)
        self.assertEqual(analyzer.hooks, [])

    def test_hook_behavior_creation(self):
        hook = HookBehavior(
            hooked_service="LoadImage",
            hook_address=0x10001000,
            original_handler=0x7EF00800,
            calls_original=True,
            persistence_mechanism="nvram_variable",
        )
        self.assertEqual(hook.hooked_service, "LoadImage")
        self.assertEqual(hook.hook_address, 0x10001000)
        self.assertTrue(hook.calls_original)
        self.assertEqual(hook.persistence_mechanism, "nvram_variable")

    def test_hook_chain_creation(self):
        chain = HookChain(service="LoadImage", total_depth=2)
        self.assertEqual(chain.service, "LoadImage")
        self.assertEqual(chain.total_depth, 2)
        self.assertEqual(chain.chain, [])

    def test_detect_persistence_mbr(self):
        analyzer = HookAnalyzer()
        paths = [
            PathSummary(
                path_id=0, depth=1, instructions=10,
                state=ExecutionState.HALTED,
                memory_writes=[
                    MemoryWrite(address=0x7C00, size=512, value=0, pc=0x1000, is_symbolic=False)
                ],
            )
        ]
        hook = HookBehavior(hooked_service="test", hook_address=0x1000)
        result = analyzer.detect_persistence(hook, paths)
        self.assertEqual(result, 'mbr_modification')

    def test_detect_persistence_spi(self):
        analyzer = HookAnalyzer()
        paths = [
            PathSummary(
                path_id=0, depth=1, instructions=10,
                state=ExecutionState.HALTED,
                memory_writes=[
                    MemoryWrite(address=0xFF000100, size=4, value=0, pc=0x1000, is_symbolic=False)
                ],
            )
        ]
        hook = HookBehavior(hooked_service="test", hook_address=0x1000)
        result = analyzer.detect_persistence(hook, paths)
        self.assertEqual(result, 'spi_flash_write')

    def test_detect_evasion_conditional(self):
        analyzer = HookAnalyzer()
        hook = HookBehavior(
            hooked_service="test", hook_address=0x1000,
            passthrough_paths=2, intercept_paths=1,
            filter_conditions=["check_guid"],
        )
        evasions = analyzer.detect_evasion(hook, [])
        self.assertIn('conditional_activation', evasions)
        self.assertIn('input_filtering', evasions)

    def test_summary_empty(self):
        analyzer = HookAnalyzer()
        summary = analyzer.summary()
        self.assertEqual(summary['total_hooks_analyzed'], 0)
        self.assertEqual(summary['services_hooked'], [])


class TestBehaviorReport(TestCase):
    """Test behavior report generation."""

    def test_report_creation(self):
        report = BehaviorReport()
        self.assertEqual(report.binary_name, "")
        self.assertEqual(report.findings, [])
        self.assertFalse(report.is_bootkit)
        self.assertEqual(report.confidence, 0.0)

    def test_add_finding(self):
        report = BehaviorReport()
        report.add_finding(
            category='hook',
            severity=4,
            title='BST hook: LoadImage',
            description='Installs hook on LoadImage',
        )
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].category, 'hook')
        self.assertEqual(report.findings[0].severity, 4)

    def test_critical_findings(self):
        report = BehaviorReport()
        report.add_finding('hook', 4, 'Critical', 'desc')
        report.add_finding('info', 0, 'Info', 'desc')
        self.assertEqual(len(report.critical_findings), 1)

    def test_high_findings(self):
        report = BehaviorReport()
        report.add_finding('hook', 4, 'Critical', 'desc')
        report.add_finding('persist', 3, 'High', 'desc')
        report.add_finding('info', 0, 'Info', 'desc')
        self.assertEqual(len(report.high_findings), 2)

    def test_to_dict(self):
        report = BehaviorReport(
            binary_name='test.efi',
            binary_size=1024,
            entry_point=0x10000000,
            is_bootkit=True,
            confidence=0.85,
        )
        d = report.to_dict()
        self.assertEqual(d['binary_name'], 'test.efi')
        self.assertEqual(d['binary_size'], 1024)
        self.assertEqual(d['entry_point'], '0x10000000')
        self.assertTrue(d['is_bootkit'])
        self.assertEqual(d['confidence'], 0.85)

    def test_text_summary(self):
        report = BehaviorReport(
            binary_name='bootkit.efi',
            binary_size=2048,
            entry_point=0x10000000,
            is_bootkit=True,
            confidence=0.9,
            paths_explored=5,
            hooks_detected=2,
            techniques=['transparent_hook'],
        )
        report.add_finding('hook', 4, 'BST Hook', 'Hooks LoadImage')
        text = report.text_summary()
        self.assertIn('bootkit.efi', text)
        self.assertIn('BOOTKIT DETECTED', text)
        self.assertIn('transparent_hook', text)
        self.assertIn('BST Hook', text)


class TestBehaviorReportBuilder(TestCase):
    """Test report builder."""

    def test_builder_creation(self):
        builder = BehaviorReportBuilder()
        self.assertIsNotNone(builder)

    def test_set_binary_info(self):
        builder = BehaviorReportBuilder()
        builder.set_binary_info('test.efi', 1024, 0x10000000)
        report = builder.build()
        self.assertEqual(report.binary_name, 'test.efi')
        self.assertEqual(report.binary_size, 1024)
        self.assertEqual(report.entry_point, 0x10000000)

    def test_compute_verdict_clean(self):
        builder = BehaviorReportBuilder()
        builder.set_binary_info('clean.efi', 512, 0x10000000)
        report = builder.build()
        self.assertFalse(report.is_bootkit)
        self.assertEqual(report.confidence, 0.0)

    def test_finding_creation(self):
        finding = BehaviorFinding(
            category='hook',
            severity=4,
            title='Test Finding',
            description='A test finding',
            evidence={'key': 'value'},
        )
        self.assertEqual(finding.category, 'hook')
        self.assertEqual(finding.severity, 4)
        self.assertEqual(finding.evidence['key'], 'value')
