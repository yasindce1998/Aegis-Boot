"""
Unit tests for the Live UEFI Introspection Engine (Phase 6).

Tests cover:
- QMP client protocol handling
- Memory watcher change detection
- Breakpoint engine GDB protocol
- Event stream classification
- Live detector heuristics
- Introspection runner orchestration

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from AegisScanner.introspection.qemu_monitor import QMPClient, QMPError
from AegisScanner.introspection.memory_watch import (
    MemoryWatcher, MemoryRegion, MemoryChange, ChangeType,
)
from AegisScanner.introspection.breakpoint_engine import (
    BreakpointEngine, Breakpoint, BreakpointHit, BreakpointType, GDBProtocolError,
)
from AegisScanner.introspection.event_stream import (
    EventStream, EventType, IntrospectionEvent, Severity,
)
from AegisScanner.introspection.live_detector import LiveDetector, LiveFinding
from AegisScanner.introspection.introspection_runner import (
    IntrospectionRunner, IntrospectionConfig,
)


class TestQMPClient(unittest.TestCase):
    """Test QMP client protocol handling."""

    def test_init_socket_path(self):
        client = QMPClient(socket_path="/tmp/qemu.sock")
        self.assertEqual(client._socket_path, "/tmp/qemu.sock")
        self.assertEqual(client._host, "localhost")

    def test_init_tcp(self):
        client = QMPClient(host="127.0.0.1", port=5555)
        self.assertIsNone(client._socket_path)
        self.assertEqual(client._host, "127.0.0.1")
        self.assertEqual(client._port, 5555)

    def test_parse_xp_output(self):
        client = QMPClient(host="localhost", port=4444)
        # xp outputs 32-bit words in little-endian hex
        output = "0000000007f00000: 0x6c6c6548 0x0000006f"
        result = client._parse_xp_output(output, 8)
        self.assertEqual(result, b'Hello\x00\x00\x00')

    def test_parse_registers_output(self):
        client = QMPClient(host="localhost", port=4444)
        output = (
            "RAX=0000000007f0a000 RBX=0000000000000001 RCX=0000000007f0b000\n"
            "RDX=0000000000000000 RSI=0000000000000010 RDI=0000000007e50000\n"
            "RIP=0000000007c00100 RSP=0000000007f0fff0 RBP=0000000007f0ffe0\n"
        )
        regs = client._parse_registers(output)
        # Implementation lowercases register names
        self.assertEqual(regs['rax'], 0x07f0a000)
        self.assertEqual(regs['rip'], 0x07c00100)
        self.assertEqual(regs['rsp'], 0x07f0fff0)

    def test_disconnect_without_connect(self):
        client = QMPClient(host="localhost", port=4444)
        client.disconnect()  # Should not raise


class TestMemoryWatcher(unittest.TestCase):
    """Test memory polling and change detection."""

    def setUp(self):
        self.mock_qmp = MagicMock(spec=QMPClient)
        self.watcher = MemoryWatcher(self.mock_qmp)

    def test_add_region(self):
        region = MemoryRegion(name="test", base_address=0x7000000, size=0x100)
        self.watcher.add_region(region)
        self.assertIn("test", self.watcher._regions)

    def test_remove_region(self):
        region = MemoryRegion(name="test", base_address=0x7000000, size=0x100)
        self.watcher.add_region(region)
        self.watcher.remove_region("test")
        self.assertNotIn("test", self.watcher._regions)

    def test_add_bst_watch(self):
        self.watcher.add_bst_watch(0x7F00000)
        self.assertIn("BST", self.watcher._regions)
        region = self.watcher._regions["BST"]
        self.assertEqual(region.base_address, 0x7F00000)
        self.assertEqual(region.size, 0x1B0)
        self.assertIn(0xC0, region.pointer_offsets)  # LoadImage

    def test_bst_offsets_coverage(self):
        self.assertIn(0x40, MemoryWatcher.BST_OFFSETS)  # RaiseTPL
        self.assertIn(0xE0, MemoryWatcher.BST_OFFSETS)  # ExitBootServices
        self.assertIn(0xC0, MemoryWatcher.BST_OFFSETS)  # LoadImage
        self.assertIn(0xC8, MemoryWatcher.BST_OFFSETS)  # StartImage

    def test_detect_pointer_change(self):
        self.watcher.add_bst_watch(0x7F00000)

        # Initial snapshot
        original_bst = b'\x00' * 0x1B0
        # Set LoadImage pointer at offset 0xC0
        original_bst = (
            original_bst[:0xC0]
            + struct.pack('<Q', 0x7100000)
            + original_bst[0xC8:]
        )
        self.mock_qmp.read_physical_memory.return_value = original_bst
        self.watcher.take_snapshot("BST")

        # Modified BST - LoadImage hooked
        modified_bst = (
            original_bst[:0xC0]
            + struct.pack('<Q', 0xDEADBEEF)
            + original_bst[0xC8:]
        )
        self.mock_qmp.read_physical_memory.return_value = modified_bst
        changes = self.watcher.check_changes()

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change_type, ChangeType.POINTER_MODIFIED)
        self.assertEqual(changes[0].offset, 0xC0)
        self.assertEqual(changes[0].new_value_int, 0xDEADBEEF)

    def test_no_changes_detected(self):
        region = MemoryRegion(name="static", base_address=0x1000, size=64,
                              pointer_offsets=[0, 8, 16])
        self.watcher.add_region(region)
        data = b'\x42' * 64
        self.mock_qmp.read_physical_memory.return_value = data
        self.watcher.take_snapshot("static")

        # Same data - no changes
        changes = self.watcher.check_changes()
        self.assertEqual(len(changes), 0)

    def test_detect_code_injection(self):
        region = MemoryRegion(
            name="runtime", base_address=0x5000000, size=32,
            detect_code_injection=True,
        )
        self.watcher.add_region(region)

        original = b'\x00' * 32
        self.mock_qmp.read_physical_memory.return_value = original
        self.watcher.take_snapshot("runtime")

        # Inject MOV RAX pattern
        injected = b'\x48\xb8' + struct.pack('<Q', 0xDEAD) + b'\xff\xe0' + b'\x00' * 18
        self.mock_qmp.read_physical_memory.return_value = injected
        changes = self.watcher.check_changes()

        code_changes = [c for c in changes if c.change_type == ChangeType.CODE_INJECTED]
        self.assertGreater(len(code_changes), 0)

    def test_get_bst_pointers(self):
        self.watcher.add_bst_watch(0x7F00000)
        bst_data = b'\x00' * 0x1B0
        # Set a few pointers
        bst_data = bytearray(bst_data)
        struct.pack_into('<Q', bst_data, 0xC0, 0x7100000)  # LoadImage
        struct.pack_into('<Q', bst_data, 0xC8, 0x7100100)  # StartImage
        struct.pack_into('<Q', bst_data, 0xE0, 0x7100200)  # ExitBootServices
        self.mock_qmp.read_physical_memory.return_value = bytes(bst_data)

        pointers = self.watcher.get_bst_pointers()
        self.assertEqual(pointers["LoadImage"], 0x7100000)
        self.assertEqual(pointers["StartImage"], 0x7100100)
        self.assertEqual(pointers["ExitBootServices"], 0x7100200)

    def test_callback_invoked(self):
        callback = MagicMock()
        self.watcher.add_callback(callback)
        self.watcher.add_bst_watch(0x7F00000)

        original = b'\x00' * 0x1B0
        original = bytearray(original)
        struct.pack_into('<Q', original, 0xC0, 0x7100000)
        self.mock_qmp.read_physical_memory.return_value = bytes(original)
        self.watcher.take_snapshot("BST")

        modified = bytearray(original)
        struct.pack_into('<Q', modified, 0xC0, 0xBADC0DE)
        self.mock_qmp.read_physical_memory.return_value = bytes(modified)
        self.watcher.check_changes()

        callback.assert_called_once()
        change = callback.call_args[0][0]
        self.assertEqual(change.change_type, ChangeType.POINTER_MODIFIED)


class TestBreakpointEngine(unittest.TestCase):
    """Test GDB protocol integration."""

    def test_init(self):
        engine = BreakpointEngine(host="127.0.0.1", port=9999)
        self.assertEqual(engine._host, "127.0.0.1")
        self.assertEqual(engine._port, 9999)
        self.assertFalse(engine.connected)

    def test_breakpoint_type_values(self):
        self.assertEqual(BreakpointType.SOFTWARE.value, 0)
        self.assertEqual(BreakpointType.HARDWARE_EXEC.value, 1)
        self.assertEqual(BreakpointType.HARDWARE_WRITE.value, 2)
        self.assertEqual(BreakpointType.HARDWARE_READ.value, 3)
        self.assertEqual(BreakpointType.HARDWARE_ACCESS.value, 4)

    def test_parse_x86_64_registers(self):
        # RAX = 0x0000000007f0a000 in little-endian hex
        rax_le = struct.pack('<Q', 0x07f0a000).hex()
        rbx_le = struct.pack('<Q', 0x00000001).hex()
        rcx_le = struct.pack('<Q', 0x07f0b000).hex()
        rdx_le = struct.pack('<Q', 0x00000000).hex()
        # Fill remaining registers
        remaining = '00' * 16 * 14  # 14 more registers

        hex_data = rax_le + rbx_le + rcx_le + rdx_le + remaining
        regs = BreakpointEngine._parse_x86_64_registers(hex_data)

        self.assertEqual(regs['rax'], 0x07f0a000)
        self.assertEqual(regs['rbx'], 0x00000001)
        self.assertEqual(regs['rcx'], 0x07f0b000)

    def test_disconnect_without_connect(self):
        engine = BreakpointEngine()
        engine.disconnect()  # Should not raise

    def test_operations_require_connection(self):
        engine = BreakpointEngine()
        with self.assertRaises(GDBProtocolError):
            engine.add_breakpoint(0x1000)
        with self.assertRaises(GDBProtocolError):
            engine.continue_execution()
        with self.assertRaises(GDBProtocolError):
            engine.read_registers()


class TestEventStream(unittest.TestCase):
    """Test event processing and classification."""

    def setUp(self):
        self.stream = EventStream()

    def test_emit_custom_event(self):
        event = self.stream.emit_custom(
            EventType.VM_STATE_CHANGE,
            Severity.INFO,
            "VM paused",
        )
        self.assertEqual(event.event_type, EventType.VM_STATE_CHANGE)
        self.assertEqual(event.severity, Severity.INFO)
        self.assertEqual(len(self.stream.get_events()), 1)

    def test_subscribe(self):
        received = []
        self.stream.subscribe(lambda e: received.append(e))
        self.stream.emit_custom(EventType.VM_STATE_CHANGE, Severity.INFO, "test")
        self.assertEqual(len(received), 1)

    def test_filter(self):
        self.stream.add_filter(lambda e: e.severity == Severity.CRITICAL)
        self.stream.emit_custom(EventType.VM_STATE_CHANGE, Severity.INFO, "filtered out")
        self.stream.emit_custom(EventType.CODE_INJECTION, Severity.CRITICAL, "passes filter")
        self.assertEqual(len(self.stream.get_events()), 1)
        self.assertEqual(self.stream.get_events()[0].event_type, EventType.CODE_INJECTION)

    def test_process_memory_change_pointer(self):
        change = MemoryChange(
            region_name="BST",
            address=0x7F000C0,
            offset=0xC0,  # LoadImage
            change_type=ChangeType.POINTER_MODIFIED,
            old_value=struct.pack('<Q', 0x7100000),
            new_value=struct.pack('<Q', 0xDEADBEEF),
            timestamp=time.time(),
        )
        event = self.stream.process_memory_change(change)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, EventType.BST_HOOK_INSTALLED)
        self.assertEqual(event.severity, Severity.CRITICAL)  # LoadImage is high-value

    def test_process_memory_change_code_injection(self):
        change = MemoryChange(
            region_name="runtime",
            address=0x5000000,
            offset=0,
            change_type=ChangeType.CODE_INJECTED,
            old_value=b'\x00' * 16,
            new_value=b'\x48\xb8' + struct.pack('<Q', 0xDEAD) + b'\xff\xe0\x00\x00\x00\x00',
            timestamp=time.time(),
        )
        event = self.stream.process_memory_change(change)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, EventType.CODE_INJECTION)
        self.assertEqual(event.severity, Severity.CRITICAL)

    def test_process_breakpoint_hit(self):
        bp = Breakpoint(bp_id=1, address=0x7100000, bp_type=BreakpointType.HARDWARE_WRITE,
                        label="BST.LoadImage")
        hit = BreakpointHit(
            breakpoint=bp, pc=0x7100000,
            registers={'rax': 0xDEAD, 'rip': 0x7100000},
            timestamp=time.time(),
        )
        event = self.stream.process_breakpoint_hit(hit)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, EventType.BREAKPOINT_HIT)

    def test_get_events_filter_by_type(self):
        self.stream.emit_custom(EventType.VM_STATE_CHANGE, Severity.INFO, "a")
        self.stream.emit_custom(EventType.CODE_INJECTION, Severity.CRITICAL, "b")
        self.stream.emit_custom(EventType.VM_STATE_CHANGE, Severity.INFO, "c")

        results = self.stream.get_events(event_type=EventType.CODE_INJECTION)
        self.assertEqual(len(results), 1)

    def test_get_events_filter_by_severity(self):
        self.stream.emit_custom(EventType.VM_STATE_CHANGE, Severity.INFO, "low")
        self.stream.emit_custom(EventType.CODE_INJECTION, Severity.CRITICAL, "high")

        results = self.stream.get_events(min_severity=Severity.HIGH)
        self.assertEqual(len(results), 1)

    def test_get_stats(self):
        self.stream.emit_custom(EventType.VM_STATE_CHANGE, Severity.INFO, "a")
        self.stream.emit_custom(EventType.VM_STATE_CHANGE, Severity.INFO, "b")
        stats = self.stream.get_stats()
        self.assertEqual(stats['total_events'], 2)
        self.assertEqual(stats['by_type']['vm_state_change'], 2)

    def test_clear(self):
        self.stream.emit_custom(EventType.VM_STATE_CHANGE, Severity.INFO, "test")
        self.stream.clear()
        self.assertEqual(len(self.stream.get_events()), 0)

    def test_high_value_bst_hooks(self):
        self.assertIn("LoadImage", EventStream.HIGH_VALUE_BST_HOOKS)
        self.assertIn("StartImage", EventStream.HIGH_VALUE_BST_HOOKS)
        self.assertIn("ExitBootServices", EventStream.HIGH_VALUE_BST_HOOKS)
        self.assertIn("SetVariable", EventStream.HIGH_VALUE_BST_HOOKS)
        self.assertIn("GetVariable", EventStream.HIGH_VALUE_BST_HOOKS)


class TestLiveDetector(unittest.TestCase):
    """Test real-time detection heuristics."""

    def setUp(self):
        self.stream = EventStream()
        self.detector = LiveDetector(self.stream)

    def test_set_baseline(self):
        pointers = {"LoadImage": 0x7100000, "StartImage": 0x7100100}
        self.detector.set_baseline(pointers)
        self.assertEqual(self.detector._baseline_pointers["LoadImage"], 0x7100000)

    def test_detect_bst_hook(self):
        self.detector.set_baseline({"LoadImage": 0x7100000})

        change = MemoryChange(
            region_name="BST",
            address=0x7F000C0,
            offset=0xC0,
            change_type=ChangeType.POINTER_MODIFIED,
            old_value=struct.pack('<Q', 0x7100000),
            new_value=struct.pack('<Q', 0x1000000),  # Outside legitimate range
            timestamp=time.time(),
        )
        finding = self.detector.analyze_memory_change(change)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")
        self.assertIn("LoadImage", finding.title)
        self.assertEqual(finding.mitre_id, "T1542.001")

    def test_legitimate_pointer_change_not_flagged(self):
        change = MemoryChange(
            region_name="BST",
            address=0x7F000C0,
            offset=0xC0,
            change_type=ChangeType.POINTER_MODIFIED,
            old_value=struct.pack('<Q', 0x7100000),
            new_value=struct.pack('<Q', 0x7200000),  # Within legitimate range
            timestamp=time.time(),
        )
        finding = self.detector.analyze_memory_change(change)
        self.assertIsNone(finding)

    def test_detect_code_injection(self):
        shellcode = b'\x48\xb8' + struct.pack('<Q', 0xDEADBEEF) + b'\xff\xe0' + b'\x00' * 18
        change = MemoryChange(
            region_name="runtime",
            address=0x5000000,
            offset=0,
            change_type=ChangeType.CODE_INJECTED,
            old_value=b'\x00' * 32,
            new_value=shellcode,
            timestamp=time.time(),
        )
        finding = self.detector.analyze_memory_change(change)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.mitre_id, "T1055.012")

    def test_detect_pe_injection(self):
        pe_data = b'MZ' + b'\x90' * 62
        change = MemoryChange(
            region_name="runtime",
            address=0x5000000,
            offset=0,
            change_type=ChangeType.DATA_WRITTEN,
            old_value=b'\x00' * 64,
            new_value=pe_data,
            timestamp=time.time(),
        )
        finding = self.detector.analyze_memory_change(change)
        self.assertIsNotNone(finding)
        self.assertIn("PE Image", finding.title)

    def test_small_data_write_not_flagged(self):
        change = MemoryChange(
            region_name="runtime",
            address=0x5000000,
            offset=0,
            change_type=ChangeType.DATA_WRITTEN,
            old_value=b'\x00' * 4,
            new_value=b'\x42' * 4,
            timestamp=time.time(),
        )
        finding = self.detector.analyze_memory_change(change)
        self.assertIsNone(finding)

    def test_check_trampoline_mov_rax_jmp(self):
        # MOV RAX, imm64; JMP RAX
        trampoline = b'\x48\xb8' + struct.pack('<Q', 0xCAFEBABE) + b'\xff\xe0'
        finding = self.detector.check_trampoline(trampoline, 0x7100000)
        self.assertIsNotNone(finding)
        self.assertIn("mov_rax_jmp", finding.title)
        self.assertEqual(finding.mitre_id, "T1574.013")

    def test_check_trampoline_jmp_rip_rel(self):
        # JMP [RIP+offset]
        trampoline = b'\xff\x25' + struct.pack('<i', 0x100) + b'\x00\x00'
        finding = self.detector.check_trampoline(trampoline, 0x7100000)
        self.assertIsNotNone(finding)
        self.assertIn("jmp_rip_rel", finding.title)

    def test_no_trampoline_in_normal_data(self):
        normal_data = b'\x00' * 16
        finding = self.detector.check_trampoline(normal_data, 0x7100000)
        self.assertIsNone(finding)

    def test_get_summary(self):
        # Trigger a finding
        change = MemoryChange(
            region_name="runtime",
            address=0x5000000,
            offset=0,
            change_type=ChangeType.CODE_INJECTED,
            old_value=b'\x00' * 32,
            new_value=b'\x48\xb8' + b'\x00' * 30,
            timestamp=time.time(),
        )
        self.detector.analyze_memory_change(change)

        summary = self.detector.get_summary()
        self.assertEqual(summary['total_findings'], 1)
        self.assertIn('critical', summary['by_severity'])

    def test_analyze_bst_hook_event(self):
        event = IntrospectionEvent(
            event_type=EventType.BST_HOOK_INSTALLED,
            severity=Severity.CRITICAL,
            timestamp=time.time(),
            description="BST hook on LoadImage",
            address=0x7F000C0,
            details={"function": "LoadImage", "new_pointer": "0xdeadbeef"},
        )
        finding = self.detector.analyze_event(event)
        self.assertIsNotNone(finding)
        self.assertIn("LoadImage", finding.title)


class TestIntrospectionRunner(unittest.TestCase):
    """Test the orchestrator."""

    def test_default_config(self):
        config = IntrospectionConfig()
        self.assertEqual(config.qmp_host, "localhost")
        self.assertEqual(config.qmp_port, 4444)
        self.assertEqual(config.gdb_port, 1234)
        self.assertEqual(config.poll_interval, 0.5)
        self.assertTrue(config.use_gdb)

    def test_runner_init(self):
        runner = IntrospectionRunner()
        self.assertFalse(runner.is_running)
        self.assertIsNone(runner.events)
        self.assertIsNone(runner.detector)

    @patch('AegisScanner.introspection.introspection_runner.QMPClient')
    @patch('AegisScanner.introspection.introspection_runner.BreakpointEngine')
    def test_connect_success(self, mock_gdb_cls, mock_qmp_cls):
        mock_qmp = MagicMock()
        mock_qmp_cls.return_value = mock_qmp

        mock_gdb = MagicMock()
        mock_gdb_cls.return_value = mock_gdb

        runner = IntrospectionRunner()
        result = runner.connect()

        self.assertTrue(result)
        self.assertIsNotNone(runner.events)
        self.assertIsNotNone(runner.detector)

    @patch('AegisScanner.introspection.introspection_runner.QMPClient')
    def test_connect_failure(self, mock_qmp_cls):
        mock_qmp_cls.return_value.connect.side_effect = QMPError("Connection refused")

        runner = IntrospectionRunner()
        result = runner.connect()

        self.assertFalse(result)

    @patch('AegisScanner.introspection.introspection_runner.QMPClient')
    @patch('AegisScanner.introspection.introspection_runner.BreakpointEngine')
    def test_setup_monitoring_with_bst(self, mock_gdb_cls, mock_qmp_cls):
        mock_qmp = MagicMock()
        mock_qmp_cls.return_value = mock_qmp
        mock_qmp.read_physical_memory.return_value = b'\x00' * 0x1B0

        mock_gdb = MagicMock()
        mock_gdb_cls.return_value = mock_gdb

        runner = IntrospectionRunner()
        runner.connect()
        result = runner.setup_monitoring(bst_address=0x7F00000)

        self.assertTrue(result)

    @patch('AegisScanner.introspection.introspection_runner.QMPClient')
    @patch('AegisScanner.introspection.introspection_runner.BreakpointEngine')
    def test_poll_once(self, mock_gdb_cls, mock_qmp_cls):
        mock_qmp = MagicMock()
        mock_qmp_cls.return_value = mock_qmp

        mock_gdb = MagicMock()
        mock_gdb_cls.return_value = mock_gdb

        # Setup with BST that doesn't change
        bst_data = b'\x00' * 0x1B0
        mock_qmp.read_physical_memory.return_value = bst_data

        runner = IntrospectionRunner()
        runner.connect()
        runner.setup_monitoring(bst_address=0x7F00000)

        findings = runner.poll_once()
        self.assertEqual(len(findings), 0)

    @patch('AegisScanner.introspection.introspection_runner.QMPClient')
    @patch('AegisScanner.introspection.introspection_runner.BreakpointEngine')
    def test_stop_returns_summary(self, mock_gdb_cls, mock_qmp_cls):
        mock_qmp = MagicMock()
        mock_qmp_cls.return_value = mock_qmp
        mock_qmp.read_physical_memory.return_value = b'\x00' * 0x1B0

        mock_gdb = MagicMock()
        mock_gdb.halted = False
        mock_gdb_cls.return_value = mock_gdb

        config = IntrospectionConfig(session_timeout=1.0, poll_interval=0.2)
        runner = IntrospectionRunner(config)
        runner.connect()
        runner.setup_monitoring(bst_address=0x7F00000)
        runner.start()
        time.sleep(0.5)
        summary = runner.stop()

        self.assertIn('session', summary)
        self.assertIn('findings', summary)
        self.assertIn('findings_count', summary)
        self.assertEqual(summary['findings_count'], 0)

    def test_bst_search_ranges(self):
        self.assertGreater(len(IntrospectionRunner.BST_SEARCH_RANGES), 0)
        for start, end in IntrospectionRunner.BST_SEARCH_RANGES:
            self.assertLess(start, end)


class TestEventTypes(unittest.TestCase):
    """Test event type enumeration completeness."""

    def test_all_event_types_defined(self):
        expected = [
            'BST_HOOK_INSTALLED', 'BST_HOOK_REMOVED', 'CODE_INJECTION',
            'MEMORY_TAMPER', 'NEW_DRIVER_LOADED', 'PCR_EXTEND',
            'SECURE_BOOT_BYPASS', 'RUNTIME_SERVICE_HOOK', 'SMM_CALLOUT',
            'SUSPICIOUS_ALLOC', 'BREAKPOINT_HIT', 'VM_STATE_CHANGE',
        ]
        for name in expected:
            self.assertTrue(hasattr(EventType, name))

    def test_severity_ordering(self):
        severities = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        self.assertEqual(len(severities), 5)

    def test_event_to_dict(self):
        event = IntrospectionEvent(
            event_type=EventType.CODE_INJECTION,
            severity=Severity.CRITICAL,
            timestamp=1000.0,
            description="test injection",
            address=0xDEAD,
            details={"key": "value"},
            source="test",
        )
        d = event.to_dict()
        self.assertEqual(d['type'], 'code_injection')
        self.assertEqual(d['severity'], 'critical')
        self.assertEqual(d['address'], '0xdead')
        self.assertEqual(d['details'], {"key": "value"})

    def test_live_finding_to_dict(self):
        finding = LiveFinding(
            title="Test Finding",
            severity="high",
            description="Test description",
            evidence={"addr": "0x1000"},
            timestamp=1000.0,
            detector="test_detector",
            mitre_id="T1542.001",
        )
        d = finding.to_dict()
        self.assertEqual(d['title'], "Test Finding")
        self.assertEqual(d['mitre_id'], "T1542.001")
        self.assertEqual(d['detector'], "test_detector")


if __name__ == '__main__':
    unittest.main()
