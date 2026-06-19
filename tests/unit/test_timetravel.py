"""
Unit tests for the Time-Travel Debugging module (Phase 7).

Tests the trace format, recorder, replayer, analyzer, and timeline
components of the timetravel package.
"""

import struct
import tempfile
import time
from pathlib import Path
from unittest import TestCase

from src.AegisScanner.timetravel.trace_format import (
    EVENT_SIZE,
    EVENT_STRUCT,
    HEADER_SIZE,
    HEADER_STRUCT,
    TRACE_MAGIC,
    TRACE_VERSION,
    Architecture,
    MemoryAccessType,
    TraceEvent,
    TraceEventType,
    TraceHeader,
    TraceReader,
    TraceWriter,
)
from src.AegisScanner.timetravel.recorder import (
    RecordingConfig,
    TraceRecorder,
)
from src.AegisScanner.timetravel.replayer import (
    ReplayState,
    TraceReplayer,
)
from src.AegisScanner.timetravel.trace_analyzer import (
    AnalysisResult,
    MemoryRegionStats,
    TraceAnalyzer,
)
from src.AegisScanner.timetravel.timeline import (
    Timeline,
    TimelineEvent,
    TimelineEventKind,
)


class TestTraceFormat(TestCase):
    """Test binary trace format constants and structures."""

    def test_magic_bytes(self):
        self.assertEqual(TRACE_MAGIC, b'AGTT')

    def test_version(self):
        self.assertEqual(TRACE_VERSION, 1)

    def test_event_size_is_48(self):
        self.assertEqual(EVENT_SIZE, 48)

    def test_header_size_is_56(self):
        self.assertEqual(HEADER_SIZE, 56)

    def test_event_struct_calcsize(self):
        self.assertEqual(EVENT_STRUCT.size, 48)

    def test_header_struct_calcsize(self):
        self.assertEqual(HEADER_STRUCT.size, 56)


class TestTraceEventType(TestCase):
    """Test TraceEventType enumeration."""

    def test_instruction_is_zero(self):
        self.assertEqual(TraceEventType.INSTRUCTION, 0)

    def test_memory_write_is_one(self):
        self.assertEqual(TraceEventType.MEMORY_WRITE, 1)

    def test_bst_access_is_seven(self):
        self.assertEqual(TraceEventType.BST_ACCESS, 7)

    def test_marker_is_twelve(self):
        self.assertEqual(TraceEventType.MARKER, 12)

    def test_all_types_unique(self):
        values = [e.value for e in TraceEventType]
        self.assertEqual(len(values), len(set(values)))


class TestMemoryAccessType(TestCase):
    """Test MemoryAccessType enumeration."""

    def test_byte_is_one(self):
        self.assertEqual(MemoryAccessType.BYTE, 1)

    def test_qword_is_eight(self):
        self.assertEqual(MemoryAccessType.QWORD, 8)


class TestTraceHeader(TestCase):
    """Test TraceHeader serialization."""

    def test_pack_unpack_roundtrip(self):
        header = TraceHeader(
            start_time_ns=1234567890,
            arch=Architecture.X86_64,
            event_count=100,
            bst_address=0x7FFE0000,
            first_pc=0x1000,
        )
        data = header.pack()
        self.assertEqual(len(data), HEADER_SIZE)
        restored = TraceHeader.unpack(data)
        self.assertEqual(restored.magic, TRACE_MAGIC)
        self.assertEqual(restored.version, TRACE_VERSION)
        self.assertEqual(restored.arch, Architecture.X86_64)
        self.assertEqual(restored.start_time_ns, 1234567890)
        self.assertEqual(restored.event_count, 100)
        self.assertEqual(restored.bst_address, 0x7FFE0000)
        self.assertEqual(restored.first_pc, 0x1000)

    def test_invalid_magic_raises(self):
        bad_data = b'XXXX' + b'\x00' * (HEADER_SIZE - 4)
        with self.assertRaises(ValueError):
            TraceHeader.unpack(bad_data)

    def test_architecture_enum(self):
        self.assertEqual(Architecture.X86_64, 0)
        self.assertEqual(Architecture.AARCH64, 1)
        self.assertEqual(Architecture.RISCV64, 2)


class TestTraceEvent(TestCase):
    """Test TraceEvent serialization."""

    def test_pack_unpack_roundtrip(self):
        event = TraceEvent(
            timestamp_ns=5000,
            event_type=TraceEventType.MEMORY_WRITE,
            access_type=MemoryAccessType.QWORD,
            flags=0,
            pc=0xDEAD0000,
            address=0x7FFE00C0,
            value=0xCAFEBABE,
            aux_data=0x11111111,
        )
        data = event.pack()
        self.assertEqual(len(data), EVENT_SIZE)
        restored = TraceEvent.unpack(data)
        self.assertEqual(restored.timestamp_ns, 5000)
        self.assertEqual(restored.event_type, TraceEventType.MEMORY_WRITE)
        self.assertEqual(restored.access_type, MemoryAccessType.QWORD)
        self.assertEqual(restored.pc, 0xDEAD0000)
        self.assertEqual(restored.address, 0x7FFE00C0)
        self.assertEqual(restored.value, 0xCAFEBABE)
        self.assertEqual(restored.aux_data, 0x11111111)

    def test_is_memory_write(self):
        event = TraceEvent(
            timestamp_ns=0,
            event_type=TraceEventType.MEMORY_WRITE,
        )
        self.assertTrue(event.is_memory_write)
        self.assertFalse(event.is_bst_access)

    def test_is_bst_access(self):
        event = TraceEvent(
            timestamp_ns=0,
            event_type=TraceEventType.BST_ACCESS,
        )
        self.assertTrue(event.is_bst_access)
        self.assertFalse(event.is_memory_write)


class TestTraceWriterReader(TestCase):
    """Test TraceWriter and TraceReader I/O."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.agtt', delete=False)
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_write_read_single_event(self):
        header = TraceHeader(start_time_ns=1000, bst_address=0x8000)
        event = TraceEvent(
            timestamp_ns=2000,
            event_type=TraceEventType.INSTRUCTION,
            pc=0x1000,
            value=0x90,
        )
        with TraceWriter(self.path, header) as writer:
            writer.write_event(event)
            self.assertEqual(writer.event_count, 1)

        with TraceReader(self.path) as reader:
            h = reader.header
            self.assertEqual(h.event_count, 1)
            self.assertEqual(h.bst_address, 0x8000)
            ev = reader.read_event()
            self.assertIsNotNone(ev)
            self.assertEqual(ev.timestamp_ns, 2000)
            self.assertEqual(ev.pc, 0x1000)
            end = reader.read_event()
            self.assertIsNone(end)

    def test_write_read_multiple_events(self):
        header = TraceHeader(start_time_ns=0)
        events = [
            TraceEvent(timestamp_ns=i * 100,
                       event_type=TraceEventType.INSTRUCTION,
                       pc=0x1000 + i)
            for i in range(10)
        ]
        with TraceWriter(self.path, header) as writer:
            for ev in events:
                writer.write_event(ev)

        with TraceReader(self.path) as reader:
            self.assertEqual(reader.event_count, 10)
            read_events = list(reader.iter_events())
            self.assertEqual(len(read_events), 10)
            self.assertEqual(read_events[5].pc, 0x1005)

    def test_seek_event(self):
        header = TraceHeader(start_time_ns=0)
        with TraceWriter(self.path, header) as writer:
            for i in range(20):
                writer.write_event(TraceEvent(
                    timestamp_ns=i,
                    event_type=TraceEventType.INSTRUCTION,
                    pc=i * 0x10,
                ))

        with TraceReader(self.path) as reader:
            ev = reader.seek_event(15)
            self.assertIsNotNone(ev)
            self.assertEqual(ev.pc, 15 * 0x10)


class TestRecordingConfig(TestCase):
    """Test RecordingConfig."""

    def test_default_values(self):
        cfg = RecordingConfig()
        self.assertEqual(cfg.qemu_binary, "qemu-system-x86_64")
        self.assertEqual(cfg.memory_mb, 256)
        self.assertTrue(cfg.record_replay)
        self.assertEqual(cfg.qmp_port, 4445)

    def test_trace_path(self):
        cfg = RecordingConfig(output_dir="/tmp", trace_name="test")
        self.assertEqual(cfg.trace_path, Path("/tmp/test.agtt"))

    def test_replay_log_path(self):
        cfg = RecordingConfig(output_dir="/tmp", trace_name="test")
        self.assertEqual(cfg.replay_log_path, Path("/tmp/test.rr"))


class TestTraceRecorder(TestCase):
    """Test TraceRecorder functionality."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = RecordingConfig(
            output_dir=self.tmpdir,
            trace_name="unit_test",
            bst_address=0x7FFE0000,
        )
        self.recorder = TraceRecorder(self.config)

    def tearDown(self):
        if self.recorder.is_recording:
            self.recorder.stop_recording()
        trace_path = Path(self.tmpdir) / "unit_test.agtt"
        trace_path.unlink(missing_ok=True)

    def test_start_stop(self):
        self.assertFalse(self.recorder.is_recording)
        self.recorder.start_recording()
        self.assertTrue(self.recorder.is_recording)
        result = self.recorder.stop_recording()
        self.assertFalse(self.recorder.is_recording)
        self.assertIn("trace_path", result)
        self.assertEqual(result["event_count"], 0)

    def test_record_events(self):
        self.recorder.start_recording()
        self.recorder.record_instruction(0x1000, 0x90)
        self.recorder.record_instruction(0x1001, 0xCC)
        self.recorder.record_memory_write(0x1002, 0x8000, 0xDEAD, size=8)
        result = self.recorder.stop_recording()
        self.assertEqual(result["event_count"], 3)

    def test_record_bst_modification(self):
        self.recorder.start_recording()
        self.recorder.record_bst_modification(
            pc=0x2000, offset=0xC0,
            old_value=0x11111111, new_value=0x22222222,
        )
        result = self.recorder.stop_recording()
        self.assertEqual(result["event_count"], 1)

    def test_callback_invoked(self):
        captured = []
        self.recorder.add_callback(lambda ev: captured.append(ev))
        self.recorder.start_recording()
        self.recorder.record_instruction(0x1000)
        self.recorder.stop_recording()
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].pc, 0x1000)

    def test_take_snapshot(self):
        self.recorder.start_recording()
        self.recorder.take_snapshot({"LoadImage": 0x1111, "StartImage": 0x2222})
        snapshots = self.recorder.get_snapshots()
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["LoadImage"], 0x1111)
        self.recorder.stop_recording()

    def test_build_qemu_command(self):
        cmd = self.recorder.build_qemu_command()
        self.assertIn("qemu-system-x86_64", cmd)
        self.assertIn("-m", cmd)
        self.assertIn("256", cmd)
        self.assertIn("-icount", cmd)
        self.assertIn("-nographic", cmd)


class TestReplayState(TestCase):
    """Test ReplayState."""

    def test_default_state(self):
        state = ReplayState()
        self.assertEqual(state.event_index, 0)
        self.assertFalse(state.bst_modified)

    def test_bst_modified(self):
        state = ReplayState(bst_pointers={0xC0: 0x1234})
        self.assertTrue(state.bst_modified)

    def test_memory_at(self):
        state = ReplayState(memory={0x8000: 42})
        self.assertEqual(state.memory_at(0x8000), 42)
        self.assertIsNone(state.memory_at(0x9000))

    def test_clone(self):
        state = ReplayState(
            event_index=5,
            memory={0x100: 0xFF},
            bst_pointers={0xC0: 0xAA},
        )
        clone = state.clone()
        self.assertEqual(clone.event_index, 5)
        clone.memory[0x200] = 0xBB
        self.assertNotIn(0x200, state.memory)


class TestTraceReplayer(TestCase):
    """Test TraceReplayer."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.agtt', delete=False)
        self.tmp.close()
        self.path = Path(self.tmp.name)
        self._write_test_trace()

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def _write_test_trace(self):
        header = TraceHeader(
            start_time_ns=0,
            bst_address=0x7FFE0000,
        )
        events = [
            TraceEvent(timestamp_ns=100, event_type=TraceEventType.INSTRUCTION,
                       pc=0x1000),
            TraceEvent(timestamp_ns=200, event_type=TraceEventType.INSTRUCTION,
                       pc=0x1004),
            TraceEvent(timestamp_ns=300, event_type=TraceEventType.MEMORY_WRITE,
                       access_type=MemoryAccessType.QWORD,
                       pc=0x1008, address=0x8000, value=0xDEAD),
            TraceEvent(timestamp_ns=400, event_type=TraceEventType.BST_ACCESS,
                       access_type=MemoryAccessType.QWORD,
                       pc=0x100C, address=0x7FFE00C0, value=0xCAFE,
                       aux_data=0x1111),
            TraceEvent(timestamp_ns=500, event_type=TraceEventType.INSTRUCTION,
                       pc=0x1010),
        ]
        with TraceWriter(self.path, header) as writer:
            for ev in events:
                writer.write_event(ev)

    def test_open_close(self):
        replayer = TraceReplayer(self.path)
        header = replayer.open()
        self.assertEqual(header.bst_address, 0x7FFE0000)
        self.assertEqual(replayer.total_events, 5)
        replayer.close()

    def test_step(self):
        with TraceReplayer(self.path) as replayer:
            ev = replayer.step()
            self.assertEqual(ev.pc, 0x1000)
            self.assertEqual(replayer.current_index, 1)

    def test_step_n(self):
        with TraceReplayer(self.path) as replayer:
            events = replayer.step_n(3)
            self.assertEqual(len(events), 3)
            self.assertEqual(replayer.current_index, 3)

    def test_run_to_bst_write(self):
        with TraceReplayer(self.path) as replayer:
            ev = replayer.run_to_bst_write()
            self.assertIsNotNone(ev)
            self.assertEqual(ev.event_type, TraceEventType.BST_ACCESS)
            self.assertEqual(ev.value, 0xCAFE)

    def test_state_tracking(self):
        with TraceReplayer(self.path) as replayer:
            replayer.run_to_index(5)
            state = replayer.state
            self.assertEqual(state.memory.get(0x8000), 0xDEAD)
            self.assertTrue(state.bst_modified)
            self.assertEqual(state.bst_pointers.get(0xC0), 0xCAFE)

    def test_run_to_memory_write(self):
        with TraceReplayer(self.path) as replayer:
            ev = replayer.run_to_memory_write(0x8000)
            self.assertIsNotNone(ev)
            self.assertEqual(ev.value, 0xDEAD)

    def test_find_first_write_to(self):
        with TraceReplayer(self.path) as replayer:
            result = replayer.find_first_write_to(0x7FFE00C0)
            self.assertIsNotNone(result)
            idx, ev = result
            self.assertEqual(ev.value, 0xCAFE)

    def test_find_bst_modifications(self):
        with TraceReplayer(self.path) as replayer:
            mods = replayer.find_bst_modifications()
            self.assertEqual(len(mods), 1)
            self.assertEqual(mods[0][1].value, 0xCAFE)

    def test_breakpoint(self):
        with TraceReplayer(self.path) as replayer:
            replayer.add_breakpoint(0x1008)
            ev = replayer.run_to_breakpoint()
            self.assertIsNotNone(ev)
            self.assertEqual(ev.pc, 0x1008)

    def test_is_at_end(self):
        with TraceReplayer(self.path) as replayer:
            self.assertFalse(replayer.is_at_end)
            replayer.run_to_index(5)
            self.assertTrue(replayer.is_at_end)


class TestTraceAnalyzer(TestCase):
    """Test TraceAnalyzer."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.agtt', delete=False)
        self.tmp.close()
        self.path = Path(self.tmp.name)
        self._write_test_trace()
        self.analyzer = TraceAnalyzer(self.path, bst_base=0x7FFE0000)
        self.analyzer.load(cache_events=True)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def _write_test_trace(self):
        header = TraceHeader(
            start_time_ns=0,
            bst_address=0x7FFE0000,
        )
        events = [
            TraceEvent(timestamp_ns=100, event_type=TraceEventType.INSTRUCTION,
                       pc=0x1000, value=0x90),
            TraceEvent(timestamp_ns=200, event_type=TraceEventType.MEMORY_WRITE,
                       pc=0x1004, address=0x9000, value=0xAA),
            TraceEvent(timestamp_ns=300, event_type=TraceEventType.BST_ACCESS,
                       pc=0x1008, address=0x7FFE00C0, value=0xBBBB,
                       aux_data=0xAAAA),
            TraceEvent(timestamp_ns=400, event_type=TraceEventType.MEMORY_WRITE,
                       pc=0x100C, address=0xBBBB, value=0x48),
            TraceEvent(timestamp_ns=500, event_type=TraceEventType.BST_ACCESS,
                       pc=0x1010, address=0x7FFE00E0, value=0xCCCC,
                       aux_data=0xDDDD),
        ]
        with TraceWriter(self.path, header) as writer:
            for ev in events:
                writer.write_event(ev)

    def test_load(self):
        self.assertEqual(self.analyzer.event_count, 5)

    def test_find_first_bst_modification(self):
        result = self.analyzer.find_first_bst_modification()
        self.assertTrue(result.found)
        self.assertEqual(result.event_index, 2)
        self.assertEqual(result.details["service_name"], "LoadImage")
        self.assertEqual(result.details["old_value"], 0xAAAA)
        self.assertEqual(result.details["new_value"], 0xBBBB)

    def test_find_first_bst_modification_specific_offset(self):
        result = self.analyzer.find_first_bst_modification(offset=0xE0)
        self.assertTrue(result.found)
        self.assertEqual(result.event_index, 4)
        self.assertEqual(result.details["service_name"], "ExitBootServices")

    def test_find_first_bst_modification_not_found(self):
        result = self.analyzer.find_first_bst_modification(offset=0x28)
        self.assertFalse(result.found)

    def test_find_all_bst_modifications(self):
        results = self.analyzer.find_all_bst_modifications()
        self.assertEqual(len(results), 2)

    def test_find_writes_to_address(self):
        results = self.analyzer.find_writes_to_address(0x9000)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].event.value, 0xAA)

    def test_find_writes_from_pc(self):
        results = self.analyzer.find_writes_from_pc(0x1004)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].event.address, 0x9000)

    def test_find_instruction_at(self):
        result = self.analyzer.find_instruction_at(0x1000)
        self.assertIsNotNone(result)
        self.assertTrue(result.found)
        self.assertEqual(result.event.value, 0x90)

    def test_find_instruction_at_not_found(self):
        result = self.analyzer.find_instruction_at(0xFFFF)
        self.assertFalse(result.found)

    def test_analyze_memory_region(self):
        stats = self.analyzer.analyze_memory_region(0x8000, 0x2000)
        self.assertEqual(stats.write_count, 1)
        self.assertEqual(stats.first_write_index, 1)
        self.assertIn(0x1004, stats.unique_pcs)

    def test_compute_execution_profile(self):
        profile = self.analyzer.compute_execution_profile()
        self.assertEqual(profile["total_events"], 5)
        self.assertEqual(profile["bst_modifications"], 2)
        self.assertEqual(profile["first_bst_modification_index"], 2)
        self.assertGreater(profile["unique_pcs"], 0)

    def test_find_hook_installation_sequence(self):
        result = self.analyzer.find_hook_installation_sequence(0xC0)
        self.assertTrue(result["found"])
        self.assertEqual(result["service_name"], "LoadImage")
        self.assertEqual(result["old_handler"], 0xAAAA)
        self.assertEqual(result["new_handler"], 0xBBBB)
        self.assertEqual(result["modifying_pc"], 0x1008)


class TestTimeline(TestCase):
    """Test Timeline construction."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.agtt', delete=False)
        self.tmp.close()
        self.path = Path(self.tmp.name)
        self._write_test_trace()

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def _write_test_trace(self):
        header = TraceHeader(
            start_time_ns=0,
            bst_address=0x7FFE0000,
        )
        events = [
            TraceEvent(timestamp_ns=100, event_type=TraceEventType.INSTRUCTION,
                       pc=0x1000),
            TraceEvent(timestamp_ns=200, event_type=TraceEventType.BST_ACCESS,
                       pc=0x2000, address=0x7FFE00C0, value=0xAAAA,
                       aux_data=0xBBBB),
            TraceEvent(timestamp_ns=300, event_type=TraceEventType.BOOT_SERVICE_CALL,
                       pc=0x3000, value=0xE0),
            TraceEvent(timestamp_ns=400, event_type=TraceEventType.SMI_ENTRY,
                       pc=0x4000),
            TraceEvent(timestamp_ns=500, event_type=TraceEventType.MARKER,
                       pc=0x5000, value=42),
        ]
        with TraceWriter(self.path, header) as writer:
            for ev in events:
                writer.write_event(ev)

    def test_build_from_trace(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        self.assertGreater(timeline.event_count, 0)

    def test_boot_start_always_present(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        boot_events = timeline.filter_by_kind(TimelineEventKind.BOOT_START)
        self.assertEqual(len(boot_events), 1)

    def test_bst_hook_detected(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        hooks = timeline.get_hooks_installed()
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0].severity, 4)
        self.assertEqual(hooks[0].details["service_name"], "LoadImage")

    def test_exit_boot_services_detected(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        ebs = timeline.filter_by_kind(TimelineEventKind.EXIT_BOOT_SERVICES)
        self.assertEqual(len(ebs), 1)

    def test_smi_detected(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        smi = timeline.filter_by_kind(TimelineEventKind.SMI_TRIGGERED)
        self.assertEqual(len(smi), 1)
        self.assertEqual(smi[0].severity, 2)

    def test_marker_detected(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        markers = timeline.filter_by_kind(TimelineEventKind.MARKER)
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0].details["marker_id"], 42)

    def test_filter_by_severity(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        critical = timeline.filter_by_severity(4)
        self.assertEqual(len(critical), 1)

    def test_suspicious_events(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        suspicious = timeline.get_suspicious_events()
        self.assertGreater(len(suspicious), 0)

    def test_summary(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        summary = timeline.summary()
        self.assertIn("total_events", summary)
        self.assertIn("hooks_installed", summary)
        self.assertEqual(summary["hooks_installed"], 1)
        self.assertIn("LoadImage", summary["hook_targets"])

    def test_to_report(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        report = timeline.to_report()
        self.assertIsInstance(report, list)
        self.assertGreater(len(report), 0)
        self.assertIn("kind", report[0])
        self.assertIn("timestamp_ns", report[0])

    def test_build_from_events(self):
        events = [
            TraceEvent(timestamp_ns=100, event_type=TraceEventType.BST_ACCESS,
                       pc=0x1000, address=0x7FFE00C0, value=0x9999,
                       aux_data=0x1111),
        ]
        timeline = Timeline(bst_base=0x7FFE0000)
        timeline.build_from_events(events)
        hooks = timeline.get_hooks_installed()
        self.assertEqual(len(hooks), 1)

    def test_time_between(self):
        timeline = Timeline(self.path, bst_base=0x7FFE0000)
        timeline.build_from_trace()
        dt = timeline.time_between(
            TimelineEventKind.BOOT_START,
            TimelineEventKind.BST_HOOK_INSTALLED,
        )
        self.assertIsNotNone(dt)
        self.assertEqual(dt, 200)


class TestTimelineEvent(TestCase):
    """Test TimelineEvent properties."""

    def test_timestamp_conversions(self):
        ev = TimelineEvent(
            kind=TimelineEventKind.BOOT_START,
            timestamp_ns=1_000_000_000,
            event_index=0,
        )
        self.assertEqual(ev.timestamp_s, 1.0)
        self.assertEqual(ev.timestamp_ms, 1000.0)

    def test_to_dict(self):
        ev = TimelineEvent(
            kind=TimelineEventKind.BST_HOOK_INSTALLED,
            timestamp_ns=500,
            event_index=3,
            pc=0x1234,
            description="Hook installed",
            severity=4,
        )
        d = ev.to_dict()
        self.assertEqual(d["kind"], "BST_HOOK_INSTALLED")
        self.assertEqual(d["pc"], "0x1234")
        self.assertEqual(d["severity"], 4)
