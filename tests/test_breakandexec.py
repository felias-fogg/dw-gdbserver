from unittest.mock import Mock, MagicMock, patch, call, create_autospec
from unittest import TestCase
from dwgdbserver.xavrdebugger import XAvrDebugger
from dwgdbserver.dwgdbserver import GdbHandler, EndOfSession, FatalError, Memory, MonitorCommand, BreakAndExec, DebugWIRE, SIGINT, SIGTRAP, SIGHUP
from dwgdbserver.util.instr import instrmap
import logging

logging.basicConfig(level=logging.CRITICAL)

class TestBreakAndExec(TestCase):

    def setUp(self):
        mock_mon = create_autospec(MonitorCommand, specSet=True, instance=True)
        mock_dbg = create_autospec(XAvrDebugger, spec_set=False, instance=True)
        mock_dbg.memory_info = Mock()
        mock_dbg.memory_info.memory_info_by_name.return_value = {'size' : 100 }
        self.bp = BreakAndExec(1, mock_mon, mock_dbg, Mock())
        self.bp.mon.is_old_exec.return_value = False
        self.bp.mon.is_safe.return_value = True

    def test_insertBreakpoint_old_exec(self):
        self.bp.mon.is_old_exec.return_value = True
        self.assertTrue(self.bp.insertBreakpoint(2))
        self.bp.dbg.software_breakpoint_set.assert_called_with(2)
        
    def test_insertBreakpoint_impossible_hwbps(self):
        self.bp._bpactive = 1
        self.bp.mon.is_onlyhwbps.return_value = True
        self.assertFalse(self.bp.insertBreakpoint(2))

    def test_insertBreakpoint_possible_hwbps(self):
        self.bp.mon.is_onlyhwbps.return_value = True
        self.assertTrue(self.bp.insertBreakpoint(2))
        self.assertTrue(self.bp.insertBreakpoint(2))
        self.assertFalse(self.bp.insertBreakpoint(4))

    def test_insertBreakpoint_odd(self):
        self.bp.mon.is_onlyhwbps.return_value = False
        self.assertFalse(self.bp.insertBreakpoint(3))
        self.assertTrue(self.bp.insertBreakpoint(2))

    def test_insertBreakpoints_regular(self):
        self.bp.mon.is_onlyhwbps.return_value = False
        self.bp._readFlashWord.side_effect = [ 0x9598, 0x1111, 0x2222, 0x3333 ]
        self.assertTrue(self.bp.insertBreakpoint(100))
        self.assertTrue(self.bp.insertBreakpoint(200))
        self.assertEqual(self.bp._bp, {100: {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None,
                                    'opcode': 0x9598, 'secondword' : 0x1111, 'timestamp' : 1 },
                                       200:  {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None,
                                    'opcode': 0x2222, 'secondword' : 0x3333, 'timestamp' : 2 }})
        
    def test_removeBreakpoint_old_exec(self):
        self.bp.mon.is_old_exec.return_value = True
        self.bp.removeBreakpoint(2)
        self.bp.dbg.software_breakpoint_clear.assert_called_with(2)

    def test_removeBreakpoints_regular_idempotent(self):
        self.bp.mon.is_onlyhwbps.return_value = False
        self.bp._bp = {100: {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None,
                                 'opcode': 0x9598, 'secondword' : 0x1111, 'timestamp' : 1 },
                       200:  {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None,
                                  'opcode': 0x2222, 'secondword' : 0x3333, 'timestamp' : 2 }}
        self.bp._bpactive = 2
        self.bp.removeBreakpoint(100)
        self.assertEqual(self.bp._bpactive, 1)
        self.bp.removeBreakpoint(100)
        self.assertEqual(self.bp._bpactive, 1)
        self.bp.removeBreakpoint(200)
        self.assertEqual(self.bp._bpactive, 0)
        self.bp.removeBreakpoint(200)
        self.assertEqual(self.bp._bpactive, 0)
        self.bp.removeBreakpoint(200)
        self.assertEqual(self.bp._bpactive, 0)
        self.assertEqual(self.bp._bp, {100: {'inuse' : True, 'active': False, 'inflash': False, 'hwbp' : None,
                                    'opcode': 0x9598, 'secondword' : 0x1111, 'timestamp' : 1 },
                                       200:  {'inuse' : True, 'active': False, 'inflash': False, 'hwbp' : None,
                                    'opcode': 0x2222, 'secondword' : 0x3333, 'timestamp' : 2 }})

    def test_updateBreakpoints_update_remove_sethwbp(self):
        self.maxDiff = None
        self.bp._hw[0] = 0x300
        self.bp.mon.is_onlyhwbps.return_value = False
        self.bp.mon.is_onlyswbps.return_value = False
        self.bp._bstamp = 6
        self.bp._bp = {100: {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None, # will get swbp
                                 'opcode': 0x9598, 'secondword' : 0x1111, 'timestamp' : 2 }, 
                       200:  {'inuse' : True, 'active': False, 'inflash': True, 'hwbp' : None, # will remove swbp
                                  'opcode': 0x2221, 'secondword' : 0x3331, 'timestamp' : 5 },
                       300:  {'inuse' : True, 'active': False, 'inflash': False, 'hwbp' : 1, # will remove hwbp
                                  'opcode': 0x2222, 'secondword' : 0x3332, 'timestamp' : 1 },
                       400:  {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None, # gets an hwbp
                                  'opcode': 0x2223, 'secondword' : 0x3333, 'timestamp' : 3 }}
        self.bp.updateBreakpoints()
        self.assertEqual(self.bp._bp, {100: {'inuse' : True, 'active': True, 'inflash': True, 'hwbp' : None,
                                    'opcode': 0x9598, 'secondword' : 0x1111, 'timestamp' : 2 },
                                       400:  {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : 1,
                                    'opcode': 0x2223, 'secondword' : 0x3333, 'timestamp' : 3 }})
        self.assertEqual(self.bp._hw, [ 400 ])
        self.bp.dbg.software_breakpoint_clear.assert_called_with(200)
        self.bp.dbg.software_breakpoint_set.assert_called_with(100)

    def test_updateBreakpoints_update_remove_stealhwbp(self):
        self.maxDiff = None
        self.bp._hw[0] = 0x100
        self.bp._firsttime = False
        self.bp.mon.is_onlyhwbps.return_value = False
        self.bp.mon.is_onlyswbps.return_value = False
        self.bp._bstamp = 6
        self.bp._bpactive = 3
        self.bp._bp = {100: {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : 1, # will have to give up hwbp
                                 'opcode': 0x9598, 'secondword' : 0x1111, 'timestamp' : 1 }, 
                       200:  {'inuse' : True, 'active': False, 'inflash': True, 'hwbp' : None, # will remove swbp
                                  'opcode': 0x2221, 'secondword' : 0x3331, 'timestamp' : 2 },
                       300:  {'inuse' : True, 'active': False, 'inflash': True, 'hwbp' : None, # will remove swbp
                                  'opcode': 0x2222, 'secondword' : 0x3332, 'timestamp' : 3 },
                       400:  {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None, # will become swbp
                                  'opcode': 0x2223, 'secondword' : 0x3333, 'timestamp' : 4 },
                       500:  {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None, # gets hwbp
                                  'opcode': 0x2224, 'secondword' : 0x3334, 'timestamp' : 5 }}
        self.bp.updateBreakpoints()
        self.assertEqual(self.bp._bp, {100: {'inuse' : True, 'active': True, 'inflash': True, 'hwbp' : None,
                                    'opcode': 0x9598, 'secondword' : 0x1111, 'timestamp' : 1 },
                                       400:  {'inuse' : True, 'active': True, 'inflash': True, 'hwbp' : None,
                                    'opcode': 0x2223, 'secondword' : 0x3333, 'timestamp' : 4 },
                                       500:  {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : 1, 
                                    'opcode': 0x2224, 'secondword' : 0x3334, 'timestamp' : 5 }})
        self.assertEqual(self.bp._hw, [ 500 ])
        self.bp.dbg.software_breakpoint_clear.assert_has_calls([call(200), call(300)], any_order=True)
        self.bp.dbg.software_breakpoint_set.assert_has_calls([call(100), call(400)], any_order=True)
        self.assertEqual(self.bp._bpactive, 3)

    def test_cleanupBreakpoints(self):
        self.bp._hw = [1]
        self.bp._bp = { 1: 1}
        self.bp._bpactive = 1
        self.bp.cleanupBreakpoints()
        self.assertEqual(self.bp._hw, [None])
        self.assertEqual(self.bp._bp, {})
        self.assertEqual(self.bp._bpactive, 0)
        self.bp.dbg.software_breakpoint_clear_all.assert_called_once()

    def test_resumeExecution_old_exec(self):
        self.bp.mon.is_onlyswbps.return_value = False
        self.bp.mon.is_old_exec.return_value = True
        self.bp.resumeExecution(2224)
        self.bp.dbg.program_counter_write(1112)
        self.bp.dbg.run.assert_called_once()

    def test_resumeExecution_with_hwbp(self):
        self.bp.mon.is_onlyswbps.return_value = False
        self.bp._hw[0] = 8888
        self.bp.resumeExecution(2224)
        self.bp.dbg.program_counter_write(1112)
        self.bp.dbg.run_to.assert_called_with(8888)

    def test_resumeExecution_without_hwbp(self):
        self.bp.mon.is_onlyswbps.return_value = True
        self.bp._hw[0] = None
        self.bp.resumeExecution(None)
        self.bp.dbg.program_counter_read.assert_called_once()
        self.bp.dbg.run.assert_called_once()

    def test_resumeExecution_at_break_one_word_with_hwbp(self):
        self.bp._bstamp = 3
        self.bp.mon.is_onlyswbps.return_value = False
        self.bp._hw = [ 100 ]
        self.bp._bp[100] = {'opcode' : 0x9000, 'secondword' : 0xFFFF, 'hwbp' : 1, 'active' : True, 'timestamp' : 2, 'inflash' : False } 
        self.bp._bp[2224] = {'opcode' : 0xffb6, 'secondword' : 0xFFFF, 'hwbp' : None, 'active' : True,
                                 'timestamp' : 1, 'inflash' : None }
        self.bp.resumeExecution(2224)
        self.bp.dbg.run_to.assert_called_with(100)

    def test_resumeExecution_at_break_two_word_instr_with_hwbp(self):
        self.bp.mon.is_onlyswbps.return_value = False
        self.bp._hw = [ 100 ]
        self.bp._bp[100] = {'opcode' : 0x9000, 'secondword' : 0xFFFF, 'hwbp' : 1, 'active' : True, 'timestamp' : 2, 'inflash' : False } 
        self.bp._bp[2224] = {'opcode' : 0x9000, 'secondword' : 0xFFFF, 'active' : True, 'hwbp' : None, 'timestamp' : 1, 'inflash' : True} 
        self.bp.resumeExecution(2224)
        self.bp.dbg.run_to.assert_called_with(100)

    def test_singleStep_old_exec(self):
        self.bp.mon.is_old_exec.return_value = True
        self.bp.dbg.program_counter_read.return_value = 22
        self.assertTrue(self.bp.singleStep(None), SIGTRAP)
        self.bp.dbg.program_counter_read.assert_called_once()
        self.bp.dbg.step.assert_called_once()
        self.bp.dbg.run_to.assert_not_called()


    def test_singleStep_twoWordInstr_at_BP_without_start(self):
        self.bp.dbg.program_counter_read.return_value = 22
        self.bp._bp[44] = { 'inflash' : True, 'opcode' : 0x9000, 'secondword' :  0xFFFF }
        self.bp._readFlashWord.assert_not_called()
        self.assertEqual(self.bp.singleStep(None), SIGTRAP)
        self.bp.dbg.program_counter_write.assert_called_with(24)
        self.bp.dbg.step.assert_not_called()
        self.bp.dbg.run_to.assert_not_called()


    def test_singleStep_unsafe_with_start(self):
        self.bp.mon.is_safe.return_value = False
        self.assertEqual(self.bp.singleStep(42), SIGTRAP)
        self.bp.dbg.program_counter_write.assert_called_with(21)
        self.bp.dbg.program_counter_read.assert_not_called()
        self.bp._readFlashWord.assert_not_called()
        self.bp.dbg.step.assert_called_once()
        self.bp.dbg.run_to.assert_not_called()
        
    def test_singleStep_safe_nobranch_oneWordInstr(self):
        self.bp.dbg.program_counter_read.return_value = 22
        self.bp._readFlashWord.side_effect = [ 0x8FF4, 0x8FFF ]
        self.assertFalse(self.bp.twoWordInstr(0x8FF4))
        self.assertFalse(self.bp.branchInstr(0x9000))
        self.assertEqual(self.bp.singleStep(None), None)
        self.bp._readFlashWord.assert_called_once()
        self.bp.dbg.step.assert_not_called()
        self.bp.dbg.run_to.assert_called_with(46)

    def test_singleStep_safe_nobranch_twoWordInstr(self):
        self.bp.dbg.program_counter_read.return_value = 22
        self.bp._readFlashWord.side_effect = [ 0x9000, 0x88FF ]
        self.assertTrue(self.bp.twoWordInstr(0x9000))
        self.assertFalse(self.bp.branchInstr(0x9000))
        self.assertEqual(self.bp.singleStep(None), None)
        self.bp.dbg.step.assert_not_called()
        self.bp.dbg.run_to.assert_called_with(48)

    def test_singleStep_safe_branch_oneWordInstr(self):
        self.bp.dbg.program_counter_read.return_value = 22
        self.bp._readFlashWord.side_effect = [ 0x9518, 0x8FFF ]
        self.assertFalse(self.bp.twoWordInstr(0x9518))
        self.assertTrue(self.bp.branchInstr(0x9518))
        self.bp.dbg.status_register_read.side_effect = [ bytearray([0x88]), bytearray([0x07]) ]
        self.assertEqual(self.bp.singleStep(None), SIGTRAP)
        self.bp._readFlashWord.assert_called_once()
        self.bp.dbg.status_register_write.assert_has_calls([ call(bytearray([0x08])), call(bytearray([0x87])) ])
        self.assertEqual(self.bp.dbg.status_register_read.call_count, 2)
        self.bp.dbg.step.assert_called_once()
        self.bp.dbg.run_to.assert_not_called()

    def test_singleStep_safe_branch_twoWordInstr(self):
        self.bp.dbg.program_counter_read.return_value = 22
        self.bp._readFlashWord.side_effect = [ 0x950C, 0x8FFF ]
        self.assertTrue(self.bp.twoWordInstr(0x950C))
        self.assertTrue(self.bp.branchInstr(0x950C))
        self.bp.dbg.status_register_read.side_effect = [ bytearray([0x88]), bytearray([0x07]) ]
        self.assertEqual(self.bp.singleStep(None), 5)
        self.bp._readFlashWord.assert_called_once()
        self.bp.dbg.status_register_write.assert_has_calls([ call(bytearray([0x08])), call(bytearray([0x87])) ])
        self.assertEqual(self.bp.dbg.status_register_read.call_count, 2)
        self.bp.dbg.step.assert_called_once()
        self.bp.dbg.run_to.assert_not_called()

    def test_singleStep_safe_brie(self):
        self.bp.dbg.program_counter_read.return_value = 22
        self.bp._readFlashWord.side_effect = [ 0xF017 ]
        self.assertTrue(self.bp.branchOnIBit(0xF017)) # BRIE .+2
        self.bp.dbg.status_register_read.side_effect = [ bytearray([0x88]) ]
        self.assertEqual(self.bp.singleStep(None), None)
        self.bp._readFlashWord.assert_called_once()
        self.assertEqual(self.bp.dbg.status_register_read.call_count, 1)
        self.bp.dbg.step.assert_not_called()
        self.bp.dbg.run_to.assert_called_with(50)

    def test_branchInstr(self):
        for instr in range(0x10000):
            self.assertEqual(self.bp.branchInstr(instr),
                                 instrmap.get(instr,(None, None, None))[2] in ['branch', 'cond', 'icond'],
                                 "Failed at 0x%04X" % instr)

    def test_branchOnIBit(self):
        for instr in range(0x10000):
            self.assertEqual(self.bp.branchOnIBit(instr),
                                 instrmap.get(instr,(None, None, None))[2] in ['icond'],
                                 "Failed at 0x%04X" % instr)

    def test_computeDestinationOfBranch(self):
        self.assertEqual(self.bp.computeDestinationOfBranch(0xF02F, 1, 20), 32)
        self.assertEqual(self.bp.computeDestinationOfBranch(0xF3FF, 1, 20), 20)
        self.assertEqual(self.bp.computeDestinationOfBranch(0xF02F, 0, 20), 22)
        self.assertEqual(self.bp.computeDestinationOfBranch(0xF3FF, 0, 20), 22)
        self.assertEqual(self.bp.computeDestinationOfBranch(0xF42F, 0, 20), 32)
        self.assertEqual(self.bp.computeDestinationOfBranch(0xF7FF, 0, 20), 20)
        self.assertEqual(self.bp.computeDestinationOfBranch(0xF42F, 1, 20), 22)
        self.assertEqual(self.bp.computeDestinationOfBranch(0xF7FF, 1, 20), 22)
                
    def test_twoWordInstr(self):
        for instr in range(0x10000):
            self.assertEqual(self.bp.twoWordInstr(instr),
                                 instrmap.get(instr,(None, None, None))[1] == 2,
                                 "Failed at 0x%04X" % instr)

        
