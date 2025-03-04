from unittest.mock import Mock, MagicMock, patch, call, create_autospec
from unittest import TestCase
import socket
from dwgdbserver.xavrdebugger import XAvrDebugger
from dwgdbserver.dwgdbserver import GdbHandler, EndOfSession, Memory, MonitorCommand, BreakAndExec, DebugWIRE, SIGINT, SIGTRAP, SIGHUP
from pyedbglib.protocols.edbgprotocol import EdbgProtocol 
import logging

logging.basicConfig(level=logging.CRITICAL)

# generate an RSP packet from a string
def rsp(packet):
    checksum = sum(packet.encode("ascii")) % 256
    return ("$%s#%02x" % (packet, checksum)).encode("ascii")

class TestGdbHandler(TestCase):

    def setUp(self):
        mock_socket = create_autospec(socket.socket, spec_set=True, instance=True)
        mock_dbg = create_autospec(XAvrDebugger, spec_set=False, instance=True)
        mock_dbg.memory_info = MagicMock()
        mock_dbg.device_info = MagicMock()
        mock_dbg.transport = MagicMock()
        mock_dbg.edbg_protocol = MagicMock()
        mock_dbg.memory_info.memory_info_by_name('flash')['size'].__gt__ = lambda self, compare: False
        # setting up the GbdHandler instance we want to test
        self.gh = GdbHandler(mock_socket, mock_dbg, "atmega328p")
        self.gh.dw =  create_autospec(DebugWIRE, specSet=True, instance=True)
        self.gh.mon = create_autospec(MonitorCommand, specSet=True, instance=True)
        self.gh.mem = create_autospec(Memory, specSet=True, instance=True)
        self.gh.bp = create_autospec(BreakAndExec, specSet=True, instance=True)

    def test_rsp_packet_construction(self):
        self.assertEqual(b'$#00', rsp(''))
        self.assertEqual(b'$abc#26', rsp('abc'))
        
    def test_unknownPacket(self):
        self.gh.dispatch('_', b'')
        self.gh.socket.sendall.assert_called_with(rsp(""))

    def test_extendedRemoteHandler(self):
        self.assertFalse(self.gh.extended_remote_mode)
        self.gh.dispatch('!', b'')
        self.assertTrue(self.gh.extended_remote_mode)
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_stopReasonHandler_none(self):
        self.gh.lastSIGVAL = None
        self.gh.dispatch('?', b'')
        self.gh.socket.sendall.assert_called_with(rsp("S00"))

    def test_stopReasonHandler_SIGINT(self):
        self.gh.lastSIGVAL = SIGINT
        self.gh.dispatch('?', b'')
        self.gh.socket.sendall.assert_called_with(rsp("S02"))

    def test_continueHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.mem.is_flash_empty.return_value = True
        self.gh.mon.is_noload.return_value = False
        self.gh.dbg.status_register_read.return_value = [0x55]
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.program_counter_read.return_value = 0x00003421
        self.gh.dispatch('c',b'')
        self.gh.socket.sendall.assert_called_with(rsp("S01"))
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('c',b'')
        self.gh.socket.sendall.assert_called_with(rsp("S04"))

    def test_continueHandler_with_start(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mon.is_old_exec.return_value = True
        self.gh.mem.is_flash_empty.return_value = False
        self.gh.dispatch('c',b'2244')
        self.gh.dbg.program_counter_write.assert_called_with(0x00001122)
        self.gh.dbg.program_counter_write.assert_called_once()
        self.gh.dbg.run.assert_called_once()
        self.gh.socket.sendall.assert_not_called()

    def test_continueHandler_without_start(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mon.is_old_exec.return_value = True
        self.gh.mem.is_flash_empty.return_value = False
        self.gh.dbg.program_counter_read.return_value = 1
        self.gh.dispatch('c',b'')
        self.gh.dbg.program_counter_write.assert_called_with(1)
        self.gh.dbg.run.assert_called_once()
        self.gh.socket.sendall.assert_not_called()

    def test_continueWithSignalHandler(self):
        self.gh.continueHandler = Mock()
        self.gh.dispatch('C',b'09;2244')
        self.gh.dispatch('C',b'09')
        self.gh.continueHandler.assert_has_calls([call('2244'), call('')])

    def test_continueWithSignalHandler_without_start(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mon.is_old_exec.return_value = True
        self.gh.mem.is_flash_empty.return_value = False
        self.gh.dbg.program_counter_read.return_value = 3
        self.gh.dispatch('C',b'09')
        self.gh.dbg.program_counter_write.assert_called_with(3)
        self.assertEqual(self.gh.dbg.run.call_count,1)
        self.gh.socket.sendall.assert_not_called()

    def test_detachHandler(self):
        with self.assertRaises(EndOfSession):
            self.gh.dispatch('D',b'')
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_getRegisterHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('g',b'')
        self.gh.socket.sendall.assert_called_with(rsp("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000341200000000"))

    def test_getRegisterHandler(self):
        self.gh.dbg.program_counter_read.return_value = 0x00003421
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.status_register_read.return_value = [0x55]
        self.gh.dbg.register_file_read.return_value = bytearray(list(range(32)))
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('g',b'')
        self.gh.socket.sendall.assert_called_with(rsp("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f55341242680000"))

    def test_setRegisterHandle_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('G',b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f66341242680000')
        self.gh.dbg.program_counter_write.assert_not_called()
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_setRegisterHandle(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('G',b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f66341242680000')
        self.gh.dbg.register_file_write.assert_called_with(bytearray(list(range(32))))
        self.gh.dbg.status_register_write.assert_called_with(bytearray([0x66]))
        self.gh.dbg.stack_pointer_write.assert_called_with(bytearray(bytearray([0x34, 0x12])))
        self.gh.dbg.program_counter_write.assert_called_with(0x00003421)
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_setThreadHandler(self):
        self.gh.dispatch('H',b'')
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_getMemoryHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('m',b'')
        self.gh.socket.sendall.assert_called_with(rsp("E01"))

    def test_getMemoryHandler_chunk(self):
        # read chunk from memory
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mem.readmem.return_value = b'\x01\x02\x03\x04'
        self.gh.dispatch('m',b'800101,4')
        self.gh.mem.readmem.assert_called_with("800101", "4")
        self.gh.socket.sendall.assert_called_with(rsp("01020304"))

    def test_getMemoryHandler_empty_request(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mem.readmem.return_value = None
        self.gh.dispatch('m',b'800101,0')
        self.gh.socket.sendall.assert_called_with(rsp("OK"))
        self.gh.mem.readmem.assert_not_called()

    def test_getMemoryHandler_empty_return(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mem.readmem.return_value = b''
        self.gh.dispatch('m',b'800101,4')
        self.gh.mem.readmem.assert_called_with("800101", "4")
        self.gh.socket.sendall.assert_called_with(rsp("E14"))

    def test_setMemoryHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('M', b'800100,0:')
        self.gh.socket.sendall.assert_called_with(rsp('E01'))

    def test_setMemoryHandler_byte(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mem.writemem.return_value = "OK"
        self.gh.dispatch('M', b'800100,1:63')
        self.gh.mem.writemem.assert_called_with("800100", bytes([0x63]))
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

    def test_getOneRegisterHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('p', b'22')
        self.gh.socket.sendall.assert_called_with(rsp("E01"))

    def test_getOneRegisterHandler_pc(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dbg.program_counter_read.return_value = 0x123
        self.gh.dispatch('p', b'22')
        self.gh.socket.sendall.assert_called_with(rsp("46020000"))

    def test_getOneRegisterHandler_sp(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x23,0x01])
        self.gh.dispatch('p', b'21')
        self.gh.socket.sendall.assert_called_with(rsp("2301"))

    def test_getOneRegisterHandler_sreg(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dbg.status_register_read.return_value = bytearray([0x01])
        self.gh.dispatch('p', b'20')
        self.gh.socket.sendall.assert_called_with(rsp("01"))

    def test_getOneRegisterHandler_reg(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dbg.sram_read.return_value = bytearray([0x23])
        self.gh.dispatch('p', b'07')
        self.gh.socket.sendall.assert_called_with(rsp("23"))

    def test_setOneRegisterHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('P', b'22=04200000')
        self.gh.socket.sendall.assert_called_with(rsp("E01"))

    def test_setOneRegisterHandler_pc(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('P', b'22=04200000')
        self.gh.dbg.program_counter_write.assert_called_with(0x2004>>1)
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_setOneRegisterHandler_sp(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('P', b'21=0420')
        self.gh.dbg.stack_pointer_write.assert_called_with(bytearray([0x04, 0x20]))
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_setOneRegisterHandler_sreg(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('P', b'20=04')
        self.gh.dbg.status_register_write.assert_called_with(bytearray([0x04]))
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_setOneRegisterHandler_reg(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('P', b'10=ee')
        self.gh.dbg.sram_write.assert_called_with(0x10, bytearray([0xee]))
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_attachedHandler(self):
        self.gh.dispatch('qAttached', b'')
        self.gh.socket.sendall.assert_called_with(rsp("1"))

    def test_offsetsHandler(self):
        self.gh.dispatch('qOffsets', b'')
        self.gh.socket.sendall.assert_called_with(rsp("Text=000;Data=000;Bss=000"))

    def test_monitorCommand(self):
        self.gh.mon.dispatch.return_value = ('reset', 'Bla')
        self.gh.dispatch('qRcmd', b',7265736574')
        self.gh.dbg.reset.assert_called_once()
        self.gh.socket.sendall.assert_called_with(rsp("426C610A"))
        
    @patch('dwgdbserver.dwgdbserver.time.sleep',Mock()) # we do not want to sleep in a test!
    def test_sendPowerCycle_magic(self):
        self.gh.dbg.transport.device.product_string = 'MEDBG'
        self.assertEqual(self.gh.sendPowerCycle(), True)

    def test_sendPowerCycle_manual(self):
        self.gh.dbg.transport.device.product_string = 'XMEDBG'
        self.assertEqual(self.gh.sendPowerCycle(), False)
        self.gh.socket.sendall.assert_called_with(rsp("O2A2A2A20506C6561736520706F7765722D6379636C6520746865207461726765742073797374656D202A2A2A0A"))

    def test_supportedHandler(self):
        self.gh.dw.warmStart.return_value = True
        self.gh.dispatch('qSupported', b'')
        self.gh.socket.sendall.assert_called_with(rsp("PacketSize={0:X};qXfer:memory-map:read+".format(self.gh.packet_size)))
        self.gh.mon.set_dw_mode_active.assert_called_once()

    def test_firstThreadInfoHandler(self):
        self.gh.dispatch('qfThreadInfo', b'')
        self.gh.socket.sendall.assert_called_with(rsp("m01"))

    def test_subsequentThreadInfoHandler(self):
        self.gh.dispatch('qsThreadInfo', b'')
        self.gh.socket.sendall.assert_called_with(rsp("l"))

    def test_memoryMapHandler(self):
        self.gh.mon.is_noxml.return_value = False
        self.gh.mem.memoryMap.return_value="map"
        self.gh.dispatch('qXfer', b':memory-map:read::0,1000')
        self.gh.mem.memoryMap.assert_called_once()

    def test_stepHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value=False
        self.gh.mem.is_flash_empty.return_value = True
        self.gh.mon.is_noload.return_value = False
        self.gh.dispatch('s', b'')
        self.gh.socket.sendall.assert_called_with(rsp("S01"))
        self.gh.mon.is_dw_mode_active.return_value=True
        self.gh.dispatch('s', b'')
        self.gh.socket.sendall.assert_called_with(rsp("S04"))

    def test_stepHandler_with_start(self):
        self.gh.mon.is_dw_mode_active.return_value=True
        self.gh.mem.is_flash_empty.return_value = False
        self.gh.mon.is_noload.return_value = False
        self.gh.mon.is_old_exec.return_value = True
        self.gh.dbg.program_counter_read.return_value = 0x00000102
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.status_register_read.return_value = [0x55]
        self.gh.dispatch('s', b'00000202')
        self.gh.dbg.program_counter_read.assert_called_once()
        self.gh.dbg.program_counter_write.assert_called_with(0x101)
        self.gh.dbg.step.assert_called_once()
        self.gh.socket.sendall.assert_called_with(rsp("T0520:55;21:3412;22:04020000;thread:1;"))

    def test_stepHandler_with_start_new(self):
        self.gh.mon.is_dw_mode_active.return_value=True
        self.gh.mem.is_flash_empty.return_value = False
        self.gh.mon.is_noload.return_value = False
        self.gh.mon.is_old_exec.return_value = False
        self.gh.bp.singleStep.return_value=None
        self.gh.dispatch('s', b'00000202')
        self.gh.dbg.program_counter_read.assert_not_called()
        self.gh.dbg.program_counter_write.assert_not_called()
        self.gh.bp.singleStep.assert_called_once()
        self.gh.socket.sendall.assert_not_called()

    def test_stepHandler_without_start(self):
        self.gh.mon.is_dw_mode_active.return_value=True
        self.gh.mem.is_flash_empty.return_value = False
        self.gh.mon.is_noload.return_value = False
        self.gh.mon.is_old_exec.return_value = True
        self.gh.dbg.program_counter_read.return_value = 0x00000101
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.status_register_read.return_value = [0x55]
        self.gh.dispatch('s', b'')
        self.gh.dbg.program_counter_read.assert_has_calls([call(), call()])
        self.gh.dbg.program_counter_write.assert_called_with(0x101)
        self.gh.dbg.step.assert_called_once()
        self.gh.socket.sendall.assert_called_with(rsp("T0520:55;21:3412;22:02020000;thread:1;"))

    def test_stepHandler_without_start_new(self):
        self.gh.mon.is_dw_mode_active.return_value=True
        self.gh.mem.is_flash_empty.return_value = False
        self.gh.mon.is_noload.return_value = False
        self.gh.mon.is_old_exec.return_value = False
        self.gh.bp.singleStep.return_value = None
        self.gh.dispatch('s', b'')
        self.gh.dbg.program_counter_read.assert_called_once()
        self.gh.dbg.program_counter_write.assert_not_called()
        self.gh.bp.singleStep.assert_called_once()
        self.gh.socket.sendall.assert_not_called()

    def test_stepWithSignalHandler(self):
        self.gh.stepHandler = Mock()
        self.gh.dispatch('S', b'09;4545')
        self.gh.dispatch('S', b'09')
        self.gh.stepHandler.assert_has_calls([call('4545'), call('')])

    def test_threadAliveHandler(self):
        self.gh.dispatch('T', b'')
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_flashDoneHandler(self):
        self.gh.mem.listOfChunks.return_value = [0, 0x100]
        self.gh.dispatch('vFlashDone', b'')
        self.gh.mem.flashPages.assert_has_calls([call(0,0), call(0x100,0x100)])
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_flashEraseHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('vFlashErase', b':100,10')
        self.gh.socket.sendall.assert_called_with(rsp("E01"))
        
    def test_flashEraseHandler_fresh(self):
        self.gh.vflashDone = False
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('vFlashErase', b':100,10')
        self.gh.dispatch('vFlashErase', b':200,10')
        self.gh.dispatch('vFlashErase', b':300,40')
        self.gh.mem.insertNewChunk.assert_has_calls([call(0x100,0x10), call(0x200,0x10), call(0x300,0x40)])
        self.gh.socket.sendall.assert_has_calls([call(rsp("OK")), call(rsp("OK")), call(rsp("OK"))])

    def test_flashWriteHandler_success(self):
        self.gh.mem.insertNewBlock.return_value = True
        self.gh.dispatch('vFlashWrite', b':0100:ABC')
        self.gh.mem.insertNewBlock.assert_called_with(0x100,[ord('A'), ord('B'), ord('C')])
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_escape(self):
        seq = [ 0x7d, 0xFF, 0x2A, 0x00, 0x23, 0x24 ]
        self.assertEqual(self.gh.escape(seq),bytes([0x7d, 0x5d, 0xFF, 0x7D, 0x0A, 0x00, 0x7D, 0x03, 0x7D, 0x04]))

    def test_unescape(self):
        seq = [0x7d, 0x5d, 0xFF, 0x7D, 0x0A, 0x00, 0x7D, 0x03, 0x7D, 0x04]
        self.assertEqual(self.gh.unescape(seq),[ 0x7d, 0xFF, 0x2A, 0x00, 0x23, 0x24 ])

    def test_killHandler_not_exteded_remote(self):
        self.gh.extended_remote_mode = False
        with self.assertRaises(EndOfSession):
            self.gh.dispatch('vKill', b'')
        self.gh.dbg.reset.assert_called_once()

    def test_killHandler_exteded_remote(self):
        self.gh.extended_remote_mode = True
        self.gh.dispatch('vKill', b'')
        self.gh.dbg.reset.assert_called_once()
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_runHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('vRun', b'')
        self.gh.socket.sendall.assert_called_with(rsp("S01"))

    def test_runHandler(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dbg.program_counter_read.return_value = 0x00000101
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.status_register_read.return_value = [0x77]
        self.gh.dispatch('vRun', b'')
        self.gh.socket.sendall.assert_called_with(rsp("T0520:77;21:3412;22:02020000;thread:1;"))
        self.gh.dbg.reset.assert_called_once()

    def test_setBinaryMemoryHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('m',b'')
        self.gh.socket.sendall.assert_called_with(rsp("E01"))

    def test_setBinaryMemoryHandler_byte(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mem.writemem.return_value = "OK"
        self.gh.dispatch('X', b'800100,1:}]')
        self.gh.mem.writemem.assert_called_with("800100", bytearray([0x7D]))
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

    def test_removeBreakpointHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('z',b'0,111,2')
        self.gh.socket.sendall.assert_called_with(rsp('E01'))
        
    def test_removeBreakpointHandler_wrong_type(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('z',b'2,111,2')
        self.gh.socket.sendall.assert_called_with(rsp(''))
        
    def test_removeBreakpointHandler_old(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mon.is_old_exec.return_value = True
        self.gh.dispatch('z',b'0,222,2')
        # note: for  breakpoints, it is always the byte address! 
        self.gh.dbg.software_breakpoint_clear.assert_called_with(0x222)
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

    def test_removeBreakpointHandler_new(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mon.is_old_exec.return_value = False
        self.gh.dispatch('z',b'0,222,2')
        # note: for  breakpoints, it is always the byte address! 
        self.gh.bp.removeBreakpoint.assert_called_with(0x222)
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

    def test_addBreakpointHandler_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.dispatch('Z',b'0,111,2')
        self.gh.socket.sendall.assert_called_with(rsp('E01'))
        
    def test_addBreakpointHandler_wrong_type(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dispatch('Z',b'2,111,2')
        self.gh.socket.sendall.assert_called_with(rsp(''))
        
    def test_addBreakpointHandler_old(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mon.is_old_exec.return_value = True
        self.gh.dispatch('Z',b'0,222,2')
        # note: for  breakpoints, it is always the byte address! 
        self.gh.dbg.software_breakpoint_set.assert_called_with(0x222)
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

    def test_addBreakpointHandler_new(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.mon.is_old_exec.return_value = False
        self.gh.dispatch('Z',b'0,222,2')
        # note: for  breakpoints, it is always the byte address! 
        self.gh.bp.insertBreakpoint.assert_called_with(0x222)
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

    def test_pollEvents_impossible(self):
        self.gh.mon.is_dw_mode_active.return_value = False
        self.gh.pollEvents()
        self.gh.dbg.poll_event.assert_not_called()

    def test_pollEvents_positive(self):
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dbg.poll_event.return_value = 0x101
        self.gh.mon.is_dw_mode_active.return_value = True
        self.gh.dbg.program_counter_read.return_value = 0x00000101
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.status_register_read.return_value = [0x88]
        self.gh.pollEvents()
        self.gh.dbg.poll_event.assert_called_once()
        self.gh.socket.sendall.assert_called_with(rsp("T0520:88;21:3412;22:02020000;thread:1;"))

    @patch('dwgdbserver.dwgdbserver.select.select', Mock(return_value=[None, None, None]))
    def test_pollGdbInput_false(self):
        self.assertFalse(self.gh.pollGdbInput())

    @patch('dwgdbserver.dwgdbserver.select.select', Mock(return_value=[[1], None, None]))
    def test_pollGdbInput_true(self):
        self.assertTrue(self.gh.pollGdbInput())

    def test_sendPacket(self):
        self.gh.sendPacket("abc")
        self.gh.socket.sendall.assert_called_with(rsp("abc"))

    def test_sendReplyPacket(self):
        self.gh.sendReplyPacket("Hello World")
        self.gh.socket.sendall.assert_called_with(rsp("48656C6C6F20576F726C640A"))

    def test_sendDebugMessage(self):
        self.gh.sendDebugMessage("Hello World")
        self.gh.socket.sendall.assert_called_with(rsp("O48656C6C6F20576F726C640A"))

    def test_sendSignal_none(self):
        self.gh.sendSignal(None)
        self.gh.socket.sendall.assert_not_called()
        self.assertEqual(self.gh.lastSIGVAL, None)

    def test_sendSignal_SIGINT(self):
        self.gh.dbg.program_counter_read.return_value = 0x00000404
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.status_register_read.return_value = [0x99]
        self.gh.sendSignal(SIGINT)
        self.gh.socket.sendall.assert_called_with(rsp("T0220:99;21:3412;22:08080000;thread:1;"))

    def test_sendSignal_SIGINT(self):
        self.gh.sendSignal(SIGHUP)
        self.gh.socket.sendall.assert_called_with(rsp("S01"))

    def test_handleData_ACK_NACK(self):
        self.gh.lastmessage = 'bla'
        self.gh.handleData(b'++---+---')
        self.gh.socket.sendall.assert_called_with(rsp("bla"))

    def test_handleData_NACK_ACK_ignore_NAK(self):
        self.gh.lastmessage = 'bla'
        self.gh.handleData(b'--------+ ---')
        self.gh.socket.sendall.assert_called_with(rsp(""))

    def test_handleData_CTRLC(self):
        self.gh.dbg.program_counter_read.return_value = 0x00000404
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x11])
        self.gh.dbg.status_register_read.return_value = [0x11]
        self.gh.handleData(b'\x03')
        self.gh.socket.sendall.assert_called_with(rsp("T0220:11;21:3411;22:08080000;thread:1;"))

    def test_handleData_Packets(self):
        self.gh.handleData(b'+++$qfThreadInfo#bb$qsThreadInfo#c8-')
        self.gh.socket.sendall.assert_has_calls([call(b'+'), call(rsp('m01')),  call(b'+'), call(rsp('l')),  call(rsp('l'))])

    def test_handleData_wrong_checksum(self):
        self.gh.handleData(b'$qfThreadInfo#cc')
        self.gh.socket.sendall.assert_called_with(b"-")


