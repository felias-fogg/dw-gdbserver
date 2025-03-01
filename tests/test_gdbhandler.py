from unittest.mock import Mock, MagicMock, patch, call
from unittest import TestCase
from dwgdbserver.xavrdebugger import XAvrDebugger
from dwgdbserver.dwgdbserver import GdbHandler, EndOfSession
import logging

logging.basicConfig(level=logging.CRITICAL)

# generate an RSP packet from a string
def rsp(packet):
    checksum = sum(packet.encode("ascii")) % 256
    return ("$%s#%02x" % (packet, checksum)).encode("ascii")

class TestGdbHandler(TestCase):

    def setUp(self):
        mock_socket = MagicMock()
        mock_dbg = MagicMock()
        #only used when testing memory size in init of BreakAndExec:
        mock_dbg.memory_info.memory_info_by_name('flash')['size'].__gt__ = lambda self, compare: False
        #for checking the interface:
        mock_dbg.device_info = { 'interface' : 'debugWIRE+ISP' }
        # setting up the GbdHandler instance we want to test
        self.gh = GdbHandler(mock_socket, mock_dbg, "atmega328p")
        #for testing flash reads and writes
        self.gh.flash_start = 0
        self.gh.flash_page_size = 2
        self.gh.flash_size = 12
        self.gh.multi_buffer = 3
        self.gh.multi_page_size = 6
        self.gh.sram_start = 0x100
        self.gh.sram_size = 16

    def test_rsp_packet_construction(self):
        self.assertEqual(b'$#00', rsp(''))
        self.assertEqual(b'$abc#26', rsp('abc'))
        
    def test_sendPacket(self):
        self.gh.sendPacket("abc")
        self.gh.socket.sendall.assert_called_with(rsp("abc"))

    def test_unknownPacket(self):
        self.gh.dispatch('*', b'')
        self.gh.socket.sendall.assert_called_with(rsp(""))

    def test_extendedRemoteHandler(self):
        self.assertFalse(self.gh.extended_remote_mode)
        self.gh.dispatch('!', b'')
        self.assertTrue(self.gh.extended_remote_mode)
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_stopReasonHandler(self):
        self.gh.dispatch('?', b'')
        self.gh.socket.sendall.assert_called_with(rsp("S00"))\

    def test_continueHandler_impossible(self):
        self.assertFalse(self.gh.mon.dw_mode_active)
        self.assertFalse(self.gh.vflashdone)
        self.assertFalse(self.gh.mon.noload)
        self.assertTrue(self.gh.mon.old_exec)
        self.gh.dbg.status_register_read.return_value = [0x55]
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.program_counter_read.return_value = 0x00003421
        self.gh.dispatch('c',b'')
        self.gh.socket.sendall.assert_called_with(rsp("T0120:55;21:3412;22:42680000;thread:1;"))
        self.gh.mon.dw_mode_active = True
        self.gh.dispatch('c',b'')
        self.gh.socket.sendall.assert_called_with(rsp("T0420:55;21:3412;22:42680000;thread:1;"))

    def test_continueHandler_with_start(self):
        self.gh.mon.dw_mode_active = True
        self.gh.mon.noload = True
        self.gh.dispatch('c',b'2244')
        self.gh.dbg.program_counter_write.assert_called_with(0x00001122)
        self.gh.dbg.program_counter_write.assert_called_once()
        self.gh.dbg.run.assert_called_once()

    def test_continueHandler_without_start(self):
        self.gh.mon.dw_mode_active = True
        self.gh.mon.noload = True
        self.gh.dispatch('c',b'')
        self.gh.dbg.program_counter_write.assert_called_once()
        self.gh.dbg.run.assert_called_once()

    def test_continueWithSignalHandler(self):
        self.gh.mon.noload = True
        self.gh.mon.dw_mode_active = True
        self.gh.dispatch('C',b'09;2244')
        self.gh.dbg.program_counter_write.assert_called_with(0x00001122)
        self.assertEqual(self.gh.dbg.run.call_count,1)

    def test_detachHandler(self):
        with self.assertRaises(EndOfSession):
            self.gh.dispatch('D',b'')
        self.gh.socket.sendall.assert_called_with(rsp("OK"))

    def test_getRegisterHandler(self):
        self.gh.dbg.program_counter_read.return_value = 0x00003421
        self.gh.dbg.stack_pointer_read.return_value = bytearray([0x34, 0x12])
        self.gh.dbg.status_register_read.return_value = [0x55]
        self.gh.dbg.register_file_read.return_value = bytearray(list(range(32)))
        self.gh.mon.dw_mode_active = True
        self.gh.dispatch('g',b'')
        self.gh.socket.sendall.assert_called_with(rsp("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f55341242680000"))

    def test_setRegisterHandle(self):
        self.gh.mon.dw_mode_active = True
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
        # with dw_mode_active = False
        self.gh.dispatch('m',b'')
        self.gh.socket.sendall.assert_called_with(rsp("E01"))

    def test_getMemoryHandler_sram(self):
        # read sram
        self.gh.mon.dw_mode_active = True
        self.gh.dbg.sram_read.return_value=bytearray([1,2,3,4])
        self.gh.dispatch('m',b'800101,4')
        self.gh.dbg.sram_read.assert_called_with(0x101, 4)
        self.gh.socket.sendall.assert_called_with(rsp("01020304"))

    def test_getMemoryHandler_eeprom(self):    
        # read eeprom
        self.gh.mon.dw_mode_active = True
        self.gh.dbg.eeprom_read.return_value=bytearray([0x13,0x12,0x11])
        self.gh.dispatch('m',b'810202,3')
        self.gh.socket.sendall.assert_called_with(rsp("131211"))

    def test_getMemoryHandler_undef_areas(self):    
        # read from areas undef for debugWIRE
        self.gh.mon.dw_mode_active = True
        self.gh.dispatch('m',b'820002,3')
        self.gh.dispatch('m',b'830002,3')
        self.gh.dispatch('m',b'840002,3')
        self.gh.dispatch('m',b'850002,3')
        self.gh.socket.sendall.assert_has_calls([call(rsp("E14"))]*4, )

    def test_getMemoryHandler_flash(self):    
        # read from flash cache
        self.gh.mon.dw_mode_active = True
        self.gh.mem.flash = { 0x0000: [4, bytearray([0x11,0x12,0x13,0x14])], 0x0004: [8, bytearray([0x21,0x22,0x23,0x24])]}
        self.gh.dispatch('m', b'000002,3')
        self.gh.socket.sendall.assert_called_with(rsp("131421"))
        # read from flash memory w/o getting anything back
        self.gh.mem.dbg.flash_read.return_value = bytearray()
        self.gh.dispatch('m', b'000022,3')
        self.gh.socket.sendall.assert_called_with(rsp("E14"))
        
    def test_setMemoryHandler_impossible(self):
        self.gh.dispatch('M', b'800100,0:')
        self.gh.socket.sendall.assert_called_with(rsp('E01'))

    def test_setMemoryHandler_empty(self):
        self.gh.mon.dw_mode_active = True
        self.gh.dispatch('M', b'800100,0:')
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

    def test_setMemoryHandler_sram(self):
        self.gh.mon.dw_mode_active = True
        self.gh.dispatch('M', b'800100,1:63')
        self.gh.dbg.sram_write.assert_called_with(0x100, bytes([0x63]))
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

    def test_setMemoryHandler_eeprom(self):
        self.gh.mon.dw_mode_active = True
        self.gh.dispatch('M', b'810100,1:64')
        self.gh.dbg.eeprom_write.assert_called_with(0x100, bytes([0x64]))
        self.gh.socket.sendall.assert_called_with(rsp('OK'))

        
