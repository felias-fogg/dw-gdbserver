import logging
from unittest.mock import Mock, MagicMock, patch, call, create_autospec
from unittest import TestCase

from dwgdbserver.xnvmdebugwire import XNvmAccessProviderCmsisDapDebugwire
from dwgdbserver.xavr8target import XTinyAvrTarget
from dwgdbserver.deviceinfo.devices.attiny85 import DEVICE_INFO

from pymcuprog.avrdebugger import AvrDebugger
from pymcuprog.avr8target import AvrDevice
from pymcuprog.deviceinfo import deviceinfo
from pymcuprog.nvmupdi import NvmAccessProviderCmsisDapUpdi
from pymcuprog.pymcuprog_errors import PymcuprogToolConfigurationError,\
     PymcuprogNotSupportedError

from pyedbglib.protocols.avr8protocol import Avr8Protocol
from pyedbglib.protocols.edbgprotocol import EdbgProtocol
from pyedbglib.util import binary

logging.basicConfig(level=logging.ERROR)

class TestXAvr8Target(TestCase):

    def setUp(self):
        self.xa = XTinyAvrTarget(MagicMock())
        self.xa.protocol = create_autospec(Avr8Protocol)

    def test_memtype_write_from_string(self):
        self.assertEqual(self.xa.memtype_write_from_string('flash'), Avr8Protocol.AVR8_MEMTYPE_FLASH_PAGE)
        self.assertEqual(self.xa.memtype_write_from_string('eeprom'), Avr8Protocol.AVR8_MEMTYPE_EEPROM)
        self.assertEqual(self.xa.memtype_write_from_string('internal_sram'), Avr8Protocol.AVR8_MEMTYPE_SRAM)

    def test_setup_config(self):
        self.xa.setup_config(DEVICE_INFO)
        self.xa.protocol.write_device_data.assert_has_calls([call(bytearray([0x40, 0x00,
                                                                             0x00, 0x20, 0x00, 0x00,
                                                                             0x00, 0x00, 0x00, 0x00,
                                                                             0xC0, 0x1F, 0x00, 0x00,
                                                                             0x60, 0x00,
                                                                             0x00, 0x02,
                                                                             0x04,
                                                                             0x01,
                                                                             0x01,
                                                                             0, 0, 0,
                                                                             0x22,
                                                                             0x1F,
                                                                             0x1E,
                                                                             0x1C,
                                                                             0x1D,
                                                                             0x57,
                                                                             0x51]))])

    def test_statreg_read(self):
        self.xa.protocol.memory_read.return_value=bytearray([0x7F])
        self.assertEqual(self.xa.statreg_read(), b'\x7F')
        self.xa.protocol.memory_read.assert_called_with(Avr8Protocol.AVR8_MEMTYPE_SRAM, 0x5F, 1)

    def test_statreg_write(self):
        self.xa.statreg_write(b'\x06')
        self.xa.protocol.memory_write.assert_called_with(Avr8Protocol.AVR8_MEMTYPE_SRAM, 0x5F, b'\x06')

    def test_regfile_read(self):
        rfile = bytearray(list(range(32)))
        self.xa.protocol.memory_read.return_value=rfile
        self.assertEqual(self.xa.regfile_read(),rfile)
        self.xa.protocol.memory_read.assert_called_with(Avr8Protocol.AVR8_MEMTYPE_SRAM, 0, 32)

    def test_regfile_write(self):
        rfile = bytearray(list(range(32)))
        self.xa.regfile_write(rfile)
        self.xa.protocol.memory_write.assert_called_with(Avr8Protocol.AVR8_MEMTYPE_SRAM, 0, rfile)

    def test_stack_pointer_read(self):
        self.xa.protocol.memory_read.return_value='b\x23\x01'
        self.assertEqual(self.xa.stack_pointer_read(),'b\x23\x01')
        self.xa.protocol.memory_read.assert_called_with(Avr8Protocol.AVR8_MEMTYPE_SRAM, 0x5D, 2)

    def test_stack_pointer_write(self):
        self.xa.stack_pointer_write('b\x23\x01')
        self.xa.protocol.memory_write.assert_called_with(Avr8Protocol.AVR8_MEMTYPE_SRAM, 0x5D, 'b\x23\x01')

    def test_breakpoint_clear(self):
        self.assertEqual(self.xa.breakpoint_clear(),0)
