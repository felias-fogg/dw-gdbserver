from unittest.mock import Mock, MagicMock, patch, call, create_autospec
from unittest import TestCase
from dwgdbserver.xavrdebugger import XAvrDebugger
from dwgdbserver.dwgdbserver import DebugWIRE, SIGINT, SIGTRAP, SIGHUP
from dwgdbserver.xnvmdebugwire import  XNvmAccessProviderCmsisDapDebugwire
import logging

logging.basicConfig(level=logging.CRITICAL)


class TestDebugWire(TestCase):

    def setUp(self):
        mock_dbg = create_autospec(XAvrDebugger, spec_set=False, instance=True)
        mock_nvm = create_autospec(XNvmAccessProviderCmsisDapDebugwire, spec_set=False, instance=True)
        self.dw = DebugWIRE(mock_dbg, "atmega328")
        self.dw.spidevice = Mock()
        self.dw.dbg.device = Mock()
        self.dw.dbg.device.read_device_id.return_value = bytearray([0x95, 0x0F]) # atmega328p
        
    def test_warmStart_not_ready(self):
        self.dw.dbg.setup_session.side_effect=Mock(side_effect=Exception("Test"))
        self.assertFalse(self.dw.warmStart())
        
