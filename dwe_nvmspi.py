"""
SPI NVM implementation
NB: This is a stub - not all features are implemented.
"""
from pyedbglib.protocols.avrispprotocol import AvrIspProtocol

from pymcuprog.nvm import NvmAccessProviderCmsisDapAvr
from pymcuprog.nvmspi import NvmAccessProviderCmsisDapSpi

class DWENvmAccessProviderCmsisDapSpi(NvmAccessProviderCmsisDapSpi):
    """
    NVM Access the SPI way
    """

    def __init__(self, transport, device_info):
        # do not call the super because we do not want the warning!
        NvmAccessProviderCmsisDapAvr.__init__(self, device_info)

        #self._log_incomplete_stack('AVR-ISP/SPI')

        self.isp = AvrIspProtocol(transport)
        self.isp.enter_progmode()

