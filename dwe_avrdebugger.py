"""
Python AVR MCU debugger
"""
import time
import sys

import logging
from logging import getLogger
from pyedbglib.protocols import housekeepingprotocol
from pyedbglib.protocols.avr8protocol import Avr8Protocol
from pyedbglib.util import binary

from pymcuprog.utils import read_target_voltage
from pymcuprog.avrdebugger import AvrDebugger
from pymcuprog.deviceinfo import deviceinfo
from pymcuprog.nvmupdi import NvmAccessProviderCmsisDapUpdi
from pymcuprog.nvmdebugwire import NvmAccessProviderCmsisDapDebugwire
from dwe_nvmdebugwire import DWENvmAccessProviderCmsisDapDebugwire
from pymcuprog.nvmspi import NvmAccessProviderCmsisDapSpi
from pymcuprog.pymcuprog_errors import PymcuprogToolConfigurationError, PymcuprogNotSupportedError, PymcuprogError



class FatalErrorException(Exception):
    """Termination of session because of a fatal error"""
    def __init__(self, msg=None, code=0):
        super(FatalErrorException, self).__init__(msg)

class DWEAvrDebugger(AvrDebugger):
    """
    AVR debugger wrapper

    :param transport: transport object to communicate through
    :type transport: object(hid_transport)
    :param use_events_for_run_stop_state: True to use HID event channel, False to polling
    :type use_events_for_run_stop_state: boolean
    """
    def __init__(self, transport, device, use_events_for_run_stop_state=True):
        super(DWEAvrDebugger, self).__init__(transport)
        # Gather device info
        # moved here so that we have mem + device info even before dw has been started
        try:
            self.device_info = deviceinfo.getdeviceinfo(device)
        except ImportError:
            raise PymcuprogNotSupportedError("No device info for device: {}".format(device))
        if not self.device_info['interface'].upper() in ("UPDI", "ISP+DW"):
            raise PymcuprogToolConfigurationError("pymcuprog debug wrapper only supports UPDI and ISP+DW devices")

        # Memory info for the device
        self.memory_info = deviceinfo.DeviceMemoryInfo(self.device_info)

    def setup_session(self, device, frequency=900000, options=""):
        """
        Sets up the device for a debug session

        :param device: name of the device to debug
        :param frequency: UPDI clock frequency in Hz
        :type frequency: int
        :param options: dictionary of options for starting the session
        :type options: dict
        """
        self.logger.info("Setting up %s for debugging", device)


        # Start a session
        if self.device_info['interface'].upper() == "UPDI":
            self.device = NvmAccessProviderCmsisDapUpdi(self.transport, self.device_info, frequency, options)
            # Default setup for NVM Access Provider is prog session - override with debug info
            self.device.avr.setup_debug_session(interface=Avr8Protocol.AVR8_PHY_INTF_PDI_1W,
                                                khz=frequency // 1000,
                                                use_hv=Avr8Protocol.UPDI_HV_NONE)
        elif self.device_info['interface'].upper() == "ISP+DW":
            # For debugWIRE, first try ISP and switch to debugWIRE
            # Then enable debugWIRE by asking for power-cycle or do it yourself
            # leaving and re-entering progmode seems necessary for getting things done!
            self.spidevice = None
            if not 'skip_isp' in options:
                trydw = False
                try:
                    self.spidevice = NvmAccessProviderCmsisDapSpi(self.transport, self.device_info)
                    device_id = self.spidevice.read_device_id()
                except Exception as e:
                    self.logger.debug(e)
                    self.logger.debug("ISP access not possible, will try debugWIRE")
                    trydw = True
                if not trydw:
                    if self.device_info['device_id'] != int.from_bytes(device_id,byteorder='little'):
                        raise FatalErrorException("Wrong MCU signature: 0x{:X}, expected: 0x{:X}".format(
                            int.from_bytes(device_id,byteorder='little'),
                            self.device_info['device_id']))
                    fuses = self.spidevice.read(self.memory_info.memory_info_by_name('fuses'), 0, 3)
                    self.logger.debug("Fuses read: %X %X %X",fuses[0], fuses[1], fuses[2])
                    lockbits = self.spidevice.read(self.memory_info.memory_info_by_name('lockbits'), 0, 1)
                    self.logger.debug("Lockbits read: %X", lockbits[0])
                    if (lockbits[0] != 0xFF):
                        self.logger.debug("MCU is locked. Will be erased.")
                        self.spidevice.erase()
                        lockbits = self.spidevice.read(self.memory_info.memory_info_by_name('lockbits'), 0, 1)
                        self.logger.debug("Lockbits after erase: %X", lockbits[0])
                        if 'bootrst_fuse' in self.device_info:
                            # unprogramm bit 0 in high or extended fuse
                            self.logger.debug("BOOTRST fuse will be unprogrammed.")
                            # leave and re-enter programming mode
                            self.spidevice.stop()
                            self.spidevice.isp.enter_progmode()
                            self.spidevice.write(self.memory_info.memory_info_by_name('fuses'),
                                                    self.device_info['bootrst_fuse'],
                                                    bytearray([fuses[self.device_info['bootrst_fuse']] | 0x01]) )
                    # program the DWEN bit
                    # again, leaving and re-entering programming mode seems to be safe 
                    self.spidevice.stop()
                    self.spidevice.isp.enter_progmode()
                    fuses = self.spidevice.read(self.memory_info.memory_info_by_name('fuses'), 0, 3)
                    self.logger.debug("Fuses read again: %X %X %X",fuses[0], fuses[1], fuses[2])
                    fuses[1] &= (0xFF & ~(self.device_info['dwen_fusebit']))
                    self.logger.debug("New high fuse: 0x%X", fuses[1])
                    self.spidevice.write(self.memory_info.memory_info_by_name('fuses'), 1,
                                            fuses[1:2])
                    self.spidevice.stop()
                    # ask user for power-cycle and wait for voltage to come up again
                    wait_start = time.monotonic()
                    last_message = 0
                    if 'callback' in options:
                        options['callback']()
                    power_cycle = False
                    while time.monotonic() - wait_start < 150:
                        if (time.monotonic() - last_message > 20):
                            print("*** Please power-cycle the target system ***")
                            last_message = time.monotonic()
                        if read_target_voltage(self.housekeeper) < 0.5:
                            wait_start = time.monotonic()
                            self.logger.debug("Power-cycle recognized")
                            while  read_target_voltage(self.housekeeper) < 1.5 and \
                              time.monotonic() - wait_start < 20:
                                time.sleep(0.1)
                            if read_target_voltage(self.housekeeper) < 1.5:
                                raise FatalErrorException("Timed out waiting for repowering target")
                            time.sleep(0.6) # wait for debugWIRE system to be ready to accept connections 
                            power_cycle = True
                            break
                    if not power_cycle:
                        raise FatalErrorException("Timed out waiting for power-cycle")
            # now we can hopyfully activate debugWIRE
            self.device = DWENvmAccessProviderCmsisDapDebugwire(self.transport, self.device_info)
            self.device.avr.setup_debug_session()
            idbytes = self.device.read_device_id()
            sig = (0x1E<<16) + (idbytes[1]<<8) + idbytes[0]
            if sig != self.device_info['device_id']:
                raise FatalErrorException("Wrong MCU signature: 0x{:X}, expected: 0x{:X}".format(
                              sig, self.device_info['device_id']))
            
    def start_debugging(self, flash_data=None):
        """
        Start the debug session

        :param flash_data: flash data content to program in before debugging
        :type flash data: list of bytes
        """
        self.logger.info("Starting debug session")
        self.device.start()

        if self.device_info['interface'].upper() == "UPDI":
            # The UPDI device is now in prog mode
            device_id = self.device.read_device_id()
            self.logger.debug("Device ID read: %X", binary.unpack_le24(device_id))

            # If the user wants content on the AVR, put it there now
            if flash_data:
                if not isinstance(flash_data, list):
                    raise PymcuprogNotSupportedError("Content can only be provided as a list of binary values")
                # First chip-erase
                self.logger.info("Erasing target")
                self.device.erase()
                
                # Then program
                self.logger.info("Programming target")
                self.device.write(self.memory_info.memory_info_by_name('flash'), 0, flash_data)

                # Flush events before starting
                self.flush_events()
                
                self.logger.info("Leaving prog mode (with auto-attach)")
                self.device.avr.protocol.leave_progmode()
                
                self._wait_for_break()

    def stack_pointer_write(self, data):
        """
        Writes the stack pointer

        :param data: 2 bytes representing stackpointer in little endian 
        :type: bytearray
        """
        self.logger.debug("Writing stack pointer")
        self.device.avr.stack_pointer_write(data)

    def status_register_read(self):
        """
        Reads the status register from the AVR

        :return: 8-bit SREG value
        :rytpe: one byte
        """
        self.logger.debug("Reading status register")
        return self.device.avr.statreg_read()

    def status_register_write(self, data):
        """
        Writes new value to status register
        :param data: SREG
        :type: one byte
        """

        self.logger.debug("Write status register: %s", data)
        self.device.avr.statreg_write(data)

    def register_file_read(self):
        """
        Reads out the AVR register file (R0::R31)

        :return: 32 bytes of register file content as bytearray
        :rtype: bytearray
        """
        self.logger.debug("Reading register file")
        return self.device.avr.regfile_read()

    def register_file_write(self, regs):
        """
        Writes the AVR register file (R0::R31)

        :param data: 32 byte register file content as bytearray
        :raises ValueError: if 32 bytes are not given
        """
        self.logger.debug("Writing register file")
        self.device.avr.regfile_write(regs)

    def disable_debugwire(self):
        """
        Disables debugWIRE and unprograms the DWEN fusebit. After this call,
        there is no connection to the target anymore. For this reason all critical things
        needs to be done before, such as cleaning up breakpoints. 
        """
        # clear all breakpoints
        self.software_breakpoint_clear_all()
        # disable DW
        self.device.avr.protocol.debugwire_disable()
        # now open an ISP programming session again
        if not self.spidevice:
            self.spidevice = NvmAccessProviderCmsisDapSpi(self.transport, self.device_info)
        self.spidevice.isp.enter_progmode()
        fuses = self.spidevice.read(self.memory_info.memory_info_by_name('fuses'), 0, 3)
        self.logger.debug("Fuses read: %X %X %X",fuses[0], fuses[1], fuses[2])
        fuses[1] |= self.device_info['dwen_fusebit']
        self.logger.debug("New high fuse: 0x%X", fuses[1])
        self.spidevice.write(self.memory_info.memory_info_by_name('fuses'), 1,
                                         fuses[1:2])
        self.spidevice.stop()
                
