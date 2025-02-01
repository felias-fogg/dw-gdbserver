"""
debugWIRE GDBServer 
"""
VERSION="0.0.3"

SIGHUP  = "S01"     # connection to target lost
SIGINT  = "S02"     # Interrupt  - user interrupted the program (UART ISR) 
SIGILL  = "S04"     # Illegal instruction
SIGTRAP = "S05"     # Trace trap  - stopped on a breakpoint
SIGABRT = "S06"     # Abort because of some fatal error
SIGTERM = "S15"     # Cannot execute because not in dW mode

import site

site.addsitedir("../pyedbglib")
site.addsitedir("../pymcuprog")
site.addsitedir("../../Library/Python/3.13/lib/python/site-packages")

# args, logging
import sys
import argparse
import os
import logging
from logging import getLogger
import textwrap

# communication
import socket
import select
import binascii
import time

from pyedbglib.hidtransport.hidtransportfactory import hid_transport
import pymcuprog
from pymcuprog.avrdebugger import AvrDebugger
from dwe_avrdebugger import DWEAvrDebugger
from pymcuprog.backend import Backend
from pymcuprog.pymcuprog_main import _setup_tool_connection


class EndOfSession(Exception):
    """Termination of session"""
    def __init__(self, msg=None, code=0):
        super(EndOfSession, self).__init__(msg)

class GdbHandler():
    """
    GDB handler
    Maps between incoming GDB requests and AVR debugging protocols (via pymcuprog)
    """
    def __init__ (self, socket, avrdebugger):
        self.logger = getLogger(__name__)
        self.socket = socket
        self.dbg = avrdebugger
        self.last_SIGVAL = "S00"
        self.packet_size = 4050
        self.keep_dw_enabled = False
        self.connected = False
        self.dw_mode_active = False
        self.extended_remote_mode = False
        self.kill_timeout = 0

        self.packettypes = {
            '!' : self.extendedRemoteHandler,
            '?' : self.stopReasonHandler,
            'c' : self.continueHandler,
            # 'C' : self.continueWithSignalHandler, # - never happens in our context
            'D' : self.detachHandler,
            'g' : self.getRegisterHandler,
            'G' : self.setRegisterHandler,
            'H' : self.setThreadHandler,
            # 'k' : self.killHandler, # never used because vKill is supported
            'm' : self.getMemoryHandler,
            'M' : self.setMemoryHandler,
            'p' : self.getOneRegisterHandler,
            'P' : self.setOneRegisterHandler,
            'q' : self.queryHandler,
            # 'Q' : self.settingHandler, # - no relevant cases
            # 'R' : self.restartHandler, # - never used because vRun is supported
            's' : self.stepHandler,
            # 'S' : self.stepWithSignalHandler, # - also never happens
            'T' : self.threadAliveHandler,
            'v' : self.vCommandHandler,
            'X' : self.setMemoryBinaryHandler,
            'z' : self.removeBreakpointHandler,
            'Z' : self.addBreakpointHandler,
            }
            

    def dispatch(self, packet):
        """
        Dispatches command to the right handler
        """
        try:
            self.handler = self.packettypes[packet[0:1]]
        except (KeyError, IndexError):
            self.logger.debug("Unhandled GDB RSP packet type: %s", packet[1:2])
            self.sendPacket("")
        self.handler(packet)

    def extendedRemoteHandler(self, packet):
        """
        '!': GDB tries to switch to extended remote mode and we accept
        """
        self.extended_remote_mode = True
        self.sendPacket("OK")

    def stopReasonHandler(self, packet):
        """
        '?': Send reason for last stop: the last signal
        """
        self.sendPacket(self.last_SIGVAL)

    def continueHandler(self, packet):
        """
        'c': Continue execution, either at current address or at given address
        """
        if len(packet) > 1:
            addr = packet[1:]
            self.logger.debug("Set PC to 0x%s",addr)
            #set PC - note, byte address converted to word address
            self.dbg.program_counter_write(int(addr,16)>>1)
        self.logger.debug("Continue")
        self.dbg.run()

    def detachHandler(self, packet):
        """
        'D': Just reset MCU. All the real housekeeping will take place when the connection is terminated
        """
        self.logger.debug("detaching ...")
        self.dbg.reset()
        raise EndOfSession("Session ended by client ('detach')")

    def getRegisterHandler(self, packet):
        """
        'g': Send the current register values R[0:31] + SREAG + SP to GDB
        """
        self.logger.debug("GDB reading registers: %s", packet)
        regs = self.dbg.register_file_read()
        sreg = self.dbg.status_register_read()
        sp = self.dbg.stack_pointer_read()
        regString = ""
        for reg in regs:
            regString = regString + format(reg, '02x')
        sregString = ""
        for reg in sreg:
            sregString = sregString + format(reg, '02x')
        spString = ""
        for reg in sp:
            spString = spString + format(reg, '02x')
        regString = regString + sregString + spString
        self.sendPacket(regString)

    def setRegisterHandler(self, packet):
        """
        'G': Receive new register ( R[0:31] + SREAG + SP) values from GDB
        """
        newRegData = int(packet[1:],16)
        newdata = newRegData.to_bytes(35, byteorder='big')
        self.dbg.register_file_write(newdata[:32])
        self.dbg.status_register_write(newdata[32:33])
        self.dbg.stack_pointer_write(newdata[33:])
        self.logger.debug("Setting new register data from GDB: %s", newRegData)
        self.sendPacket("OK")

    def setThreadHandler(self, packet):
        """
        'H': set thread id for next operation. Since we only have one, it is always OK
        """
        self.logger.debug("Set current thread")
        self.sendPacket('OK')

    def getMemoryHandler(self, packet):
        """
        'm': provide GDB with memory contents
        """
        addrSize = packet[1:]
        addr = addrSize.split(",")[0]
        size = addrSize.split(",")[1]
        self.logger.debug("Reading memory: addr=%s, size=%d", addr, int(size,16))
        addrSection = "00"
        if len(addr) > 4:
            if len(addr) == 6:
                addrSection = addr[:2]
                addr = addr[2:]
            else:
                addrSection = "0" + addr[0]
                addr = addr[1:]
        data = bytearray()
        self.logger.debug("Addr section: %s",addrSection)
        if addrSection == "80": # ram
            data = self.dbg.sram_read(int(addr, 16), int(size, 16))
        elif addrSection == "81": # eeprom
            data = self.dbg.eeprom_read(int(addr, 16), int(size, 16))
        elif addrSection == "82" and self.device_info['interface'].upper() != 'ISP+DW': # fuse
            data = self.dbg.read_fuse(int(addr, 16), int(size, 16))
        elif addrSection == "83" and self.device_info['interface'].upper() != 'ISP+DW': # lock
            data = self.dbg.read_lock(int(addr, 16), int(size, 16))
        elif addrSection == "84": # signature
            data = self.dbg.read_signature(int(addr, 16), int(size, 16))
        elif addrSection == "85" and self.device_info['interface'].upper() != 'ISP+DW': # user_signature
            data = self.dbg.read_user_signature(int(addr, 16), int(size, 16))
        elif addrSection == "00": # flash
            data = self.dbg.flash_read(int(addr, 16), int(size, 16))
        else:
            self.logger.debug("Illegal memtype: %s", addrSection)
            self.sendPacket("E13")
            return
        self.logger.debug(data)
        dataString = ""
        for byte in data:
            dataString = dataString + format(byte, '02x')
        self.logger.debug("Data: %s",dataString)
        self.sendPacket(dataString)

    def setMemoryHandler(self, packet):
        """
        'M': GDB sends new data for MCU memory
        """
        addrSizeData = packet[1:]
        addr = addrSizeData.split(",")[0]
        size = (addrSizeData.split(",")[1]).split(":")[0]
        data = (addrSizeData.split(",")[1]).split(":")[1]
        self.logger.debug("Memory write addr=%s, size=%s, data=%s", addr, size, data)
        addrSection = "00"
        if len(addr) > 4:
            if len(addr) == 6:
                addrSection = addr[:2]
                addr = addr[2:]
            else:
                addrSection = "0" + addr[0]
                addr = addr[1:]
        data = int(data, 16)
        self.logger.debug(data)
        data = data.to_bytes(int(size, 16), byteorder='big')
        self.logger.debug(data)
        self.logger.debug(addrSection)
        if addrSection == "80": #ram
            data = self.dbg.sram_write(int(addr, 16), data)
        elif addrSection == "81": #eeprom
            data = self.dbg.eeprom_write(int(addr, 16), data)
        elif addrSection == "82" and self.device_info['interface'].upper() != 'ISP+DW': #fuse
            data = self.dbg.write_fuse(int(addr, 16), data)
        elif addrSection == "83" and self.device_info['interface'].upper() != 'ISP+DW': #lock
            data = self.dbg.write_lock(int(addr, 16), data)
        elif addrSection == "84": #signature
            data = self.dbg.write_signature(int(addr, 16), data)
        elif addrSection == "85" and self.device_info['interface'].upper() != 'ISP+DW': #user signature
            data = self.dbg.write_user_signature(int(addr, 16), data)
        else:
            # Flash write not supported here
            # EACCES
            self.logger.debug("Illegal memtype: %s", addrSection)
            self.sendPacket("E13")
            return
        self.sendPacket("OK")

        
    def getOneRegisterHandler(self, packet):
        """
        'p': read register and send to GDB
        currently only PC
        """
        if len(packet) > 1:
            if packet[1:] == "22":
                # GDB defines PC register for AVR to be REG34(0x22)
                pc = self.dbg.program_counter_read()
                pc = pc << 1 # MCU internal address is a word address, GDB uses byte addresses
                pcString = format(pc, '08x')
                pcByteAr = bytearray.fromhex(pcString.upper())
                pcByteAr.reverse()
                pcByteString = ''.join(format(x, '02x') for x in pcByteAr)
                self.logger.debug("PC: %s", pcByteString)
                self.sendPacket(pcByteString)
                return
        self.logger.debug("Unhandled command: '%s'", packet)
        self.sendPacket("")
        
    def setOneRegisterHandler(self, packet):
        """
        'P': set a single register with a new value given by GDB
        currently not implemented, but should
        """
        self.logger.debug("Unhandled command: '%s'", packet)
        self.sendPacket("")

    def queryHandler(self, packet):
        """
        'q': Query packet
        """
        if len(packet) > 1:
            query = packet[1:]
            self.logger.debug(query)
            if query == "Attached":
                self.sendPacket("0")
                return
            if "Supported" in query:
                self.sendPacket("PacketSize={0:X}".format(self.packet_size))
                self.dbg.software_breakpoint_clear_all()
                return
            if "Symbol::" in query:
                self.sendPacket("OK")
                return
            if query[0] == "C":
                self.sendPacket("")
                return
            if "Offsets" in query:
                self.sendPacket("Text=000;Data=000;Bss=000")
                return
            if "Rcmd" in query:
                payload = query.split(',')[1]
                self.logger.debug("monitor command: %s",binascii.unhexlify(payload))
                handleMonitorCommand(binascii.unhexlify(payload))
                return
        self.logger.debug("Unhandled query: %s", packet)
        self.sendPacket("")


    def stepHandler(self, packet):
        """
        's': single step, perhaps starting a different address
        """
        if len(packet) > 1:
            addr = packet[1:]
            self.logger.debug("Set PC to 0x%s",addr)
            #set PC - note, byte address converted to word address
            self.dbg.program_counter_write(int(addr,16)>>1)
        self.logger.debug("Single-step")
        self.dbg.step()
        self.sendPacket(SIGTRAP)
        self.last_SIGVAL = SIGTRAP
 
    def threadAliveHandler(self, packet):
        """
        'T': Is thread still alive? Yes, always!
        """
        self.logger.debug("Thread alive: YES!");
        self.sendPacket('OK')

    def vCommandHandler(self, packet):
        """
        'v': v-commands; we cater for the following:
        'vRun': reset and wait to be started from address 0
        'vKill': ordinary kill command
        We may latter support vFlashWrite, vFlashErase, and vFlashDone
        """
        if packet[0:4] == 'vRun':
            self.logger.debug("(Re-)start the process and stop")
            self.dbg.reset()
            self.sendPacket(SIGTRAP)
            self.last_SIGVAL = SIGTRAP
        elif packet[0:5] == 'vKill':
            self.logger.debug("Killing process")
            self.dbg.reset()
            self.sendPacket("OK")
            if not self.extended_remote_mode:
                raise EndOfSession
            else:
                self.kill_timeout = 1000
                
        else:
            self.logger.debug("Unhandled command: %s", packet)
            self.sendPacket("")

    def setMemoryBinaryHandler(self, packet):
        """
        'X': load binary file, record contents in binary
        Must be implemented!
        """
        self.logger.debug("Unhandled command: %s", packet)
        self.sendPacket("")
        

    def removeBreakpointHandler(self, packet):
        """
        'z': Remove a breakpoint
        """
        breakpointType = packet[1]
        addr = packet.split(",")[1]
        self.logger.debug("Remove BP at %s", addr)
        if breakpointType == "0":
            #SW breakpoint
            self.dbg.software_breakpoint_clear(int(addr, 16))
            self.sendPacket("OK")
        elif breakpointType == "1":
            #HW breakpoint
            self.dbg.hardware_breakpoint_clear()
            self.sendPacket("OK")
        else:
            #Not Supported
            self.sendPacket("")


    def addBreakpointHandler(self, packet):
        """
        'Z': Set a breakpoint
        """
        breakpointType = packet[1]
        addr = packet.split(",")[1]
        self.logger.debug("Set BP at %s", addr)
        length = packet.split(",")[2]
        if breakpointType == "0":
            #SW breakpoint
            self.dbg.software_breakpoint_set(int(addr, 16))
            self.sendPacket("OK")
        elif breakpointType == "1":
            #HW breakpoint
            self.dbg.hardware_breakpoint_set(int(addr, 16))
            self.sendPacket("OK")
        else:
            #Not Supported
            self.sendPacket("")

    def handleMonitorCommand(self, cmd):
        """
        Monitor commands that directly manipulate the server
        """
        tokens = cmd.split()
        if len(tokens) == 1:
            tokens += [""]
        if "help".startswith(tokens[0]):
            self.sendDebugMessage("monitor help                - this help text")
            self.sendDebugMessage("monitor version             - print version")
            self.sendDebugMessage("monitor debugwire [on|off]  - activate/deactivate debugWIRE mode")
            self.sendDebugMessage("monitor reset               - reset MCU")
            self.sendDebugMessage("monitor timer [freeze|run]  - freeze/run timers when stopped")
            self.sendDebugMessage("monitor breakbpoints [all|software|hardware]")
            self.sendDebugMessage("                            - allow bps of a certain kind only")
            self.sendDebugMessage("monitor singlestep [atomic|interruptible]")
            self.sendDebugMessage("                            - single stepping mode")
            self.sendDebugMessage("The first option is always the default one")
            self.sendPacket("OK")
        elif "version".startswith(tokens[0]):
            self.sendReplyPacket("Version {}",VERSION)
        elif "debugwire".startswith(token[0]):
            self.sendReplyPacket("monitor debugwire NYI")
        elif "reset".startswith(token[0]):
            self.dbg.reset()
            self.sendReplyPacket("MCU has been reset")
        elif "timer".startswith(token[0]):
            self.sendReplyPacket("timer NYI")
        elif "breakpoints".startswith(token[0]):
            self.sendReplyPacket("breakpoints NYI")
        elif "singlestep".startswith(token[0]):
            self.sendReplyPacket("singlestep NYI")
        else:
            self.sendReplyPacket("E09")

    def sendReplyPacket(self, mes):
        self.sendPacket(binascii.hexlify(bytearray(mes.encode('utf-8'))).decode("ascii").upper())

    def sendDebugMessage(self, mes):
        self.sendPacket('O' + binascii.hexlify(bytearray(mes.encode('utf-8'))).decode("ascii").upper())
    
    def pollEvents(self):
        """
        Checks the AvrDebugger for incoming events (breaks)
        """
        pc = self.dbg.poll_event()
        if pc:
            self.logger.info("BREAK received")
            self.sendPacket(SIGTRAP)
            self.last_SIGVAL = SIGTRAP
        if self.kill_timeout:
            self.kill_timeout -= 1
            if self.kill_timeout == 0:
                raise EndOfSession


    def sendPacket(self, packetData):
        """
        Sends a GDB response packet
        """
        checksum = sum(packetData.encode("ascii")) % 256
        message = "$" + packetData + "#" + format(checksum, '02x')
        if packetData == "":
            message = "$#00"
        self.logger.debug("<- %s", message)
        self.socket.sendall(message.encode("ascii"))

    def handleData(self, data):
        if data.decode("ascii").count("$") > 0:
            for _ in range(data.decode("ascii").count("$")):
                validData = True
                data = data.decode("ascii")
                checksum = (data.split("#")[1])[:2]
                packet_data = (data.split("$")[1]).split("#")[0]
                if int(checksum, 16) != sum(packet_data.encode("ascii")) % 256:
                    self.logger.warning("Checksum Wrong in packet: %s", data)
                    validData = False
                if validData:
                    self.socket.sendall(b"+")
                    self.logger.debug("<- +")
                else:
                    self.socket.sendall(b"-")
                    self.logger.debug("<- -")
                self.dispatch(packet_data)
        elif data == b"\x03":
            self.logger.info("Stop")
            self.dbg.stop()
            self.sendPacket(SIGTRAP)
            self.socket.sendall(b"+")
            self.logger.debug("<- +")

    def stopDebugSession(self):
        """
        Check whether user requested to leave debugWIRE mode by having issued 
        a 'monitor debugwire off' command. If so, disable debugWIRE mode and 
        disable DWEN fuse bit. In any case, stop the debugging session
        """
        self.dbg.stop_debugging()


class AvrGdbRspServer(object):
    def __init__(self, avrdebugger, port):
        self.port = port
        self.logger = getLogger(__name__)
        self.avrdebugger = avrdebugger
        self.connection = None
        self.gdb_socket = None
        self.handler = None
        self.address = None

    def serve(self):
        self.gdb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info("Starting dw-gdbserver on port %s", self.port)
        self.gdb_socket.bind(("127.0.0.1", self.port))
        self.gdb_socket.listen()
        self.connection, self.address = self.gdb_socket.accept()
        self.connection.setblocking(0)
        self.logger.info('Connection from %s', self.address)
        self.handler = GdbHandler(self.connection, self.avrdebugger)
        while True:
            # Should iterate through buffer and take out commands/escape characters
            ready = select.select([self.connection], [], [], 0.5)
            if ready[0]:
                data = self.connection.recv(4096)
                if len(data) > 0:
                    self.logger.debug("-> %s", data.decode('ascii'))
                    self.handler.handleData(data)
            self.handler.pollEvents()


    def __del__(self):
        self.handler.stopDebugSession() # stop debugWIRE if requested by user and disconnect from Debugger
        if self.connection:
            self.connection.close()
        if self.gdb_socket:
            self.gdb_socket.close()



def main():
    """
    Configures the CLI and parses the arguments
    """
    parser = argparse.ArgumentParser(usage="%(prog)s [options]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\n\
    GDBserver for debugWIRE MCUs 
            '''))

    # Device to program
    parser.add_argument("-d", "--device",
                            dest='dev',
                            type=str,
                            help="device to debug")
    
    parser.add_argument('-g', '--gede',  action="store_true",
                            help='start gede')    

    parser.add_argument('-p', '--port',  type=int, default=2000, dest='port',
                            help='local port on machine (default 2000)')
    
    parser.add_argument('-s', '--start',  dest='prg', 
                            help='start specified program or "noop"')
    
    # Tool to use
    parser.add_argument("-t", "--tool",
                            type=str, choices=['atmelice', 'edbg', 'icd4', 'ice4', 'jtagice3', 'medbg', 'nedbg',
                                                   'pickit4', 'powerdebugger', 'snap', 'dw-link'],
                            help="tool to connect to")

    parser.add_argument("-u", "--usbsn",
                            type=str,
                            dest='serialnumber',
                            help="USB serial number of the unit to use")

    parser.add_argument("-v", "--verbose",
                            default="warning", choices=['debug', 'info', 'warning', 'error', 'critical'],
                            help="Logging verbosity level")

    parser.add_argument("-V", "--version",
                            help="Print dw-gdbserver version number and exit",
                            action="store_true")

    # Parse args
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(stream=sys.stdout,level=args.verbose.upper())

    logger = getLogger()
    if args.version:
        print("dw-gdbserver version {}".format(VERSION))
        return 0

    # Use pymcuprog backend for initial connection here
    backend = Backend()
    toolconnection = _setup_tool_connection(args)
    device = None

    try:
        backend.connect_to_tool(toolconnection)

        # Read device name from debugger
        device = backend.read_kit_device()

    except pymcuprog.pymcuprog_errors.PymcuprogToolConnectionError:
        print("*** No debugging tool found ***")
        sys.exit(1)
        
    finally:
        backend.disconnect_from_tool()

    if not device:
        device = args.dev
    elif args.dev:
        if arg.dev != device:
            print("Expected MCU:", args.mcu %s,", attached MCU: %s", device)
            sys.exit(1)

    if not device:
        print("Please specify target MCU with -d option")
        sys.exit(1)
            
    transport = hid_transport()
    transport.connect(serial_number=toolconnection.serialnumber, product=toolconnection.tool_name)

    try:
        # Attach debugger
        logger.info("Attaching AvrDebugger to device: %s", device)
        avrdebugger = DWEAvrDebugger(transport)
        avrdebugger.setup_session(device)
        avrdebugger.start_debugging()
        logger.info("Attached")
    except:
        print("--- Could not connect to", device, "---")
        sys.exit(1)

    # Start server 
    logger.info("Starting dw-gdbserver")
    server = AvrGdbRspServer(avrdebugger, args.port)
    try:
        server.serve()
        
    except (EndOfSession, SystemExit, KeyboardInterrupt):
        logger.info("End of session")
        
#    except Exception as e:
#        print("Fatal Error:",e)
    
if __name__ == "__main__":
    sys.exit(main())
