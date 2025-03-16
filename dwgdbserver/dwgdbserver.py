"""
debugWIRE GDBServer 
"""

NOSIG   = 0     # no signal
SIGHUP  = 1     # no connection
SIGINT  = 2     # Interrupt  - user interrupted the program (UART ISR) 
SIGILL  = 4     # Illegal instruction
SIGTRAP = 5     # Trace trap  - stopped on a breakpoint
SIGABRT = 6     # Abort because of a fatal error or no breakpoint available

# args, logging
import importlib.metadata
import time
import sys
import argparse
import os
import logging
from logging import getLogger
import textwrap

# communication
import socket
import select

# utilities
import binascii
import time

# debugger modules
import pymcuprog
from pyedbglib.protocols.avr8protocol import Avr8Protocol 
from pyedbglib.protocols.edbgprotocol import EdbgProtocol 
from pyedbglib.hidtransport.hidtransportfactory import hid_transport
from dwgdbserver.xavrdebugger import XAvrDebugger
from pymcuprog.backend import Backend
from pymcuprog.pymcuprog_main import  _clk_as_int # _setup_tool_connection
from pymcuprog.toolconnection import ToolUsbHidConnection, ToolSerialConnection
from pymcuprog.nvmspi import NvmAccessProviderCmsisDapSpi
from pymcuprog.deviceinfo import deviceinfo
from pymcuprog.utils import read_target_voltage
from pymcuprog.pymcuprog_errors import PymcuprogToolConfigurationError, PymcuprogNotSupportedError, PymcuprogError
from dwgdbserver.deviceinfo.devices.alldevices import dev_id, dev_name

# alternative debug server that connects to the dw-link hardware debugger
import dwgdbserver.dwlink

class EndOfSession(Exception):
    """Termination of session"""
    def __init__(self, msg=None, code=0):
        super(EndOfSession, self).__init__(msg)

class FatalError(Exception):
    """Termination of session because of a fatal error"""
    def __init__(self, msg=None, code=0):
        super(FatalError, self).__init__(msg)

class GdbHandler():
    """
    GDB handler
    Maps between incoming GDB requests and AVR debugging protocols (via pymcuprog)
    """
    def __init__ (self, socket, avrdebugger, devicename):
        self.logger = getLogger('GdbHandler')
        self.socket = socket
        self.dbg = avrdebugger
        self.dw = DebugWIRE(avrdebugger, devicename)
        self.mon = MonitorCommand()
        self.mem = Memory(avrdebugger, self.mon)
        self.bp = BreakAndExec(1, self.mon, avrdebugger, self.mem.flashReadWord)
        self.devicename = devicename
        self.lastSIGVAL = 0
        self.lastmessage = ""
        self.packet_size = 8000
        self.extended_remote_mode = False
        self.vflashdone = False # set to True after vFlashDone received and will then trigger clearing the flash cache


        self.packettypes = {
            '!'           : self.extendedRemoteHandler,
            '?'           : self.stopReasonHandler,
            'c'           : self.continueHandler,
            'C'           : self.continueWithSignalHandler, # signal will be ignored
            'D'           : self.detachHandler,
            'g'           : self.getRegisterHandler,
            'G'           : self.setRegisterHandler,
            'H'           : self.setThreadHandler,
          # 'k'           : kill - never used because vKill is supported
            'm'           : self.getMemoryHandler,
            'M'           : self.setMemoryHandler,
            'p'           : self.getOneRegisterHandler,
            'P'           : self.setOneRegisterHandler,
            'qAttached'   : self.attachedHandler,
            'qOffsets'    : self.offsetsHandler,
            'qRcmd'       : self.monitorCmdHandler,
            'qSupported'  : self.supportedHandler,
            'qfThreadInfo': self.firstThreadInfoHandler,
            'qsThreadInfo': self.subsequentThreadInfoHandler,
            'qXfer'       : self.memoryMapHandler,
          # 'Q'           : general set commands - no relevant cases
          # 'R'           : run command - never used because vRun is supported
            's'           : self.stepHandler,
            'S'           : self.stepWithSignalHandler, # signal will be ignored
            'T'           : self.threadAliveHandler,
            'vCont'       : self.vcontHandler,
            'vFlashDone'  : self.vflashDoneHandler,
            'vFlashErase' : self.vflashEraseHandler,
            'vFlashWrite' : self.vflashWriteHandler,
            'vKill'       : self.killHandler,
            'vRun'        : self.runHandler,
            'X'           : self.setBinaryMemoryHandler,
            'z'           : self.removeBreakpointHandler,
            'Z'           : self.addBreakpointHandler,
            }


    def dispatch(self, cmd, packet):
        """
        Dispatches command to the right handler
        """
        try:
            self.handler = self.packettypes[cmd]
        except (KeyError, IndexError):
            self.logger.debug("Unhandled GDB RSP packet type: %s", cmd)
            self.sendPacket("")
            return
        try:
            if cmd != 'X' and cmd != 'vFlashWrite': # no binary data
                packet = packet.decode('ascii')
            self.handler(packet)
        except (FatalError, PymcuprogNotSupportedError, PymcuprogError) as e:
            self.logger.critical(e)
            self.sendSignal(SIGABRT)

    def extendedRemoteHandler(self, packet):
        """
        '!': GDB tries to switch to extended remote mode and we accept
        """
        self.logger.debug("RSP packet: set exteded remote")
        self.extended_remote_mode = True
        self.sendPacket("OK")

    def stopReasonHandler(self, packet):
        """
        '?': Send reason for last stop: the last signal
        """
        self.logger.debug("RSP packet: ask for last stop reason")
        if not self.lastSIGVAL: self.lastSIGVAL = NOSIG
        self.sendPacket("S{:02X}".format(self.lastSIGVAL))
        self.logger.debug("Reason was %s",self.lastSIGVAL)

    def continueHandler(self, packet):
        """
        'c': Continue execution, either at current address or at given address
        """
        self.logger.debug("RSP packet: Continue")
        if not self.mon.is_dw_mode_active():
            self.logger.debug("Cannot start execution because not connected")
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire enable'")
            self.sendSignal(SIGHUP)
            return
        if self.mem.isFlashEmpty() and not self.mon.is_noload():
            self.logger.debug("Cannot start execution without prior load")
            self.sendDebugMessage("Load executable first before starting execution")
            self.sendSignal(SIGILL)
            return
        newpc = None
        if packet:
            newpc = int(packet,16)
            self.logger.debug("Set PC to 0x%X before resuming execution", newpc)
        self.bp.resumeExecution(newpc)

    def continueWithSignalHandler(self, packet):
        """
        'C': continue with signal, which we ignore here
        """
        self.continueHandler((packet+";").split(";")[1])
        
    def detachHandler(self, packet):
        """
       'D': Detach. All the real housekeeping will take place when the connection is terminated
        """
        self.logger.debug("RSP packet: Detach")
        self.sendPacket("OK")
        raise EndOfSession("Session ended by client ('detach')")

    def getRegisterHandler(self, packet):
        """
        'g': Send the current register values R[0:31] + SREG + SP + PC to GDB
        """
        self.logger.debug("RSP packet: GDB reading registers")
        if self.mon.is_dw_mode_active():
            regs = self.dbg.register_file_read()
            sreg = self.dbg.status_register_read()
            sp = self.dbg.stack_pointer_read()
            pc = self.dbg.program_counter_read() << 1 # get PC as word adress and make a byte address
            regString = ""
            for reg in regs:
                regString = regString + format(reg, '02x')
            sregString = ""
            for reg in sreg:
                sregString = sregString + format(reg, '02x')
            spString = ""
            for reg in sp:
                spString = spString + format(reg, '02x')
            pcstring = binascii.hexlify(pc.to_bytes(4,byteorder='little')).decode('ascii')
            regString = regString + sregString + spString + pcstring
        else:
            regString = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000341200000000"
        self.sendPacket(regString)
        self.logger.debug("Data sent: %s", regString)
        
        
    def setRegisterHandler(self, packet):
        """
        'G': Receive new register ( R[0:31] + SREAG + SP + PC) values from GDB
        """
        self.logger.debug("RSP packet: GDB writing registers")
        self.logger.debug("Data received: %s", packet)
        if self.mon.is_dw_mode_active():
            newdata = binascii.unhexlify(packet)
            self.dbg.register_file_write(newdata[:32])
            self.dbg.status_register_write(newdata[32:33])
            self.dbg.stack_pointer_write(newdata[33:35])
            self.dbg.program_counter_write((int(binascii.hexlify(bytes(reversed(newdata[35:]))),16)) >> 1)
            self.logger.debug("Setting new register data from GDB: %s", packet)
        self.sendPacket("OK")

    def setThreadHandler(self, packet):
        """
        'H': set thread id for next operation. Since we only have one, it is always OK
        """
        self.logger.debug("RSP packet: Set current thread")
        self.sendPacket('OK')

    def getMemoryHandler(self, packet):
        """
        'm': provide GDB with memory contents
        """
        if not self.mon.is_dw_mode_active():
            self.logger.debug("RSP packet: memory read, but not connected")
            self.sendPacket("E01")
            return
        addr = packet.split(",")[0]
        size = packet.split(",")[1]
        isize = int(size, 16)
        self.logger.debug("RSP packet: Reading memory: addr=%s, size=%d", addr, isize)
        if isize == 0:
            self.sendPacket("OK")
            return
        data = self.mem.readmem(addr, size)
        if data:
            dataString = (binascii.hexlify(data)).decode('ascii')
            self.logger.debug("Data retrieved: %s", dataString)
            self.sendPacket(dataString)
        else:
            self.logger.error("Cannot access memory for address 0x%s", addr)
            self.sendPacket("E14")

    def setMemoryHandler(self, packet):
        """
        'M': GDB sends new data for MCU memory
        """
        if not self.mon.is_dw_mode_active():
            self.logger.debug("RSP packet: Memory write, but not connected")
            self.sendPacket("E01")
            return
        addr = packet.split(",")[0]
        size = (packet.split(",")[1]).split(":")[0]
        data = (packet.split(",")[1]).split(":")[1]
        self.logger.debug("RSP packet: Memory write addr=%s, size=%s, data=%s", addr, size, data)
        data = binascii.unhexlify(data)
        if len(data) != int(size,16):
            self.logger.error("Size of data packet does not fit: %s", packet)
            self.sendPacket("E15")
            return
        reply = self.mem.writemem(addr, data)
        self.sendPacket(reply)

        
    def getOneRegisterHandler(self, packet):
        """
        'p': read register and send to GDB
        currently only PC
        """
        if not self.mon.is_dw_mode_active():
            self.logger.debug("RSP packet: read register command, but not connected")
            self.sendPacket("E01")
            return
        if packet == "22":
            # GDB defines PC register for AVR to be REG34(0x22)
            # and the bytes have to be given in reverse order (big endian)
            pc = self.dbg.program_counter_read() << 1
            self.logger.debug("RSP packet: read PC command: 0x%X", pc)
            pcByteString = binascii.hexlify((pc).to_bytes(4,byteorder='little')).decode('ascii')
            self.sendPacket(pcByteString)
        elif packet == "21": # SP
            spByteString = (binascii.hexlify(self.dbg.stack_pointer_read())).decode('ascii')
            self.logger.debug("RSP packet: read SP command (little endian): 0x%s", spByteString)
            self.sendPacket(spByteString)
        elif packet == "20": # SREG
            sregByteString =  (binascii.hexlify(self.dbg.status_register_read())).decode('ascii')
            self.logger.debug("RSP packet: read SREG command: 0x%s", sregByteString)
            self.sendPacket(sregByteString)
        else:
            regByteString =  (binascii.hexlify(self.dbg.sram_read(int(packet,16), 1))).decode('ascii')
            self.logger.debug("RSP packet: read Reg%s command: 0x%s", packet, regByteString)
            self.sendPacket(regByteString)            
        
    def setOneRegisterHandler(self, packet):
        """
        'P': set a single register with a new value given by GDB
        """
        if not self.mon.is_dw_mode_active():
            self.logger.debug("RSP packet: write register command, but not connected")
            self.sendPacket("E01")
            return
        if packet[0:3] == "22=": # PC
            pc = int(binascii.hexlify(bytearray(reversed(binascii.unhexlify(packet[3:])))),16)
            self.logger.debug("RSP packet: write PC=0x%X", pc)
            self.dbg.program_counter_write(pc>>1) # write PC as word address
        elif packet[0:3] == "21=": # SP (already in little endian order)
            self.logger.debug("RSP packet: write SP (little endian)=%s", packet[3:])
            self.dbg.stack_pointer_write(binascii.unhexlify(packet[3:]))
        elif packet[0:3] == "20=": # SREG
            self.logger.debug("RSP packet: write SREG=%s",packet[3:])
            self.dbg.status_register_write(binascii.unhexlify(packet[3:]))
        else:
            self.logger.debug("RSP packet: write REG%d=%s",int(packet[0:2],16),packet[3:])
            self.dbg.sram_write(int(packet[0:2],16), binascii.unhexlify(packet[3:]))
        self.sendPacket("OK")
            

    def attachedHandler(self,packet):
        """
        'qAttached': whether detach or kill will be used when quitting GDB
        """
        self.logger.debug("RSP packet: attached query, will answer '1'")
        self.sendPacket("1")

    def offsetsHandler(self, packet):
        """
        'qOffsets': Querying offsets of the different memory areas
        """
        self.logger.debug("RSP packet: offset query, will answer 'Text=000;Data=000;Bss=000'")
        self.sendPacket("Text=000;Data=000;Bss=000")

    def monitorCmdHandler(self, packet):
        """
        'qRcmd': Monitor commands that directly get info or set values in the gdbserver
        """
        payload = packet[1:]
        self.logger.debug("RSP packet: monitor command: %s",binascii.unhexlify(payload).decode('ascii'))
        tokens = binascii.unhexlify(payload).decode('ascii').split()
        try:
            response = self.mon.dispatch(tokens)
            if response[0] == 'dwon':
                self.dw.coldStart(graceful=False, callback=self.sendPowerCycle)
            elif response[0] == 'dwoff':
                self.dw.disable()
            elif response[0] == 'reset':
                self.dbg.reset()
            elif response[0] in [0, 1]:
                self.dbg.device.avr.protocol.set_byte(Avr8Protocol.AVR8_CTXT_OPTIONS,
                                                    Avr8Protocol.AVR8_OPT_RUN_TIMERS,
                                                    response[0])
            elif 'power o' in response[0]:
                self.dbg.edbg_protocol.set_byte(EdbgProtocol.EDBG_CTXT_CONTROL,
                                                    EdbgProtocol.EDBG_CONTROL_TARGET_POWER,
                                                    'on' in response[0])
            elif 'power q' in response[0]:
                resp = self.dbg.edbg_protocol.query(EdbgProtocol.EDBG_QUERY_COMMANDS)
                self.logger.info("Commands: %s", resp)
            if response[0] == 'livetest':
                from testcases import runtests
                runtests()
        except (FatalError, PymcuprogNotSupportedError, PymcuprogError) as e:
            self.logger.critical(e)
            self.sendReplyPacket("Fatal error: %s\nNo execution is possible any longer" % e)
        else:
            self.sendReplyPacket(response[1])


    def sendPowerCycle(self):
        if self.dbg.transport.device.product_string.lower().startswith('medbg'):
            # mEDBG are the only ones it will work with, I believe.
            # I tried to use a try/except construction,
            # but this confuses the debugger and it is stuck
            # in an illegal state (the housekeeper does not respond)
            self.logger.debug("Try automatic power-cycling")
            self.dbg.edbg_protocol.set_byte(EdbgProtocol.EDBG_CTXT_CONTROL,
                                                EdbgProtocol.EDBG_CONTROL_TARGET_POWER,
                                                0)
            time.sleep(0.5)
            self.dbg.edbg_protocol.set_byte(EdbgProtocol.EDBG_CTXT_CONTROL,
                                                EdbgProtocol.EDBG_CONTROL_TARGET_POWER,
                                                1)
            time.sleep(0.1)
            self.logger.info("Automatic power-cycling successful")
            return True
        self.sendDebugMessage("*** Please power-cycle the target system ***")
        return False
        
    def supportedHandler(self, packet):
        """
        'qSupported': query for features supported by the gbdserver; in our case packet size and memory map
        Because this is also the command send after a connection with 'target remote' is made,
        we will try to establish a connection to the debugWIRE target.
        """
        self.logger.debug("RSP packet: qSupported query, will answer 'PacketSize={0:X};qXfer:memory-map:read+'".format(self.packet_size))
        # Try to start a debugWIRE debugging session
        # if we are already in debugWIRE mode, this will work
        # if not, one has to use the 'monitor debugwire on' command later on
        if  self.dw.warmStart(graceful=True):
            self.mon.set_dw_mode_active()
        self.logger.debug("dw_mode_active=%d",self.mon.is_dw_mode_active())
        self.sendPacket("PacketSize={0:X};qXfer:memory-map:read+".format(self.packet_size))

    def firstThreadInfoHandler(self, packet):
        """
        'qfThreadInfo': get info about active threads
        """
        self.logger.debug("RSP packet: first thread info query, will answer 'm01'")
        self.sendPacket("m01")

    def subsequentThreadInfoHandler(self, packet):
        """
        'qsThreadInfo': get more info about active threads
        """
        self.logger.debug("RSP packet: subsequent thread info query, will answer 'l'")
        self.sendPacket("l") # the previously given thread was the last one

    def memoryMapHandler(self, packet):
        """
        'qXfer:memory-map:read' - provide info about memory map so that the vFlash commands are used
        """
        if ":memory-map:read" in packet and not self.mon.is_noxml(): 
            self.logger.debug("RSP packet: memory map query")
            map = self.mem.memoryMap()
            self.sendPacket(map)
            self.logger.debug("Memory map=%s", map)            
        else:
            self.logger.debug("Unhandled query: qXfer%s", packet)
            self.sendPacket("")

    def stepHandler(self, packet):
        """
        's': single step, perhaps starting at a different address
        """
        self.logger.debug("RSP packet: single-step")
        if not self.mon.is_dw_mode_active():
            self.logger.debug("Cannot single-step because not connected")
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire on'")
            self.sendSignal(SIGHUP)
            return
        if self.mem.isFlashEmpty() and not self.mon.is_noload():
            self.logger.debug("Cannot single-step without prior load")
            self.sendDebugMessage("Load executable first before starting execution")
            self.sendSignal(SIGILL)
            return
        newpc = None
        if packet:
            newpc = int(packet,16)
            self.logger.debug("Set PC to 0x%s before single step",newpc)
        self.sendSignal(self.bp.singleStep(newpc))

    def stepWithSignalHandler(self, packet):
        """
        'S': single-step with signal, which we ignore here
        """
        self.stepHandler((packet+";").split(";")[1])
 
    def threadAliveHandler(self, packet):
        """
        'T': Is thread still alive? Yes, always!
        """
        self.logger.debug("RSP packet: thread alive query, will answer 'OK'");
        self.sendPacket('OK')

    def vcontHandler(self, packet):
        """
        'vCont': eversything about execution
        """
        self.logger.debug("RSP packet: vCont")
        if packet == '?': # asks for capabilities
            self.logger.debug("Tell GDB about vCont capabilities: c, C, s, S, r")
            self.sendPacket("vCont;c;C;s;S;r")
        elif packet[0] == ';':
            if packet[1] in ['c', 'C']:
                self.continueHandler("")
            elif packet[1] in ['s', 'S']:
                self.stepHandler("");
            elif packet[1] == 'r':
                range = packet[2:].split(':')[0].split(',')
                self.sendSignal(self.bp.rangeStep(int(range[0],16), int(range[1],16)))
            else:
                self.sendPacket("") # unknown
        else:
            self.sendPacket("") # unknown
            

    def vflashDoneHandler(self, packet):
        """
        'vFlashDone': everything is there, now we can start flashing! 
        """
        self.logger.debug("RSP packet: vFlashDone")
        self.vflashdone = True
        self.logger.info("Starting to flash ...")
        try:
            self.mem.flashPages()
        except:
            self.logger.error("Flashing was unsuccessful")
            self.sendPacket("E11")            
            raise
        self.logger.info("Flash done")
        self.sendPacket("OK")            
        
    def vflashEraseHandler(self, packet):
        """
        'vFlashErase': Since we cannot and need not to erase pages,
        we only use this command to clear the cache when there was a previous
        vFlashDone command.
        """
        self.logger.debug("RSP packet: vFlashErase")
        if self.vflashdone:
            self.vflashdone = False
            self.mem.initFlash() # clear cache
        if self.mon.is_dw_mode_active():
            if self.mem.isFlashEmpty():
                self.logger.info("Loading executable ...")
            self.sendPacket("OK")
        else:
            self.sendPacket("E01")
            
    def vflashWriteHandler(self, packet):
        """
        'vFlashWrite': chunks of the program data we need to flash
        """
        addrstr = (packet.split(b':')[1]).decode('ascii')
        data = self.unescape(packet[len(addrstr)+2:])
        addr = int(addrstr, 16)
        self.logger.debug("RSP packet: vFlashWrite starting at 0x%04X", addr)
        #insert new block in flash cache
        self.mem.storeToCache(addr, data)
        self.sendPacket("OK")

    @staticmethod
    def escape(data):
        """
        Escape binary data to be sent to Gdb.

        :param: data Bytes-like object containing raw binary.
        :return: Bytes object with the characters in '#$}*' escaped as required by Gdb.
        """
        result = []
        for c in data:
            if c in tuple(b'#$}*'):
                # Escape by prefixing with '}' and xor'ing the char with 0x20.
                result += [0x7d, c ^ 0x20]
            else:
                result.append(c)
        return bytes(result)

    @staticmethod
    def unescape(data):
        """
        De-escapes binary data from Gdb.
        
        :param: data Bytes-like object with possibly escaped values.
        :return: List of integers in the range 0-255, with all escaped bytes de-escaped.
        """
        data_idx = 0

        # unpack the data into binary array
        result = list(data)

        # check for escaped characters
        while data_idx < len(result):
            if result[data_idx] == 0x7d:
                result.pop(data_idx)
                result[data_idx] = result[data_idx] ^ 0x20
            data_idx += 1

        return result

    def killHandler(self, packet):
        """
        'vKill': Kill command. Will be called, when the user requests a 'kill', but also 
        when in extended-remote mode, when a 'run' is issued. In ordinary remote mode, it
        will disconnect, in extended-remote it will not, and you can restart or load a modified 
        file and run that one.
        """
        self.logger.debug("RSP packet: kill process, will reset CPU")
        if self.mon.is_dw_mode_active():
            self.dbg.reset()
        self.sendPacket("OK")
        if not self.extended_remote_mode:
            self.logger.debug("Terminating session ...")
            raise EndOfSession

    def runHandler(self, packet):
        """
        'vRun': reset and wait to be started from address 0 
        """
        self.logger.debug("RSP packet: run")
        if not self.mon.is_dw_mode_active():
            self.logger.debug("Cannot start execution because not connected")
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire on'")
            self.sendSignal(SIGHUP)
            return
        self.logger.debug("Resetting CPU and wait for start")
        self.dbg.reset()
        self.sendSignal(SIGTRAP)

    def setBinaryMemoryHandler(self, packet):
        """
        'X': Binary load
        """
        addr = (packet.split(b',')[0]).decode('ascii')
        size = int(((packet.split(b',')[1]).split(b':')[0]).decode('ascii'),16)
        data = self.unescape((packet.split(b':')[1]))
        self.logger.debug("RSP packet: X, addr=0x%s, length=%d, data=%s" % (addr, size, data))
        if not self.mon.is_dw_mode_active() and size > 0:
            self.logger.debug("RSP packet: Memory write, but not connected")
            self.sendPacket("E01")
            return
        if len(data) != size:
            self.logger.error("Size of data packet does not fit: %s", packet)
            self.sendPacket("E15")
            return
        try:
            reply = self.mem.writemem(addr, bytearray(data))
        except:
            self.logger.error("Loading binary data was unsuccessful")
            self.sendPacket("E11")
            raise
        self.sendPacket(reply)

    def removeBreakpointHandler(self, packet):
        """
        'z': Remove a breakpoint
        """
        if not self.mon.is_dw_mode_active():
            self.sendPacket("E01")
            return
        breakpoint_type = packet[0]
        addr = packet.split(",")[1]
        self.logger.debug("RSP packet: remove BP of type %s at %s", breakpoint_type, addr)
        if breakpoint_type == "0" or breakpoint_type == "1":
            self.bp.removeBreakpoint(int(addr, 16))
            self.sendPacket("OK")
        else:
            self.logger.debug("Breakpoint type %s not supported", breakpoint_type)
            self.sendPacket("")

    def addBreakpointHandler(self, packet):
        """
        'Z': Set a breakpoint
        """
        if not self.mon.is_dw_mode_active():
            self.sendPacket("E01")
            return
        breakpoint_type = packet[0]
        addr = packet.split(",")[1]
        self.logger.debug("RSP packet: set BP of type %s at %s", breakpoint_type, addr)
        length = packet.split(",")[2]
        if breakpoint_type == "0" or breakpoint_type == "1":
            if self.bp.insertBreakpoint(int(addr, 16)):
                self.sendPacket("OK")
            else:
                self.sendPacket("E07")
        else:
            self.logger.debug("Breakpoint type %s not supported", breakpoint_type)
            self.sendPacket("")

    def pollEvents(self):
        """
        Checks the AvrDebugger for incoming events (breaks)
        """
        if not self.mon.is_dw_mode_active(): # if DW is not enabled yet, simply return
            return
        pc = self.dbg.poll_event()
        if pc:
            self.logger.debug("MCU stopped execution")
            self.sendSignal(SIGTRAP)

    def pollGdbInput(self):
        """
        Checks whether input from GDB is waiting. If so while singelstepping, we might stop.
        """
        ready = select.select([self.socket], [], [], 0) # just look, never wait
        return bool(ready[0])

    def sendPacket(self, packetData):
        """
        Sends a GDB response packet
        """
        checksum = sum(packetData.encode("ascii")) % 256
        message = "$" + packetData + "#" + format(checksum, '02x')
        self.logger.debug("<- %s", message)
        self.lastmessage = packetData
        self.socket.sendall(message.encode("ascii"))

    def sendReplyPacket(self, mes):
        """
        Send a packet as a reply to a monitor command to be displayed in the debug console
        """
        self.sendPacket(binascii.hexlify(bytearray((mes+"\n").encode('utf-8'))).decode("ascii").upper())

    def sendDebugMessage(self, mes):
        """
        Send a packet that always should be displayed in the debug console when the system
        is in active mode.
        """
        self.sendPacket('O' + binascii.hexlify(bytearray((mes+"\n").encode('utf-8'))).decode("ascii").upper())
    
    def sendSignal(self, signal):
        """
        Sends signal to GDB
        """
        self.lastSIGVAL = signal
        if signal: # do nothing if None or 0
            if signal in [SIGHUP, SIGILL, SIGABRT]:
                self.sendPacket("S{:02X}".format(signal))
                return
            sreg = self.dbg.status_register_read()[0]
            spl, sph = self.dbg.stack_pointer_read()
            pc = self.dbg.program_counter_read() << 1 # get PC as word adress and make a byte address
            pcstring = binascii.hexlify(pc.to_bytes(4,byteorder='little')).decode('ascii')
            stoppacket = "T{:02X}20:{:02X};21:{:02X}{:02X};22:{};thread:1;".format(signal, sreg, spl, sph, pcstring)
            self.sendPacket(stoppacket)

    def handleData(self, data):
        """
        Analyze the incomming data stream from GDB. Allow more than one RSP record per packet, although this should
        not be necessary because each packet needs to be acknowledged by a '+' from us. 
        """
        while data:
            if data[0] == ord('+'): # ACK
                self.logger.debug("-> +")
                data = data[1:]
                if not data or data[0] not in b'+-': # if no ACKs/NACKs are following, delete last message
                    self.lastmessage = None
            elif data[0] == ord('-'): # NAK, resend last message
                # remove multiple '-'
                i = 0
                while (i < len(data) and data[i] == ord('-')):
                    i += 1
                data = data[i:]
                self.logger.debug("-> -")
                if (self.lastmessage):
                    self.logger.debug("Resending packet to GDB")
                    self.sendPacket(self.lastmessage)
                else:
                    self.sendPacket("")
            elif data[0] == 3: # CTRL-C
                self.logger.info("CTRL-C")
                self.dbg.stop()
                self.sendSignal(SIGINT)
                #self.socket.sendall(b"+")
                #self.logger.debug("<- +")
                data = data[1:]
            elif data[0] == ord('$'): # start of message
                validData = True
                self.logger.debug('-> %s', data)
                checksum = (data.split(b"#")[1])[:2]
                packet_data = (data.split(b"$")[1]).split(b"#")[0]
                if int(checksum, 16) != sum(packet_data) % 256:
                    self.logger.warning("Checksum Wrong in packet: %s", data)
                    validData = False
                if not validData:
                    self.socket.sendall(b"-")
                    self.logger.debug("<- -")
                else:
                    self.socket.sendall(b"+")
                    self.logger.debug("<- +")
                    # now split into command and data (or parameters) and dispatch
                    if not (chr(packet_data[0]) in 'vqQ'):
                        i = 1
                    else:
                        for i in range(len(packet_data)+1):
                            if i == len(packet_data) or not chr(packet_data[i]).isalpha():
                                break
                    self.dispatch(packet_data[:i].decode('ascii'),packet_data[i:])
                data = data[(data.index(b"#")+2):]
            else: # ignore character
                data = data[1:]

class Memory(object):
    """
    This class is responsible for access to all kinds of memory, for loading the flash memory, 
    and for managing the flash cache.

    Flash cache is implemented as a growing bytearray. We start always at 0x0000 and fill empty
    spaces by 0xFF. _flashmem_start_prog points always to the first adddress from which we need to 
    programm flash memory. Neither the end of the flash cache nor _flashmem_start_prog need to be 
    aligned with multi_page_size (page_size multiplied by buffers_per_flash_page).
    When programming, we will restart at a lower adderess or add 0xFF at the end. 
    """

    def __init__(self, dbg, mon):
        self.logger = getLogger('Memory')
        self.dbg = dbg
        self.mon = mon
        self._flash = bytearray() # bytearray starting at 0x0000
        # some device info that is needed throughout
        self._flash_start = self.dbg.memory_info.memory_info_by_name('flash')['address']
        self._flash_page_size = self.dbg.memory_info.memory_info_by_name('flash')['page_size']
        self._flash_size = self.dbg.memory_info.memory_info_by_name('flash')['size']
        self._multi_buffer = self.dbg.device_info.get('buffers_per_flash_page',1)
        self._multi_page_size = self._multi_buffer*self._flash_page_size
        self._sram_start = self.dbg.memory_info.memory_info_by_name('internal_sram')['address']
        self._sram_size = self.dbg.memory_info.memory_info_by_name('internal_sram')['size']
        self._eeprom_start = self.dbg.memory_info.memory_info_by_name('eeprom')['address']
        self._eeprom_size = self.dbg.memory_info.memory_info_by_name('eeprom')['size']
        self._flashmem_start_prog = 0

    def initFlash(self):
        """
        Initialize flash by emptying it.
        """
        self._flash = bytearray()
        self._flashmem_start_prog = 0

    def isFlashEmpty(self):
        """
        Return true if flash cache is empty.
        """
        return len(self._flash) == 0

    def flashFilled(self):
        """
        Return how many bytes have already be filled.
        """
        return len(self._flash)

    def readmem(self, addr, size):
        """
        Read a chunk of memory and return a bytestring or bytearray. The parameter addr and size should be
        hex strings.
        """
        iaddr, method, _ = self.memArea(addr)
        isize = int(size, 16)
        return method(iaddr, isize)

    def writemem(self, addr, data):
        """
        Write a chunk of memory and return a reply string. The parameter addr and size should be
        hex strings.
        """
        iaddr, _, method = self.memArea(addr)
        if not data:
            return "OK"
        result = method(iaddr, data)
        if result == False:
            return "E14"
        else:
            return "OK"

    def memArea(self, addr):
        """
        This function returns a triple consisting of the real address as an int, the read, and the write method.
        If illegal address section, report and return (0, lambda *x: bytes(), lambda *x: False) 
        """
        addrSection = "00"
        if len(addr) > 4:
            if len(addr) == 6:
                addrSection = addr[:2]
                addr = addr[2:]
            else:
                addrSection = "0" + addr[0]
                addr = addr[1:]
        iaddr = int(addr,16)
        self.logger.debug("Address section: %s",addrSection)
        if addrSection == "80": # ram
            return(iaddr, self.dbg.sram_read, self.dbg.sram_write)
        elif addrSection == "81": # eeprom
            return(iaddr, self.dbg.eeprom_read, self.dbg.eeprom_write) 
        elif addrSection == "00": # flash
            return(iaddr, self.flashRead, self.flashWrite)
        self.logger.error("Illegal memtype in memory access operation at %s: %s", addr, addrSection)
        return (0, lambda *x: bytes(), lambda *x: False)

    def flashRead(self, addr, size):
        """ 
        Read flash contents from cache that had been constructed during loading the file.
        It is faster and circumvents the problem that with some debuggers only page-sized
        access is possible. If there is nothing in the cache or it is explicitly disallowed, 
        fall back to reading the flash page-wise (which is the only way supported by mEDBG).
        """
        self.logger.debug("Trying to read %d bytes starting at 0x%X", size, addr)
        if not self.mon.is_dw_mode_active():
            self.logger.error("Cannot read from memory when DW mode is disabled")
            return bytearray([0xFF]*size)
        if self.mon.is_cache() and addr + size <= self.flashFilled():
            return self._flash[addr:addr+size]
        baseaddr = (addr // self._flash_page_size) * self._flash_page_size
        endaddr = addr + size
        pnum = ((endaddr - baseaddr) +  self._flash_page_size - 1) // self._flash_page_size
        self.logger.debug("No cache, request %d pages starting at 0x%X", pnum, baseaddr)
        response = bytearray()        
        for p in range(pnum):
            response +=  self.dbg.flash_read(baseaddr + (p * self._flash_page_size),
                                                  self._flash_page_size)
        self.logger.debug("Response from page read: %s", response)
        response = response[addr-baseaddr:addr-baseaddr+size]
        return(response)
    
    def flashReadWord(self, addr):
        """
        Read one word at an even address from flash (LSB first!) and return it as a word value.
        """
        return(int.from_bytes(self.flashRead(addr, 2), byteorder='little'))

    def flashWrite(self, addr, data):
        """
        This writes an abitrary chunk of data to flash. If addr is lower than len(self._flash),
        the cache is cleared. This should do the right thing when loading is implemented with X-records. 
        """
        if addr < len(self._flash):
            self.initFlash()
        self.storeToCache(addr, data)
        self.flashPages()

    def storeToCache(self, addr, data):
        """
        Store chunks into the flash cache. Programming will take place later.
        """
        if addr < len(self._flash):
            raise FatalError("Overlapping  flash areas at 0x%X" % addr)
        self._flash.extend(bytearray([0xFF]*(addr - len(self._flash) )))
        self._flash.extend(data)

    def flashPages(self):
        """
        Write pages to flash memory, starting at _flashmem_start_prog up to len(self._flash)-1.
        Since programming takes place in chunks of size self._multi_page_size, beginning and end
        needs to be adjusted. At the end, we may add some 0xFFs.
        """
        startaddr = (self._flashmem_start_prog // self._multi_page_size) * self._multi_page_size
        stopaddr = ((len(self._flash) + self._multi_page_size - 1) //
                            self._multi_page_size) * self._multi_page_size
        pgaddr = startaddr
        while pgaddr < stopaddr:
            self.logger.debug("Flashing page starting at 0x%X", pgaddr)
            pagetoflash = self._flash[pgaddr:pgaddr + self._multi_page_size]
            currentpage = bytearray([])
            if self.mon.is_fastload():
                # interestingly, it is faster to read single pages than a multi-page chunk!
                for p in range(self._multi_buffer):
                    currentpage += self.dbg.flash_read(pgaddr+(p*self._flash_page_size), self._flash_page_size)
            if currentpage[:len(pagetoflash)] == pagetoflash:
                self.logger.debug("Skip flashing page because already flashed at 0x%X", pgaddr)
            else:
                self.logger.debug("Flashing now from 0x%X to 0x%X", pgaddr, pgaddr+len(pagetoflash))
                pagetoflash.extend(bytearray([0xFF]*(self._multi_page_size-len(pagetoflash)))) # fill incomplete page
                flashmemtype = self.dbg.device.avr.memtype_write_from_string('flash')
                self.dbg.device.avr.write_memory_section(flashmemtype,
                                                            pgaddr,
                                                            pagetoflash,
                                                            self._flash_page_size,
                                                            allow_blank_skip=(self._multi_buffer == 1))
                if self.mon.is_verify():
                    readbackpage = bytearray([])
                    for p in range(self._multi_buffer):
                        readbackpage += self.dbg.flash_read(pgaddr+(p*self._flash_page_size),
                                                                     self._flash_page_size)
                    #self.logger.debug("pagetoflash: %s", pagetoflash.hex())
                    #self.logger.debug("readback: %s", readbackpage.hex())
                    if readbackpage != pagetoflash:
                        raise FatalError("Flash verification error on page 0x{:X}".format(pgaddr))
            pgaddr += self._multi_page_size
        self.flashmem_start_prog = len(self._flash)
    
    def memoryMap(self):
        """
        Return a memory map in XML format. Include registers, IO regs, and EEPROM in SRAM area
        """
        return ('l<memory-map><memory type="ram" start="0x{0:X}" length="0x{1:X}"/>' + \
                             '<memory type="flash" start="0x{2:X}" length="0x{3:X}">' + \
                             '<property name="blocksize">0x{4:X}</property>' + \
                             '</memory></memory-map>').format(0 + 0x800000, \
                             (0x10000 + self._eeprom_start + self._eeprom_size),
                              self._flash_start, self._flash_size, self._multi_page_size)


class BreakAndExec(object):
    """
    This class manages breakpoints, supports flashwear minimizing execution, and 
    makes interrupt-safe single stepping possible.
    """

    def __init__(self, hwbps, mon, dbg, readFlashWord):
        self.mon = mon
        self.dbg = dbg
        self.logger = getLogger('BreakAndExec')
        self._hwbps = hwbps
        self._readFlashWord = readFlashWord
        self._hw = [None]*self._hwbps
        self._bp = dict()
        self._bpactive = 0
        self._bstamp = 0
        self._bigmem = self.dbg.memory_info.memory_info_by_name('flash')['size'] > 128*1024 # more than 128 MB
        self._rangeStart = 0
        self._rangeStop = 0
        self._rangeWord = []
        self._rangeExit = set()
        if self._bigmem:
            raise FatalError("Cannot deal with address spaces larger than 128 MB")


    def insertBreakpoint(self, address):
        """
        Generate a new breakpoint at given address, do not allocate flash or hwbp yet
        Will return False if no breakpoint can be set.
        This method will be called immediately before GDB starts executing or single-stepping
        """
        if address % 2 != 0:
            self.logger.error("Breakpoint at odd address: 0x%X", address)
            return False
        if self.mon.is_old_exec():
            self.dbg.software_breakpoint_set(address)
            return True
        if address in self._bp: # bp already set, needs to be activated
            self.logger.debug("Already existing BP at 0x%X will be re-activated",address)
            if not self._bp[address]['active']: # if already active, ignore
                if self._bpactive >= self._hwbps and self.mon.is_onlyhwbps():
                    self.logger.debug("Cannot set breakpoint at 0x%X because there are too many", address)
                    return False
                self._bp[address]['active'] = True
                self._bpactive += 1
                self.logger.debug("Set BP at 0x%X to active", address)
            else:
                self.logger.debug("There is already a BP at 0x%X active", address)
            return True

        self.logger.debug("New BP at 0x%X", address)
        if self._bpactive >= self._hwbps and self.mon.is_onlyhwbps():
            self.logger.error("Too many HWBPs requested. No BP at: 0x%X", address)
            return False
        opcode = self._readFlashWord(address)
        secondword = self._readFlashWord(address+2)
        self._bstamp += 1
        self._bp[address] =  {'inuse' : True, 'active': True, 'inflash': False, 'hwbp' : None,
                                 'opcode': opcode, 'secondword' : secondword, 'timestamp' : self._bstamp }
        self.logger.debug("New BP at 0x%X: %s", address,  self._bp[address])
        self._bpactive += 1
        self.logger.debug("Now %d active BPs", self._bpactive)
        return True

    def removeBreakpoint(self, address):
        """
        Will mark a breakpoint as non-active, but it will stay in flash memory.
        This method is called immmediately after execution is stopped.
        """
        if address % 2 != 0:
            self.logger.error("Breakpoint at odd address: 0x%X", address)
            return
        if self.mon.is_old_exec():
            self.dbg.software_breakpoint_clear(address)
            return True
        if not (address in self._bp) or not self._bp[address]['active']:
            self.logger.debug("BP at 0x%X was removed before", address)
            return # was already removed before
        self._bp[address]['active'] = False
        self._bpactive -= 1
        self.logger.debug("BP at 0x%X is now inactive", address)
        self.logger.debug("Only %d BPs are now active", self._bpactive)

    def updateBreakpoints(self):
        """
        This is called directly before execution is started. It will remove inactive breakpoints,
        will assign the hardware breakpoints to the most recently added breakpoints, and
        request to set active breakpoints into flash, if they not there already.
        """
        # remove inactive BPs
        self.logger.debug("Updating breakpoints before execution")
        for a in list(self._bp.keys()):
            if self.mon.is_onlyswbps() and self._bp[a]['hwbp']:
                self.logger.debug("Removing HWBP at 0x%X  because only SWBPs allowed", a)
                self._bp[a]['hwbp'] = None
                self._hw = [None]*self._hwbps
            if not self._bp[a]['active']:
                self.logger.debug("BP at 0x%X is not active anymore", a)
                if self._bp[a]['inflash']:
                    self.logger.debug("Removed as a SW BP")
                    self.dbg.software_breakpoint_clear(a)
                if self._bp[a]['hwbp']:
                    self.logger.debug("Removed as a HW BP")
                    self._hw[self._bp[a]['hwbp']-1] = None
                del self._bp[a]
        # all remaining BPs are active
        # assign HWBPs to the most recently introduced BPs
        # but take into account the possibility that hardware breakpoints are not allowed
        sortedbps = sorted(self._bp.items(), key=lambda entry: entry[1]['timestamp'], reverse=True)
        self.logger.debug("Sorted BP list: %s", sortedbps)
        for h in range(min(self._hwbps*(1-self.mon.is_onlyswbps()),len(sortedbps))):
            self.logger.debug("Consider BP at 0x%X", sortedbps[0][0])
            if sortedbps[h][1]['hwbp'] or sortedbps[h][1]['inflash']:
                self.logger.debug("BP at 0x%X is already assigned, either HWBP or SWBP", sortedbps[h][0])
                continue
            if None in self._hw: # there is still an available hwbp
                self.logger.debug("There is still a free HWBP at index: %s", self._hw.index(None))
                self._bp[sortedbps[h][0]]['hwbp'] = self._hw.index(None)+1
                self._hw[self._hw.index(None)] = sortedbps[h][0]
            else: # steal hwbp from oldest
                self.logger.debug("Trying to steal HWBP")
                stealbps = sorted(self._bp.items(), key=lambda entry: entry[1]['timestamp'])
                for s in range(len(stealbps)):
                    if stealbps[s][1]['hwbp']:
                        self.logger.debug("BP at 0x%X is a HWBP", stealbps[s][0])
                        self._bp[sortedbps[h][0]]['hwbp'] = stealbps[s][1]['hwbp']
                        self.logger.debug("Now BP at 0x%X is the HWP", sortedbps[h][0])
                        self._hw[stealbps[s][1]['hwbp']-1] = sortedbps[h][0]
                        self._bp[stealbps[s][0]]['hwbp'] = None
                        break
        # now request SW BPs, if they are not already in flash, and set the HW registers
        for a in self._bp:
            if self._bp[a]['inflash']:
                self.logger.debug("BP at 0x%X is already in flash", a)
                continue # already in flash
            if self._bp[a]['hwbp'] and self._bp[a]['hwbp'] > 1:
                self.logger.error("This case should not happen with debugWIRE!")
                #set HW BP, the '1' case will be handled by run_to
                # this is future implementation when JTAG or UPDI enter the picture
                continue
            if not self._bp[a]['inflash'] and not self._bp[a]['hwbp']:
                self.logger.debug("BP at 0x%X will now be set as a SW BP", a)
                self.dbg.software_breakpoint_set(a)
                self._bp[a]['inflash'] = True

    def cleanupBreakpoints(self):
        """
        Remove all breakpoints from flash
        """
        ### You need to cleanup also the corresponding HW BPs
        self.logger.info("Deleting all breakpoints ...")
        self._hw = [None for x in range(self._hwbps)]
        self.dbg.software_breakpoint_clear_all()
        self._bp = {}
        self._bpactive = 0

    def resumeExecution(self, addr):
        """
        Start execution at given addr (byte addr). If none given, use the actual PC.
        Update breakpoints in memory and the HWBP. 
        """
        self.updateBreakpoints()
        if addr:
            self.dbg.program_counter_write(addr>>1)
        else:
            addr = self.dbg.program_counter_read() << 1
        if self.mon.is_old_exec():
            self.dbg.run()
            return
        if self._hw[0] != None:
            self.logger.debug("Run to cursor at 0x%X starting at 0x%X", self._hw[0], addr)
            self.dbg.run_to(self._hw[0]) # according to docu, it is the word address, but in reality it is the byte address!
        else:
            self.logger.debug("Now start executing at 0x%X without HWBP", addr)
            self.dbg.run()
        return None

    def singleStep(self, addr):
        """
        Perform a single step. This can mean to simulate a two-word instruction or ask the hardware debugger
        to do a single step. 
        If mon.safe is true, it means that we will make every effort to not end up in the interrupt vector table. 
        For all straight-line instructions, we will use the hardware breakpoint to break after one step.
        If an interrupt occurs, we may break in the ISR, if there is a breakpoint, or we will not notice it at all.
        For all remaining instruction (except those branching on the I-bit), we clear the I-bit before and set it 
        afterwards (if necessary). For those branching on the I-Bit, we will evaluate and then set the hardware BP. 
        """
        if addr:
            self.dbg.program_counter_write(addr>>1)
        else:
            addr = self.dbg.program_counter_read() << 1
        self.logger.debug("One single step at 0x%X", addr)
        if self.mon.is_old_exec():
            self.dbg.step()
            return SIGTRAP
        self.updateBreakpoints()
        # if there is a two word instruction and a SWBP at the place where we want to step, simulate!
        if (addr in self._bp and self._bp[addr]['inflash']
                and self.twoWordInstr(self._bp[addr]['opcode'])):
            self.logger.debug("Two-word instruction at SWBP")
            addr = self.simTwoWordInstr(self._bp[addr]['opcode'], self._bp[addr]['secondword'], addr)
            self.logger.debug("New PC(byte addr)=0x%X, return SIGTRAP", addr)
            self.dbg.program_counter_write(addr>>1)
            return SIGTRAP
        # if stepping is unsafe, just use the AVR stepper
        if self.mon.is_safe() == False:
            self.logger.debug("Use AVR stepper, return SIGTRAP")
            self.dbg.step()
            return SIGTRAP
        # now we have to do the dance using the HWBP or masking the I-bit
        opcode = self._readFlashWord(addr)
        self.logger.debug("Interrupt-safe stepping begins here")
        if self.mon.is_onlyhwbps() and self._bpactive >= self._hwbps: # all HWBPs in use
            self.logger.error("We need a HWBP for single-stepping, but all are in use: SIGABRT")
            return SIGABRT
        self.stealHWBP0()
        destination = None
        # compute destination for straight-line instructions and branches on I-Bit
        if not self.branchInstr(opcode):
            destination = addr + 2 + 2*int(self.twoWordInstr(opcode))
            self.logger.debug("This is not a branch instruction. Destination=0x%X", destination)
        if self.branchOnIBit(opcode):
            ibit = bool(self.dbg.status_register_read()[0] & 0x80)
            destination = self.computeDestinationOfIBranch(opcode, ibit, addr)
            self.logger.debug("Branching on I-Bit. Destination=0x%X", destination)
        if destination != None:
            self.logger.debug("Run to cursor..., return None")
            self.dbg.run_to(destination)
            return None
        # for the remaining branch instructions, clear I-bit before and set it afterwards (if it was on before)
        self.logger.debug("Remaining branch instructions")
        sreg = self.dbg.status_register_read()[0]
        self.logger.debug("sreg=0x%X", sreg)
        ibit = sreg & 0x80
        sreg &= 0x7F # clear I-Bit
        self.logger.debug("New sreg=0x%X",sreg)
        self.dbg.status_register_write(bytearray([sreg]))
        self.logger.debug("Now make a step...")
        self.dbg.step()
        sreg = self.dbg.status_register_read()[0]
        self.logger.debug("New sreg=0x%X", sreg)
        sreg |= ibit
        self.logger.debug("Restored sreg=0x%X", sreg)
        self.dbg.status_register_write(bytearray([sreg]))
        self.logger.debug("Returning with SIGTRAP")
        return SIGTRAP

    def stealHWBP0(self):
        if (self._hw[0]): # steal HWBP0
            self.logger.debug("Steal HWBP0 from BP at 0x%X", self._hw[0])
            self._bp[self._hw[0]]['hwbp'] = None
            self._bp[self._hw[0]]['inflash'] = True
            self.dbg.software_breakpoint_set(self._hw[0])
            self._hw[0] = None


    def rangeStep(self, start, end):
        """
        range stepping: Break only if we leave the interval start-end. If there is only
        one exit point, we watch that. If it is an inside point (e.g., RET), we single-step on it.
        Otherwise, we break at each branching point and single-step this branching instruction.
        In principle this can be generalized to n exit points (n being the number of hardware BPs).
        """
        self.logger.debug("Range stepping from 0x%X to 0x%X" % (start, end))
        if not self.mon.is_range():
            self.logger.debug("Range stepping forbidden")
            return self.singleStep(None)
        if start%2 != 0 or end%2 != 0:
            self.logger.error("Range addresses in range stepping are ill-formed")
            return self.singleStep(None)
        if self.mon.is_onlyhwbps() and self._bpactive >= self._hwbps: # all HWBPs in use
            self.logger.error("We need a HWBP for single-stepping, but all are in use: SIGABRT")
            return SIGABRT
        self.stealHWBP0()
        self.updateBreakpoints()
        self.buildRange(start, end)
        addr = self.dbg.program_counter_read() << 1
        if addr in self._rangeExit: # possible exit point inside range
            return(self.singleStep(None))
        if len(self._rangeExit) == 1: # only one exit point overall
            # if more HWBPs, one could use them here!
            # #MOREHWBPS
            self.dbg.run_to(list(self._rangeExit)[0])
            return None
        if addr in self._rangeBranch:
            return(self.singleStep(None))
        for i in range(len(self._rangeBranch)):
            if addr < self._rangeBranch[i] :
                self.dbg.run_to(self._rangeBranch[i])
                return None
        return(self.singleStep(None))

    def buildRange(self, start, end):
        """
        Collect all instructions in the range and anaylze them. Find all points, where
        an instruction possibly leaves the range. This includes the first instruction 
        after the range, provided it is reachable. These points are remembered in 
        self._rangeExit. If the number of exits is less or equal than the number of 
        hardware BPs, then one can check for all them. In case of DW this number is one.
        However, this is enough for handling _delay_ms(_). In all other cases, we stop at all
        branching instructions, memorized in self._rangeBranch, and single-step them.
        """
        if start == self._rangeStart and end == self._rangeEnd:
            return # previously analyzed
        self._rangeWord = []
        self._rangeInstr = []
        self._rangeExit = set()
        self._rangeBranch = []
        self._rangeStart = start
        self._rangeEnd = end
        for a in range(start, end+2, 2):
            self._rangeWord += [ self._readFlashWord(a) ]
        i = 0
        while i < len(self._rangeWord) - 1:
            dest = []
            opcode = self._rangeWord[i]
            secondword = self._rangeWord[i+1]
            if self.branchInstr(opcode):
                self._rangeBranch += [ start + (i * 2) ]
            if self.twoWordInstr(opcode):
                if self.branchInstr(opcode): # JMP and CALL
                    dest = [ secondword << 1 ]
                else: # STS and LDS
                    dest = [ start + (i + 2) * 2 ]
            else:
                if not self.branchInstr(opcode): # straight-line ops
                    dest = [start + (i + 1) * 2]
                elif self.skipOperation(opcode): # CPSE, SBIC, SBIS, SBRC, SBRS
                    dest = [start + (i + 1) * 2,
                               start + (i + 2 + self.twoWordInstr(secondword)) * 2]
                elif self.condBranchOperation(opcode): # BRBS, BRBC
                    dest = [start + (i + 1) * 2,
                                self.computePossibleDestinationOfBranch(opcode, start + (i * 2))]
                elif self.relativeBranchOperation(opcode): # RJMP, RCALL
                    dest = [start + (i + 1) * 2,
                                self.computeDestinationOfRelativeBranch(opcode, start + (i * 2))]
                else: # IJMP, EIJMP, RET, ICALL, RETI, EICALL
                    dest = [ -1 ]
            self.logger.debug("Dest at 0x%X: %s" % (start + i*2, [hex(x) for x in dest]))
            if -1 in dest:
                self._rangeExit.add(start + (i * 2))
            else:
                self._rangeExit = self._rangeExit.union([ a for a in dest if a < start or a >= end ])
            i += 1 + self.twoWordInstr(opcode)
        self._rangeBranch += [ end ]
        self.logger.debug("Exit points: %s", {hex(x) for x in self._rangeExit})
        self.logger.debug("Branch points: %s", [hex(x) for x in self._rangeBranch])

    @staticmethod
    def branchInstr(opcode):
        if (opcode & 0xFC00) == 0x1000: # CPSE
            return True
        if (opcode & 0xFFEF) == 0x9409: # IJMP / EIJMP
            return True
        if (opcode & 0xFFEE) == 0x9508: # RET, ICALL, RETI, EICALL
            return True
        if (opcode & 0xFE0C) == 0x940C: # CALL, JMP
            return True
        if (opcode & 0xFD00) == 0x9900: # SBIC, SBIS
            return True
        if (opcode & 0xE000) == 0xC000: # RJMP, RCALL
            return True
        if (opcode & 0xF800) == 0xF000: # BRBS, BRBC
            return True
        if (opcode & 0xFC08) == 0xFC00: # SBRC, SBRS
            return True
        return False

    @staticmethod
    def relativeBranchOperation(opcode):
        if (opcode & 0xE000) == 0xC000: # RJMP, RCALL
            return True
        return False

    @staticmethod
    def computeDestinationOfRelativeBranch(opcode, addr):
        rdist = opcode & 0x0FFF
        tsc = rdist - int((rdist << 1) & 2**12)
        return addr + 2 + (tsc*2)

    @staticmethod
    def skipOperation(opcode):
        if (opcode & 0xFC00) == 0x1000: # CPSE
            return True
        if (opcode & 0xFD00) == 0x9900: # SBIC, SBIS
            return True
        if (opcode & 0xFC08) == 0xFC00: # SBRC, SBRS
            return True
        return False

    @staticmethod
    def condBranchOperation(opcode):
        if (opcode & 0xF800) == 0xF000: # BRBS, BRBC
            return True
        return False

    @staticmethod
    def branchOnIBit(opcode):
        return (opcode & 0xF807) == 0xF007 # BRID, BRIE

    @staticmethod
    def computePossibleDestinationOfBranch(opcode, addr):
        rdist = ((opcode >> 3) & 0x007F)
        tsc = rdist - int((rdist << 1) & 2**7) # compute twos complement
        return addr + 2 + (tsc*2)


    @staticmethod
    def computeDestinationOfIBranch(opcode, ibit, addr):
        branch = ibit ^ bool(opcode & 0x0400 != 0)
        if not branch:
            return addr + 2
        else:
            return self.computePossibleDestinationOfBranch(opcode, addr)

    @staticmethod
    def twoWordInstr(opcode):
        return(((opcode & ~0x01F0) == 0x9000) or ((opcode & ~0x01F0) == 0x9200) or
                ((opcode & 0x0FE0E) == 0x940C) or ((opcode & 0x0FE0E) == 0x940E))

    def simTwoWordInstr(self, opcode, secondword, addr):
        """
        Simulate a two-word instruction with opcode and 2nd word secondword. Update all registers (except PC)
        and return the (byte-) address where execution will continue.
        """
        if (opcode & ~0x1F0) == 0x9000: # lds
            register = (opcode & 0x1F0) >> 4
            val = self.dbg.sram_read(secondword, 1)
            self.dbg.sram_write(register, val)
            self.logger.debug("Simulating lds")
            addr += 4
        elif (opcode & ~0x1F0) == 0x9200: # sts 
            register = (opcode & 0x1F0) >> 4
            val = self.dbg.sram_read(register, 1)
            self.dbg.sram_write(secondword, val)
            self.logger.debug("Simulating sts")
            addr += 4
        elif (opcode & 0x0FE0E) == 0x940C: # jmp 
            # since debugWIRE works only on MCUs with a flash address space <= 64 kwords
            # we do not need to use the bits from the opcode. Just put in a reminder: #BIGMEM
            addr = secondword << 1 ## now byte address
            self.logger.debug("Simulating jmp 0x%X", addr << 1)
        elif (opcode & 0x0FE0E) == 0x940E: # call
            returnaddr = (addr + 4) >> 1 # now word address
            self.logger.debug("Simulating call to 0x%X", secondword << 1)
            sp = int.from_bytes(self.dbg.stack_pointer_read(),byteorder='little')
            self.logger.debug("Current stack pointer: 0x%X", sp)
            # since debugWIRE works only on MCUs with a flash address space <= 64 kwords
            # we only need to decrement the SP by 2. Just put in a reminder: #BIGMEM
            sp -= 2
            self.logger.debug("New stack pointer: 0x%X", sp)
            self.dbg.stack_pointer_write(sp.to_bytes(2,byteorder='little'))
            self.dbg.sram_write(sp+1, returnaddr.to_bytes(2,byteorder='big'))
            # since debugWIRE works only on MCUs with a flash address space <= 64 kwords
            # we do not need to use the bits from the opcode. Just put in a reminder: #BIGMEM
            addr = secondword << 1
        return addr

    
class MonitorCommand(object):
    """
    This class implements all the monitor commands
    It manages state variables, gives responses and selects
    the right action. The return value of the dispatch method is
    a pair consisting of an action identifier and the string to be displayed.
    """ 
    def __init__(self):
        self._dw_mode_active = False
        self._dw_activated_once = False
        self._noload = False # when true, one may start execution even without a previous load
        self._onlyhwbps = False
        self._onlyswbps = False
        self._fastload = True
        self._cache = True
        self._safe = True
        self._verify = True
        self._timersfreeze = True
        self._noxml = False
        self._power = True
        self._old_exec = False
        self._range = True

        self.moncmds = {
            'breakpoints'  : self.monBreakpoints,
            'caching'      : self.monCache,
            'debugwire'    : self.monDebugwire,
            'help'         : self.monHelp,
            'info'         : self.monInfo,
            'load'         : self.monLoad,
            'onlyloaded'   : self.monNoload,
            'reset'        : self.monReset,
            'rangestepping': self.monRangeStepping,
            'singlestep'   : self.monSinglestep,
            'timers'       : self.monTimers,
            'verify'       : self.monFlashVerify,
            'version'      : self.monVersion,
            'NoXML'        : self.monNoXML,
            'OldExecution' : self.monOldExecution,
            'Target'       : self.monTarget,
            }

    def is_onlyhwbps(self):
        return self._onlyhwbps

    def is_onlyswbps(self):
        return self._onlyswbps

    def is_cache(self):
        return self._cache

    def is_dw_mode_active(self):
        return self._dw_mode_active

    def set_dw_mode_active(self):
        self._dw_mode_active = True
        self._dw_activated_once = True

    def is_dw_activated_once(self):
        return self._dw_deactivated_once

    def is_fastload(self):
        return self._fastload

    def is_noload(self):
        return self._noload

    def is_range(self):
        return self._range

    def is_safe(self):
        return self._safe

    def is_timersfreeze(self):
        return self._timersfreeze

    def is_verify(self):
        return self._verify

    def is_old_exec(self):
        return self._old_exec

    def is_noxml(self):
        return self._noxml

    def is_power(self):
        return self._power

    def dispatch(self, tokens):
        if not tokens:
            return(self.monHelp(list()))
        if len(tokens) == 1:
            tokens += [""]
        handler = self.monUnknown
        for cmd in self.moncmds:
            if cmd.startswith(tokens[0]):
                if handler == self.monUnknown:
                    handler = self.moncmds[cmd]
                else:
                    handler = self.monAmbigious
        # For these internal monitor commands, we require that
        # they are fully spelled out so that they are not
        # invoked by a mistyped abbreviation
        if handler == self.monNoXML and tokens[0] != "NoXML":
            handler = self.monUnknown
        if handler == self.monTarget and tokens[0] != "Target":
            handler = self.monUnknown
        if handler == self.monOldExecution and tokens[0] != "OldExecution":
            handler = self.monUnknown
        return(handler(tokens[1:]))

    def monUnknown(self, tokens):
        return("", "Unknown 'monitor' command")

    def monAmbigious(self, tokens):
        return("", "Ambigious 'monitor' command")

    def monBreakpoints(self, tokens):
        if not tokens[0]:
            if self._onlyhwbps and self._onlyswbps:
                return("", "Internal confusion: No breakpoints are allowed")
            elif self._onlyswbps: 
                return("", "Only software breakpoints are allowed")
            elif self._onlyhwbps:
                return("", "Only hardware breakpoints are allowed")
            else:
                return("", "All breakpoints are allowed")
        elif 'all'.startswith(tokens[0]):
            self._onlyhwbps = False
            self._onlyswbps = False
            return("", "All breakpoints are now allowed")
        elif 'hardware'.startswith(tokens[0]):
            self._onlyhwbps = True
            self._onlyswbps = False
            return("", "Only hardware breakpoints are now allowed")
        elif 'software'.startswith(tokens[0]):
            self._onlyhwbps = False
            self._onlyswbps = True
            return("", "Only software breakpoints are now allowed")
        else:
            return self.monUnknown(tokens[0])

    def monCache(self, tokens):
        if (("enable".startswith(tokens[0]) and tokens[0] != "") or
                (tokens[0] == "" and self._cache == True)):
            self._cache = True
            return("", "Flash memory will be cached")
        elif (("disable".startswith(tokens[0]) and tokens[0] != "") or
                  (tokens[0] == "" and self._cache == False)):
            self._cache = False
            return("", "Flash memory will not be cached")
        else:
            return self.monUnknown(tokens[0])
        
    def monDebugwire(self, tokens):
        if tokens[0] =="":
            if self._dw_mode_active:
                return("", "debugWIRE mode is enabled")
            else:
                return("", "debugWIRE mode is disabled")
        elif "enable".startswith(tokens[0]):
            if not self._dw_mode_active:
                if self._dw_activated_once:
                    return("", "Cannot reactivate debugWIRE\nYou have to exit and restart the debugger")
                self._dw_mode_active = True
                self._dw_activated_once = True
                return("dwon", "debugWIRE mode is now enabled")
            else:
                return("", "debugWIRE mode was already enabled")
        elif "disable".startswith(tokens[0]):
            if self._dw_mode_active:
                self._dw_mode_active = False
                return("dwoff", "debugWIRE mode is now disabled")
            else:
                return("", "debugWIRE mode was already disabled")
        else:
            return self.monUnknown(tokens[0])

    def monFlashVerify(self, tokens):
        if (("enable".startswith(tokens[0]) and tokens[0] != "") or
                (tokens[0] == "" and self._verify == True)):
            self._verify = True
            return("", "Always verifying that load operations are successful")
        elif (("disable".startswith(tokens[0]) and tokens[0] != "") or
                  (tokens[0] == "" and self._verify == False)):
            self._verify = False
            return("", "Load operations are not verified")
        else:
            return self.monUnknown(tokens[0])

    def monHelp(self, tokens):
        return("", """monitor help                       - this help text
monitor version                    - print version
monitor info                       - print info about target and debugger
monitor debugwire [enable|disable] - activate/deactivate debugWIRE mode
monitor reset                      - reset MCU
monitor onlyloaded [enable|disable] 
                                   - execute only with loaded executable
monitor load [readbeforewrite|writeonly]
                                   - optimize loading by first reading flash 
monitor verify [enable|disable]    - verify that loading was successful
monitor caching [on|off]           - use loaded executable as cache 
monitor timers [freeze|run]        - freeze/run timers when stopped
monitor breakpoints [all|software|hardware]
                                   - allow breakpoints of a certain kind
monitor singlestep [safe|interruptible]
                                   - single stepping mode
monitor rangestepping [enable|disable]
                                   - allow range stepping
The first option is always the default one
If no parameter is specified, the current setting is returned""")

    def monInfo(self,tokens):
        return ('info', """dw-gdbserver Version: """ + importlib.metadata.version("dwgdbserver") + """
Target:    {}
DebugWIRE: """ + "enabled" if self._dw_mode_active else "disabled" + """
Voltage:   {}

Breakpoints: """ + ("all types" if (not self._onlyhwbps and not self._onlyswbps) else 
                       ("only hardware bps" if self._onlyhwbps else "only software bps")) + """
Execute only when loaded: """ + "enabled" if not self._noload else "disabled" + """
Load mode: """ + "read before write" if self._fastload else "write only" + """
Verify after load: """ + "enabled" if self._verify else "disabled" + """
Caching loaded binary: """ + "enabled" if self._cache else "disabled" + """
Timers: """ + "frozen when stopped" if self._timersfreeze else "run when stopped" + """
Single-stepping: """ + "safe" if self._safe else "interruptible")



    def monLoad(self,tokens):
        if (("readbeforewrite".startswith(tokens[0])  and tokens[0] != "") or
            (tokens[0] == "" and self._fastload == True)):
            self._fastload = True
            return("", "Reading before writing when loading")
        elif (("writeonly".startswith(tokens[0])  and tokens[0] != "") or
                  (tokens[0] == "" and self._fastload == False)):
            self._fastload = False
            return("", "No reading before writing when loading")
        else:
            return self.monUnknown(tokens[0])

    def monNoload(self, tokens):
        if (("enable".startswith(tokens[0])  and tokens[0] != "") or
                (tokens[0] == "" and self._noload == False)):
            self._noload = False
            return("",  "Execution without prior 'load' command is impossible")
        elif (("disable".startswith(tokens[0])  and tokens[0] != "")  or
                  (tokens[0] == "" and self._noload == True)):
            self._noload = True
            return("", "Execution without prior 'load' command is possible")
        else:
            return self.monUnknown(tokens[0])
        
    def monRangeStepping(self, tokens):
        if (("enable".startswith(tokens[0])  and tokens[0] != "") or
                (tokens[0] == "" and self._range == True)):
            self._range = True
            return("",  "Range stepping is possible")
        elif (("disable".startswith(tokens[0])  and tokens[0] != "")  or
                  (tokens[0] == "" and self._range == False)):
            self._noload = True
            return("", "Range stepping is impossible")
        else:
            return self.monUnknown(tokens[0])
        
    def monReset(self, tokens):
        if self._dw_mode_active:
            return("reset", "MCU has been reset")
        else:
            return("","Enable debugWIRE mode first") 

    def monSinglestep(self, tokens):
        if (("safe".startswith(tokens[0]) and tokens[0] != "") or
                (tokens[0] == "" and self._safe == True)):
            self._safe = True
            return("", "Single-stepping is interrupt-safe")
        elif (("interruptible".startswith(tokens[0]) and tokens[0] != "")  or
                  (tokens[0] == "" and self._safe == False)):
            self._safe = False
            return("", "Single-stepping is interruptible")
        else:
            return self.monUnknown(tokens[0])

    def monTimers(self, tokens):
        if (("freeze".startswith(tokens[0]) and tokens[0] != "") or
                (tokens[0] == "" and self._timersfreeze == True)):
            self._timersfreeze = True
            return(0, "Timers are frozen when execution is stopped")
        elif (("run".startswith(tokens[0])  and tokens[0] != "") or
                  (tokens[0] == "" and self._timersfreeze == False)):
            self._timersfreeze = False
            return(1, "Timers will run when execution is stopped")
        else:
            return self.monUnknown(tokens[0])

    def monVersion(self, tokens):
        return("", "dw-gdbserver {}".format(importlib.metadata.version("dwgdbserver")))

    def monLiveTests(self, tokens):
        return("test", "Now we are running a number of tests on the real target")

    def monNoXML(self, tokens):
        self._noxml = True
        return("", "XML disabled")

    def monOldExecution(self, tokens):
        self._old_exec = True
        return("", "Old execution mode")

    def monTarget(self, tokens):
        if ("on".startswith(tokens[0]) and len(tokens[0]) > 1):
            self._power = True
            res = ("power on", "Target power on")
        elif ("off".startswith(tokens[0]) and len(tokens[0]) > 1):
            self._power = False
            res = ("power off", "Target power off")
        elif ("query".startswith(tokens[0]) and len(tokens[0]) > 1):
            res = ("power query", "Target query")
        elif tokens[0] == "":
            if self._power == True:
                res = ("", "Target power is on")
            else:
                res = ("", "Target power is off")
        else:
            return self.monUnknown(tokens[0])
        return res

class DebugWIRE(object):
    """
    This class takes care of attaching to and detaching from a debugWIRE target, which is a bit
    complicated. The target is either in ISP or debugWIRE mode and the transition from ISP to debugWIRE 
    involves power-cycling the target, which one would not like to do every time connecting to the
    target. Further, if one does this transition, it is necessary to restart the debugging tool by a 
    housekeeping end_session/start_session sequence. 
    """
    def __init__(self, dbg, devicename):
        self.dbg = dbg
        self.spidevice = None
        self.devicename = devicename
        self.logger = getLogger('DebugWIRE')

    def warmStart(self, graceful=True):
        """
        Try to establish a connection to the debugWIRE OCD. If not possible (because we are still in ISP mode) and
        graceful=True, the function returns false, otherwise true. If not graceful, an exception is thrown when we are
        unsuccessul in establishing the connection.
        """
        try:
            self.dbg.setup_session(self.devicename)
            idbytes = self.dbg.device.read_device_id()
            sig = (0x1E<<16) + (idbytes[1]<<8) + idbytes[0]
            self.logger.debug("Device signature by debugWIRE: %X", sig)
            self.dbg.start_debugging()
            self.dbg.reset()
        except FatalError:
            raise
        except Exception as e:
            if graceful:
                self.logger.debug("Graceful exception: %s",e)
                return False  # we will try to connect later
            else:
                raise
        # Check device signature
        if sig != self.dbg.device_info['device_id']:
            # Some funny special cases of chips pretending to be someone else when in debugWIRE mode
            if sig == 0x1E930F and self.dbg.device_info['device_id'] == 0x1E930A: return # pretends to be a 88P, but is 88
            if sig == 0x1E940B and self.dbg.device_info['device_id'] == 0x1E9406: return # pretends to be a 168P, but is 168
            if sig == 0x1E950F and self.dbg.device_info['device_id'] == 0x1E9514: return # pretends to be a 328P, but is 328
            raise FatalError("Wrong MCU: '{}', expected: '{}'".format(dev_name[sig], dev_name[self.dbg.device_info['device_id']]))
        # read out program counter and check whether it contains stuck to 1 bits
        pc = self.dbg.program_counter_read()
        self.logger.debug("PC=%X",pc)
        if pc << 1 > self.dbg.memory_info.memory_info_by_name('flash')['size']:
            raise FatalError("Program counter of MCU has stuck-at-1-bits")
        # disable running timers while stopped
        self.dbg.device.avr.protocol.set_byte(Avr8Protocol.AVR8_CTXT_OPTIONS,
                                                  Avr8Protocol.AVR8_OPT_RUN_TIMERS,
                                                  0)
        return True

    def coldStart(self, graceful=False, callback=None, allow_erase=True):
        """
        On the assumption that we are in ISP mode, first DWEN is programmed, then a power-cycle is performed
        and finally, we enter debugWIRE mode. If graceful is True, we allow for a failed attempt to connect to
        the ISP core assuming that we are already in debugWIRE mode. If callback is Null or returns False, 
        we wait for a manual power cycle. Otherwise, we assume that the callback function does the job.
        """
        try:
            self.enable(erase_if_locked=allow_erase)
            self.powerCycle(callback=callback)
        except (PymcuprogError, FatalError):
            raise
        except Exception as e:
            self.logger.debug("Graceful exception: %s",e)
            if not graceful:
                raise
        # end current tool session and start a new one
        self.logger.info("Restarting the debugging tool before entering debugWIRE mode")
        self.dbg.housekeeper.end_session()
        self.dbg.housekeeper.start_session()
        # now start the debugWIRE session
        return self.warmStart(graceful=False)
            
               
    def powerCycle(self, callback=None):
        # ask user for power-cycle and wait for voltage to come up again
        wait_start = time.monotonic()
        last_message = 0
        magic = False
        if callback:
            magic = callback()
        if magic: # callback has done all the work
            return
        self.dbg.housekeeper.end_session() # might be necessary after an unsuccessful power-cycle
        self.dbg.housekeeper.start_session()
        while time.monotonic() - wait_start < 150:
            if (time.monotonic() - last_message > 20):
                print("*** Please power-cycle the target system ***")
                last_message = time.monotonic()
            if read_target_voltage(self.dbg.housekeeper) < 0.5:
                wait_start = time.monotonic()
                self.logger.debug("Power-cycle recognized")
                while  read_target_voltage(self.dbg.housekeeper) < 1.5 and \
                  time.monotonic() - wait_start < 20:
                    time.sleep(0.1)
                if read_target_voltage(self.dbg.housekeeper) < 1.5:
                    raise FatalError("Timed out waiting for repowering target")
                time.sleep(1) # wait for debugWIRE system to be ready to accept connections 
                return
            time.sleep(0.1)
        raise FatalError("Timed out waiting for power-cycle")
 
    def disable(self):
        """
        Disables debugWIRE and unprograms the DWEN fusebit. After this call,
        there is no connection to the target anymore. For this reason all critical things
        needs to be done before, such as cleaning up breakpoints. 
        """
        # stop core
        self.dbg.device.avr.protocol.stop()
        # clear all breakpoints
        self.dbg.software_breakpoint_clear_all()
        # disable DW
        self.dbg.device.avr.protocol.debugwire_disable()
        # detach from OCD
        self.dbg.device.avr.protocol.detach()
        # De-activate physical interface
        self.dbg.device.avr.deactivate_physical()
        # it seems necessary to reset the debug tool again
        self.logger.info("Restarting the debug tool before unprogramming the DWEN fuse")
        self.dbg.housekeeper.end_session()
        self.dbg.housekeeper.start_session()
        # now open an ISP programming session again
        self.spidevice = NvmAccessProviderCmsisDapSpi(self.dbg.transport, self.dbg.device_info)
        self.spidevice.isp.enter_progmode()
        fuses = self.spidevice.read(self.dbg.memory_info.memory_info_by_name('fuses'), 0, 3)
        self.logger.debug("Fuses read: %X %X %X",fuses[0], fuses[1], fuses[2])
        fuses[1] |= self.dbg.device_info['dwen_mask']
        self.logger.debug("New high fuse: 0x%X", fuses[1])
        self.spidevice.write(self.dbg.memory_info.memory_info_by_name('fuses'), 1,
                                         fuses[1:2])
        fuses = self.spidevice.read(self.dbg.memory_info.memory_info_by_name('fuses'), 0, 3)
        fuses = self.spidevice.read(self.dbg.memory_info.memory_info_by_name('fuses'), 0, 3)
        self.logger.debug("Fuses read after DWEN disable: %X %X %X",fuses[0], fuses[1], fuses[2])
        self.spidevice.isp.leave_progmode()

    def enable(self, erase_if_locked=True):
        """
        Enables debugWIRE mode by programming the DWEN fuse bit. If the chip is locked,
        it will be erased. Also the BOOTRST fusebit is disabled.
        Since the implementation of ISP programming is somewhat funny, a few stop/start 
        sequences and double reads are necessary.
        """
        self.logger.info("Try to connect using ISP")
        self.spidevice = NvmAccessProviderCmsisDapSpi(self.dbg.transport, self.dbg.device_info)
        device_id = int.from_bytes(self.spidevice.read_device_id(),byteorder='little')
        if self.dbg.device_info['device_id'] != device_id:
            raise FatalError("Wrong MCU: '{}', expected: '{}'".format(
                dev_name[device_id],
                dev_name[self.dbg.device_info['device_id']]))
        fuses = self.spidevice.read(self.dbg.memory_info.memory_info_by_name('fuses'), 0, 3)
        self.logger.debug("Fuses read: %X %X %X",fuses[0], fuses[1], fuses[2])
        lockbits = self.spidevice.read(self.dbg.memory_info.memory_info_by_name('lockbits'), 0, 1)
        self.logger.debug("Lockbits read: %X", lockbits[0])
        if (lockbits[0] != 0xFF):
            self.logger.info("MCU is locked. Will be erased.")
            self.spidevice.erase()
            lockbits = self.spidevice.read(self.dbg.memory_info.memory_info_by_name('lockbits'), 0, 1)
            self.logger.debug("Lockbits after erase: %X", lockbits[0])
        if 'bootrst_fuse' in self.dbg.device_info:
            # unprogramm bit 0 in high or extended fuse
            self.logger.debug("BOOTRST fuse will be unprogrammed.")
            bfuse = self.dbg.device_info['bootrst_fuse']
            fuses[bfuse] |= 0x01
            self.spidevice.write(self.dbg.memory_info.memory_info_by_name('fuses'), bfuse, fuses[bfuse:bfuse+1])
        # program the DWEN bit
        # leaving and re-entering programming mode is necessary, otherwise write has no effect
        self.spidevice.isp.leave_progmode()
        self.spidevice.isp.enter_progmode()
        fuses[1] &= (0xFF & ~(self.dbg.device_info['dwen_mask']))
        self.logger.debug("New high fuse: 0x%X", fuses[1])
        self.spidevice.write(self.dbg.memory_info.memory_info_by_name('fuses'), 1, fuses[1:2])
        fuses = self.spidevice.read(self.dbg.memory_info.memory_info_by_name('fuses'), 0, 3)
        fuses = self.spidevice.read(self.dbg.memory_info.memory_info_by_name('fuses'), 0, 3) # needs to be done twice!
        self.logger.debug("Fuses read again: %X %X %X",fuses[0], fuses[1], fuses[2])
        self.spidevice.isp.leave_progmode()
        # in order to start a debugWIRE session, a power-cycle is now necessary, but
        # this has to be taken care of by the calling process
        

class AvrGdbRspServer(object):
    def __init__(self, avrdebugger, devicename, port):
        self.avrdebugger = avrdebugger
        self.devicename = devicename
        self.port = port
        self.logger = getLogger("AvrGdbRspServer")
        self.connection = None
        self.gdb_socket = None
        self.handler = None
        self.address = None

    def serve(self):
        self.gdb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger.info("Listening on port {} for gdb connection".format(self.port))
        if not (self.logger.getEffectiveLevel() in [logging.DEBUG, logging.INFO]): # make sure that this message can be seen
            print("Listening on port {} for gdb connection".format(self.port))
        self.gdb_socket.bind(("127.0.0.1", self.port))
        self.gdb_socket.listen()
        self.connection, self.address = self.gdb_socket.accept()
        self.connection.setblocking(0)
        self.logger.info('Connection from %s', self.address)
        self.handler = GdbHandler(self.connection, self.avrdebugger, self.devicename)
        while True:
            ready = select.select([self.connection], [], [], 0.5)
            if ready[0]:
                data = self.connection.recv(8192)
                if len(data) > 0:
                    # self.logger.debug("Received over TCP/IP: %s",data)
                    self.handler.handleData(data)
            self.handler.pollEvents()


    def __del__(self):
        try:
            self.handler.bp.cleanupBreakpoints()
            self.avrdebugger.stop_debugging()
        except Exception as e:
            self.logger.debug("Graceful exception during stopping: %s",e)
        finally:
            time.sleep(1) # sleep 1 second before closing in order to allow the client to close first
            self.logger.info("Closing socket")
            if self.gdb_socket:
                self.gdb_socket.close()
            self.logger.info("Closing connection")
            if self.connection:
                self.connection.close()


            
def _setup_tool_connection(args, logger):
    """
    Copied from pymcuprog_main and modified so that no messages printed on the console
    """
    toolconnection = None

    # Parse the requested tool from the CLI
    if args.tool == "uart":
        baudrate = _clk_as_int(args)
        # Embedded GPIO/UART tool (eg: raspberry pi) => no USB connection
        toolconnection = ToolSerialConnection(serialport=args.uart, baudrate=baudrate, timeout=args.uart_timeout)
    else:
        usb_serial = args.serialnumber
        product = args.tool
        if usb_serial and product:
            logger.info("Connecting to {0:s} ({1:s})'".format(product, usb_serial))
        else:
            if usb_serial:
                logger.info("Connecting to any tool with USB serial number '{0:s}'".format(usb_serial))
            elif product:
                logger.info("Connecting to any {0:s}".format(product))
            else:
                logger.info("Connecting to anything possible")
        toolconnection = ToolUsbHidConnection(serialnumber=usb_serial, tool_name=product)

    return toolconnection


def main():
    """
    Configures the CLI and parses the arguments
    """
    parser = argparse.ArgumentParser(usage="%(prog)s [options]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\n\
    GDBserver for debugWIRE MCUs 
            '''))

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
                            type=str, choices=['atmelice', 'edbg', 'jtagice3', 'medbg', 'nedbg',
                                                   'pickit4', 'powerdebugger', 'snap', 'dwlink'],
                            help="tool to connect to")

    parser.add_argument("-u", "--usbsn",
                            type=str,
                            dest='serialnumber',
                            help="USB serial number of the unit to use")

    parser.add_argument("-v", "--verbose",
                            default="info", choices=['debug', 'info', 'warning', 'error', 'critical'],
                            help="Logging verbosity level")

    parser.add_argument("-V", "--version",
                            help="Print dw-gdbserver version number and exit",
                            action="store_true")

    # Parse args
    args = parser.parse_args()

    # Setup logging
    if args.verbose.upper() in ["INFO", "WARNING", "ERROR"]:
        form = "[%(levelname)s] %(message)s"
    else:
        form = "[%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(stream=sys.stderr,level=args.verbose.upper(), format = form)
    logger = getLogger()

    if args.verbose.upper() == "DEBUG":
        getLogger('pyedbglib').setLevel(logging.INFO)
    if args.verbose.upper() != "DEBUG":
        getLogger('pyedbglib.hidtransport.hidtransportbase').setLevel(logging.CRITICAL) # suppress messages from hidtransport
        getLogger('pyedbglib.protocols').setLevel(logging.CRITICAL) # supress spurious error messages from pyedbglib
        getLogger('pymcuprog.nvm').setLevel(logging.CRITICAL) # suppress errors of not connecting: It is intended!
        getLogger('pymcuprog.avr8target').setLevel(logging.ERROR) # we do not want to see the "read flash" messages

    if args.version:
        print("dw-gdbserver version {}".format(importlib.metadata.version("dwgdbserver")))
        return 0

    if args.dev and args.dev == "?":
        print("Supported devices:")
        for d in sorted(dev_id):
            print(d)
        return 0

    device = args.dev

    if not device:
        print("Please specify target MCU with -d option")
        return(1)

    if device.lower() not in dev_id:
        logger.critical("Device '%s' is not supported by dw-gdbserver", device)
        sys.exit(1)
            
    if args.tool == "dwlink":
        dwgdbserver.dwlink.main(args)
        return
        
    # Use pymcuprog backend for initial connection here
    backend = Backend()
    toolconnection = _setup_tool_connection(args, logger)

    try:
        backend.connect_to_tool(toolconnection)
    except pymcuprog.pymcuprog_errors.PymcuprogToolConnectionError:
        dwgdbserver.dwlink.main(args)
        return(0)
        
    finally:
        backend.disconnect_from_tool()

    transport = hid_transport()
    transport.connect(serial_number=toolconnection.serialnumber, product=toolconnection.tool_name)
    logger.info("Connected to %s", transport.hid_device.get_product_string())

    logger.info("Starting dw-gdbserver")
    avrdebugger = XAvrDebugger(transport, device)
    server = AvrGdbRspServer(avrdebugger, device, args.port)
    try:
        server.serve()
        
    except (EndOfSession, SystemExit, KeyboardInterrupt):
        logger.info("End of session")
        print("--- exit ---\r\n")
        return(0)
        
    except Exception as e:
        if logger.getEffectiveLevel() != logging.DEBUG:
            logger.critical("Fatal Error: %s",e)
        else:
            raise
    
if __name__ == "__main__":
    sys.exit(main())
