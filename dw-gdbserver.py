"""
debugWIRE GDBServer 
"""
VERSION="0.9.12"

SIGHUP  = "S01"     # no connection
SIGINT  = "S02"     # Interrupt  - user interrupted the program (UART ISR) 
SIGILL  = "S04"     # Illegal instruction
SIGTRAP = "S05"     # Trace trap  - stopped on a breakpoint
SIGABRT = "S06"     # Abort because of a fatal error

import site


# args, logging
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
import binascii
import time
import usb

from pyedbglib.hidtransport.hidtransportfactory import hid_transport
import pymcuprog
from pymcuprog.avrdebugger import AvrDebugger
from dwe_avrdebugger import DWEAvrDebugger
from pymcuprog.backend import Backend
from pymcuprog.pymcuprog_main import  _clk_as_int # _setup_tool_connection
from pymcuprog.toolconnection import ToolUsbHidConnection, ToolSerialConnection
from pymcuprog.nvmspi import NvmAccessProviderCmsisDapSpi
from pymcuprog.deviceinfo import deviceinfo
from pymcuprog.utils import read_target_voltage
from pymcuprog.pymcuprog_errors import PymcuprogToolConfigurationError, PymcuprogNotSupportedError, PymcuprogError

# alternative debug server that connects to the dw-link hardware debugger
import dwlink

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
    def __init__ (self, socket, avrdebugger, devicename, powercycle=True):
        self.logger = getLogger('GdbHandler')
        self.socket = socket
        self.dbg = avrdebugger
        self.dw = DebugWIRE(avrdebugger, devicename)
        self.mon = MonitorCommand(self)
        self.devicename = devicename
        self.powercycle = powercycle
        self.lastSIGVAL = "S00"
        self.packet_size = 4000
        self.extended_remote_mode = False
        self.flash = {} # indexed by the start address, these are pairs [endaddr, data]
        self.vflashdone = False # set to True after vFlashDone received and will then trigger clearing the flash cache 

        self.packettypes = {
            '!'           : self.extendedRemoteHandler,
            '?'           : self.stopReasonHandler,
            'c'           : self.continueHandler,
            'C'           : self.continueHandler, # signal will be ignored
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
            'S'           : self.stepHandler, # signal will be ignored
            'T'           : self.threadAliveHandler,
            'vFlashDone'  : self.flashDoneHandler,
            'vFlashErase' : self.flashEraseHandler,
            'vFlashWrite' : self.flashWriteHandler,
            'vKill'       : self.killHandler,
            'vRun'        : self.runHandler,
          # 'X'           : binary load - not necessary because vFlashWrite is used
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
        
        if cmd != 'X' and cmd != 'vFlashWrite': # no binary data
            packet = packet.decode('ascii')
        self.handler(packet)

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
        self.sendPacket(self.lastSIGVAL)
        self.logger.debug("Reason was %s",self.lastSIGVAL)

    def continueHandler(self, packet):
        """
        'c': Continue execution, either at current address or at given address
        """
        self.logger.debug("RSP packet: Continue")
        if not self.mon.dw_mode_active:
            self.logger.debug("Cannot start execution because not connected")
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire on'")
            self.sendSignal(SIGHUP)
            return
        if not self.vflashdone and not self.mon.noload:
            self.logger.debug("Cannot start execution without prior load")
            self.sendDebugMessage("Load executable first before starting execution")
            self.sendSignal(SIGILL)
            return
        if packet:
            self.logger.debug("Set PC to 0x%s",packet)
            #set PC - note, byte address converted to word address
            self.dbg.program_counter_write(int(packet,16)>>1)
        self.logger.debug("Resume execution")
        self.dbg.run()

    def detachHandler(self, packet):
        """
        'D': Detach. All the real housekeeping will take place when the connection is terminated
        """
        self.logger.debug("RSP packet: Detach")
        self.sendPacket("OK")
        raise EndOfSession("Session ended by client ('detach')")

    def getRegisterHandler(self, packet):
        """
        'g': Send the current register values R[0:31] + SREAG + SP + PC to GDB
        """
        self.logger.debug("RSP packet: GDB reading registers")
        if self.mon.dw_mode_active:
            regs = self.dbg.register_file_read()
            sreg = self.dbg.status_register_read()
            sp = self.dbg.stack_pointer_read()
            pc = self.dbg.program_counter_read() << 1 # get PC as word adress
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
        if self.mon.dw_mode_active:
            newRegData = int(packet,16)
            newdata = newRegData.to_bytes(35, byteorder='big')
            self.dbg.register_file_write(newdata[:32])
            self.dbg.status_register_write(newdata[32:33])
            self.dbg.stack_pointer_write(newdata[33:35])
            self.dbg.program_counter_write(int(binascii.hexlify(int(newdata[35:],16).to_bytes(4,byteorder='little'))) >> 1)
            self.logger.debug("Setting new register data from GDB: %s", newRegData)
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
        if not self.mon.dw_mode_active:
            self.logger.debug("RSP packet: memory read, but not connected")
            self.sendPacket("E05")
            return
        addr = packet.split(",")[0]
        size = packet.split(",")[1]
        self.logger.debug("RSP packet: Reading memory: addr=%s, size=%d", addr, int(size,16))
        addrSection = "00"
        if len(addr) > 4:
            if len(addr) == 6:
                addrSection = addr[:2]
                addr = addr[2:]
            else:
                addrSection = "0" + addr[0]
                addr = addr[1:]
        data = bytearray()
        iaddr = int(addr,16)
        isize = int(size,16)
        self.logger.debug("Addr section: %s",addrSection)
        if addrSection == "80": # ram
            data = self.dbg.sram_read(iaddr, isize)
        elif addrSection == "81": # eeprom
            data = self.dbg.eeprom_read(addr, isize)
        elif addrSection == "82" and self.dbg.device_info['interface'].upper() != 'ISP+DW': # fuse
            data = self.dbg.read_fuse(iaddr, isize)
        elif addrSection == "83" and self.dbg.device_info['interface'].upper() != 'ISP+DW': # lock
            data = self.dbg.read_lock(iaddr, isize)
        elif addrSection == "84": # signature
            data = self.dbg.read_signature(iaddr, isize)
        elif addrSection == "85" and self.dbg.device_info['interface'].upper() != 'ISP+DW': # user_signature
            data = self.dbg.read_user_signature(iaddr, isize)
        elif addrSection == "00": # flash
            inewaddr = iaddr
            inewsize = isize
            if iaddr % 2 != 0:
                inewaddr -= 1
                inewsize += 1
            if inewsize % 2 != 0: 
                inewsize += 1
            data = self.dbg.flash_read(inewaddr, inewsize)
            if inewaddr != iaddr:
                data = data[1:]
                inewsize -= 1
            if inewsize != isize:
                data = data[:-1]
        else:
            self.logger.error("Illegal memtype in memory read operation: %s", addrSection)
            self.sendPacket("E13")
            return
        self.logger.debug(data)
        dataString = ""
        for byte in data:
            dataString = dataString + format(byte, '02x')
        self.logger.debug("Data sent: %s",dataString)
        self.sendPacket(dataString)

    def setMemoryHandler(self, packet):
        """
        'M': GDB sends new data for MCU memory
        """
        if not self.mon.dw_mode_active:
            self.logger.debug("RSP packet: Memory write, but not connected")
            self.sendPacket("E05")
            return
        addr = packet.split(",")[0]
        size = (packet.split(",")[1]).split(":")[0]
        data = (packet.split(",")[1]).split(":")[1]
        self.logger.debug("RSP packet: Memory write addr=%s, size=%s, data=%s", addr, size, data)
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
        elif addrSection == "82" and self.dbg.device_info['interface'].upper() != 'ISP+DW': #fuse
            data = self.dbg.write_fuse(int(addr, 16), data)
        elif addrSection == "83" and self.dbg.device_info['interface'].upper() != 'ISP+DW': #lock
            data = self.dbg.write_lock(int(addr, 16), data)
        elif addrSection == "84": #signature
            data = self.dbg.write_signature(int(addr, 16), data)
        elif addrSection == "85" and self.dbg.device_info['interface'].upper() != 'ISP+DW': #user signature
            data = self.dbg.write_user_signature(int(addr, 16), data)
        else:
            # Flash write not supported here
            # EACCES
            self.logger.error("Illegal memtype in memory write operation: %s", addrSection)
            self.sendPacket("E13")
            return
        self.sendPacket("OK")

        
    def getOneRegisterHandler(self, packet):
        """
        'p': read register and send to GDB
        currently only PC
        """
        if not self.mon.dw_mode_active:
            self.logger.debug("RSP packet: read register command, but not connected")
            self.sendPacket("E05")
            return
        if packet == "22":
            # GDB defines PC register for AVR to be REG34(0x22)
            # and the bytes have to be given in reverse order (big endian)
            pc = self.dbg.program_counter_read() << 1
            self.logger.debug("RSP packet: read PC command: 0x{:X}".format(pc))
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
        if not self.mon.dw_mode_active:
            self.logger.debug("RSP packet: write register command, but not connected")
            self.sendPacket("E05")
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
        if len(tokens) == 1:
            tokens += [""]
        self.mon.dispatch(tokens)

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
        self.mon.dw_mode_active = self.dw.warmStart(graceful=True)
        self.logger.debug("dw_mode_active=%d",self.mon.dw_mode_active)            
        self.sendPacket("PacketSize={0:X};qXfer:memory-map:read+".format(self.packet_size))

    def firstThreadInfoHandler(self, packet):
        """
        'qfThreadInfoHandler': get info about active threads
        """
        self.logger.debug("RSP packet: first thread info query, will answer 'm01'")
        self.sendPacket("m01")

    def subsequentThreadInfoHandler(self, packet):
        """
        'qsThreadInfoHandler': get more info about active threads
        """
        self.logger.debug("RSP packet: subsequent thread info query, will answer 'l'")
        self.sendPacket("l") # the previously given thread was the last one

    def memoryMapHandler(self, packet):
        """
        'qXfer:memory-map:read' - provide info about memory map so that the vFlash commands are used
        """
        if ":memory-map:read" in packet: # include registers and IO regs in SRAM area
            self.logger.debug("RSP packet: memory map query")
            memorymap = ('l<memory-map><memory type="ram" start="{0}" length="{1}"/>' + \
                             '<memory type="flash" start="{2}" length="{3}">' + \
                             '<property name="blocksize">{4}</property>' + \
                             '</memory></memory-map>').format(0 + 0x800000, \
                             (self.dbg.memory_info.memory_info_by_name('internal_sram')['address'] + \
                              self.dbg.memory_info.memory_info_by_name('internal_sram')['size']), \
                              self.dbg.memory_info.memory_info_by_name('flash')['address'], \
                              self.dbg.memory_info.memory_info_by_name('flash')['size'], \
                              self.dbg.memory_info.memory_info_by_name('flash')['page_size'])
            self.sendPacket(memorymap)
            self.logger.debug("Memory map=%s", memorymap)            
        else:
            self.logger.debug("Unhandled query: qXfer%s", packet)
            self.sendPacket("")

    def stepHandler(self, packet):
        """
        's': single step, perhaps starting at a different address
        """
        self.logger.debug("RSP packet: single-step")
        if not self.mon.dw_mode_active:
            self.logger.debug("Cannot single-step because not connected")
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire on'")
            self.sendSignal(SIGHUP)
            return
        if not self.vflashdone and not self.mon.noload:
            self.logger.debug("Cannot single-step without prior load")
            self.sendDebugMessage("Load executable first before starting execution")
            self.sendSignal(SIGILL)
            return
        if packet:
            self.logger.debug("Set PC to 0x%s",packet)
            #set PC - note, byte address converted to word address
            self.dbg.program_counter_write(int(packet,16)>>1)
        self.logger.debug("Single-step")
        self.dbg.step()
        self.sendSignal(SIGTRAP)
 
    def threadAliveHandler(self, packet):
        """
        'T': Is thread still alive? Yes, always!
        """
        self.logger.debug("RSP packet: thread alive query, will answer 'OK'");
        self.sendPacket('OK')

    def flashDoneHandler(self, packet):
        """
        'vFlashDone': everything is there, now we can start flashing! 
        """
        self.logger.debug("RSP packet: flash done")
        self.vflashdone = True
        for x,y in zip(sorted(self.flash), sorted(self.flash)[1:]):
            if (self.flash[x][0] > y):
                self.logger.critical("Chunk starting at 0x%04X overlaps chunk starting at 0x%04X", x, y)
        pgsiz = self.dbg.memory_info.memory_info_by_name('flash')['page_size']
        multbuf = self.dbg.device_info.get('buffer_per_flashpage',1)
        mpgsiz = pgsiz*multbuf
        self.logger.info("Starting to flash ...")
        memtype = self.dbg.device.avr.memtype_write_from_string('flash')
        for chunkaddr in sorted(self.flash):
            i = chunkaddr + len(self.flash[chunkaddr][1])
            while i < self.flash[chunkaddr][0]:
                self.flash[chunkaddr][1].append(0xFF)
                i += 1
            # now send it page by page
            # if multbuf > 1, then read/write in multbuf batches
            pgaddr = chunkaddr
            while pgaddr < self.flash[chunkaddr][0]:
                self.logger.debug("Flashing page starting at 0x%X", pgaddr)
                currentpage = self.dbg.flash_read(pgaddr, mpgsiz)
                if currentpage == self.flash[chunkaddr][1][pgaddr-chunkaddr:pgaddr-chunkaddr+mpgsiz]:
                    self.logger.debug("Skip flashing page because already flashed at 0x%X", pgaddr)
                else:
                    self.dbg.device.avr.write_memory_section(memtype,
                                                                pgaddr,
                                                                self.flash[chunkaddr][1][pgaddr-chunkaddr: 
                                                                                         pgaddr-chunkaddr+mpgsiz],
                                                                pgsiz,
                                                                allow_blank_skip=True)
                pgaddr += mpgsiz
        self.logger.info("Flash done")
        self.sendPacket("OK")            

    def flashEraseHandler(self, packet):
        """
        'vFlashErase': we use the information in this command 
         to prepare a buffer for the program we need to flash;
         in case of multi page buffers, we correct start and end address
        """

        self.logger.debug("RSP packet: flash erase")
        if self.vflashdone:
            self.vflashdone = False
            self.flash = {} # clear flash 
        if self.mon.dw_mode_active:
            if not self.flash:
                self.logger.info("Loading executable ...")
            addrstr, sizestr = packet[1:].split(',')
            beg_addr = int(addrstr, 16)
            end_addr = beg_addr + int(sizestr, 16)
            pgsiz = self.dbg.memory_info.memory_info_by_name('flash')['page_size']
            multbuf = self.dbg.device_info.get('buffer_per_flashpage',1)
            mpgsiz = pgsiz*multbuf
            beg_addr = (beg_addr//mpgsiz)*mpgsiz
            end_addr = ((end_addr+mpgsiz-1)//mpgsiz)*mpgsiz
            self.logger.debug("Flash erase: 0x%04X -- 0x%04X", beg_addr, end_addr)
            self.flash[beg_addr] = [ end_addr, bytearray() ]
            self.sendPacket("OK")
        else:
            self.sendPacket("E05")
            
    def flashWriteHandler(self, packet):
        """
        'vFlashWrite': chunks of the program we need to flash
        """
        addrstr = (packet.split(b':')[1]).decode('ascii')
        data = self.unescape(packet[len(addrstr)+2:])
        addr = int(addrstr, 16)
        self.logger.debug("RSP packet: flash write starting at 0x%04X", addr)
        #find right chunk
        for chunkaddr in self.flash:
            if chunkaddr <= addr and addr < self.flash[chunkaddr][0]: # right chunk found
                i = chunkaddr + len(self.flash[chunkaddr][1])
                while i < addr:
                    self.flash[chunkaddr][1].append(0xFF)
                    i += 1
                self.flash[chunkaddr][1].extend(data)
                if len(self.flash[chunkaddr][1]) + chunkaddr > self.flash[chunkaddr][0]: # should not happen
                    self.logger.error("Address for data 0x%X larger than addr 0x%X in packet vFlashWrite: 0x%X",
                                          len(self.flash[chunkaddr][1]) + chunkaddr, self.flash[chunkaddr][0], addr)
                    self.sendPacket("E03")
                else:
                    self.sendPacket("OK")
                return
        self.logger.error("No previous vFlashErase packet for vFlashWrite at: 0x%X", addr)
        self.sendPacket("E03")

    def escape(self, data):
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

    def unescape(self, data):
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
        when in extended-remote mode, a 'run' is issued. In ordinary remote mode, it
        will disconnect, in extended-remote it will not, and you can restart or load a modified 
        file and run that one.
        """
        self.logger.debug("RSP packet: kill process, will reset CPU")
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
        if not self.mon.dw_mode_active:
            self.logger.debug("Cannot start execution because not connected")
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire on'")
            self.sendSignal(SIGHUP)
            return
        self.logger.debug("Resetting CPU and wait for start")
        self.dbg.reset()
        self.sendSignal(SIGTRAP)

    def removeBreakpointHandler(self, packet):
        """
        'z': Remove a breakpoint
        """
        if not self.mon.dw_mode_active:
            self.sendPacket("E09")
            return
        breakpoint_type = packet[0]
        addr = packet.split(",")[1]
        self.logger.debug("RSP packet: remove BP of type %s at %s", breakpoint_type, addr)
        if breakpoint_type == "0" or breakpoint_type == "1":
            self.dbg.software_breakpoint_clear(int(addr, 16))
            self.sendPacket("OK")
        else:
            self.logger.debug("Breakpoint type %s not supported", breakpoint_type)
            self.sendPacket("")

    def addBreakpointHandler(self, packet):
        """
        'Z': Set a breakpoint
        """
        if not self.mon.dw_mode_active:
            self.sendPacket("E09")
            return
        breakpoint_type = packet[0]
        addr = packet.split(",")[1]
        self.logger.debug("RSP packet: set BP of type %s at %s", breakpoint_type, addr)
        length = packet.split(",")[2]
        if breakpoint_type == "0" or breakpoint_type == "1":
            self.dbg.software_breakpoint_set(int(addr, 16))
            self.sendPacket("OK")
        else:
            self.logger.debug("Breakpoint type %s not supported", breakpoint_type)
            self.sendPacket("")

    def pollEvents(self):
        """
        Checks the AvrDebugger for incoming events (breaks)
        """
        if not self.mon.dw_mode_active: # if DW is not enabled yet, simply return
            return
        pc = self.dbg.poll_event()
        if pc:
            self.logger.info("BREAK received")
            self.sendSignal(SIGTRAP)

    def sendPacket(self, packetData):
        """
        Sends a GDB response packet
        """
        checksum = sum(packetData.encode("ascii")) % 256
        message = "$" + packetData + "#" + format(checksum, '02x')
        if packetData == "":
            message = "$#00"
        self.logger.debug("<- %s", message)
        self.lastmessage = packetData
        self.socket.sendall(message.encode("ascii"))

    def sendDebugMessage(self, mes):
        """
        Send a packet that always should be displayed in the debug console
        """
        self.sendPacket('O' + binascii.hexlify(bytearray((mes+"\n").encode('utf-8'))).decode("ascii").upper())
    
    def sendSignal(self, signal):
        """
        Sends signal to GDB
        """
        self.sendPacket(signal)
        self.lastSIGVAL = signal

    def handleData(self, data):
        while data:
            if data[0] == ord('+'): # ACK
                self.logger.debug("-> +")
                self.lastmessage = None
                data = data[1:]
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
                self.logger.info("Stop")
                self.dbg.stop()
                self.sendPacket(SIGTRAP)
                self.socket.sendall(b"+")
                self.logger.debug("<- +")
                data = data[1:]
            elif data[0] == ord('$'): # start of message
                validData = True
                self.logger.debug('-> %s', data)
                checksum = (data.split(b"#")[1])[:2]
                packet_data = (data.split(b"$")[1]).split(b"#")[0]
                if int(checksum, 16) != sum(packet_data) % 256:
                    self.logger.warning("Checksum Wrong in packet: %s", data)
                    validData = False
                if validData:
                    self.socket.sendall(b"+")
                    self.logger.debug("<- +")
                else:
                    self.socket.sendall(b"-")
                    self.logger.debug("<- -")
                # now split into command and data (or parameters) and dispatch
                if chr(packet_data[0]) in '!?ABcCdDFgGHiIkmMpPrRsStTxXzZ':
                    i = 1
                else:
                    for i in range(len(packet_data)+1):
                        if i == len(packet_data) or not chr(packet_data[i]).isalpha():
                            break
                self.dispatch(packet_data[:i].decode('ascii'),packet_data[i:])
                data = (data.split(b"#")[1])[2:]

    def stopDebugSession(self):
        """
        Check whether user has already disabled debugWIRE mode. Otherwise, we simply disconnect.
        """
        if self.mon.dw_mode_active:
            self.dbg.stop_debugging()

class MonitorCommand(object):
    """
    This class implements all the monitor commands
    """ 
    def __init__(self, handler):
        self.handler = handler
        self.dw = self.handler.dw
        self.dw_mode_active = False
        self.dw_deactivated_once = False
        self.noload = False # when true, one may start execution even without a previous load

        self.moncmds = {
            'breakpoints' : self.monBreakpoints,
            'debugwire'   : self.monDebugwire,
            'help'        : self.monHelp,
            'noload'      : self.monNoload,
            'reset'       : self.monReset,
            'singlestep'  : self.monSinglestep,
            'timer'       : self.monTimer,
            'version'     : self.monVersion
            }

    def dispatch(self, tokens):
        if not tokens:
            self.monHelp(list())
            return
        handler = self.monUnknown
        for cmd in self.moncmds:
            if cmd.startswith(tokens[0]):
                if handler == self.monUnknown:
                    handler = self.moncmds[cmd]
                else:
                    handler = self.monAmbigious
        handler(tokens[1:])

    def monUnknown(self, tokens):
        self.sendReplyPacket("Unknown 'monitor' command")

    def monAmbigious(self, tokens):
        self.sendReplyPacket("Ambigious 'monitor' command")

    def monBreakpoints(self, tokens):
        self.sendReplyPacket("Currently, only software breakpoints are used")

    def monDebugwire(self, tokens):
        if "on".startswith(tokens[0]) and len(tokens[0]) > 1:
            if self.dw_deactivated_once:
                self.handler.sendDebugMessage("Cannot reactivate debugWIRE")
                self.sendReplyPacket("You have to exit and restart the debugger")
            else:
                if not self.dw_mode_active:
                    self.dw_mode_active = self.dw.coldStart(graceful=False, callback= self.sendPowerCycle)
                    self.sendReplyPacket("debugWIRE mode is now enabled")
                    return
                else:
                    self.sendReplyPacket("debugWIRE mode was already enabled")
        elif "off".startswith(tokens[0]) and len(tokens[0]) > 1:
            if self.dw_mode_active:
                self.dw_mode_active = False
                self.dw_deactivated_once = True
                self.dw.disable()
            self.sendReplyPacket("debugWIRE mode is disabled")
        elif tokens[0] =="":
            if self.dw_mode_active:
                self.sendReplyPacket("debugWIRE mode is enabled")
            else:
                self.sendReplyPacket("debugWIRE mode is disabled")

    def sendPowerCycle(self):
        self.handler.sendDebugMessage("*** Please power-cycle the target system ***")

    def monHelp(self, tokens):
        self.handler.sendDebugMessage("monitor help                - this help text")
        self.handler.sendDebugMessage("monitor version             - print version")
        self.handler.sendDebugMessage("monitor debugwire [on|off]  - activate/deactivate debugWIRE mode")
        self.handler.sendDebugMessage("monitor reset               - reset MCU")
        self.handler.sendDebugMessage("monitor noload              - execute even when no code has been loaded")
        self.handler.sendDebugMessage("monitor timer [freeze|run]  - freeze/run timers when stopped")
        self.handler.sendDebugMessage("monitor breakpoints [all|software|hardware]")
        self.handler.sendDebugMessage("                            - allow bps of a certain kind only")
        self.handler.sendDebugMessage("monitor singlestep [safe|interruptible]")
        self.handler.sendDebugMessage("                            - single stepping mode")
        self.handler.sendDebugMessage("The first option is always the default one")
        self.sendReplyPacket("If no parameter is specified, the current setting is printed")

    def monNoload(self, tokens):
        self.noload = True
        self.sendReplyPacket("Execution without prior 'load' command is now possible")

    def monReset(self, tokens):
        if self.dw_mode_active:
            self.handler.dbg.reset()
            self.sendReplyPacket("MCU has been reset")
        else:
            self.sendReplyPacket("Enable debugWIRE mode first") 

    def monSinglestep(self, tokens):
        self.sendReplyPacket("Currently, single-stepping is always interruptible")

    def monTimer(self, tokens):
        self.sendReplyPacket("Currently, timers are always frozen when execution is stopped")

    def monVersion(self, tokens):
        self.sendReplyPacket("dw-gdbserver {}".format(VERSION))

    def sendReplyPacket(self, mes):
        """
        Send a packet as a reply to a monitor command to be displayed in the debug console
        """
        self.handler.sendPacket(binascii.hexlify(bytearray((mes+"\n").encode('utf-8'))).decode("ascii").upper())

class BreakAndExec(object):
    """
    This class manages breakpoints, supports flashwear minimizing execution, and 
    makes interrupt-safe single stepping possible.
    """

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
            self.logger.debug("Graceful exception: %s",e)
            if graceful:
                return False  # we will try to connect later
            else:
                raise
        # Now read out program counter and check whether it contains stuck to 1 bits
        pc = self.dbg.program_counter_read()
        self.logger.debug("PC=%X",pc)
        if pc != 0:
            raise FatalError("Program counter of MCU has stuck-at-1-bits")
        # Check device signature
        if sig != self.dbg.device_info['device_id']:
            # Some funny special cases of chips pretending to be someone else when in debugWIRE mode
            if sig == 0x1E930F and self.dbg.device_info['device_id'] == 0x1E930A: return # pretends to be a 88P, but is 88
            if sig == 0x1E940B and self.dbg.device_info['device_id'] == 0x1E9406: return # pretends to be a 168P, but is 168
            if sig == 0x1E950F and self.dbg.device_info['device_id'] == 0x1E9514: return # pretends to be a 328P, but is 328
            raise FatalError("Wrong MCU signature: 0x{:X}, expected: 0x{:X}".format(sig, self.dbg.device_info['device_id']))
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
        self.logger.info("Restart the debugging tool before entreing debugWIRE mode")
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
        # clear all breakpoints
        self.dbg.software_breakpoint_clear_all()
        # disable DW
        self.dbg.device.avr.protocol.debugwire_disable()
        # deactivate the physical interface
        self.dbg.device.stop()
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
        Enables debugWIRE mpode by programming theDWEN fuse bit. If the chip is locked,
        it will be erased. In this case, also the BOOTRST fusebit is disabled.
        Since the implementation of ISP programming is somewhat funny, a few stop/start 
        sequences and double reads are necessary.
        """
        self.logger.info("Try to connect using ISP")
        self.spidevice = NvmAccessProviderCmsisDapSpi(self.dbg.transport, self.dbg.device_info)
        device_id = int.from_bytes(self.spidevice.read_device_id(),byteorder='little')
        if self.dbg.device_info['device_id'] != device_id:
            raise FatalError("Wrong MCU signature: 0x{:X}, expected: 0x{:X}".format(
                device_id,
                self.dbg.device_info['device_id']))
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
                data = self.connection.recv(4096)
                if len(data) > 0:
                    # self.logger.debug("Received over TCP/IP: %s",data)
                    self.handler.handleData(data)
            self.handler.pollEvents()


    def __del__(self):
        if self.handler and self.handler.mon.dw_mode_active:
            self.handler.stopDebugSession() # stop debugWIRE 
        time.sleep(1) # sleep 1 second before closing in order to allow the client to close first
        if self.connection:
            self.connection.close()
        if self.gdb_socket:
            self.gdb_socket.close()


            
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
                loger.info("Connecting to any tool with USB serial number '{0:s}'".format(usb_serial))
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

    getLogger('pyedbglib.hidtransport.hidtransportbase').setLevel(logging.WARNING) # suppress info messages from hidtransport
    getLogger('pyedbglib.protocols').setLevel(logging.CRITICAL) # supress spurious error messages from pyedbglib
    getLogger('pymcuprog.nvm').setLevel(logging.CRITICAL) # suppress errors of not connecting: It is intended!
    if args.verbose.upper() == "DEBUG":
        getLogger('pyedbglib').setLevel(logging.INFO)

    
    if args.version:
        print("dw-gdbserver version {}".format(VERSION))
        return 0

    # look for VID/PIDs of possible debuggers
    usbdevices = usb.core.find(find_all=True, idVendor=0x03EB)
    nousb = True
    for device in usbdevices:
        if device.idVendor == 0x03EB and \
            device.idProduct in [ 0x2140,  0x2141, 0x2144,  0x2111, 0x216A, 0x2145, 0x2175, 0x2177, 0x2180]:
            nousb = False

    if args.tool == "dwlink" or (nousb and not args.tool):
        dwlink.main(args)
        return
        
    # Use pymcuprog backend for initial connection here
    backend = Backend()
    toolconnection = _setup_tool_connection(args, logger)
    device = None

    try:
        backend.connect_to_tool(toolconnection)
    except pymcuprog.pymcuprog_errors.PymcuprogToolConnectionError:
        dwlink.main(args)
        return(0)
        
    finally:
        backend.disconnect_from_tool()

    device = args.dev

    if not device:
        print("Please specify target MCU with -d option")
        return(1)
            
    transport = hid_transport()
    transport.connect(serial_number=toolconnection.serialnumber, product=toolconnection.tool_name)
    logger.info("Connected to %s", transport.hid_device.get_product_string())

    logger.info("Starting dw-gdbserver")
    avrdebugger = DWEAvrDebugger(transport, device)
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
