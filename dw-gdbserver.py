"""
debugWIRE GDBServer 
"""
VERSION="0.9.3"

SIGINT  = "S02"     # Interrupt  - user interrupted the program (UART ISR) 
SIGILL  = "S04"     # Illegal instruction
SIGTRAP = "S05"     # Trace trap  - stopped on a breakpoint

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
from dwe_avrdebugger import DWEAvrDebugger, FatalErrorException
from pymcuprog.backend import Backend
from pymcuprog.pymcuprog_main import _setup_tool_connection
from pymcuprog.nvmspi import NvmAccessProviderCmsisDapSpi
from pymcuprog.deviceinfo import deviceinfo

# alternative debug server that connects to the dw-link hardware debugger
import dwlink

class EndOfSession(Exception):
    """Termination of session"""
    def __init__(self, msg=None, code=0):
        super(EndOfSession, self).__init__(msg)

class GdbHandler():
    """
    GDB handler
    Maps between incoming GDB requests and AVR debugging protocols (via pymcuprog)
    """
    def __init__ (self, socket, avrdebugger, devicename, powercycle=True):
        self.logger = getLogger('GdbHandler')
        self.socket = socket
        self.dbg = avrdebugger
        self.devicename = devicename
        self.powercycle = powercycle
        self.last_SIGVAL = "S00"
        self.packet_size = 4000
        self.dw_mode_active = False
        self.dw_deactivated_once = False
        self.extended_remote_mode = False
        self.flash = {} # indexed by the start address, these are pairs [endaddr, data]
        self.vflashdone = False # set to True after vFlashDone received and will then trigger clearing the flash cache 

        self.packettypes = {
            '!'           : self.extendedRemoteHandler,
            '?'           : self.stopReasonHandler,
            'c'           : self.continueHandler,
          # 'C'           : continue with signal - never happens in our context
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
          # 'S'           : stepping with signal - also never happens in our context
            'T'           : self.threadAliveHandler,
            'vFlashDone'  : self.flashDoneHandler,
            'vFlashErase' : self.flashEraseHandler,
            'vFlashWrite' : self.flashWriteHandler,
            'vKill'       : self.killHandler,
            'vRun'        : self.runHandler,
            'X'           : self.setMemoryBinaryHandler,
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
        self.logger.debug("Continue")
        if not self.dw_mode_active:
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire on'")
            self.sendPacket("E05")
            self.last_SIGVAL = SIGABRT
            return
        if packet:
            self.logger.debug("Set PC to 0x%s",packet)
            #set PC - note, byte address converted to word address
            self.dbg.program_counter_write(int(packet,16)>>1)
        self.dbg.run()

    def detachHandler(self, packet):
        """
        'D': Detach. All the real housekeeping will take place when the connection is terminated
        """
        self.logger.debug("Detaching ...")
        self.sendPacket("OK")
        raise EndOfSession("Session ended by client ('detach')")

    def getRegisterHandler(self, packet):
        """
        'g': Send the current register values R[0:31] + SREAG + SP + PC to GDB
        """
        self.logger.debug("GDB reading registers")
        if self.dw_mode_active:
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
            self.sendPacket(regString)
        else:
            self.sendPacket("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000341200000000")

    def setRegisterHandler(self, packet):
        """
        'G': Receive new register ( R[0:31] + SREAG + SP + PC) values from GDB
        """
        if self.dw_mode_active:
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
        self.logger.debug("Set current thread")
        self.sendPacket('OK')

    def getMemoryHandler(self, packet):
        """
        'm': provide GDB with memory contents
        """
        if not self.dw_mode_active:
            self.sendPacket("E05")
            return
        addr = packet.split(",")[0]
        size = packet.split(",")[1]
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
        elif addrSection == "82" and self.dbg.device_info['interface'].upper() != 'ISP+DW': # fuse
            data = self.dbg.read_fuse(int(addr, 16), int(size, 16))
        elif addrSection == "83" and self.dbg.device_info['interface'].upper() != 'ISP+DW': # lock
            data = self.dbg.read_lock(int(addr, 16), int(size, 16))
        elif addrSection == "84": # signature
            data = self.dbg.read_signature(int(addr, 16), int(size, 16))
        elif addrSection == "85" and self.dbg.device_info['interface'].upper() != 'ISP+DW': # user_signature
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
        if not self.dw_mode_active:
            self.sendPacket("E05")
            return
        addr = packet.split(",")[0]
        size = (packet.split(",")[1]).split(":")[0]
        data = (packet.split(",")[1]).split(":")[1]
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
            self.logger.debug("Illegal memtype: %s", addrSection)
            self.sendPacket("E13")
            return
        self.sendPacket("OK")

        
    def getOneRegisterHandler(self, packet):
        """
        'p': read register and send to GDB
        currently only PC
        """
        if not self.dw_mode_active:
            self.sendPacket("E05")
            return
        if packet == "22":
            # GDB defines PC register for AVR to be REG34(0x22)
            # and the bytes have to be given in reverse order (big endian)
            pc = self.dbg.program_counter_read()
            self.logger.debug("get PC command: 0x{:X}".format(pc))
            pcByteString = binascii.hexlify((pc << 1).to_bytes(4,byteorder='little')).decode('ascii')
            self.sendPacket(pcByteString)
        elif packet == "21": # SP
            spByteString = (binascii.hexlify(self.dbg.stack_pointer_read())).decode('ascii')
            self.logger.debug("get SP command: 0x%s", spByteString)
            self.sendPacket(spByteString)
        elif packet == "20": # SREG
            sregByteString =  (binascii.hexlify(self.dbg.status_register_read())).decode('ascii')
            self.logger.debug("get SREG command: 0x%s", sregByteString)
            self.sendPacket(sregByteString)
        else:
            regByteString =  (binascii.hexlify(self.dbg.sram_read(int(packet,16), 1))).decode('ascii')
            self.logger.debug("get Reg%s command: 0x%s", regByteString)
            self.sendPacket(regByteString)            
        
    def setOneRegisterHandler(self, packet):
        """
        'P': set a single register with a new value given by GDB
        """
        if not self.dw_mode_active:
            self.sendPacket("E05")
            return
        if packet[0:3] == "22=": # PC
            self.logger.debug("set PC command")
            pc = int(binascii.hexlify(int(packet[3:],16).to_bytes(4,byteorder='little'))) >> 1
            self.dbg.program_counter_write(pc)
        elif packet[0:3] == "21=": # SP (already in right order)
            self.logger.debug("set SP command")
            self.dbg.stack_pointer_write(binascii.unhexlify(packet[3:]))
        elif packet[0:3] == "20=": # SREG
            self.logger.debug("set SREG command")
            self.dbg.status_register_write(binascii.unhexlify(packet[3:]))
        else:
            self.logger.debug("set REG%d command",int(packet[0:2],16) )
            self.dbg.sram_write(int(packet[0:2],16), binascii.unhexlify(packet[3:]))
        self.sendPacket("OK")
            

    def attachedHandler(self,packet):
        """
        'qAttached': whether detach or kill will be used when quitting GDB
        """
        self.logger.debug("Attached query")
        self.sendPacket("1")

    def offsetsHandler(self, packet):
        """
        'qOffsets': Querying offsets of the different memory areas
        """
        self.logger.debug("Offset query")
        self.sendPacket("Text=000;Data=000;Bss=000")

    def monitorCmdHandler(self, packet):
        """
        'qRcmd': Monitor commands that directly get info or set values in the gdbserver
        """
        payload = packet[1:]
        self.logger.debug("monitor command: %s",binascii.unhexlify(payload).decode('ascii'))
        tokens = binascii.unhexlify(payload).decode('ascii').split()
        if len(tokens) == 1:
            tokens += [""]
        if len(tokens) == 0 or "help".startswith(tokens[0]):
            self.sendDebugMessage("monitor help                - this help text")
            self.sendDebugMessage("monitor version             - print version")
            self.sendDebugMessage("monitor debugwire [on|off]  - activate/deactivate debugWIRE mode")
            self.sendDebugMessage("monitor reset               - reset MCU")
            self.sendDebugMessage("monitor timer [freeze|run]  - freeze/run timers when stopped")
            self.sendDebugMessage("monitor breakpoints [all|software|hardware]")
            self.sendDebugMessage("                            - allow bps of a certain kind only")
            self.sendDebugMessage("monitor singlestep [atomic|interruptible]")
            self.sendDebugMessage("                            - single stepping mode")
            self.sendDebugMessage("The first option is always the default one")
            self.sendReplyPacket("If no parameter is specified, the current setting is printed")            
        elif "version".startswith(tokens[0]):
            self.sendReplyPacket("dw-gdbserver Version {}".format(VERSION))
        elif "debugwire".startswith(tokens[0]):
            if tokens[1][0:2] == "on":
                if self.dw_deactivated_once:
                    self.sendDebugMessage("Cannot reactivate debugWIRE")
                    self.sendReplyPacket("You have to exit and restart the debugger")
                else:
                    if not self.dw_mode_active:
                        # Attach debugger
                        self.logger.debug("Attaching AvrDebugger to device: %s", self.devicename)
                        if self.powercycle:
                            opt = {'callback': self.sendPowerCycle}
                        else:
                            opt = ""
                        self.dbg.setup_session(self.devicename, options=opt)
                        self.dbg.start_debugging()
                        #time.sleep(1)
                        #self.dbg.reset()
                        # Now read out program counter and check whether it contains stuck to 1 bits
                        pc = self.dbg.program_counter_read()
                        self.logger.debug("PC=%X",pc)
                        if (pc << 1) > self.dbg.device_info['flash_size_bytes']:
                            raise FatalErrorException("Program counter of MCU has stuck-at-1-bits")
                        self.logger.debug("Attached")
                        self.dw_mode_active = True
                    self.sendReplyPacket("debugWIRE mode is enabled")
            elif tokens[1][0:2] == "of":
                if self.dw_mode_active:
                    self.dw_mode_active = False
                    self.dw_deactivated_once = True
                    self.dbg.disable_debugwire()
                self.sendReplyPacket("debugWIRE mode is disabled")
            elif tokens[1] =="":
                if self.dw_mode_active: self.sendReplyPacket("debugWIRE mode is enabled")
                else: self.sendReplyPacket("debugWIRE mode is disabled")
        elif "reset".startswith(tokens[0]):
            self.dbg.reset()
            self.sendReplyPacket("MCU has been reset")
        elif "timer".startswith(tokens[0]):
            self.sendReplyPacket("Currently, timers are always frozen when execution is stopped")
        elif "breakpoints".startswith(tokens[0]):
            self.sendReplyPacket("Currently, only software breakpoints are used")
        elif "singlestep".startswith(tokens[0]):
            self.sendReplyPacket("Currently, single-stepping is always interruptible")
        else:
            self.sendReplyPacket("Unknown monitor command")

    def sendReplyPacket(self, mes):
        """
        Send a packet as a reply to a monitor command to be displayed in the debug console
        """
        self.sendPacket(binascii.hexlify(bytearray((mes+"\n").encode('utf-8'))).decode("ascii").upper())

    def sendDebugMessage(self, mes):
        """
        Send a packet that always should be displayed in the debug console
        """
        self.sendPacket('O' + binascii.hexlify(bytearray((mes+"\n").encode('utf-8'))).decode("ascii").upper())
    
    def sendPowerCycle(self):
        self.sendDebugMessage("*** Please power-cycle the target system ***")

    def supportedHandler(self, packet):
        """
        'qSupported': query for features supported by the gbdserver; in our case packet size and memory map
        Because this is also the command send after a connection with 'target remote' is made,
        we will try to establish a connection to the debugWIRE target.
        """
        self.logger.debug("qSupported query")

        # Try to start a debugWIRE debugging session
        # if we are already in debugWIRE mode, this will work
        # if not, one has to use the 'monitor debugwire on' command later on
        try:
            self.dbg.setup_session(self.devicename, options={'skip_isp': True})
            self.dbg.start_debugging()
            time.sleep(1)
            pc = self.dbg.program_counter_read()
            self.logger.debug("PC=%X",pc)
            self.dbg.reset()
            pc = self.dbg.program_counter_read()
            self.logger.debug("PC=%X",pc)
            self.dw_mode_active = True
        except FatalErrorException:
            raise
        except Exception:
            # we will try to connect later
            pass

        if self.dw_mode_active:
            # Now read out program counter and check whether it contains stuck to 1 bits
            pc = self.dbg.program_counter_read()
            self.logger.debug("PC=%X",pc)
            if pc != 0:
                raise FatalErrorException("Program counter of MCU has stuck-at-1-bits")

        self.logger.debug("dw_mode_active=%d",self.dw_mode_active)            
        self.sendPacket("PacketSize={0:X};qXfer:memory-map:read+".format(self.packet_size))

    def firstThreadInfoHandler(self, packet):
        """
        'qfThreadInfoHandler': get info about active threads
        """
        self.logger.debug("First thread info query")
        self.sendPacket("m01")

    def subsequentThreadInfoHandler(self, packet):
        """
        'qsThreadInfoHandler': get more info about active threads
        """
        self.logger.debug("successive thread info query")
        self.sendPacket("l") # the proviously given thread was the last one

    def memoryMapHandler(self, packet):
        """
        'qXfer:memory-map:read' - provide info about memory map so that the vFlash commands are used
        """
        if ":memory-map:read" in packet: # include registers and IO regs in SRAM area
            self.sendPacket(('l<memory-map><memory type="ram" start="{0}" length="{1}"/>' + \
                             '<memory type="flash" start="{2}" length="{3}">' + \
                             '<property name="blocksize">{4}</property>' + \
                             '</memory></memory-map>').format(0 + 0x800000, \
                             (self.dbg.memory_info.memory_info_by_name('internal_sram')['address'] + \
                              self.dbg.memory_info.memory_info_by_name('internal_sram')['size']), \
                              self.dbg.memory_info.memory_info_by_name('flash')['address'], \
                              self.dbg.memory_info.memory_info_by_name('flash')['size'], \
                              self.dbg.memory_info.memory_info_by_name('flash')['page_size']))
            self.logger.debug("Memory map query")
        else:
            self.logger.debug("Unhandled query: qXfer%s", packet)
            self.sendPacket("")

    def stepHandler(self, packet):
        """
        's': single step, perhaps starting a different address
        """
        if not self.dw_mode_active:
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire on'")
            self.sendPacket("E05")
            self.last_SIGVAL = SIGABRT
            return
        if packet:
            self.logger.debug("Set PC to 0x%s",packet)
            #set PC - note, byte address converted to word address
            self.dbg.program_counter_write(int(packet,16)>>1)
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

    def flashDoneHandler(self, packet):
        """
        'vFlashDone': everything is there, now we can start flashing! 
        """
        self.vflashdone = True
        pagesize = self.dbg.memory_info.memory_info_by_name('flash')['page_size']
        self.logger.info("Starting to flash ...")
        memtype = self.dbg.device.avr.memtype_write_from_string('flash')
        for chunkaddr in sorted(self.flash):
            i = chunkaddr + len(self.flash[chunkaddr][1])
            while i < self.flash[chunkaddr][0]:
                self.flash[chunkaddr][1].append(0xFF)
                i += 1
            # now send it page by page
            pgaddr = chunkaddr
            while pgaddr < self.flash[chunkaddr][0]:
                self.logger.debug("Flashing page starting at 0x%X", pgaddr)
                currentpage = self.dbg.flash_read(pgaddr, pagesize)
                if currentpage == self.flash[chunkaddr][1][pgaddr-chunkaddr:pgaddr-chunkaddr+pagesize]:
                    self.logger.debug("Skip flashing page because already flashed at 0x%X", pgaddr)
                else:
                    self.dbg.device.avr.write_memory_section(memtype,
                                                             pgaddr,
                                                             self.flash[chunkaddr][1][pgaddr-chunkaddr:pgaddr-chunkaddr+pagesize],
                                                             pagesize,
                                                             allow_blank_skip=False)
                pgaddr += pagesize
        self.logger.info("Flash done")
        self.sendPacket("OK")            

    def flashEraseHandler(self, packet):
        """
        'vFlashErase': we use the information in this command 
         to prepare a buffer for the program we need to flash
        """

        if self.vflashdone:
            self.vflashdone = False
            self.flash = {} # clear flash (might be a re-load)
        if self.dw_mode_active:
            addrstr, sizestr = packet[1:].split(',')
            addr = int(addrstr, 16)
            size = int(sizestr, 16)
            self.logger.debug("Flash erase: 0x%X, 0x%X", addr, size)
            self.flash[addr] = [ addr+size, bytearray() ]
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
        self.logger.debug("Flash write starting at 0x%X", addr)
        #find right chunk
        for chunkaddr in self.flash:
            if chunkaddr <= addr and addr < self.flash[chunkaddr][0]: # right chunk found
                i = chunkaddr + len(self.flash[chunkaddr][1])
                while i < addr:
                    self.flash[chunkaddr][1].append(0xFF)
                    i += 1
                self.flash[chunkaddr][1].extend(data)
                if len(self.flash[chunkaddr][1]) + chunkaddr >= self.flash[chunkaddr][0]: # should not happen
                    self.debugger.error("Address out of range in packet vFlashWrite: 0x%X", addr)
                    self.sendPacket("E03")
                else:
                    self.sendPacket("OK")
                return
        self.debugger.error("No previous vFlashErase packet for vFlashWrite at: 0x%X", addr)
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
        self.logger.debug("Killing process")
        self.dbg.reset()
        self.sendPacket("OK")
        if not self.extended_remote_mode:
            raise EndOfSession

    def runHandler(self, packet):
        """
        'vRun': reset and wait to be started from address 0 
        """
        self.logger.debug("(Re-)start the process and stop")
        if not self.dw_mode_active:
            self.sendDebugMessage("Enable debugWIRE first: 'monitor debugwire on'")
            self.sendPacket("E05")
            self.last_SIGVAL = SIGABRT
            return
        self.dbg.reset()
        self.sendPacket(SIGTRAP)
        self.last_SIGVAL = SIGTRAP

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
        breakpointType = packet[0]
        addr = packet.split(",")[1]
        self.logger.debug("Remove BP at %s", addr)
        if breakpointType == "0" or breakpointType == "1":
            self.dbg.software_breakpoint_clear(int(addr, 16))
            self.sendPacket("OK")
        else:
            #Not Supported
            self.sendPacket("")


    def addBreakpointHandler(self, packet):
        """
        'Z': Set a breakpoint
        """
        breakpointType = packet[0]
        addr = packet.split(",")[1]
        self.logger.debug("Set BP at %s", addr)
        length = packet.split(",")[2]
        if breakpointType == "0" or breakpointType == "1":
            self.dbg.software_breakpoint_set(int(addr, 16))
            self.sendPacket("OK")
        else:
            #Not Supported
            self.sendPacket("")

    def pollEvents(self):
        """
        Checks the AvrDebugger for incoming events (breaks)
        """
        if not self.dw_mode_active: # if DW is not enabled yet, simply return
            return
        pc = self.dbg.poll_event()
        if pc:
            self.logger.info("BREAK received")
            self.sendPacket(SIGTRAP)
            self.last_SIGVAL = SIGTRAP


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
                for i in range(len(packet_data)+1):
                    if i == len(packet_data) or not chr(packet_data[i]).isalpha():
                        break
                if i == 0:
                    i = 1 # the case that '!' and '?' are the command chars
                self.dispatch(packet_data[:i].decode('ascii'),packet_data[i:])
                data = (data.split(b"#")[1])[2:]

    def stopDebugSession(self):
        """
        Check whether user has already disabled debugWIRE mode. Otherwise, we simply disconnect.
        """
        if self.dw_mode_active:
            self.dbg.stop_debugging()


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
        print("Info : Listening on port {} for gdb connection".format(self.port)) # this is for cortex-debug!
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
#                    self.logger.debug("Received over TCP/IP: %s",data)
                    self.handler.handleData(data)
            self.handler.pollEvents()


    def __del__(self):
        if self.handler and self.handler.dw_mode_active:
            self.handler.stopDebugSession() # stop debugWIRE 
        time.sleep(1) # sleep 1 second before closing in order to allow the client to close first
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
                            default="warning", choices=['debug', 'info', 'warning', 'error', 'critical'],
                            help="Logging verbosity level")

    parser.add_argument("-V", "--version",
                            help="Print dw-gdbserver version number and exit",
                            action="store_true")

    # Parse args
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(stream=sys.stderr,level=args.verbose.upper(), format ='%(name)s - %(levelname)s - %(message)s')
    logger = getLogger()
    #getLogger('pyedbglib.protocols').setLevel(logging.CRITICAL) # supress spurious error messages from pyedbglib
    #getLogger('pymcuprog.nvm').setLevel(logging.CRITICAL) # suppress errors of not connecting: It is intended!
    #if args.verbose.upper() == "DEBUG":
    #    getLogger('pyedbglib').setLevel(logging.INFO)

    
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
    toolconnection = _setup_tool_connection(args)
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

    # Start server 
    # logger.info("Starting dw-gdbserver")
    avrdebugger = DWEAvrDebugger(transport, device)
    server = AvrGdbRspServer(avrdebugger, device, args.port)
    try:
        server.serve()
        
    except (EndOfSession, SystemExit, KeyboardInterrupt):
        logger.info("End of session")
        print("--- exit ---\r\n")
        return(0)
        
#    except Exception as e:
#        print("Fatal Error:",e)
    
if __name__ == "__main__":
    sys.exit(main())
