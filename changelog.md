# Changelog

### V0.9.11 (15-Feb-2025)

- Changed: Cleaned up info messages when starting up
- Changed: Streamlined debug log messages in GDB handler
- Changed: `continue` and `single step` now receive SIGHUP when not connected to debugWIRE 
- Added: S and C record handling is now necessary because GDB propagates signals other than SIGTRP
- Added: Check for overlapping chunks when flashing
- Fixed: Reading single bytes (even at mis-aligned byte addresses) works now.
- Added: `monitor noload`, which allows for execution even if no prior `load` command has been executed

### V0.9.10 (14-Feb-2025)

- Fixed: Before starting the final ISP session in order to unprogram the DWEN fuse, another restart of the tool is performed by housekeeping end_session/start_session. This fixes the problem I observed earlier when the fusebit was not unprogrammed after leaving the debugger.
- Added: In dw-harvest.py, the `OCD` property `BUFFERS_PER_FLASH_PAGE` is evaluated. This seems to be the one that signals that the MCU has a 4-page erase command. I yet have to find a way of not deleting the other 3 pages when writing to one of the pages in a block of 4 pages.

### V0.9.9 (14-Feb-2025)

- Fixed: The packet parsing procedure had ignored the fact that
  single-letter commands can be immediately followed by a hex number;
  now we treat those commands in the right way.

### V0.9.8 (14-Feb-2025)

- Added: `monitor noload` will allow execution even without a previous
  load command. It will be taken as a request to cache the entire
  flash in the debugger.

### V0.9.6 (13-Feb-2025)

- Changed: All debugWIRE relevant start/finish methods have been moved
to dw-gdbserver. The code has been placed into a new class DebugWIRE.

### V0.9.5 (13-Feb-2025)

- Fixed: After enabling debugWIRE by setting the DWEN fuse and power-cycling, the
debugging tool is restarted by a
housekeeper.end\_session()/housekeeper.start\_session() pair.
With that, debugging works now after having just enabled the debugWIRE mode.

### V0.9.4 (13-Feb-2025)
- much of the startup/shutdown code is now modularized and ready to be
  move over to dw-gdbserver

### V0.9.3 (13-Feb-2025)
- Changed: power_cycle is now a method 

### V0.9.2 (11-Feb-2025)

- Apparently, one should not request a reset after connecting. Removing that helped a lot. 
- MCUs with Stuck-at-1-bits are identified.
- Added code to honor the fact that the ATmega88/168/328 pretend to be P-versions when in debugWIRE mode
- Set the EEARH field in the activation record to EEARl+1. This seems to be the right choice when following the datasheet for the ATmega48. And it led to success in starting thr MCU.

### V0.9.1 (11-Feb-2025)

- Works now with ATmega328P
- harvested all debugWIRE MCUs with the new scrip‚t dw-harvest.py
- does not work with ATmega48, and probably not with others ...

### V0.9.0 (8-Feb-2025)

- basic functionality for using it as a gdbserver is implemented
- if already in debugWIRE mode, debugging is started right after `target remote`
- suppressed some spurious error messages from `nvmspi` and `jtagice3protocol` by setting the log level to `CRITICAL` for these modules
- set `pyedglib` log level to `INFO` when general level is `DEBUG`

### V0.0.9 (7-Feb-2025)

- `monitor debugwire on` now first tries ISP and will ask for power-cycle
- if ISP does not work, we switch directly DW on
- `monitor debugwire off`  only works once, but this is OK!
- the device parameter is now tested against DW and ISP targets
- multiple NAKs caused by time-outs waiting for power-cycling are bulk deleted
- implemented a callback function when calling `dbg.setup_session` for notifying in the debug console that a power-cycle is necessary
- Added `dwe_nvmspi.py` in order to suppress the warning message in the initial method

### V0.0.8 (6-Feb-2025)

- check first on whether there are potential debuggers at all and if not, we start dw-link immediately
- checked for each command that dw_mode is active; if not an error reply is given 
- added field `dwen_fuse` to the device description for debugWIRE devices (its always in the high fuse)
- in avrdebug.py, put part of `setup_session`  into `__init__` so that device and memory infos are available before connecting to the device

### V0.0.7 (6-Feb-2025)

- integrated the dw-server script as the slightly rewritten dwlink module; you can now require the tool `dwlink` or it will be tried as the last alternative if no other debuggers are found; the reason for being last is that the discovery process for dw-link can take some time

### V0.0.6 (6-Feb-2025)

- adding support for single register get/set

### V0.0.5 (6-Feb-2005)

- flash programming has been implemented
- now, each memory page is checked before flashing in order to avoid flashing identical contents, speeds up loading from 1kB/sec to 14kB/sec

- rewrote "handleData" so that it is now able to cope with NAKs (which are very unlikely)

### V0.0.4 (2-Feb-2025)

- in extended-remote mode, one stays now in session after a "kill"
  command, and the program can be restarted with "run"
- quit is now done with "detach" (because we reply with "1" to "qAttached"), and it is not possible to re-attach after detaching!
- the server now waits a second after having sent the detach so that
  the client can close first, reducing the likelihood of an "address
  already in use" error
- refactored things again in order to allow for binary payloads (X and
  vFlashWrite)
- each command now has its own handler
- the server now provides a (minimal) memory map in XML format so that GDB uses
  the vFlash commands
- providing the map means, however, that we now have to pretend to use hardware
  breakpoints, because GDB believes that flash memory is read-only

### V0.0.3 (1-Feb-2025)

- extended-remote works now (important when using Gede)
- kill/quit/detach do now the reasonable things
- when starting a load command, at least the packets got interpreted
  the right way; in the original version, the accepted packet size was
  much larger than the read block, which clashed

### V0.0.2 (31-Jan-2025)

- Refactoring of the GdbHandler class. It looks much better now, but the functionality is the same. 

### V0.0.1 (30-Jan-2025)

- Almost all packets are handled. In particular, the load function is not there yet, and there is no support for X-packages.

### V0.0.0-pre1 (24-Jan-2025)

- Setting up the framework by using pyavrdebug (by mraardvark). Identified the modules that need changes in pymcuprog and implemented the first version of modules with specialized classes that I will use. Later on, these could be used to create a PR. I prefixed the module names with dwe_ (standing for debugWIRE enabled) and the classes with DWE:
  - dwe_avr8target.py
  - dwe_avrdebug.py
  - dwe_nvmdebugwire.py

- In addition, I prepared a new deviceinfo/devices folder, which will be populated with all the devices that will be supported.

