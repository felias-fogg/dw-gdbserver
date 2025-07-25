# Changelog

### V2.3.2 (25-Jul-2025)

- Change in README, finalizing development in this repo!

### v2.3.0 (22-July-2025)

- Added: Write-only registers are extracted from the ATDF files and listed in the masked_registers list in the device files
- Added: SRAM reads will honor the list of masked registers (see sram_masked_read)
- Changed: Regenerated all device files so that they now contain the marked_registers
- Added: SVD handling. The directory `svd` contains svd files for all supported chips, generated by the tool atfd2svd (use my fork of it!). This is the workhorse for the script `gensvd.py` in the `svd` directory. With SVD files, GUIs such as Arduino IDE 2 can easily display register contents (but it needs to be added to the configuration file of the GUI).

- Changed: dw-gdbserver will terminate if there is no hardware debugger (or if there are too many)
- Added: Integration test that runs both avr-gdb and the current version of dw-gdbserver.
- Fixed: in _vflash_erase_handler, moved the call to cleanup_breakpoint into the if-branch when dw mode is active. Otherwise, a load command can lead to an AVR8_FAILURE_ILLEGAL_STATE error.
- Changed: Adapted a number of messages returned by the monitor command in order to make it more similar to the output of dw-link.
- Fixed: In dwlink, we look for a 'detach' command package and then disconnect immediately. Otherwise, older GDB versions choke on it and report an internal error.
- Changed: If dwlink is terminated by a Ctrl-C, the return code is now 1. This helps to terminate the infinite loop in the serv.sh script.

### V2.2.2 (14-June-2025)

- Added: Live tests that check that protected SW BPs and unprotected HW BPs work correctly.
- Added: Live test added to check that old-style execution does indeed lead to twice reprogramming a flash page at each breakpoint hit
- Fixed: Moved "BREAK" recognition in single-step after branching to old-style execution because otherwise execution would not proceed in the old-style case.

### v2.2.1 (2-May-2025)

- Changed: HW BPs will no longer be protected (when doing a single step). While protecting an HW BP is not wrong, it is unnecessary. Further, it implies you cannot run the debugger with only one HW BP in HWBP-only mode.
- Changed: If we try to single-step at a location with an SW BP, we now either simulate or request a single step from the OCD, which will execute it offline. This saves one HW BP reassignment in case of a straight-line instruction.
- Fixed: Calling cleanup_breakpoints in vErase and X-packets for flash. Without it, SW BPs might be overwritten without it being noticed by the hardware debugger. Does not happen when using the debugger of an IDE, but it may occur when debugging using the CLI.
- Added: Live tests for the above cases
- Added: Dummy tool packages for 32-bit systems. When executed, they give an error message suggesting installing a local debugging solution or reinstalling the board package when running on a 64-bit system. This is not part of the current repo but part of the distribution repos felias-fogg.github.io and the core repos.

### v2.2.0-post1 (1-May-2025)

- Readme updated: MiniCore and MicroCore include dw-gdbserver as an integrated debugging solution for Arduino IDE 2.

### v2.2.0 (30-Apr-2025)

- Fixed: We will always stop after the first step of a (repeated) range-stepping command, allowing GDB to insert a BP at the beginning of the range.

### v2.2.0-pre4 (30-Apr-2025)

- Fixed: Inactive BPs at the current location were removed before making a single step. This was functionally OK, but it increased flash wear significantly because when GDB proceeds from a BP, it first reinserts all other BPs, then it makes a single step, reinserts the overstepped BP, and finally continues execution. For this reason, when updating the BPs, we now protect an inactive BP at the current location.  This is also done in range-stepping. We also stop after one range-stepping step, when we overstepped a protected inactive BP.
- Changed: Removed 'inuse' from breakpoint entry because it was not used at all.
- Added: _read_filtered_flash_word in BreakAndExec (if we do not use the cache, it may be safer)
- Added: Live test for 'vCont;c' and vCont;s' with a BP at the current position
- Added: Live test for 'vCont;r....'

### v2.2.0-pre3 (27-Apr-2025)

- Added 'reset' in `monitor debugwire enable` command when debugWIRE mode was already enabled. This means we can use this command as a 'reset' command in CLion.
### v2.0.0-pre2 (27-Apr-2025)

- Added: Live test for 'S' packet
### v2.2.0-pre1 (24-Apr-2025)

- Added: Live tests for: 'X', C', 'g', 'G', 'm', 'M', 'p', and 'P' packages
- Fixed: p20 (SREG) package led to a typing error
- Fixed: p21 (SP) package led to a typing error

### v2.1.8-post2 (21-Apr-2025)

- Readme file changed concerning which core files are available

### v2.1.8-post1 (16-Apr-2025)

- Fixed: Pictures in the readme file are embedded using absolute URLs because PyPI cannot deal with relative ones (since it does not upload the entire GitHub repo).

### v2.1.8 (15-Apr-2025)

- Fixed: For Intel and Apple Silicon Macs, libusb is now bundled in the binary so that the user does not have to deal with the nuisance of providing the right libusb (which is actually not trivial when on an Apple Silicon Mac you have a Rosetta homebrew installation).

### v2.1.7 (15-Apr-2025)

- Added: More info logs when using automatic switching to debugWIRE mode

### v2.1.6 (14-Apr-2015)

- Fixed: Since multiple -c options are possible, applying the strip method does not work. Instead, we deal with the single relevant command now.

### v2.1.5 (13-Apr-2025)

- Fixed: Gede is now supported (and not only announced as an option)
- Fixed: Leading and trailing spaces are removed from command line arguments. A leading space happened when specifying an option in the `platformio.ini` file.
- Added: Section about how to use dw-gdbserver in different IDEs/GUIs
- Fixed: When starting or single-stepping (also when range-stepping) at a location that contains a user supplied BREAK instruction, we stop with SIGILL (because otherwise we run into an endless loop).
- Fixed: When single-stepping a SLEEP instruction, we simply advance
the PC. Otherwise, we might just got stuck at this point.
- Added: A few info logs when enabling/disabling debugWIRE
- Added: Info log for MCU reset

### v2.1.4 (12-Apr-2025)

- Fixed: Removed the non-emptiness test for the result of writing something to memory in `Memory.writemem`. This test led to a load error when using a debugger without EXPAT support, but would have also affected other write operations.

### v2.1.3 (11-Apr-2025)

- Refined the messages concerning the installation of udev rules.

### v2.1.2 (10-Apr-2025)

- Added: Make a difference between none and too many debuggers (well, it is probably not too relevant for the average user).

### v2.1.1 (7-Apr-2025)

- Fixed: Fatal errors (wrong MCU, stuck-at-1-bits) during the warm start when connecting with target remote will now be stored and shown again when trying to enable debugWIRE.
- Fixed: When such a fatal error happens, debugging is immediately stopped. Otherwise, it could happen that the debugger is in a funny state when starting the next session.
- Changed: Wait period before the exit is reduced to 0.5 seconds
- Added: Document describing how to connect the different debuggers to targets, which is linked to from README.

### v2.1.0 (6-Apr-2025)

- Added: new option `--install-udev-rules` when running under Linux. When used, dw-gdbserver must be called with `sudo`. This will install the udev rules under `/etc/udev/rules.d/`.
- Added: `NoBackendError` is now caught when trying to connect. It means that 'libusb' needs to be installed or made visible to PyUsb. The error message now says as much.
- Added: It is noticed when no hardware debugger is found, and under Linux, it is noted that udev rules must be added.
- Changed: Both errors are marked as `CRITICAL`, but the server is not terminated. When trying to start with `monitor debugwire enable`, an appropriate error message is displayed. This will help when the gdbserver is started in GUI that does not display the log output of the gdbserver.
- Changed: `AvrIspProtocolError` is called when trying to establish a debugWIRE connection, and a meaningful error message is displayed instead of terminating the server.

### v2.0.1 (4-Apr-2025)

- Changed: SerialExceptions will not be displayed in the discovery process of dw-link. Under Linux. there are far too many of those!

- Added: A note in README about libusb under macOS
- Added: General note about problems under the header **Installation**

### v2.0.0 (1-Apr-2025)

- Everything seems to be in place. Integration tests have yet to be written, but the application seems quite stable when tested.

### v2.0.0-pre6 (29-Mar-2025)

- Fixed: Exceptions in the serial thread in dwlink.py are now caught and gracefully handled. Instead of showing a backtrace and keeping the connection open, the server is immediately terminated.
- Added: Interpreting the argument "-c gdb_port <port>" provided by the Arduino IDE 2 when pretending to call OpenOCD. The good thing is that this is always an unused port!
- Added: Check the voltage before SPI programming and raise a Fatal Error if the target is not powered. This gives a more reasonable output than "ISP command failed."

### v2.0.0-pre5 (25-Mar-2025)

- Added: `monitor info` command
- Added: test cases for all modules that pass python -m unittest
- Changed: Made all modules pylint compliant

### v2.0.0-pre4 (17-Mar-2025)

- Added: Range stepping. It works most effectively with just one exit point in the range. Otherwise, we stop at every branch point and single step. It will be more effective if more hardware breakpoints are accessible. I do not see a reason to use software breakpoints to implement range stepping.
- Added `monitor rangestepping` command.
- Fixed: several bugs introduced by refactoring.

### v2.0.0-pre3 (6-Mar-2025)

- Added: Tests for GdbHandler, Memory, and BreakAndExec
- Changed: Simplified flash cache management. We only have one consecutive address space (not the potentially many caused by different vFlashErase statements)
- Changed: By now, the new execution code is the standard (`_old_exec == False`)

### v2.0.0-pre2 (2-Mar-2025)

- Changed: Refactored memory access. It now has its own class.
- Changed: All accesses to auxiliary classes are now through methods so that I can use auto-speccing.

### v2.0.0-pre1 (1-Mar-2025)

- Changed: Some monitor commands have been renamed, or the options have changed, which is why the major version number has been bumped.
- Added: The --device command line option now accepts '?' and will, in response, provide the list of supported MCUs.
- Changed: Refactorization of RSP memory read/write.
- The test suite has been set up, and tests for GdbHandler have been developed.
- Fixed: The number generated by the G packet was too large. Now, it is first split into bytes. This bug shows up only when executing the test suite probably means that it has not been used since we introduced the P command.
- Fixed: When calling cmd.startswith(inputstring) one must be aware that if inputstring is empty, the return value is True. In the monitor command parsing, I forgot that.

### v1.3.0 (25-Feb-2025)

- Added: Automatic power-cycling for mEDBG (e.g., Atmega328 XPLAINED)

### v1.2.0 (25-Feb-2025)

- Refactored: Inserting into flash cache and writing pages have been isolated from vFlashWrite and vFlashDone. Now, they can also be used in the  X command.
- Added: X command can now be used when the GDB client does not support XML.

- Added: A new monitor NoXML command for switching off XML capabilities, meaning that we cannot send a memory map and, therefore, cannot make use of the vFlash RSP commands. This command is just there for testing purposes and no "official" monitor command. It will probably go away to some point.

### v1.1.2 (24-Feb-2025)

- Fixed: Crash when stopping with ^C because sendPacket instead of sendSignal was used.

- Fixed: pyusb worked perfectly under macOS and Linux for enumerating all USB devices, but I got nothing under Windows. So, I removed this package because hidapi is doing all the work anyway.

### v1.1.0 (24-Feb-2025)

- Added: Flash verification
- Added: `monitor flashverify [on|off]`
- Changed: `monitor flashcache [on|off]` to `monitor cache [on|off]`
- Changed requirement for Python to >= 3.9

### v1.0.0 (24-Feb-2025)

- First "official" version, published on PyPi

### v0.9.16 (24-Feb-2025)

- Added: disabled "run timers when stopped" in warmStart to make sure that this indeed the default.
- Restructured project structure to make it an installable packet
- Changed: Version number is now retrieved from importlib.metadata.version

### v0.9.15 (23-FEB-2025)

- Changed: dw-harvest.py moved to deviceinfo/harvest.py
- Added: collect.py script in deviceinfo, which collects which MCUs are supported and what is the device ID/name mapping.
- Added: Early check in main whether device is supported
- Changed: We now use names instead of signatures in the error messages about the wrong MCU.

- Changed: Signals are now numbers, not strings anymore
- Changed: Instead of sending S-packets (containing only signal numbers), we now send T-packets with SREG, SP, and PC. Supposedly, this speeds up the time after a stop.

- Added: `monitor timers [freeze|run]` command implemented.

- Fixed: 'Address in use' errors happened regularly when starting dw-gdbserver after fatal errors. This occurs when the gdbserver closes the IP connection first.  To avoid this, fatal errors are now caught on the level of monitor commands or the general handler, and the server is not terminated. This forces the user to terminate the debugger, after which the gdbserver can wait some time and then terminate, freeing the IP port immediately (see https://hea-www.harvard.edu/~fine/Tech/addrinuse.html)

### v0.9.14 (21-Feb-2025)

- Fixed: Attaching to the AVR core now, because the XPLAINED-Mini board requested it.
- Fixed: XPLAINED-Mini only accepts full-page reads. Now, we either read from the cache or fall back to page-wise reading if there is nothing there.
- Fixed the problem of breakpoints not being removed when finishing.
- Implemented lazy breakpoint handling.
- Implemented assignment of hardware BPs to the most recently introduced breakpoints.
- Implemented two-word instruction simulation when starting at a breakpoint
- Implemented interrupt-safe single-stepping (+ the monitor function to enable that: `monitor singlestep safe`)
- Implemented monitor commands to disable fast loading and flash caching: `monitor load writeonly` and `monitor flashcache off` . Default is `readbeforewrite` and on, respectively.
- Implemented monitor commands for internal testing purposes: `monitor LiveTests` will initiate a live test of the gdbserver. Here the full command has to written out!
- Implemented monitor command to selectively switch new execution, single -stepping, and breakpoint handling on and off: `monitor Execution [old|new]`. Default is `old`.
- Renamed classes and modules to x... instead of dwe_ and X... instead of DWE. X standing for 'extended'.
- Tried out the SNAP, and it works without a hitch, albeit a bit slower than Atmel-ICE. Will measure load times with both.

### v0.9.13 (17-Feb-2025)

- Fixed: Learned from xedbg that there exists a field called `buffers_per_flash_block` , which can be used to tell the debugger that the MCU has a 4-page erase command. With that, ATtiny1634, 841, and 441 work now as well!
- Changed: The property `buffers_per_flash_page` as found in the ATDF files is taken as it is and not changed to something else.

### v0.9.12 (16-Feb-2025)

- Refactoring: New `MonitorCommand` class, which does all the bookkeeping and messaging
- Fixed: In the 'S' and 'C' commands, the signal was interpreted as an address

### v0.9.11 (15-Feb-2025)

- Changed: Cleaned up info messages when starting up
- Changed: Streamlined debug log messages in GDB handler
- Changed: `continue` and `single step` now receive SIGHUP when not connected to debugWIRE
- Added: S and C record handling is now necessary because GDB propagates signals other than SIGTRAP
- Added: Check for overlapping chunks when flashing
- Fixed: Reading single flash bytes (even at mis-aligned byte addresses) works now.

### v0.9.10 (14-Feb-2025)

- Fixed: Before starting the final ISP session in order to unprogram the DWEN fuse, another restart of the tool is performed by housekeeping end_session/start_session. This fixes the problem I observed earlier when the fusebit was not unprogrammed after leaving the debugger.
- Added: In dw-harvest.py, the `OCD` property `BUFFERS_PER_FLASH_PAGE` is evaluated. This seems to be the one that signals that the MCU has a 4-page erase command. I yet have to find a way of not deleting the other 3 pages when writing to one of the pages in a block of 4 pages.

### v0.9.9 (14-Feb-2025)

- Fixed: The packet parsing procedure had ignored the fact that
  single-letter commands can be immediately followed by a hex number;
  now we treat those commands in the right way.

### v0.9.8 (14-Feb-2025)

- Added: `monitor noload` will allow execution even without a previous
  load command.

### v0.9.6 (13-Feb-2025)

- Changed: All debugWIRE relevant start/finish methods have been moved
to dw-gdbserver. The code has been placed into a new class DebugWIRE.

### v0.9.5 (13-Feb-2025)

- Fixed: After enabling debugWIRE by setting the DWEN fuse and power-cycling, the
debugging tool is restarted by a
housekeeper.end\_session()/housekeeper.start\_session() pair.
With that, debugging works now after having just enabled the debugWIRE mode.

### v0.9.4 (13-Feb-2025)
- Much of the startup/shutdown code is now modularized and ready to be
  moved over to dw-gdbserver

### v0.9.3 (13-Feb-2025)
- Changed: power_cycle is now a method.

### v0.9.2 (11-Feb-2025)

- Apparently, one should not request a reset after connecting. Removing that helped a lot. Well, turned out later that this was a symptom of not restarting the housekeeping session (see V0.9.5).
- MCUs with stuck-at-1-bits are identified.
- Added code to honor the fact that the ATmega88/168/328 pretend to be P-versions when in debugWIRE mode
- Set the EEARH field in the activation record to EEARL+1. This seems to be the right choice when following the datasheet for the ATmega48. And it led to success in starting the MCU.

### v0.9.1 (11-Feb-2025)

- Works now with ATmega328P
- harvested all debugWIRE MCUs with the new script dw-harvest.py
- does not work with ATmega48, and probably not with others ...

### v0.9.0 (8-Feb-2025)

- basic functionality for using it as a gdbserver is implemented
- if already in debugWIRE mode, debugging is started right after `target remote`
- suppressed some spurious error messages from `nvmspi` and `jtagice3protocol` by setting the log level to `CRITICAL` for these modules
- set `pyedglib` log level to `INFO` when general level is `DEBUG`

### v0.0.9 (7-Feb-2025)

- `monitor debugwire on` now first tries ISP and will ask for power-cycle
- if ISP does not work, we switch directly DW on
- `monitor debugwire off`  only works once, but this is OK!
- the device parameter is now tested against DW and ISP targets
- multiple NAKs caused by time-outs waiting for power-cycling are bulk deleted
- implemented a callback function when calling `dbg.setup_session` for notifying in the debug console that a power-cycle is necessary
- Added `dwe_nvmspi.py` in order to suppress the warning message in the initial method

### v0.0.8 (6-Feb-2025)

- check first on whether there are potential debuggers at all and if not, we start dw-link immediately
- checked for each command that dw_mode is active; if not an error reply is given
- added field `dwen_fuse` to the device description for debugWIRE devices (its always in the high fuse)
- in avrdebug.py, put part of `setup_session`  into `__init__` so that device and memory infos are available before connecting to the device

### v0.0.7 (6-Feb-2025)

- integrated the dw-server script as the slightly rewritten dwlink module; you can now require the tool `dwlink` or it will be tried as the last alternative if no other debuggers are found; the reason for being last is that the discovery process for dw-link can take some time

### v0.0.6 (6-Feb-2025)

- adding support for single register get/set

### v0.0.5 (6-Feb-2005)

- flash programming has been implemented
- now, each memory page is checked before flashing in order to avoid flashing identical contents, which speeds up loading from 1kB/sec to 14kB/sec on Atmel-ICE

- rewrote "handleData" so that it is now able to cope with NAKs (which are very unlikely)

### v0.0.4 (2-Feb-2025)

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

### v0.0.3 (1-Feb-2025)

- extended-remote works now (important when using Gede)
- kill/quit/detach do now the reasonable things
- when starting a load command, at least the packets got interpreted
  the right way; in the original version, the accepted packet size was
  much larger than the read block, which clashed

### v0.0.2 (31-Jan-2025)

- Refactoring of the GdbHandler class. It looks much better now, but the functionality is the same.

### v0.0.1 (30-Jan-2025)

- Almost all packets are handled. In particular, the load function is not there yet, and there is no support for X-packages.

### v0.0.0-pre1 (24-Jan-2025)

- Setting up the framework by using pyavrdebug (by mraardvark). Identified the modules that need changes in pymcuprog and implemented the first version of modules with specialized classes that I will use. Later on, these could be used to create a PR. I prefixed the module names with dwe_ (standing for debugWIRE enabled) and the classes with DWE:
  - dwe_avr8target.py
  - dwe_avrdebug.py
  - dwe_nvmdebugwire.py

- In addition, I prepared a new deviceinfo/devices folder, which will be populated with all the devices that will be supported.
