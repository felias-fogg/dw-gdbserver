# Changelog

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

