# Changelog

### V0.0.3 (1-Feb-2025)

- extended-remote works now (important when using Gede)
- kill/quit/detach do now the reasonable things
- when starting a load command, at least the packets got interpreted
  the right way; in the original version the accepted packet size was
  much larger than the read block, which clashed


### V0.0.2 (31-Jan-2025)

- Refactoring of the GdbHandler class. Looks much better now, but the functionaliy is the same. 

### V0.0.1 (30-Jan-2025)

- Almost all packets are handled. In particular the load function is not there yet, and no support for X-packages.

### V0.0.0-pre1 (24-Jan-2025)

- Setting up the framework by using pyavrdebug (by mraardvark). Identified the modules that need changes in pymcuprog and implemented the first version of modules with specialized classes that I will use. Later on, these could be used to create a PR. I prefixed the module names with dwe_ (standing for debugWIRE enabled) and the classes with DWE:
  - dwe_avr8target.py
  - dwe_avrdebug.py
  - dwe_nvmdebugwire.py

- In addition, I prepared a new deviceinfo/devices folder, which will be populated with all the devices that are going to be supported

