# dw-gdbserver

### What is it good for?

This Python script acts as a GDB server for [**debugWIRE**](https://en.wikipedia.org/wiki/DebugWIRE) MCUs, such as the ATmega328P as known from the Arduino UNO. It interfaces with the [dw-link hardware debugger](https://github.com/felias-fogg/dw-link) by providing a serial to TCP/IP bridge. It can also communicate with Microchip EDBG debuggers such as [Atmel-ICE](https://www.microchip.com/en-us/development-tool/atatmel-ice), [MPLAB SNAP](https://www.microchip.com/en-us/development-tool/atatmel-ice) (in AVR mode), [MPLAB PICkit4](https://www.microchip.com/en-us/development-tool/pg164140) (in AVR mode), etc. In the latter cases, it uses the infrastructure provided by [pymcuprog](https://github.com/microchip-pic-avr-tools/pymcuprog) and [pyedgblib](https://github.com/microchip-pic-avr-tools/pyedbglib) to implement a full-blown GDB server. 

By the way, switching to AVR mode in the SNAP debugger is easily accomplished by using avrdude (>= Version 7.3):

```
> avrdude -c snap_isp -Pusb -xmode=avr
```

Of course, the same works for the PICkit 4 debugger. Unfortunately, the PICkit 5 debugger does not have such a mode and is therefore unusable with this script.

### Usage

If your target board is an Arduino UNO, you have to first modify it by [diconnecting the capacitor](https://wolles-elektronikkiste.de/en/debugging-for-the-arduino-uno-with-atmel-studio) that is responsible for the auto-reset feature. 

Once you have connected one of the above debuggers to a target board, you can start the debug server in a terminal window:

```
> dw-gdbserver.py -d atmega328p
Connecting to anything possible
Info : Listening on port 2000 for gdb connection
```

In another terminal window, you may now start a GDB session:

```bash
> avr-gdb <progname>.elf
GNU gdb (GDB) 15.2
Copyright (C) 2024 Free Software Foundation, Inc.
...
(gdb) target remote :2000
Remote debugging using :2000
0x00000000 in __vectors ()
(gdb) monitor debugwire
debugWIRE mode is disabled
(gdb) monitor debugwire on
*** Please power-cycle the target system ***
Ignoring packet error, continuing...
debugWIRE mode is enabled
(gdb) load
Loading section .text, size 0x596 lma 0x0
Start address 0x00000000, load size 1430
Transfer rate: 1 KB/sec, 1430 bytes/write.
(gdb) break loop
Breakpoint 1 at 0x470: file /Users/.../varblink0.ino, line 13.
Note: automatically using hardware breakpoints for read-only addresses.
(gdb) continue
...
```

### How to get into and out of debugWIRE mode

When the target chip is not powered by the debugger and is not already in debugWIRE mode,  you must request the switch to debugWIRE mode using the command `monitor debugwire on`. You will then be asked by the Python script and in the debug console to power cycle the target system. Once this is done, the chip will stay in this mode, even after terminating the debugging session. You can switch back to normal by either using `monitor debugwire off` before you leave the debugger or by using the command `Burn Bootloader` in the Arduino IDE. However, this works only with the mentioned debuggers. 

### What the future has in store for us

The script has all the basic functionality but still needs some polishing. Breakpoint handling and single-stepping will be improved, and more chips will be supported in the future (currently, it is only ATmega328P). Also, the Xplained boards with the ATmega328P(B) and ATmega168P are not yet tested and will probably need some extra work because the onboard debugger controls the supply voltage and can do the power cycling.

I also plan to have an installable version, and I will provide binaries, which can be used as tools for Arduino IDE 2. And if it all works, it is only a tiny step to generalize it to the JTAG and UPDI AVR MCUs. So, stay tuned.
