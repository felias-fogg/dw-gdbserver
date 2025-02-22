# dw-gdbserver

### What is it good for?

This Python script acts as a GDB server for [**debugWIRE**](https://debugwire.de) MCUs, such as the ATmega328P. It interfaces with the [dw-link hardware debugger](https://github.com/felias-fogg/dw-link) by providing a serial to TCP/IP bridge. It can also communicate with Microchip debuggers such as [Atmel-ICE](https://www.microchip.com/en-us/development-tool/atatmel-ice) and [MPLAB SNAP](https://www.microchip.com/en-us/development-tool/atatmel-ice) (in AVR mode). In the case of Microchip debuggers, it uses the infrastructure provided by [pymcuprog](https://github.com/microchip-pic-avr-tools/pymcuprog) and [pyedgblib](https://github.com/microchip-pic-avr-tools/pyedbglib) to implement a full-blown GDB server. 

By the way, switching to AVR mode in the SNAP debugger is easily accomplished by using avrdude (>= Version 7.3):

```
> avrdude -c snap_isp -Pusb -xmode=avr
```

### Usage

If your target board is an Arduino UNO, you have to first modify it by [diconnecting the capacitor](https://debugwire.de/arduino-boards/#requirements-on-the-electrical-characteristics-of-the-reset-line) that is responsible for the auto-reset feature. 

Once you have connected one of the above debuggers to a target board, you can start the  gdbserver in a terminal window:

```
> dw-gdbserver.py -d atmega328p
[INFO] Connecting to anything possible
[INFO] Connected to Atmel-ICE CMSIS-DAP
[INFO] Starting dw-gdbserver
[INFO] Looking for device attiny1634
[INFO] Listening on port 2000 for gdb connection

```

In another terminal window, you can now start a GDB session:

```
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

When the target chip is not powered by the debugger and is not already in debugWIRE mode,  you must request the switch to debugWIRE mode using the command `monitor debugwire on`. You will then be asked by the Python script to power cycle the target system. Once this is done, the chip will stay in this mode, even after terminating the debugging session. You can switch back to normal by using `monitor debugwire off` before you leave the debugger. 

### What the future has in store for us

The script has all the basic functionality but still needs some polishing. Breakpoint handling and single-stepping will be improved.

I also plan to have an installable version, and I will provide binaries, which can be used as tools for Arduino IDE 2. And if it all works, it is only a tiny step to generalize it to the JTAG and UPDI AVR MCUs. So, stay tuned.

### List of supported and tested hardware debuggers

Except for [dw-link](https://github.com/felias-fogg/dw-link), this list is copied from the readme file of [pyedbglib](https://github.com/microchip-pic-avr-tools/pyedbglib). Boldface means that the debuggers have been tested by me and work with this Python script.


* PKOB nano (nEDBG) - on-board debugger on Curiosity Nano
* MPLAB PICkit 4 In-Circuit Debugger (when in 'AVR mode')
* **MPLAB Snap In-Circuit Debugger** (when in 'AVR mode')
* **Atmel-ICE**
* Power Debugger
* EDBG - on-board debugger on Xplained Pro/Ultra
* mEDBG - on-board debugger on Xplained Mini/Nano
* JTAGICE3 (firmware version 3.0 or newer)
* **dw-link** - DIY debugWIRE debugger based on Arduino UNO R3


### List of supported and tested MCUs

This is the list of all debugWIRE MCUs, which should all be compatible with dw-gdbserver.py. MCUs tested with this Python script are marked bold. MCUs known not to work with the script are struck out. For the list of MCUs compatible with dw-link, you need to consult the [dw-link manual](https://github.com/felias-fogg/dw-link/blob/master/docs/manual.md).

#### ATtiny (covered by MicroCore):

- **ATtiny13**

#### ATtinys (covered by the ATTinyCore):

* **ATtiny43U**
* **ATtiny2313(A), ATtiny4313**
* **ATtiny24(A), ATtiny44(A), ATtiny84(A)**
* **ATtiny441, ATtiny841**
* **ATtiny25, ATtiny45**, **ATtiny85**
* **ATtiny261(A), ATtiny461(A), ATtiny861(A)**
* **ATtiny87, ATtiny167**
* **ATtiny828**
* **ATtiny48, ATtiny88**
* **ATtiny1634**

#### ATmegas (covered by MiniCore):

* <s>__ATmega48__</s>, __ATmega48A__, __ATmega48PA__, ATmega48PB, 
* <s>__ATmega88__</s>, __ATmega88A__, __ATmega88PA__, Atmega88PB, 
* __ATmega168__, __ATmega168A__, __ATmega168PA__, ATmega168PB, 
* **ATmega328**, __ATmega328P__, **ATmega328PB**

ATmega48 and ATmega88 (without the A-suffix) suffer from stuck-at-one bits in the program counter and are therefore not debuggable by GDB. 

#### Other ATmegas:

* ATmega8U2, ATmega16U2, ATmega32U2
* ATmega32C1, ATmega64C1, ATmega16M1, ATmega32M1, ATmega64M1, ATmegaHVE2
* AT90USB82, AT90USB162
* AT90PWM1, AT90PWM2B, AT90PWM3B
* AT90PWM81, AT90PWM161
* AT90PWM216, AT90PWM316
* ATmega8HVA, ATmega16HVA, ATmega16HVB, ATmega32HVA, ATmega32HVB, ATmega64HVE2

### Notes for Linux systems

The following text is copied verbatim from the README of pyedbglib.

HIDAPI needs to build using packages: libusb-1.0.0-dev, libudev-dev

USB devices need udev rules to be added to a file in /etc/udev/rules.d

Example of udev rules for supported debuggers:

```bash
# HIDAPI/libusb:

# JTAGICE3
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2140", MODE="0666"
# Atmel-ICE
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2141", MODE="0666"
# Power Debugger
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2144", MODE="0666"
# EDBG - debugger on Xplained Pro
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2111", MODE="0666"
# EDBG - debugger on Xplained Pro (MSD mode)
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2169", MODE="0666"
# mEDBG - debugger on Xplained Mini
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2145", MODE="0666"
# PKOB nano (nEDBG) - debugger on Curiosity Nano
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2175", MODE="0666"
# PKOB nano (nEDBG) in DFU mode - bootloader of debugger on Curiosity Nano
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2fc0", MODE="0666"
# MPLAB PICkit 4 In-Circuit Debugger
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2177", MODE="0666"
# MPLAB Snap In-Circuit Debugger
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2180", MODE="0666"
```

pyedbglib also provides helper functions for accessing serial ports.  The user has to be part of the 'dialout' group to allow this.  This can be done by executing:
```bash
sudo adduser $USER dialout
```

It may also be necessary to grant read+write permission to the port, for example:
```bash
sudo chmod a+rw /dev/ttyACM0
```
