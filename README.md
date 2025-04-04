# dw-gdbserver

### What is it good for?

This Python script acts as a [gdbserver](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Server.html#Server) for [*debugWIRE*](https://debugwire.de) MCUs, such as the ATmega328P.  It can communicate with Microchip debuggers such as [Atmel-ICE](https://www.microchip.com/en-us/development-tool/atatmel-ice) and [MPLAB SNAP](https://www.microchip.com/en-us/development-tool/pg164100) (in AVR mode), and it provides a pass-through service for the DIY hardware debugger [dw-link](https://github.com/felias-fogg/dw-link). For Microchip debuggers, it uses the infrastructure provided by [pymcuprog](https://github.com/microchip-pic-avr-tools/pymcuprog) and [pyedgblib](https://github.com/microchip-pic-avr-tools/pyedbglib) to implement a full-blown gdbserver.

By the way, switching to AVR mode in the SNAP debugger is easily accomplished by using avrdude (>= Version 7.3):

```
> avrdude -c snap_isp -Pusb -xmode=avr
```

With PICkit4 it is similar. When you repeat this command, and you get the message again that the debugger is in 'PIC' mode, you need to flash new firmware first using MPLAB X.

### Installation

If things do not go as smoothly after the installation as promised here, consult the hints [at the end of this document](#eod). For Linux, some permissions need to be granted. Under macOS, you may need to install an additional library.

##### Pypi installation

Install the script with [pipx](https://pipx.pypa.io/stable/installation/) like this. After that, you can execute the script as if it were an executable installed in your account (see below).

```
> pipx install dwgdbserver
```

After that, you can invoke the gdbserver by simply typing `dw-gdbserver` (or `dw-gdbserver.exe`) into a shell.

##### GitHub installation

Alternatively, you can download/clone the GitHub repository. You need then to install the package poetry:

```
> pipx install poetry
```

With that, you can start executing the script inside the downloaded folder as follows:

```
> poetry install
> poetry run dw-gdbserver ...
```

Furthermore, you can create a binary standalone package as follows:

```
> poetry run pyinstaller dw-gdbserver.spec
```

After that, you find an executable `dw-gdbserver` (or `dw-gdbserver.exe`) in the directory `dist/dw-gdbserver/dw-gdbserver/` together with the folder `dw-gdbserver-util`. You can copy those to a place in your `PATH`.

### Usage

If your target board is an Arduino board, you [must modify it by disconnecting the capacitor responsible for the auto-reset feature](https://debugwire.de/board-modifications/).

Once you have connected an appropriate hardware debugger to your target board, you can start the  gdbserver in a terminal window:

```
> dw-gdbserver -d atmega328p
[INFO] Connecting to anything possible
[INFO] Connected to Atmel-ICE CMSIS-DAP
[INFO] Starting dw-gdbserver
[INFO] Looking for device atmega328p
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
(gdb) monitor debugwire enable
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

### Command line options

| Optionname           | Description                                                   |
| -------------------- | ------------------------------------------------------------ |
| `--device` <br>`-d`  | The argument to this option specifies the MCU type of the target chip in lower case.  This option is mandatory. If a '?' mark is given, all supported MCUs are listed. |
| `--gede`<br>`-g`     | No argument for this option. This option will start the `Gede` debugger GUI. |
| `--port` <br>`-p`    | IP port on the local host to which GDB can connect.          |
| `--start` <br>`-s`   | Program to start or the string `noop`, when no program should be started |
| `--tool`<br>`-t`     | Specifying the debug tool. Possible values are `atmelice`, `edbg`, `jtagice3`, `medbg`, `nedbg`, `pickit4`, `powerdebugger`, `snap`, `dwlink`. Use of this option is necessary only if more than one debugging tool is connected to the computer. |
| `--usbsn` <br>`-u`   | USB serial number of the tool. This is only necessary if one has multiple debugging tools connected to the computer. |
| `--verbose` <br>`-v` | Specify verbosity level. Possible values are `debug`, `info`, `warning`, `error`, or `critical`. The default is `info`. |
| `--version` <br>`-V` | Print dw-gdbserver version number and exit.                  |



### How to get into and out of debugWIRE mode

When the MCU is not already in debugWIRE mode,  you must request the switch to debugWIRE mode using the command `monitor debugwire enable` in GDB. The debugger will then enable the DWEN fuse and either power-cycles the target by itself (if possible) or ask you to power-cycle the target system. Once this is done, the chip will stay in debugWIRE mode, even after terminating the debugging session. In other words, when starting the next debug session, the MCU is already in debugWIRE mode. You can switch back to normal mode using the command `monitor debugwire disable` before leaving the debugger.

### Monitor commands

In addition to the above mentioned command for enabling debugWIRE mode, there are a few other `monitor` commands.

| Command                                               | Action                                                       |
| ----------------------------------------------------- | ------------------------------------------------------------ |
| `monitor breakpoints` [`all`\|`software`\|`hardware`] | Restricts the kind of breakpoints the hardware debugger can use. Either *all* types are permitted, only *software* breakpoints are allowed, or only *hardware* breakpoints can be used. Using all kinds is the default. |
| `monitor caching` [`enable`\|`disable`]               | The loaded executable is used as a cache in the gdbserver when *enabled*, which is the default. |
| `monitor debugwire` [`enable`\|`disable`]             | DebugWIRE mode will be enabled or disabled. When enabling it, you may be asked to power-cycle the target. After disabling debugWIRE mode, the MCU can be programmed again using ISP programming. |
| `monitor help`                                        | Display help text.                                           |
| `monitor info`                                        | Display information about the target and the state of the debugger. |
| `monitor load` [`readbeforewrite`\|`writeonly`]       | When loading an executable, either each flash page is compared with the content to be loaded, and flashing is skipped if the content is already there, or each flash page is written without reading the current contents beforehand. The first option is the default option and there is no reason to change it. |
| `monitor onlyloaded` [`enable`\|`disable`]            | Execution is only possible when a `load` command was previously executed, which is the default. If you want to start execution without previously loading an executable, you need to disable this mode. |
| `monitor rangestepping `[`enable`\|`disable`]         | The GDB range-stepping command is supported or disabled.     |
| `monitor reset`                                       | Resets the MCU.                                              |
| `monitor singlestep` [`safe`\|`interruptible`]        | Single-stepping can either be performed in a *safe* way, where single steps are shielded against interrupts or in the default way, where a single step can lead to a jump into the interrupt dispatch table. The *safe* option is the default. |
| `monitor timer` [`freeze`\|`run`]                     | Timers can either be *frozen* when execution is stopped, or they can *run* freely. The later option is helpful when PWM output is crucial. |
| `monitor verify` [`enable`\|`disable`]                | Verify flash after loading each flash page. The cost for verifying is negligible, and doing so might diagnose flash wear problems. The default is that this option is *enabled*. |
| `monitor version`                                     | Show version of the gdbserver.                               |

The default setting is always the first one listed, except for `debugwire`, which depends on the MCU itself. All commands can, as usual, be abbreviated. For example, `mo d e` is equivalent to `monitor debugwire enable`.

### List of supported and tested hardware debuggers

Except for [dw-link](https://github.com/felias-fogg/dw-link), this list is copied from the readme file of [pyedbglib](https://github.com/microchip-pic-avr-tools/pyedbglib). Boldface means that the debuggers have been tested by me and work with this Python script.


* **MPLAB PICkit 4 In-Circuit Debugger** (when in 'AVR mode')
* **MPLAB Snap In-Circuit Debugger** (when in 'AVR mode')
* **Atmel-ICE**
* **Atmel Power Debugger**
* **mEDBG - on-board debugger on Xplained Mini/Nano**
* JTAGICE3 (firmware version 3.0 or newer)
* **[dw-link](https://github.com/felias-fogg/dw-link)** - **DIY debugWIRE debugger running on an Arduino UNO R3**


### List of supported and tested MCUs

This is the list of all debugWIRE MCUs, which should all be compatible with dw-gdbserver. MCUs tested with this Python script are marked bold. MCUs known not to work with the script are struck out. For the list of MCUs compatible with dw-link, you need to consult the [dw-link manual](https://github.com/felias-fogg/dw-link/blob/master/docs/manual.md).

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

The ATmega48 and ATmega88 (without the A-suffix) sitting on my desk suffer from stuck-at-one bits in the program counter and are, therefore, not debuggable by GDB. I suspect that this applies to all chips labeled this way. In any case, the test for stuck-at-one-bits is made when connecting to the chips.

#### Other ATmegas:

* ATmega8U2, ATmega16U2, ATmega32U2
* ATmega32C1, ATmega64C1, ATmega16M1, ATmega32M1, ATmega64M1, ATmegaHVE2
* AT90USB82, AT90USB162
* AT90PWM1, AT90PWM2B, AT90PWM3B
* AT90PWM81, AT90PWM161
* AT90PWM216, AT90PWM316
* ATmega8HVA, ATmega16HVA, ATmega16HVB, ATmega32HVA, ATmega32HVB, ATmega64HVE2

<a name=eod></a>

### Notes for macOS

If, after the installation, you get the error **usb.core.NoBackendError: No backend available** under macOS, you need to install libusb:

```
> brew install libusb
```

If the error persists, here are a few other potential cures: https://github.com/greatscottgadgets/cynthion/issues/136

### Notes for Linux systems

The following text is copied verbatim from the README of pyedbglib.

HIDAPI needs to build using packages: libusb-1.0.0-dev, libudev-dev

USB devices need udev rules to be added to a file in /etc/udev/rules.d Example of udev rules for supported debuggers:

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

### What the future has in store for us

The script has all the basic functionality but still needs some polishing.

I also plan to provide binaries, which can be used as tools for the Arduino IDE 2. And if it all works, it is only a "tiny" step to generalize it to the JTAG and UPDI AVR MCUs. So, stay tuned.
