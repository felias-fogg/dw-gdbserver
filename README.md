# dw-gdbserver

This Python script acts as a GDB server for debugWIRE MCUs over TCP/IP. It interfaces with the dw-link hardware debugger by providing a serial to TCP/IP bridge. It can also communicate with Microchip EDBG debuggers such as Atmel-ICE, Snap (in AVR mode), Pickit4 (in AVR mode), etc. In the latter cases, it uses the infrastructure provided by [pymcuprog](https://github.com/microchip-pic-avr-tools/pymcuprog) and [pyedgblib](https://github.com/microchip-pic-avr-tools/pyedbglib) to implement a full-blown GDB server. 



It is currently a work in progress, but the script is actually already doing something useful.
