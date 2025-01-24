# dw-gdbserver

This Python script acts as a GDB server for debugWIRE MCUs over TCP/IP. It interfaces with dw-link by providing a serial to TCP/IP bridge. It can also communicate with Microchip EDBG debuggers such as Atmel-ICE, Snap, Pickit4, and others. In the latter cases, it uses the infrastructure provided by [pymcuprog](https://github.com/microchip-pic-avr-tools/pymcuprog) and [pyedgblib](https://github.com/microchip-pic-avr-tools/pyedbglib) implementing a full-blown GDB server. 



The current state is that it is a work in progress and does not do anything useful, but this will hopefully change very soon. 

