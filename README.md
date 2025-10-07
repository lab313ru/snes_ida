# snes_ida
SNES Carts Loader + IDA Pro new 65816 proc module

# Description

These proc/ldr should make your reverse-engineering process of SNES games much eaises. For now it's still in early beta state, but works somehow.
Please fill free to create issues regarding any problems.

# Installation

IDA 9.2 Required.

1. Rename IDA's original `/procs/m65816.dll` into `/procs/m65816_dll`
2. Rename IDA's original `/loaders/snes.dll` into `/loaders/snes_dll`
3. Put the loader into IDA's `/loaders`, and the proc module into `/procs` folder

# TODO

Name Registers.
Demo of work with proc/ldr.
