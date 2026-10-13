# mesen_cdl.py — Mesen CDL for IDA Pro 9.x

Applies CDL files written by MesenCE with the 65816 extension (execution contexts, register
snapshots and runtime cross references) to an IDA database, and lets you browse the recorded
register values.

Works with this repository's processor module (`m65816` from `snesproc`) and with IDA's stock
`m65816` module.

## Getting the CDL file

1. Build MesenCE with the CDL extension (`Core/SNES/Debugger/SnesCdlExtension.*`).
2. Open any debugger window (Debugger, Trace Logger, Script Window, ...) and play the game:
   code/data logging and the 65816 extension only run while the debugger is active.
3. Closing the debugger (or the debugger's CDL menu -> Save) writes `<rom>.cdl` to Mesen's
   `Debugger` folder. The data accumulates across sessions; `Reset CDL` clears everything.

The first part of the file is a regular Mesen CDL, so Mesen and other CDL tools keep working with it.

## Installing

Copy `mesen_cdl.py` to `~/.idapro/plugins/` (or `<IDA>/plugins/`), or run `make install` from the
repository root, which also installs the Linux builds of the processor module and loader.

## Usage

`Edit -> Plugins -> Mesen CDL -> Apply Mesen CDL...`

| Option | What it does |
| --- | --- |
| Create code and set M/X flags | Creates an instruction at every executed address with the M/X flags it ran with (snes_ida: netnode tags `P` + manual `O`; stock module: `m`/`x`/`e` segment registers) |
| Set data bank / direct page | snes_ida: sets the operand bank (`B` tag, like the `O` hotkey) for abs/abs,X/abs,Y when DB was always the same; stock module: `B`/`D`/`PB` segment registers (most frequent value) |
| Create functions | At JSR/JSL/interrupt targets |
| Data xrefs | Every data read/write done by an instruction, including indirect and indexed ones |
| Code xrefs | Jumps and calls actually taken, including `JMP (abs,X)`, `JML [abs]`, `JSR (abs,X)` |
| DMA | Source of every general purpose DMA, attributed to the instruction that wrote `$420B`, with a comment at the source |
| Comment varying context | `Mesen: MX ...; DB ...; D ...` on instructions that ran with different flags/banks (only when that matters for the instruction) |
| Merge gap | Accesses of one instruction closer than N bytes are merged into one xref (decompressors reading a stream byte by byte would otherwise create thousands of xrefs) |

All xrefs are created as user xrefs, so reanalysis does not remove them.

### Register snapshots

For every instruction MesenCE keeps up to 16 distinct register states (A, X, Y, S, D, DB, PB, P, E),
with the frame number, hit count, a global sequence number (execution order) and the address of the
instruction that ran next.

| Hotkey | Action |
| --- | --- |
| `Ctrl+Alt+M` | Snapshot window for the instruction under the cursor (follows the cursor) |
| `Ctrl+Alt+Right` / `Ctrl+Alt+Left` | Next / previous recorded instruction in execution order |
| `Ctrl+Alt+Down` / `Ctrl+Alt+Up` | Next / previous snapshot of the current instruction |
| `Ctrl+Alt+Enter` (or double click) | Go to the instruction executed after the selected snapshot |

Hovering an instruction in the disassembly shows its contexts and first snapshots. Stepping prints
the registers to the Output window.

Because only the first 16 distinct states per instruction are kept, the execution order is complete
for the first executions of each instruction and has gaps inside long loops; `Ctrl+Alt+Right` then
jumps to the next recorded state (the sequence number shows how many instructions were skipped).

### Command line

`python3 mesen_cdl.py game.cdl` prints a summary of the file (no IDA needed).
