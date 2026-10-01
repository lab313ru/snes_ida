# snes_ida
SNES Carts Loader + IDA Pro new 65816 proc module

# Description

These proc/ldr should make your reverse-engineering process of SNES games much easier. For now it's still in early beta state, but works somehow.
Please feel free to create issues regarding any problems.

# Installation

IDA 9.3 required (the modules are built with the IDA 9.3 SDK).

Put the loader into IDA's `loaders` folder and the processor module into `procs` (or into `~/.idapro/loaders` and `~/.idapro/procs`).
IDA's stock `m65816`/`snes` modules no longer need to be renamed: the processor module is registered as `snes816`,
and in the load dialog the loader is listed as `SNES ROM (snes_ida)`.

Databases created with older builds (processor name `m65816`) still open with this module.

Linux: `make IDA_SDK=/path/to/ida-sdk/src && make install` (installs into `~/.idapro`, together with the Mesen CDL plugin from `ida_plugins`).

# References to data (DB / D)

Operands are turned into references automatically only when the accessed address is certain:

* long addresses (`LDA.L $7E1234`, `STA.L $004200`) - always;
* `abs`, `abs,X`, `abs,Y` - when the data bank (DB) of the instruction is known;
* direct page modes (`$12`, `($12),Y`, `[$12]`...) - when the direct page register (D) is known.

Otherwise the operand stays a number (press `O` & co. to choose the bank yourself).

The same holds for the targets of `JMP`/`JSR abs` and `JMP`/`JSR (abs,X)`, which use the program bank (PB): code in a
mirrored area runs from several banks (HiROM `$C0:D257` also runs as `$80:D257`, where `JSR $00CF` calls WRAM
`$7E:00CF`, not `$C0:00CF`). The target is referenced when PB is known, or when every bank the code can run from gives
the same target; otherwise it stays a number.
Hovering an instruction shows a hint: what the instruction does, the memory it accesses (bytes read / written, as
set by M / X, pointer size for indirect modes, stack traffic), register sizes (a8/a16, i8/i16), the DB / D value and where it
comes from (derived from the code, Mesen CDL, set manually), the value loaded by `PLB` / `PLD` / `TCD`, and the hotkey
to change it. The same information can be shown as short listing comments (`DB=$7E [Shift+X]`, `D=? [Shift+X]`,
`a16 [Shift+X]`...): Options -> Processor options -> "Show register info as comments".

Where DB / D come from (strongest first):

1. `Shift+X` - on an instruction whose immediate operand depends on M/X it switches the operand size; on any other
   instruction it opens a dialog with the register its operand depends on (DB for abs operands, D for direct page
   operands, PB for JMP/JSR targets, all of them for other instructions and for a selection); an empty field clears
   the manual value.
   The value is used from there on along the code, until the register changes.
   For a single instruction the dialog also has the M and X flags: a changed flag is set manually there (the code after
   it is decoded again with the new operand sizes), both fields empty make the instruction inherit them from the code
   flow again. This fixes code entered with other flags than the flow before it suggests, e.g. a `JSL` target right
   after a `SEP #$20` that is never executed.
2. The Mesen CDL plugin (`ida_plugins/mesen_cdl.py`) - values the instruction always had while the game ran.
3. Static analysis - after the auto-analysis the module follows every function and derives DB / D where the code sets
   them unambiguously: `PHK/PLB`, `LDA #imm/PHA/PLB`, `PEA/PLB/PLB`, `LDA #imm/TCD`, `PEA/PLD`, `PHB...PLB`,
   `PHD...PLD`, `TDC`, `MVN/MVP`, calls to functions that preserve or set DB / D, and DB=$00, D=$0000 in the reset handler.
   PB doesn't change inside a function; interrupt / reset handlers run in bank $00.
   A value is derived only when it is the same on every known path; the value a function is entered with is unknown.

# 24-bit values in data

`D` cycles through byte -> word -> 24-bit value (the module sets the data carousel to byte, word and tbyte when it is
still at IDA's default, and turns every 3-byte tbyte created as data into `d24`). `3` on a byte creates one too,
`*` makes a table of them.

On unexplored bytes `Q` creates a 24-bit number and `O` a 24-bit offset right away (instead of IDA's 4-byte `dl`
offset); elsewhere both keys work as usual.

A 24-bit value is a number by default (`d24 $7E0210`). `O` makes it an offset: the value is shown as the name of its
target and gets a data reference (`d24 unk_7E0210`); `O` again makes it a number. Mirrors are resolved
(`$808000` -> `$008000`, `$000210` -> `$7E0210`); values pointing to unmapped memory stay numbers.

In structures (Local Types) declare such a field with the `data24_t` type (added to Local Types by the module):

    struct s1 { data24_t ptr; };

The field is a number (`s1 <$7E0210>`); `O` on it in an instance makes it an offset in the structure, i.e. in all
its instances (`s1 <unk_7E0210>`, with references). In Local Types it reads `data24_t ptr __custom(d24,offset);` (`d24` is the listing directive, `number` / `offset` the representation),
which can also be written directly. (`data24_t` is `typedef _TBYTE`: `_TBYTE` is 3 bytes for this processor, and IDA
has no other 3-byte scalar type a field could be based on.)

# Searching for an immediate value

`Alt+I` / `Ctrl+I` (search for an immediate value, next occurrence) are replaced by the module: IDA's own search
compares only instruction operands and standard data items (byte, word, dword, qword), so a pointer stored in 3 bytes
is never found. The module's search merges IDA's results with every 3 bytes that form the value (little endian),
whatever is defined there: `d24`, bytes of a table, unexplored bytes, the operand of an instruction (reported as
the instruction). Mirrors are searched too: looking for `$008327` also finds `27 83 80` when `$80:8327` is the same
memory. The dialog has "Search Up" and "Find all occurrences" (a list of the matches); `Ctrl+I` repeats the last search
from the cursor.

Being a byte search, it also finds random matches in graphics, text and other data.

# Creating code after undefining it

`U` on code makes IDA mark the address as "not code", and the auto-analysis never creates code there again: `C` on
code before such an address used to stop right at it, while `P` (a function) went on. `C` now follows the code it
creates through such addresses (fall-through and relative branches) and clears the mark there. The auto-analysis
itself still respects it.

# M/X flags: automatic correction

When BRK / COP / WDM are marked as unused in the processor options and the code flow runs into one of them, a previous
immediate operand that depends on M or X was decoded with the wrong size (e.g. with M=0 `A9 01 8D 00 43` is
`LDA #$8D01` followed by BRK, with M=1 it is `LDA #$01` / `STA $4300`).

After the auto-analysis the module follows the flow back to the place the flags were only inherited at (function
entry, join of several paths, after a call / `PLP` / `XCE`), and switches M, X or both there when this makes the code
decode without unused opcodes. Flags set by `SEP` / `REP` or manually are never changed. The corrected flag is stored
as a manual one (`Shift+X` changes it back) and the Output window tells what was changed and why:

    8251: the code flow reached $00 at 8263, which the ROM doesn't use: M=1 (a8) set at 8251 (Shift+X to change)

# Hotkeys for offsets

| Hotkey | Description |
| - | - |
| O | Change bank to current; on a `d24` value: offset <-> number; on unexplored bytes: a `d24` offset |
| Ctrl+O | Change bank to selected |
| Shift+O | Change bank to WRAM |
| Ctrl+Shift+O | Change bank to ZERO |
| Ctrl+Alt+O | Change bank to custom |
| Q | On unexplored bytes: a `d24` number |

# TODO

Name Registers.
Demo of work with proc/ldr.
