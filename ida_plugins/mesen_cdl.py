"""
Mesen CDL loader for IDA Pro 9.x (SNES / 65816)

Applies a CDL file produced by MesenCE (with the 65816 extension) to the current database:
  * creates code at every executed instruction and sets the M/X flags it was executed with
  * sets the data bank / direct page when they are known (and unique) for an instruction
  * creates functions at subroutine entry points (JSR/JSL/interrupt targets)
  * adds runtime cross references: data reads/writes, jumps/calls (incl. indirect ones), DMA sources
And lets you browse the register snapshots recorded for every instruction, and step through them
in execution order.

Works with both the snes_ida processor module (netnode "$ 65816", tags 'P'/'O'/'B')
and IDA's stock m65816 module (segment registers m/x/e/B/D/PB).

Install: copy this file into <IDA>/plugins or ~/.idapro/plugins.
Menu: Edit -> Plugins -> Mesen CDL
Hotkeys (default):
  Ctrl+Alt+M          open the register snapshot view for the instruction under the cursor
  Ctrl+Alt+Right/Left step to the next/previous recorded instruction in execution order
  Ctrl+Alt+Down/Up    next/previous snapshot for the current instruction
  Ctrl+Alt+Enter      follow the selected snapshot to the instruction that was executed next

The parser part of the module (CdlFile) works without IDA:  python mesen_cdl.py file.cdl
"""

import os
import struct
import bisect
import zlib

try:
    import ida_idaapi
    import ida_kernwin
    import ida_bytes
    import ida_ua
    import ida_funcs
    import ida_xref
    import ida_loader
    import ida_netnode
    import ida_segregs
    import ida_idp
    import ida_auto
    import ida_nalt
    IN_IDA = True
except ImportError:
    IN_IDA = False

# ---------------------------------------------------------------------------
# File format
# ---------------------------------------------------------------------------

EXT_MAGIC = b"MSNXCDL1"

LOC_CPUBUS, LOC_PRGROM, LOC_WRAM, LOC_SRAM, LOC_REG, LOC_SA1IRAM = range(6)
LOC_NAMES = {LOC_CPUBUS: "bus", LOC_PRGROM: "rom", LOC_WRAM: "wram", LOC_SRAM: "sram",
             LOC_REG: "reg", LOC_SA1IRAM: "iram"}

XREF_READ, XREF_WRITE, XREF_JUMP, XREF_CALL, XREF_DMA = 1, 2, 3, 4, 5
XREF_NAMES = {XREF_READ: "read", XREF_WRITE: "write", XREF_JUMP: "jump", XREF_CALL: "call", XREF_DMA: "dma"}

CDL_CODE, CDL_DATA, CDL_JUMP_TARGET, CDL_SUB_ENTRY = 0x01, 0x02, 0x04, 0x08
CDL_X8, CDL_M8 = 0x10, 0x20

NO_ADDR = 0xFFFFFFFF


def loc_type(loc):
    return loc >> 28


def loc_addr(loc):
    return loc & 0xFFFFFF


def fmt_loc(loc, cpu_addr=None):
    if loc == NO_ADDR:
        return "?"
    t = loc_type(loc)
    s = "%s:%06X" % (LOC_NAMES.get(t, "?%d" % t), loc_addr(loc))
    if cpu_addr is not None and t != LOC_CPUBUS:
        s += " ($%06X)" % (cpu_addr & 0xFFFFFF)
    return s


def fmt_p(p, e):
    flags = "NVMXDIZC" if not e else "NV1BDIZC"
    return "".join(ch if p & (0x80 >> i) else ch.lower() for i, ch in enumerate(flags))


class Context(object):
    __slots__ = ("loc", "cpu_addr", "cpu", "D", "DB", "P", "E", "hits")

    def __init__(self, loc, cpu_addr, D, DB, P, E, hits):
        self.loc = loc
        self.cpu_addr = cpu_addr & 0xFFFFFF
        self.cpu = cpu_addr >> 24
        self.D, self.DB, self.P, self.E, self.hits = D, DB, P, E, hits

    @property
    def mx(self):
        return 0x30 if self.E else (self.P & 0x30)


class Snapshot(object):
    __slots__ = ("loc", "cpu_addr", "cpu", "A", "X", "Y", "S", "D", "DB", "PB", "P", "E",
                 "frame", "hits", "seq", "next_cpu", "next_loc")

    def __init__(self, rec):
        (self.loc, cpu_addr, self.A, self.X, self.Y, self.S, self.D, self.DB, self.PB, self.P, self.E,
         self.frame, self.hits, self.seq, self.next_cpu, self.next_loc) = rec
        self.cpu_addr = cpu_addr & 0xFFFFFF
        self.cpu = cpu_addr >> 24

    def regs_str(self):
        if self.E or self.P & 0x20:
            a = "%02X [B=%02X]" % (self.A & 0xFF, self.A >> 8)
        else:
            a = "%04X" % self.A
        xw = "%02X" if (self.E or self.P & 0x10) else "%04X"
        return "A=%s X=%s Y=%s S=%04X D=%04X DB=%02X PB=%02X P=%02X(%s) E=%d" % (
            a, xw % self.X, xw % self.Y, self.S, self.D, self.DB, self.PB, self.P, fmt_p(self.P, self.E), self.E)


class Xref(object):
    __slots__ = ("from_loc", "from_cpu", "cpu", "to_loc", "to_cpu", "length", "hits", "type")

    def __init__(self, rec):
        self.from_loc, from_cpu, self.to_loc, self.to_cpu, self.length, self.hits, self.type = rec
        self.from_cpu = from_cpu & 0xFFFFFF
        self.cpu = from_cpu >> 24


class CdlFile(object):
    """Parses a Mesen CDL file (CDLv2 header + CDL bytes + optional 65816 extension)."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            data = f.read()

        self.crc = None
        start = 0
        if data[:5] == b"CDLv2":
            self.crc = struct.unpack_from("<I", data, 5)[0]
            start = 9

        ext_pos = data.find(EXT_MAGIC, start)
        self.flags = data[start:ext_pos] if ext_pos >= 0 else data[start:]

        self.contexts = []
        self.snapshots = []
        self.xrefs = []
        self.max_snapshots = 0
        self.next_seq = 0
        self.has_extension = ext_pos >= 0
        if self.has_extension:
            self._parse_extension(data, ext_pos)

        # indexes
        self.snapshots.sort(key=lambda s: s.seq)
        self.seqs = [s.seq for s in self.snapshots]
        self.snaps_by_loc = {}
        for s in self.snapshots:
            self.snaps_by_loc.setdefault((s.cpu, s.loc), []).append(s)
        self.ctx_by_loc = {}
        for c in self.contexts:
            self.ctx_by_loc.setdefault((c.cpu, c.loc), []).append(c)

    def _parse_extension(self, data, pos):
        version, count = struct.unpack_from("<II", data, pos + 8)
        if version != 1:
            raise ValueError("Unsupported CDL extension version %d" % version)
        pos += 16
        for _ in range(count):
            if pos + 8 > len(data):
                break
            tag = data[pos:pos + 4]
            size = struct.unpack_from("<I", data, pos + 4)[0]
            body = data[pos + 8:pos + 8 + size]
            pos += 8 + size
            if tag == b"INFO":
                self.max_snapshots, _, self.next_seq = struct.unpack_from("<IIQ", body)
            elif tag == b"CTX ":
                n = struct.unpack_from("<I", body)[0]
                for loc, cpu, d, db, p, e, hits in struct.iter_unpack("<IIHBBB3xI", body[4:4 + n * 20]):
                    self.contexts.append(Context(loc, cpu, d, db, p, e, hits))
            elif tag == b"SNAP":
                n = struct.unpack_from("<I", body)[0]
                for rec in struct.iter_unpack("<IIHHHHHBBBB2xIIQII", body[4:4 + n * 48]):
                    self.snapshots.append(Snapshot(rec))
            elif tag == b"XREF":
                n = struct.unpack_from("<I", body)[0]
                for rec in struct.iter_unpack("<IIIIIIB3x", body[4:4 + n * 28]):
                    self.xrefs.append(Xref(rec))

    def merged_xrefs(self, max_gap):
        """Xref ranges of the same instruction/type that are at most max_gap bytes apart are merged.
        Yields (Xref of the first range, total length, total hits)."""
        groups = {}
        for x in self.xrefs:
            groups.setdefault((x.cpu, x.from_loc, x.type, loc_type(x.to_loc)), []).append(x)
        for key, xs in groups.items():
            xs.sort(key=lambda x: x.to_loc)
            first, end, hits = xs[0], xs[0].to_loc + xs[0].length, xs[0].hits
            for x in xs[1:]:
                if x.to_loc - end <= max_gap and x.type != XREF_JUMP and x.type != XREF_CALL:
                    end = max(end, x.to_loc + x.length)
                    hits += x.hits
                else:
                    yield first, end - first.to_loc, hits
                    first, end, hits = x, x.to_loc + x.length, x.hits
            yield first, end - first.to_loc, hits

    # --- snapshot navigation ---
    def snapshot_after(self, seq):
        i = bisect.bisect_right(self.seqs, seq)
        return self.snapshots[i] if i < len(self.snapshots) else None

    def snapshot_before(self, seq):
        i = bisect.bisect_left(self.seqs, seq)
        return self.snapshots[i - 1] if i > 0 else None

    def instruction_starts(self):
        """ROM offsets of executed instructions (main CPU + SA-1) -> list of contexts."""
        starts = {}
        for (cpu, loc), ctxs in self.ctx_by_loc.items():
            if loc_type(loc) == LOC_PRGROM:
                starts.setdefault(loc_addr(loc), []).extend(ctxs)
        if not starts:
            # Plain CDL file: walk the code bytes like Mesen does
            i, n = 0, len(self.flags)
            while i < n:
                f = self.flags[i]
                if f & CDL_CODE and not f & 0xC0:  # skip GSU/CX4 code
                    starts[i] = [Context((LOC_PRGROM << 28) | i, 0, 0, 0, f & 0x30, 0, 0)]
                    i += max(1, op_size(ROM_READER(i), f & 0x30)) if ROM_READER else 1
                else:
                    i += 1
        return starts


# 65816 instruction sizes (for M=1/X=1), +1 for immediate operands in 16-bit mode
_OP_SIZE = [
    2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 1, 1, 3, 3, 3, 4,  # 0
    2, 2, 2, 2, 2, 2, 2, 2, 1, 3, 1, 1, 3, 3, 3, 4,  # 1
    3, 2, 4, 2, 2, 2, 2, 2, 1, 2, 1, 1, 3, 3, 3, 4,  # 2
    2, 2, 2, 2, 2, 2, 2, 2, 1, 3, 1, 1, 3, 3, 3, 4,  # 3
    1, 2, 2, 2, 3, 2, 2, 2, 1, 2, 1, 1, 3, 3, 3, 4,  # 4
    2, 2, 2, 2, 3, 2, 2, 2, 1, 3, 1, 1, 4, 3, 3, 4,  # 5
    1, 2, 3, 2, 2, 2, 2, 2, 1, 2, 1, 1, 3, 3, 3, 4,  # 6
    2, 2, 2, 2, 2, 2, 2, 2, 1, 3, 1, 1, 3, 3, 3, 4,  # 7
    2, 2, 3, 2, 2, 2, 2, 2, 1, 2, 1, 1, 3, 3, 3, 4,  # 8
    2, 2, 2, 2, 2, 2, 2, 2, 1, 3, 1, 1, 3, 3, 3, 4,  # 9
    2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 1, 1, 3, 3, 3, 4,  # A
    2, 2, 2, 2, 2, 2, 2, 2, 1, 3, 1, 1, 3, 3, 3, 4,  # B
    2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 1, 1, 3, 3, 3, 4,  # C
    2, 2, 2, 2, 2, 2, 2, 2, 1, 3, 1, 1, 3, 3, 3, 4,  # D
    2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 1, 1, 3, 3, 3, 4,  # E
    2, 2, 2, 2, 3, 2, 2, 2, 1, 3, 1, 1, 3, 3, 3, 4,  # F
]
_IMM_M = {0x09, 0x29, 0x49, 0x69, 0x89, 0xA9, 0xC9, 0xE9}
_IMM_X = {0xA0, 0xA2, 0xC0, 0xE0}

# Opcodes whose 16-bit operand is relative to the data bank register
DB_RELATIVE_OPS = {
    0x0C, 0x0D, 0x0E, 0x1C, 0x2C, 0x2D, 0x2E, 0x4D, 0x4E, 0x6D, 0x6E, 0x8C, 0x8D, 0x8E, 0x9C,
    0xAC, 0xAD, 0xAE, 0xCC, 0xCD, 0xCE, 0xEC, 0xED, 0xEE,  # abs
    0x1D, 0x1E, 0x3C, 0x3D, 0x3E, 0x5D, 0x5E, 0x7D, 0x7E, 0x9D, 0x9E, 0xBC, 0xBD, 0xDD, 0xDE, 0xFD, 0xFE,  # abs,X
    0x19, 0x39, 0x59, 0x79, 0x99, 0xB9, 0xBE, 0xD9, 0xF9,  # abs,Y
}

# Opcodes whose effective address depends on the data bank register (abs, abs,X/Y, (dp), (dp,X), (dp),Y, (sr,S),Y)
DB_USING_OPS = {
    0x01, 0x0C, 0x0D, 0x0E, 0x11, 0x12, 0x13, 0x19, 0x1C, 0x1D, 0x1E, 0x21, 0x2C, 0x2D, 0x2E, 0x31,
    0x32, 0x33, 0x39, 0x3C, 0x3D, 0x3E, 0x41, 0x4D, 0x4E, 0x51, 0x52, 0x53, 0x59, 0x5D, 0x5E, 0x61,
    0x6D, 0x6E, 0x71, 0x72, 0x73, 0x79, 0x7D, 0x7E, 0x81, 0x8C, 0x8D, 0x8E, 0x91, 0x92, 0x93, 0x99,
    0x9C, 0x9D, 0x9E, 0xA1, 0xAC, 0xAD, 0xAE, 0xB1, 0xB2, 0xB3, 0xB9, 0xBC, 0xBD, 0xBE, 0xC1, 0xCC,
    0xCD, 0xCE, 0xD1, 0xD2, 0xD3, 0xD9, 0xDD, 0xDE, 0xE1, 0xEC, 0xED, 0xEE, 0xF1, 0xF2, 0xF3, 0xF9,
    0xFD, 0xFE,
}

# Opcodes using the direct page register
DP_USING_OPS = {
    0x01, 0x04, 0x05, 0x06, 0x07, 0x11, 0x12, 0x14, 0x15, 0x16, 0x17, 0x21, 0x24, 0x25, 0x26, 0x27,
    0x31, 0x32, 0x34, 0x35, 0x36, 0x37, 0x41, 0x45, 0x46, 0x47, 0x51, 0x52, 0x55, 0x56, 0x57, 0x61,
    0x64, 0x65, 0x66, 0x67, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x81, 0x84, 0x85, 0x86, 0x87, 0x91,
    0x92, 0x94, 0x95, 0x96, 0x97, 0xA1, 0xA4, 0xA5, 0xA6, 0xA7, 0xB1, 0xB2, 0xB4, 0xB5, 0xB6, 0xB7,
    0xC1, 0xC4, 0xC5, 0xC6, 0xC7, 0xD1, 0xD2, 0xD4, 0xD5, 0xD6, 0xD7, 0xE1, 0xE4, 0xE5, 0xE6, 0xE7,
    0xF1, 0xF2, 0xF5, 0xF6, 0xF7,
}

ROM_READER = None  # set by the IDA part: callable(rom_offset) -> opcode


def op_size(opcode, mx):
    size = _OP_SIZE[opcode]
    if opcode in _IMM_M and not mx & 0x20:
        size += 1
    elif opcode in _IMM_X and not mx & 0x10:
        size += 1
    return size


def post_mx(opcode, operand, mx, e):
    """M/X flags after SEP/REP (the snes_ida module stores the post state on SEP/REP)."""
    if e:
        return 0x30
    if opcode == 0xE2:
        return mx | (operand & 0x30)
    if opcode == 0xC2:
        return mx & ~operand & 0x30
    return mx


# ---------------------------------------------------------------------------
# IDA part
# ---------------------------------------------------------------------------

if IN_IDA:
    PLUGIN_NAME = "Mesen CDL"
    NETNODE_NAME = "$ mesen_cdl"
    MENU_PATH = "Edit/Plugins/Mesen CDL/"

    BADADDR = ida_idaapi.BADADDR

    class ProcModule(object):
        """Abstraction over the snes_ida processor module and IDA's stock m65816 module."""

        def __init__(self):
            regs = [r for r in ida_idp.ph_get_regnames()]
            self.sregs = {}
            # snes_ida module: A X Y SP PC D DB P cs ds, stock module: A X Y S cs ds B D m x e PB
            self.snes_ida = "DB" in regs and "m" not in regs
            if not self.snes_ida:
                for name in ("m", "x", "e", "B", "D", "PB"):
                    if name in regs:
                        self.sregs[name] = regs.index(name)
                self.helper = None
            else:
                self.helper = ida_netnode.netnode("$ 65816", 0, True)

        @property
        def name(self):
            return "snes_ida" if self.snes_ida else ("stock m65816" if self.sregs else "unknown")

        def set_mx(self, ea, mx, e):
            if self.snes_ida:
                self.helper.charset_ea(ea, mx, 'P')
                self.helper.charset_ea(ea, 1, 'O')
            else:
                self._set_sreg(ea, "m", 1 if mx & 0x20 else 0)
                self._set_sreg(ea, "x", 1 if mx & 0x10 else 0)
                self._set_sreg(ea, "e", 1 if e else 0)

        # snes_ida: known DB/D values per instruction, (source << 24) | (value + 1), source 2 = Mesen CDL.
        # The module derives references from them and propagates them along the code; manual values win.
        KRS_CDL, KRS_MANUAL, KRS_CDL_SAME_TARGET = 2, 3, 4

        def _set_known(self, ea, tag, value, src):
            """src None: no CDL value (removes an old one)"""
            cur = self.helper.altval_ea(ea, tag)
            if cur and (cur >> 24) == self.KRS_MANUAL:
                return
            new = ((src << 24) | (value + 1)) if src is not None else 0
            if new == cur:
                return
            if new:
                self.helper.altset_ea(ea, new, tag)
            else:
                self.helper.altdel_ea(ea, tag)
            ida_auto.plan_ea(ea)  # references and propagation are updated by the module

        @staticmethod
        def data_target(bank, addr):
            """Same as get_data_target() in the processor module."""
            if (bank < 0x40 or 0x80 <= bank < 0xC0) and addr < 0x2000:
                ea = 0x7E0000 + addr
            else:
                ea = ida_bytes.use_mapping((bank << 16) | addr)
            return ea if ida_bytes.is_mapped(ea) else BADADDR

        def set_data_bank(self, ea, opcode, db, dbs):
            """db: most frequent value, dbs: every value seen for the instruction"""
            if not self.snes_ida:
                self._set_sreg(ea, "B", db)
                return
            if len(dbs) == 1:
                self._set_known(ea, 'b', db, self.KRS_CDL)
                return
            if opcode in DB_RELATIVE_OPS:
                operand = ida_bytes.get_word(ea + 1)
                targets = set(self.data_target(v, operand) for v in dbs)
                if len(targets) == 1 and BADADDR not in targets:
                    self._set_known(ea, 'b', db, self.KRS_CDL_SAME_TARGET)
                    return
            self._set_known(ea, 'b', db, None)

        PB_TARGET_OPS = {0x20, 0x4C, 0x7C, 0xFC}  # JSR/JMP abs, JMP/JSR (abs,X): the target depends on PB

        def set_program_bank(self, ea, opcode, pb, pbs):
            """pb: most frequent program bank, pbs: every bank the instruction ran from"""
            if not self.snes_ida:
                self._set_sreg(ea, "PB", pb)
                return
            if len(pbs) == 1:
                self._set_known(ea, 'k', pb, self.KRS_CDL)
                return
            if opcode in self.PB_TARGET_OPS:
                operand = ida_bytes.get_word(ea + 1)
                targets = set(self.data_target(v, operand) for v in pbs)
                if len(targets) == 1 and BADADDR not in targets:
                    self._set_known(ea, 'k', pb, self.KRS_CDL_SAME_TARGET)
                    return
            self._set_known(ea, 'k', pb, None)

        def set_direct_page(self, ea, d, unique):
            if self.snes_ida:
                self._set_known(ea, 'D', d, self.KRS_CDL if unique else None)
            else:
                self._set_sreg(ea, "D", d)


        def _set_sreg(self, ea, name, value):
            reg = self.sregs.get(name)
            if reg is not None and ida_segregs.get_sreg(ea, reg) != value:
                ida_segregs.split_sreg_range(ea, reg, value, ida_segregs.SR_user)

    class AddressMapper(object):
        def __init__(self):
            self.cache = {}

        def __call__(self, loc, cpu_addr):
            if loc == NO_ADDR:
                return BADADDR
            key = (loc, cpu_addr)
            ea = self.cache.get(key)
            if ea is None:
                ea = self._map(loc, cpu_addr)
                self.cache[key] = ea
            return ea

        @staticmethod
        def _map(loc, cpu_addr):
            t, a = loc_type(loc), loc_addr(loc)
            if t == LOC_PRGROM:
                ea = ida_loader.get_fileregion_ea(a)
                if ea != BADADDR:
                    return ea
            cands = []
            if t == LOC_WRAM:
                cands.append(0x7E0000 + a)
            cands += [ida_bytes.use_mapping(cpu_addr), cpu_addr]
            bank, low = cpu_addr >> 16, cpu_addr & 0xFFFF
            if (bank < 0x40 or 0x80 <= bank < 0xC0) and low < 0x8000:
                cands += [ida_bytes.use_mapping(low), low]
                if low < 0x2000:
                    cands.append(0x7E0000 + low)
            for ea in cands:
                if ida_bytes.is_mapped(ea):
                    return ea
            return BADADDR

    def _get_node():
        return ida_netnode.netnode(NETNODE_NAME, 0, True)

    def _set_comment(ea, text):
        """Replaces the 'Mesen:' line of the regular comment, keeping the user's text."""
        old = ida_bytes.get_cmt(ea, False) or ""
        lines = [l for l in old.split("\n") if l and not l.startswith("Mesen:")]
        if text:
            lines.append(text)
        ida_bytes.set_cmt(ea, "\n".join(lines), False)

    class ApplyForm(ida_kernwin.Form):
        def __init__(self, path):
            ida_kernwin.Form.__init__(self, r"""STARTITEM 0
BUTTON YES* Apply
BUTTON CANCEL Cancel
Apply Mesen CDL

<CDL file:{path}>
<Create code and set M/X flags:{code}>
<Set data bank / direct page (when unique):{banks}>
<Create functions at subroutine entry points:{funcs}>
<Add data xrefs (read/write):{dxrefs}>
<Add code xrefs (jump/call, incl. indirect):{cxrefs}>
<Add DMA source xrefs and comments:{dma}>
<Comment instructions whose M/X/DB/D varies:{varcmt}>{opts}>
<Merge data xrefs of one instruction closer than (bytes):{gap}>
""", {
                "path": ida_kernwin.Form.FileInput(open=True, value=path, swidth=60),
                "gap": ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_DEC, value=16, swidth=6),
                "opts": ida_kernwin.Form.ChkGroupControl(("code", "banks", "funcs", "dxrefs", "cxrefs", "dma", "varcmt")),
            })

    class CdlApplier(object):
        def __init__(self, cdl, opts):
            self.cdl = cdl
            self.opts = opts
            self.proc = ProcModule()
            self.map = AddressMapper()
            self.stats = {}

        def _count(self, key, n=1):
            self.stats[key] = self.stats.get(key, 0) + n

        def run(self):
            ida_kernwin.show_wait_box("Applying Mesen CDL...")
            try:
                ida_auto.enable_auto(False)
                if self.opts["code"] or self.opts["banks"]:
                    self.apply_code()
                if self.opts["funcs"]:
                    self.apply_functions()
                if self.opts["dxrefs"] or self.opts["cxrefs"] or self.opts["dma"]:
                    self.apply_xrefs()
            finally:
                ida_auto.enable_auto(True)
                ida_kernwin.replace_wait_box("Waiting for auto-analysis...")
                ida_auto.auto_wait()
                ida_kernwin.hide_wait_box()
            print("[%s] processor module: %s" % (PLUGIN_NAME, self.proc.name))
            for k in sorted(self.stats):
                print("[%s]   %-28s %d" % (PLUGIN_NAME, k, self.stats[k]))

        def apply_code(self):
            global ROM_READER
            ROM_READER = lambda off: ida_bytes.get_byte(self.map((LOC_PRGROM << 28) | off, 0))
            starts = self.cdl.instruction_starts()
            order = sorted(starts)
            for n, off in enumerate(order):
                if n % 2000 == 0:
                    if ida_kernwin.user_cancelled():
                        break
                    ida_kernwin.replace_wait_box("Applying Mesen CDL: code %d/%d" % (n, len(order)))
                ctxs = starts[off]
                ea = self.map((LOC_PRGROM << 28) | off, ctxs[0].cpu_addr)
                if ea == BADADDR:
                    self._count("unmapped instructions")
                    continue
                best = max(ctxs, key=lambda c: c.hits)
                opcode = ida_bytes.get_byte(ea)
                mxs = set(c.mx for c in ctxs)
                dbs = set(c.DB for c in ctxs)
                ds = set(c.D for c in ctxs)

                if self.opts["code"]:
                    mx = best.mx
                    if opcode in (0xC2, 0xE2):
                        mx = post_mx(opcode, ida_bytes.get_byte(ea + 1), mx, best.E) if self.proc.snes_ida else mx
                    self.proc.set_mx(ea, mx, best.E)
                    size = op_size(opcode, best.mx)
                    flags = ida_bytes.get_flags(ea)
                    if not (ida_bytes.is_code(flags) and ida_bytes.get_item_size(ea) == size):
                        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
                    if ida_ua.create_insn(ea):
                        self._count("instructions")
                    else:
                        self._count("instructions failed")
                    if len(mxs) > 1:
                        self._count("instructions with mixed M/X")

                if self.opts["banks"]:
                    # the dominant value is used when it varies (the runtime xrefs cover every case)
                    db = max(dbs, key=lambda v: sum(c.hits for c in ctxs if c.DB == v))
                    d = max(ds, key=lambda v: sum(c.hits for c in ctxs if c.D == v))
                    self.proc.set_data_bank(ea, opcode, db, dbs)
                    self.proc.set_direct_page(ea, d, len(ds) == 1)
                    # program bank: from the register snapshots (the contexts don't keep it)
                    snaps = [sn for c in ctxs for sn in self.cdl.snaps_by_loc.get((c.cpu, c.loc), [])]
                    if snaps:
                        pbs = set(sn.PB for sn in snaps)
                        pb = max(pbs, key=lambda v: sum(sn.hits for sn in snaps if sn.PB == v))
                        self.proc.set_program_bank(ea, opcode, pb, pbs)
                    elif best.cpu_addr:
                        pbs = set(c.cpu_addr >> 16 for c in ctxs)
                        self.proc.set_program_bank(ea, opcode, best.cpu_addr >> 16, pbs)

                if self.opts["varcmt"]:
                    parts = []
                    if len(mxs) > 1:
                        parts.append("MX " + ", ".join("m%d x%d" % (8 if m & 0x20 else 16, 8 if m & 0x10 else 16) for m in sorted(mxs)))
                    if len(dbs) > 1 and opcode in DB_USING_OPS:
                        parts.append("DB " + ",".join("%02X" % v for v in sorted(dbs)))
                    if len(ds) > 1 and opcode in DP_USING_OPS:
                        parts.append("D " + ",".join("%04X" % v for v in sorted(ds)))
                    if parts:
                        _set_comment(ea, "Mesen: " + "; ".join(parts))
                        self._count("comments (varying context)")

        def apply_functions(self):
            for off, f in enumerate(self.cdl.flags):
                if f & CDL_SUB_ENTRY and f & CDL_CODE:
                    ea = self.map((LOC_PRGROM << 28) | off, 0)
                    if ea == BADADDR:
                        continue
                    func = ida_funcs.get_func(ea)
                    if func is not None and func.start_ea == ea:
                        continue
                    if func is not None:
                        # entry point inside another function: split it off
                        ida_funcs.set_func_end(func.start_ea, ea)
                    if ida_funcs.add_func(ea):
                        self._count("functions created")

        def apply_xrefs(self):
            dma_ranges = {}
            xrefs = list(self.cdl.merged_xrefs(self.opts.get("gap", 16)))
            total = len(xrefs)
            for n, (x, length, hits) in enumerate(xrefs):
                if n % 5000 == 0:
                    if ida_kernwin.user_cancelled():
                        break
                    ida_kernwin.replace_wait_box("Applying Mesen CDL: xrefs %d/%d" % (n, total))
                is_code = x.type in (XREF_JUMP, XREF_CALL)
                if (is_code and not self.opts["cxrefs"]) or (x.type in (XREF_READ, XREF_WRITE) and not self.opts["dxrefs"]) \
                        or (x.type == XREF_DMA and not self.opts["dma"]):
                    continue
                frm = self.map(x.from_loc, x.from_cpu)
                to = self.map(x.to_loc, x.to_cpu)
                if frm == BADADDR or to == BADADDR:
                    self._count("xrefs unmapped")
                    continue
                if x.type == XREF_JUMP:
                    if ida_xref.add_cref(frm, to, ida_xref.fl_JN | ida_xref.XREF_USER):
                        self._count("xrefs jump")
                elif x.type == XREF_CALL:
                    if ida_xref.add_cref(frm, to, ida_xref.fl_CN | ida_xref.XREF_USER):
                        self._count("xrefs call")
                else:
                    dtype = ida_xref.dr_W if x.type == XREF_WRITE else ida_xref.dr_R
                    if ida_xref.add_dref(frm, to, dtype | ida_xref.XREF_USER):
                        self._count("xrefs " + XREF_NAMES[x.type])
                    if x.type == XREF_DMA:
                        dma_ranges.setdefault(to, set()).add((length, frm))
            for to, entries in dma_ranges.items():
                text = "Mesen: DMA source " + ", ".join("%d bytes (by %X)" % (l, f) for l, f in sorted(entries))
                _set_comment(to, text)
                self._count("DMA source comments")

    # --- register snapshot viewer ---

    class SnapshotChooser(ida_kernwin.Choose):
        def __init__(self, plugin):
            ida_kernwin.Choose.__init__(
                self, "Mesen registers",
                [["Seq", 10 | ida_kernwin.Choose.CHCOL_DEC],
                 ["Frame", 7 | ida_kernwin.Choose.CHCOL_DEC],
                 ["Hits", 7 | ida_kernwin.Choose.CHCOL_DEC],
                 ["A", 6 | ida_kernwin.Choose.CHCOL_HEX],
                 ["X", 5 | ida_kernwin.Choose.CHCOL_HEX],
                 ["Y", 5 | ida_kernwin.Choose.CHCOL_HEX],
                 ["S", 5 | ida_kernwin.Choose.CHCOL_HEX],
                 ["D", 5 | ida_kernwin.Choose.CHCOL_HEX],
                 ["DB", 3 | ida_kernwin.Choose.CHCOL_HEX],
                 ["PB", 3 | ida_kernwin.Choose.CHCOL_HEX],
                 ["P", 13],
                 ["E", 2],
                 ["Next", 12 | ida_kernwin.Choose.CHCOL_EA],
                 ["CPU", 4]],
                flags=ida_kernwin.Choose.CH_CAN_REFRESH | ida_kernwin.Choose.CH_NOIDB | ida_kernwin.Choose.CH_RESTORE,
                embedded=False)
            self.plugin = plugin
            self.items = []
            self.ea = BADADDR

        def set_ea(self, ea):
            self.ea = ea
            self.items = self.plugin.snapshots_at(ea)

        def OnGetSize(self):
            return len(self.items)

        def OnGetLine(self, n):
            s = self.items[n]
            m8 = s.E or s.P & 0x20
            x8 = s.E or s.P & 0x10
            nxt = self.plugin.map(s.next_loc, s.next_cpu) if s.next_loc != NO_ADDR else BADADDR
            return ["%d" % s.seq, "%d" % s.frame, "%d" % s.hits,
                    ("%02X:%02X" % (s.A >> 8, s.A & 0xFF)) if m8 else "%04X" % s.A,
                    ("%02X" % s.X) if x8 else "%04X" % s.X,
                    ("%02X" % s.Y) if x8 else "%04X" % s.Y,
                    "%04X" % s.S, "%04X" % s.D, "%02X" % s.DB, "%02X" % s.PB,
                    "%02X %s" % (s.P, fmt_p(s.P, s.E)), "%d" % s.E,
                    ("%X" % nxt) if nxt != BADADDR else fmt_loc(s.next_loc),
                    "SA1" if s.cpu else "CPU"]

        def OnGetLineAttr(self, n):
            s = self.items[n]
            if self.plugin.current is s:
                return [0xC0FFC0, 0]
            return None

        def OnSelectionChange(self, sel):
            if isinstance(sel, (list, tuple)):
                sel = sel[0] if sel else -1
            if 0 <= sel < len(self.items):
                self.plugin.current = self.items[sel]

        def OnSelectLine(self, sel):
            if isinstance(sel, (list, tuple)):
                sel = sel[0] if sel else -1
            if 0 <= sel < len(self.items):
                self.plugin.current = self.items[sel]
                self.plugin.follow_next()
            return (ida_kernwin.Choose.NOTHING_CHANGED, )

        def OnRefresh(self, sel):
            self.set_ea(self.ea)
            idx = self.items.index(self.plugin.current) if self.plugin.current in self.items else 0
            return [ida_kernwin.Choose.ALL_CHANGED, idx]

        def OnClose(self):
            self.plugin.chooser = None

    class ActionHandler(ida_kernwin.action_handler_t):
        def __init__(self, callback):
            ida_kernwin.action_handler_t.__init__(self)
            self.callback = callback

        def activate(self, ctx):
            self.callback()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    class UiHooks(ida_kernwin.UI_Hooks):
        def __init__(self, plugin):
            ida_kernwin.UI_Hooks.__init__(self)
            self.plugin = plugin

        def screen_ea_changed(self, ea, prev_ea):
            self.plugin.on_ea_changed(ea)

        def get_custom_viewer_hint(self, viewer, place):
            try:
                if place is None or ida_kernwin.get_widget_type(viewer) != ida_kernwin.BWN_DISASM or self.plugin.cdl is None:
                    return None
                ea = place.toea()
                snaps = self.plugin.snapshots_at(ea)
                ctxs = self.plugin.contexts_at(ea)
                if not snaps and not ctxs:
                    return None
                lines = ["Mesen: %d context(s), %d snapshot(s)" % (len(ctxs), len(snaps))]
                for c in sorted(ctxs, key=lambda c: -c.hits)[:6]:
                    lines.append("  P=%02X(%s) E=%d DB=%02X D=%04X  x%d" % (c.P, fmt_p(c.P, c.E), c.E, c.DB, c.D, c.hits))
                for s in snaps[:4]:
                    lines.append("  #%d f%d: %s" % (s.seq, s.frame, s.regs_str()))
                return ("\n".join(lines) + "\n", len(lines) + 1)
            except Exception:
                return None

    class MesenCdlPlugmod(ida_idaapi.plugmod_t):
        ACTIONS = [
            ("mesen_cdl:apply", "Apply Mesen CDL...", None, "apply"),
            ("mesen_cdl:view", "Register snapshots", "Ctrl+Alt+M", "show_view"),
            ("mesen_cdl:time_next", "Step to next executed instruction", "Ctrl+Alt+Right", "time_next"),
            ("mesen_cdl:time_prev", "Step to previous executed instruction", "Ctrl+Alt+Left", "time_prev"),
            ("mesen_cdl:snap_next", "Next snapshot here", "Ctrl+Alt+Down", "snap_next"),
            ("mesen_cdl:snap_prev", "Previous snapshot here", "Ctrl+Alt+Up", "snap_prev"),
            ("mesen_cdl:follow", "Follow snapshot to next instruction", "Ctrl+Alt+Enter", "follow_next"),
            ("mesen_cdl:reload", "Reload CDL file", None, "reload"),
        ]

        def __init__(self):
            ida_idaapi.plugmod_t.__init__(self)
            self.cdl = None
            self.map = AddressMapper()
            self.chooser = None
            self.current = None
            self.ea_index = None
            for name, label, hotkey, method in self.ACTIONS:
                ida_kernwin.unregister_action(name)
                ida_kernwin.register_action(ida_kernwin.action_desc_t(
                    name, label, ActionHandler(getattr(self, method)), hotkey))
                ida_kernwin.attach_action_to_menu(MENU_PATH, name, ida_kernwin.SETMENU_APP)
            self.hooks = UiHooks(self)
            self.hooks.hook()

        def __del__(self):
            try:
                self.hooks.unhook()
                for name, _, _, _ in self.ACTIONS:
                    ida_kernwin.detach_action_from_menu(MENU_PATH, name)
                    ida_kernwin.unregister_action(name)
            except Exception:
                pass

        def run(self, arg):
            if self.cdl is None:
                self.apply()
            else:
                self.show_view()
            return True

        # --- data ---
        def load(self, path):
            try:
                self.cdl = CdlFile(path)
            except Exception as e:
                ida_kernwin.warning("Failed to read %s:\n%s" % (path, e))
                return False
            self.ea_index = None
            self.current = None
            _get_node().supset(0, path)
            c = self.cdl
            print("[%s] %s: %d CDL bytes, %d contexts, %d snapshots, %d xref ranges%s" % (
                PLUGIN_NAME, path, len(c.flags), len(c.contexts), len(c.snapshots), len(c.xrefs),
                "" if c.has_extension else " (no 65816 extension - plain CDL)"))
            self._check_crc()
            return True

        def _check_crc(self):
            c = self.cdl
            if c.crc is None:
                return
            data = bytearray()
            for off in range(0, len(c.flags), 0x1000):
                ea = ida_loader.get_fileregion_ea(off)
                if ea == BADADDR:
                    return
                data += ida_bytes.get_bytes(ea, min(0x1000, len(c.flags) - off)) or b""
            if (zlib.crc32(bytes(data)) & 0xFFFFFFFF) != c.crc:
                print("[%s] WARNING: ROM CRC32 does not match the CDL file (%08X != %08X)" % (
                    PLUGIN_NAME, zlib.crc32(bytes(data)) & 0xFFFFFFFF, c.crc))

        def ensure_loaded(self):
            if self.cdl is not None:
                return True
            path = _get_node().supstr(0)
            if path and os.path.exists(path):
                return self.load(path)
            path = ida_kernwin.ask_file(False, "*.cdl", "Select Mesen CDL file")
            return bool(path) and self.load(path)

        def _build_index(self):
            idx = {}
            for (cpu, loc), snaps in self.cdl.snaps_by_loc.items():
                ea = self.map(loc, snaps[0].cpu_addr)
                if ea != BADADDR:
                    idx.setdefault(ea, []).extend(snaps)
            for snaps in idx.values():
                snaps.sort(key=lambda s: s.seq)
            ctx = {}
            for (cpu, loc), ctxs in self.cdl.ctx_by_loc.items():
                ea = self.map(loc, ctxs[0].cpu_addr)
                if ea != BADADDR:
                    ctx.setdefault(ea, []).extend(ctxs)
            self.ea_index = idx
            self.ctx_index = ctx

        def snapshots_at(self, ea):
            if self.cdl is None:
                return []
            if self.ea_index is None:
                self._build_index()
            return self.ea_index.get(ea, [])

        def contexts_at(self, ea):
            if self.cdl is None:
                return []
            if self.ea_index is None:
                self._build_index()
            return self.ctx_index.get(ea, [])

        def snap_ea(self, s):
            return self.map(s.loc, s.cpu_addr)

        # --- actions ---
        def apply(self):
            default = _get_node().supstr(0) or ""
            if not default:
                inp = ida_nalt.get_input_file_path() or ""
                default = os.path.splitext(inp)[0] + ".cdl"
            form = ApplyForm(default)
            form.Compile()
            form.code.checked = form.banks.checked = form.funcs.checked = True
            form.dxrefs.checked = form.cxrefs.checked = form.dma.checked = form.varcmt.checked = True
            ok = form.Execute()
            opts = {k: getattr(form, k).checked for k in ("code", "banks", "funcs", "dxrefs", "cxrefs", "dma", "varcmt")}
            opts["gap"] = max(0, form.gap.value)
            path = form.path.value
            form.Free()
            if ok != 1 or not path or not self.load(path):
                return
            CdlApplier(self.cdl, opts).run()
            self.ea_index = None
            self.map = AddressMapper()

        def reload(self):
            path = _get_node().supstr(0)
            if path:
                self.load(path)
                self.refresh_view()

        def show_view(self):
            if not self.ensure_loaded():
                return
            if self.chooser is None:
                self.chooser = SnapshotChooser(self)
                self.chooser.set_ea(ida_kernwin.get_screen_ea())
                self.chooser.Show()
            else:
                self.refresh_view()

        def refresh_view(self):
            if self.chooser is not None:
                self.chooser.set_ea(ida_kernwin.get_screen_ea())
                self.chooser.Refresh()
                if self.current in self.chooser.items:
                    self.chooser.Jump(self.chooser.items.index(self.current))

        def on_ea_changed(self, ea):
            if self.chooser is not None and self.cdl is not None and ea != self.chooser.ea:
                snaps = self.snapshots_at(ea)
                if snaps and (self.current is None or self.current not in snaps):
                    # keep the time position: choose the first snapshot after the current one
                    after = [s for s in snaps if self.current is None or s.seq > self.current.seq]
                    self.current = after[0] if after else snaps[0]
                self.refresh_view()

        def _goto(self, snap):
            if snap is None:
                print("[%s] no more recorded instructions" % PLUGIN_NAME)
                return
            self.current = snap
            ea = self.snap_ea(snap)
            print("[%s] #%d frame %d @%s: %s" % (PLUGIN_NAME, snap.seq, snap.frame,
                                                  ("%X" % ea) if ea != BADADDR else fmt_loc(snap.loc, snap.cpu_addr),
                                                  snap.regs_str()))
            if ea != BADADDR:
                ida_kernwin.jumpto(ea)
            self.refresh_view()

        def _require_current(self):
            if not self.ensure_loaded():
                return False
            if self.current is None:
                snaps = self.snapshots_at(ida_kernwin.get_screen_ea())
                self.current = snaps[0] if snaps else None
            if self.current is None:
                print("[%s] no snapshot at the cursor" % PLUGIN_NAME)
                return False
            return True

        def time_next(self):
            if self._require_current():
                self._goto(self.cdl.snapshot_after(self.current.seq))

        def time_prev(self):
            if self._require_current():
                self._goto(self.cdl.snapshot_before(self.current.seq))

        def _snap_step(self, delta):
            if not self._require_current():
                return
            snaps = self.snapshots_at(self.snap_ea(self.current))
            if self.current in snaps:
                i = snaps.index(self.current) + delta
                if 0 <= i < len(snaps):
                    self._goto(snaps[i])

        def snap_next(self):
            self._snap_step(1)

        def snap_prev(self):
            self._snap_step(-1)

        def follow_next(self):
            if not self._require_current():
                return
            s = self.current
            if s.next_loc == NO_ADDR:
                print("[%s] the next instruction is unknown for this snapshot" % PLUGIN_NAME)
                return
            ea = self.map(s.next_loc, s.next_cpu)
            candidates = [n for n in self.snapshots_at(ea) if n.seq > s.seq] if ea != BADADDR else []
            if candidates:
                self._goto(candidates[0])
            else:
                print("[%s] next instruction %s: registers were not captured for this execution" % (
                    PLUGIN_NAME, ("%X" % ea) if ea != BADADDR else fmt_loc(s.next_loc, s.next_cpu)))
                if ea != BADADDR:
                    ida_kernwin.jumpto(ea)

    class MesenCdlPlugin(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_MULTI
        comment = "Apply Mesen CDL files with 65816 context/xref information"
        help = "Edit -> Plugins -> Mesen CDL"
        wanted_name = PLUGIN_NAME
        wanted_hotkey = ""

        def init(self):
            return MesenCdlPlugmod()

    def PLUGIN_ENTRY():
        return MesenCdlPlugin()


# ---------------------------------------------------------------------------
# Command line: dump a CDL file
# ---------------------------------------------------------------------------

def _dump(path, limit=20):
    c = CdlFile(path)
    print("%s: %d CDL bytes, CRC %s, extension: %s" % (path, len(c.flags),
                                                     "%08X" % c.crc if c.crc is not None else "-", c.has_extension))
    code = sum(1 for f in c.flags if f & CDL_CODE)
    data = sum(1 for f in c.flags if f & CDL_DATA and not f & CDL_CODE)
    print("code bytes %d, data bytes %d" % (code, data))
    print("contexts %d, snapshots %d (max %d/insn), xref ranges %d, next seq %d" % (
        len(c.contexts), len(c.snapshots), c.max_snapshots, len(c.xrefs), c.next_seq))
    for x in c.xrefs[:limit]:
        print("  xref %-5s %s -> %s len=%d hits=%d%s" % (XREF_NAMES.get(x.type, x.type), fmt_loc(x.from_loc, x.from_cpu),
                                                        fmt_loc(x.to_loc, x.to_cpu), x.length, x.hits, " [SA1]" if x.cpu else ""))
    for s in c.snapshots[:limit]:
        print("  #%d f%d %s: %s x%d next=%s" % (s.seq, s.frame, fmt_loc(s.loc, s.cpu_addr), s.regs_str(), s.hits,
                                               fmt_loc(s.next_loc, s.next_cpu)))
    for ctx in c.contexts[:limit]:
        print("  ctx %s P=%02X E=%d DB=%02X D=%04X x%d" % (fmt_loc(ctx.loc, ctx.cpu_addr), ctx.P, ctx.E, ctx.DB, ctx.D, ctx.hits))


if __name__ == "__main__" and not IN_IDA:
    import sys
    for p in sys.argv[1:]:
        _dump(p)
