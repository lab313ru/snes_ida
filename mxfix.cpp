// Automatic correction of the M/X flags when the code flow runs into an opcode the ROM doesn't use.
//
// When BRK / COP / WDM are disabled in the processor options, reaching one of them by the ordinary flow means the
// previous instructions were decoded with a wrong operand size: an immediate operand that depends on M or X
// took one byte too much or too little. For example with M=0 "A9 01 8D 00 43" is LDA #$8D01 followed by BRK,
// with M=1 it is LDA #$01 / STA $4300.
//
// The flow is followed back from the conflict to the point the flags were only inherited at (function entry,
// join of several paths, after a call / PLP / XCE). Flags set there by SEP/REP or manually are left alone.
// M, X or both are switched at that point when this makes the code decode without disabled opcodes;
// the flag is stored as a manual one (Shift+X changes it back) and the code is decoded again.

#include "65816.hpp"
#include <vector>

namespace {

const int MAX_WALK_BACK = 1000;
const int MAX_SIM_INSNS = 2000;
const int SIM_INSNS_AFTER_CONFLICT = 32;

bool is_disabled_opcode(uint8_t op, ushort idpflags) {
	return ((idpflags & ROM_NO_BRK) && op == 0x00)
		|| ((idpflags & ROM_NO_COP) && op == 0x02)
		|| ((idpflags & ROM_NO_WDM) && op == 0x42);
}

uint8_t insn_size(uint8_t op, uint8_t flags) {
	M mode = m65816_OpMode[op];
	if (mode == M::Imx) {
		return (flags & m65816_flags::IndexMode8) ? 2 : 3;
	}
	if (mode == M::Imm) {
		return (flags & m65816_flags::MemoryMode8) ? 2 : 3;
	}
	return m65816_OpSize[static_cast<int>(mode)];
}

// the flags after this instruction can't be derived from the ones before it
bool resets_flags(uint8_t op) {
	switch (op) {
	case 0x20: case 0x22: case 0xFC: // JSR, JSL, JSR (abs,X): the callee may change M/X
	case 0x28:                       // PLP
	case 0xFB:                       // XCE
	case 0x40:                       // RTI
	case 0x00: case 0x02:            // BRK, COP
		return true;
	default:
		return false;
	}
}

bool ends_flow(uint8_t op) {
	switch (op) {
	case 0x60: case 0x6B: case 0x40:                       // RTS, RTL, RTI
	case 0x4C: case 0x5C: case 0x6C: case 0x7C: case 0xDC: // JMP, JML
	case 0x80: case 0x82:                                  // BRA, BRL
	case 0xDB:                                             // STP
	case 0x28: case 0xFB:                                  // PLP, XCE: the flags are unknown from here
		return true;
	default:
		return false;
	}
}

// One straight piece of the path the code flow took from the start to the conflict:
// from 'start' to the jump/branch at 'jump' (BADADDR for the last piece, which ends at the conflict)
struct piece_t {
	ea_t start;
	ea_t jump;
};

// Decodes the path again with the given flags at its start, and follows it while it stays the same: every piece
// reaches its jump instruction exactly (so the jump target doesn't move). The decoding is clean when it gets past
// the conflict, or leaves the path (the jump is no longer an instruction boundary, the flow ends before it: the
// conflict is not reached anymore), and no disabled opcode is met until the flow ends or a few instructions later.
bool decodes_cleanly(const std::vector<piece_t>& path, uint8_t flags, ea_t conflict, ushort idpflags) {
	for (size_t i = 0; i < path.size(); i++) {
		bool last = i + 1 == path.size();
		bool left_path = false;
		ea_t ea = path[i].start;
		int after = 0;
		for (int n = 0;; n++) {
			if (n >= MAX_SIM_INSNS || !is_mapped(ea)) {
				return false;
			}
			if (!last && !left_path && ea > path[i].jump) {
				left_path = true; // the jump is not an instruction boundary anymore
			}
			if ((left_path || (last && ea > conflict)) && ++after > SIM_INSNS_AFTER_CONFLICT) {
				return true;
			}
			uint8_t op = get_byte(ea);
			if (is_disabled_opcode(op, idpflags)) {
				return false;
			}
			uint8_t size = insn_size(op, flags);
			if (op == 0xE2) { // SEP
				flags |= get_byte(ea + 1) & 0x30;
			}
			else if (op == 0xC2) { // REP
				flags &= ~(get_byte(ea + 1) & 0x30);
			}
			if (!last && !left_path && ea == path[i].jump) {
				break; // continue with the next piece (the jump doesn't change M/X)
			}
			if (ends_flow(op)) {
				// the old path had no end of flow before the conflict: either the decoding got past it,
				// or the path changed and the conflict is not reached anymore
				return true;
			}
			ea += size;
		}
	}
	return false;
}

// Decodes the path again: its pieces are undefined (a piece may lie below the start when a branch goes backwards),
// then the code is created again from the start of the path and from every place the rest of the code refers to.
// The jump targets of the old path itself are not used: with the new flags they may be in the middle of instructions.
void redecode_path(const std::vector<piece_t>& path, ea_t conflict) {
	std::vector<std::pair<ea_t, ea_t>> ranges;
	for (const piece_t& piece : path) {
		ea_t end = (piece.jump != BADADDR) ? get_item_end(piece.jump) : conflict + 1;
		if (end > piece.start) {
			ranges.push_back({ piece.start, end });
		}
	}
	auto in_ranges = [&](ea_t ea) {
		for (const auto& r : ranges) {
			if (ea >= r.first && ea < r.second) {
				return true;
			}
		}
		return false;
	};

	std::set<ea_t> entries;
	entries.insert(path.front().start);
	for (const auto& r : ranges) {
		for (ea_t ea = r.first; ea < r.second && ea != BADADDR; ea = next_head(ea, r.second)) {
			xrefblk_t xb;
			for (bool ok = xb.first_to(ea, XREF_CODE); ok; ok = xb.next_to()) {
				if (!in_ranges(xb.from)) {
					entries.insert(ea);
				}
			}
		}
	}

	for (const auto& r : ranges) {
		del_items(r.first, DELIT_NOTRUNC | DELIT_KEEPFUNC, r.second - r.first);
	}
	for (ea_t ea : entries) {
		auto_make_code(ea);
	}
}

// the only code reference to ea, when it is the ordinary flow or a jump (the flags are inherited from it)
ea_t single_flow_pred(ea_t ea) {
	ea_t pred = BADADDR;
	int count = 0;
	xrefblk_t xb;
	for (bool ok = xb.first_to(ea, XREF_CODE); ok; ok = xb.next_to()) {
		count++;
		if (xb.type == fl_F || xb.type == fl_JN || xb.type == fl_JF) {
			pred = xb.from;
		}
	}
	return count == 1 ? pred : BADADDR;
}

bool fix_conflict(ea_t conflict, ushort idpflags) {
	uint8_t op = get_byte(conflict);
	if (is_code(get_flags(conflict)) || !is_disabled_opcode(op, idpflags)) {
		return false; // resolved meanwhile
	}
	ea_t prev = single_flow_pred(conflict);
	if (prev == BADADDR || !is_code(get_flags(prev)) || get_item_end(prev) != conflict) {
		return false; // not reached by the ordinary flow
	}

	// back to the instruction the flags are only inherited at
	ea_t start = prev;
	uint8_t fixed_bits = 0; // flags that are certain at start
	uint8_t nearest = 0;    // flag of the nearest instruction whose size depends on M/X
	std::vector<std::pair<ea_t, ea_t>> jumps; // (jump, its target) on the path, from the conflict backwards
	for (int n = 0; n < MAX_WALK_BACK; n++) {
		if (ea_is_manual_bitmode(start)) {
			fixed_bits = 0x30;
			break;
		}
		if (nearest == 0) {
			M mode = m65816_OpMode[get_byte(start)];
			nearest = mode == M::Imm ? m65816_flags::MemoryMode8 : mode == M::Imx ? m65816_flags::IndexMode8 : 0;
		}
		ea_t pred = single_flow_pred(start);
		if (pred == BADADDR || !is_code(get_flags(pred))) {
			break;
		}
		uint8_t pred_op = get_byte(pred);
		if (resets_flags(pred_op)) {
			break;
		}
		if (pred_op == 0xE2 || pred_op == 0xC2) { // SEP / REP: the bits it sets are certain from here
			fixed_bits |= get_byte(pred + 1) & 0x30;
			if (fixed_bits == 0x30) {
				break;
			}
		}
		if (ea_is_manual_bitmode(pred)) {
			fixed_bits = 0x30;
			break;
		}
		if (get_item_end(pred) != start) {
			jumps.push_back({ pred, start }); // reached by a jump/branch
		}
		start = pred;
	}

	// pieces of the path from the start to the conflict
	std::vector<piece_t> path;
	ea_t piece_start = start;
	for (auto it = jumps.rbegin(); it != jumps.rend(); ++it) {
		path.push_back({ piece_start, it->first });
		piece_start = it->second;
	}
	path.push_back({ piece_start, BADADDR });

	uint8_t flags = ea_get_flags(start);

	// the flags may have changed since the conflict was noted (new references to the code):
	// when they already decode the path cleanly, only decode it again
	if (decodes_cleanly(path, flags, conflict, idpflags)) {
		redecode_path(path, conflict);
		return true;
	}

	uint8_t other = (nearest == m65816_flags::MemoryMode8) ? m65816_flags::IndexMode8 : m65816_flags::MemoryMode8;
	uint8_t candidates[3] = {
		nearest != 0 ? nearest : m65816_flags::MemoryMode8,
		nearest != 0 ? other : m65816_flags::IndexMode8,
		0x30,
	};

	for (uint8_t flip : candidates) {
		if ((flip & fixed_bits) != 0) {
			continue;
		}
		uint8_t new_flags = flags ^ flip;
		if (!decodes_cleanly(path, new_flags, conflict, idpflags)) {
			continue;
		}

		ea_set_flags(start, new_flags);
		ea_set_manual_bitmode(start, true);
		redecode_path(path, conflict);

		qstring what;
		if (flip & m65816_flags::MemoryMode8) {
			what.cat_sprnt("%sM=%d (a%d)", what.empty() ? "" : ", ", (new_flags & m65816_flags::MemoryMode8) ? 1 : 0, (new_flags & m65816_flags::MemoryMode8) ? 8 : 16);
		}
		if (flip & m65816_flags::IndexMode8) {
			what.cat_sprnt("%sX=%d (i%d)", what.empty() ? "" : ", ", (new_flags & m65816_flags::IndexMode8) ? 1 : 0, (new_flags & m65816_flags::IndexMode8) ? 8 : 16);
		}
		msg("%a: the code flow reached $%02X at %a, which the ROM doesn't use: %s set at %a (Shift+X to change)\n",
			start, op, conflict, what.c_str(), start);
		return true;
	}

	msg("%a: the code flow reached $%02X, which the ROM doesn't use; no M/X change before it resolves this\n", conflict, op);
	return false;
}

} // namespace

bool fix_mx_conflicts(std::set<ea_t>& conflicts, ushort idpflags) {
	bool changed = false;
	std::set<ea_t> todo;
	todo.swap(conflicts);
	for (ea_t ea : todo) {
		changed |= fix_conflict(ea, idpflags);
	}
	return changed;
}
