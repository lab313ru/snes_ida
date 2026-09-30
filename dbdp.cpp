// Static propagation of the data bank (DB) and direct page (D) registers.
//
// Every function is analysed on its own, with symbolic entry values ("DB/D of the caller"). The analysis follows
// the code flow (ordinary flow + jumps inside the function) and tracks DB, D, the accumulator and the bytes pushed
// on the stack, so that the usual idioms are understood: PHK/PLB, LDA #imm/PHA/PLB, PEA/PLB/PLB, LDA #imm/TCD,
// PEA/PLD, PHB...PLB, PHD...PLD, TDC, MVN/MVP. A value is only derived when it is the same on every known path.
//
// Calls use a summary of the callee: at its returns DB/D are either the entry values (preserved), a constant,
// or unknown. Values set by the user (Shift+X) or by the Mesen CDL plugin override the derived state
// at that instruction and are propagated further like any other known value.
//
// The result is stored as KRS_STATIC values (DATA_BANK_TAG / DIRECT_PAGE_TAG) and used by get_auto_data_ref().

#include "65816.hpp"
#include <map>
#include <vector>
#include <deque>
#include <set>

namespace {

enum val_kind_t : uint8_t {
	VK_UNK = 0,  // unknown
	VK_CONST,    // known constant
	VK_ENTRY,    // value the register had when the function was entered (DB or D)
	VK_ENTRY_LO, // low byte of the entry D (on the stack / in A)
	VK_ENTRY_HI, // high byte of the entry D
};

struct val_t {
	uint8_t kind = VK_UNK;
	uint16_t v = 0;

	static val_t unk() { return val_t(); }
	static val_t cnst(uint16_t v) { val_t r; r.kind = VK_CONST; r.v = v; return r; }
	static val_t make(uint8_t kind) { val_t r; r.kind = kind; return r; }

	bool operator==(const val_t& o) const { return kind == o.kind && (kind != VK_CONST || v == o.v); }
	bool operator!=(const val_t& o) const { return !(*this == o); }
};

inline val_t join(const val_t& a, const val_t& b) {
	return a == b ? a : val_t::unk();
}

const size_t MAX_STACK = 16;

struct state_t {
	val_t db;         // VK_CONST (bank), VK_ENTRY or VK_UNK
	val_t d;          // VK_CONST (16-bit), VK_ENTRY or VK_UNK
	val_t pb;         // program bank: VK_CONST, VK_ENTRY or VK_UNK (only JML/JSL/RTL/RTI change it, they leave the function)
	val_t a_lo, a_hi; // accumulator bytes
	// bytes pushed since the function entry (back = top of the stack);
	// stack_base_known == false: the depth relative to the entry is unknown
	bool stack_base_known = true;
	std::vector<val_t> stack;

	bool operator==(const state_t& o) const {
		return db == o.db && d == o.d && pb == o.pb && a_lo == o.a_lo && a_hi == o.a_hi && stack_base_known == o.stack_base_known && stack == o.stack;
	}

	void join_with(const state_t& o) {
		db = join(db, o.db);
		d = join(d, o.d);
		pb = join(pb, o.pb);
		a_lo = join(a_lo, o.a_lo);
		a_hi = join(a_hi, o.a_hi);
		if (stack_base_known != o.stack_base_known || stack.size() != o.stack.size()) {
			stack_base_known = false;
			stack.clear();
		}
		else {
			for (size_t i = 0; i < stack.size(); i++) {
				stack[i] = join(stack[i], o.stack[i]);
			}
		}
	}

	void push(const val_t& v) {
		if (stack.size() >= MAX_STACK) {
			stack.erase(stack.begin());
			stack_base_known = false;
		}
		stack.push_back(v);
	}

	val_t pop() {
		if (stack.empty()) {
			// either the caller's data (return address...) or an unknown depth
			stack_base_known = false;
			return val_t::unk();
		}
		val_t v = stack.back();
		stack.pop_back();
		return v;
	}

	void unknown_stack() {
		stack_base_known = false;
		stack.clear();
	}
};

// DB/D as a stack byte and back
val_t db_to_byte(const val_t& db) {
	return db.kind == VK_CONST ? val_t::cnst(db.v & 0xFF) : db.kind == VK_ENTRY ? val_t::make(VK_ENTRY) : val_t::unk();
}

val_t byte_to_db(const val_t& b) {
	return b.kind == VK_CONST ? val_t::cnst(b.v & 0xFF) : b.kind == VK_ENTRY ? val_t::make(VK_ENTRY) : val_t::unk();
}

void d_to_bytes(const val_t& d, val_t* lo, val_t* hi) {
	if (d.kind == VK_CONST) {
		*lo = val_t::cnst(d.v & 0xFF);
		*hi = val_t::cnst(d.v >> 8);
	}
	else if (d.kind == VK_ENTRY) {
		*lo = val_t::make(VK_ENTRY_LO);
		*hi = val_t::make(VK_ENTRY_HI);
	}
	else {
		*lo = *hi = val_t::unk();
	}
}

val_t bytes_to_d(const val_t& lo, const val_t& hi) {
	if (lo.kind == VK_CONST && hi.kind == VK_CONST) {
		return val_t::cnst((uint16_t)((hi.v << 8) | (lo.v & 0xFF)));
	}
	if (lo.kind == VK_ENTRY_LO && hi.kind == VK_ENTRY_HI) {
		return val_t::make(VK_ENTRY);
	}
	return val_t::unk();
}

// Effect of a call on DB/D/stack
struct summary_t {
	bool returns = false;       // at least one return was reached
	val_t db;                   // DB at the returns: VK_ENTRY = preserved
	val_t d;                    // D at the returns: VK_ENTRY = preserved
	bool stack_balanced = true; // the stack depth at every return equals the depth at the entry

	void add_return(const state_t& st) {
		bool balanced = st.stack_base_known && st.stack.empty();
		if (!returns) {
			db = st.db;
			d = st.d;
			stack_balanced = balanced;
			returns = true;
		}
		else {
			db = join(db, st.db);
			d = join(d, st.d);
			stack_balanced = stack_balanced && balanced;
		}
	}

	static summary_t unknown() {
		summary_t s;
		s.returns = true;
		s.stack_balanced = false;
		return s;
	}
};

void apply_summary(state_t& st, const summary_t& s) {
	st.db = s.db.kind == VK_ENTRY ? st.db : s.db;
	st.d = s.d.kind == VK_ENTRY ? st.d : s.d;
	st.a_lo = st.a_hi = val_t::unk(); // the callee may return values in A
	if (!s.stack_balanced) {
		st.unknown_stack();
	}
}

struct func_result_t {
	summary_t summary;
	std::map<ea_t, state_t> in_states; // state at the start of each reached instruction
};

class propagator_t {
	std::map<ea_t, func_result_t> results;
	std::map<ea_t, bool> in_progress;

public:
	ea_t reset_entry = BADADDR; // after a reset the CPU starts with DB = $00, D = $0000
	std::set<ea_t> vector_entries; // interrupt / reset handlers: always run in bank $00

	const func_result_t& analyze(func_t* pfn);
	summary_t call_summary(ea_t target);
	size_t store();

private:
	void transfer(const insn_t& insn, state_t& st, bool& is_return, bool& stop, func_result_t& res);
};

summary_t propagator_t::call_summary(ea_t target) {
	func_t* callee = get_func(target);
	if (callee == nullptr || callee->start_ea != target) {
		return summary_t::unknown();
	}
	auto it = in_progress.find(callee->start_ea);
	if (it != in_progress.end() && it->second) {
		return summary_t::unknown(); // recursion
	}
	const func_result_t& r = analyze(callee);
	return r.summary.returns ? r.summary : summary_t::unknown();
}

void override_known(ea_t ea, state_t& st) {
	uint16_t v;
	known_reg_src_t src;
	// only values that hold for every execution of the instruction are propagated
	if (ea_get_known_reg(ea, DATA_BANK_TAG, &v, &src) && (src == KRS_CDL || src == KRS_MANUAL)) {
		st.db = val_t::cnst(v & 0xFF);
	}
	if (ea_get_known_reg(ea, DIRECT_PAGE_TAG, &v, &src) && (src == KRS_CDL || src == KRS_MANUAL)) {
		st.d = val_t::cnst(v);
	}
	if (ea_get_known_reg(ea, PROGRAM_BANK_TAG, &v, &src) && (src == KRS_CDL || src == KRS_MANUAL)) {
		st.pb = val_t::cnst(v & 0xFF);
	}
}

void propagator_t::transfer(const insn_t& insn, state_t& st, bool& is_return, bool& stop, func_result_t& res) {
	uint8_t flags = ea_get_flags(insn.ea);
	bool m8 = (flags & m65816_flags::MemoryMode8) != 0;
	bool x8 = (flags & m65816_flags::IndexMode8) != 0;
	M addrMode = static_cast<M>(insn.insnpref);

	is_return = false;
	stop = false;

	auto clobber_a = [&]() {
		st.a_lo = val_t::unk();
		if (!m8) {
			st.a_hi = val_t::unk();
		}
	};

	switch (insn.itype) {
	case M65816_lda:
		if (addrMode == M::Imm) {
			st.a_lo = val_t::cnst(insn.Op1.value & 0xFF);
			if (!m8) {
				st.a_hi = val_t::cnst((insn.Op1.value >> 8) & 0xFF);
			}
		}
		else {
			clobber_a();
		}
		break;
	case M65816_adc: case M65816_and: case M65816_eor: case M65816_ora: case M65816_sbc:
	case M65816_txa: case M65816_tya:
		clobber_a();
		break;
	case M65816_asl: case M65816_lsr: case M65816_rol: case M65816_ror: case M65816_inc: case M65816_dec:
		if (addrMode == M::Regs) { // accumulator mode
			clobber_a();
		}
		break;
	case M65816_tsc:
		st.a_lo = st.a_hi = val_t::unk();
		break;
	case M65816_tdc:
		d_to_bytes(st.d, &st.a_lo, &st.a_hi);
		break;
	case M65816_xba:
		std::swap(st.a_lo, st.a_hi);
		break;
	case M65816_tcd:
		st.d = bytes_to_d(st.a_lo, st.a_hi);
		break;
	case M65816_mvn:
	case M65816_mvp:
		st.db = val_t::cnst(insn.Op2.value & 0xFF); // DB = destination bank
		st.a_lo = st.a_hi = val_t::cnst(0xFF);
		break;

	case M65816_pha:
		if (!m8) {
			st.push(st.a_hi);
		}
		st.push(st.a_lo);
		break;
	case M65816_phb:
		st.push(db_to_byte(st.db));
		break;
	case M65816_phd: {
		val_t lo, hi;
		d_to_bytes(st.d, &lo, &hi);
		st.push(hi);
		st.push(lo);
	} break;
	case M65816_phk:
		// the bank of the address in the database is not necessarily PB: HiROM code may run from a mirror
		st.push(st.pb.kind == VK_CONST ? val_t::cnst(st.pb.v & 0xFF) : val_t::unk());
		break;
	case M65816_php:
		st.push(val_t::unk());
		break;
	case M65816_phx:
	case M65816_phy:
		if (!x8) {
			st.push(val_t::unk());
		}
		st.push(val_t::unk());
		break;
	case M65816_pea: {
		uint16_t v = get_word(insn.ea + 1);
		st.push(val_t::cnst(v >> 8));
		st.push(val_t::cnst(v & 0xFF));
	} break;
	case M65816_pei:
	case M65816_per:
		st.push(val_t::unk());
		st.push(val_t::unk());
		break;
	case M65816_pla:
		st.a_lo = st.pop();
		if (!m8) {
			st.a_hi = st.pop();
		}
		break;
	case M65816_plb:
		st.db = byte_to_db(st.pop());
		break;
	case M65816_pld: {
		val_t lo = st.pop();
		val_t hi = st.pop();
		st.d = bytes_to_d(lo, hi);
	} break;
	case M65816_plp:
		st.pop();
		break;
	case M65816_plx:
	case M65816_ply:
		st.pop();
		if (!x8) {
			st.pop();
		}
		break;
	case M65816_tcs:
	case M65816_txs:
		st.unknown_stack();
		break;

	case M65816_jsr:
	case M65816_jsl: {
		// every known callee (indirect calls: user xrefs added by the Mesen CDL plugin)
		summary_t s;
		bool any = false;
		xrefblk_t xb;
		for (bool ok = xb.first_from(insn.ea, XREF_CODE | XREF_NOFLOW); ok; ok = xb.next_from()) {
			if (xb.type != fl_CN && xb.type != fl_CF) {
				continue;
			}
			summary_t cs = call_summary(xb.to);
			if (!any) {
				s = cs;
				any = true;
			}
			else {
				s.db = join(s.db, cs.db);
				s.d = join(s.d, cs.d);
				s.stack_balanced = s.stack_balanced && cs.stack_balanced;
			}
		}
		// JSR (abs,X): the targets seen so far are not necessarily all of them
		bool indirect = addrMode == M::Iax;
		apply_summary(st, (any && !indirect) ? s : summary_t::unknown());
	} break;
	case M65816_brk:
	case M65816_cop:
		apply_summary(st, summary_t::unknown());
		break;

	case M65816_rts:
	case M65816_rtl:
	case M65816_rti:
		res.summary.add_return(st);
		is_return = true;
		break;
	case M65816_stp:
		stop = true;
		break;
	default:
		break;
	}
}

bool is_branch_opcode(uint8_t op) {
	M mode = m65816_OpMode[op];
	return mode == M::Rel || mode == M::Rell;
}

// PB a function is entered with, when every call gives the same bank: JSL / JML long carry it in the operand;
// JSR / JMP / branches keep the PB of the calling instruction, used when it is known from the Mesen CDL or set manually.
// Any other reference (indirect long jump, data, ordinary flow) makes it unknown.
val_t entry_pb_from_callers(func_t* pfn) {
	int bank = -1;
	xrefblk_t xb;
	for (bool ok = xb.first_to(pfn->start_ea, XREF_ALL); ok; ok = xb.next_to()) {
		if (!xb.iscode || xb.type == fl_F) {
			return val_t::make(VK_ENTRY);
		}
		if (get_func(xb.from) == pfn) {
			continue; // a loop back to the entry: the same PB
		}
		int b;
		uint8_t op = get_byte(xb.from);
		if (op == 0x22 || op == 0x5C) { // JSL / JML long
			b = get_byte(xb.from + 3);
		}
		else if (op == 0x20 || op == 0x4C || op == 0x7C || op == 0xFC || is_branch_opcode(op)) {
			uint16_t v;
			known_reg_src_t src;
			if (!ea_get_known_reg(xb.from, PROGRAM_BANK_TAG, &v, &src) || (src != KRS_CDL && src != KRS_MANUAL)) {
				return val_t::make(VK_ENTRY);
			}
			b = v & 0xFF;
		}
		else {
			return val_t::make(VK_ENTRY);
		}
		if (bank >= 0 && bank != b) {
			return val_t::make(VK_ENTRY);
		}
		bank = b;
	}
	return bank >= 0 ? val_t::cnst((uint16_t)bank) : val_t::make(VK_ENTRY);
}

const func_result_t& propagator_t::analyze(func_t* pfn) {
	auto found = results.find(pfn->start_ea);
	if (found != results.end()) {
		return found->second;
	}

	in_progress[pfn->start_ea] = true;
	func_result_t res;

	state_t entry;
	entry.db = val_t::make(VK_ENTRY);
	entry.d = val_t::make(VK_ENTRY);
	entry.pb = vector_entries.count(pfn->start_ea) != 0 ? val_t::cnst(0) : entry_pb_from_callers(pfn);
	if (pfn->start_ea == reset_entry) {
		entry.db = val_t::cnst(0);
		entry.d = val_t::cnst(0);
	}
	res.in_states[pfn->start_ea] = entry;

	std::deque<ea_t> work;
	work.push_back(pfn->start_ea);
	size_t steps = 0;

	while (!work.empty() && steps++ < 500000) {
		ea_t ea = work.front();
		work.pop_front();

		insn_t insn;
		if (!is_code(get_flags(ea)) || decode_insn(&insn, ea) <= 0) {
			continue;
		}

		state_t st = res.in_states[ea];
		override_known(ea, st);
		res.in_states[ea] = st; // what the instruction starts with (used for the stored values)

		bool is_return, stop;
		transfer(insn, st, is_return, stop, res);
		if (is_return || stop) {
			continue;
		}

		auto propagate = [&](ea_t to) {
			func_t* tf = get_func(to);
			if (tf == nullptr || tf->start_ea != pfn->start_ea) {
				// jump out of the function: a tail call when it is a function start
				summary_t s = (tf != nullptr && tf->start_ea == to) ? call_summary(to) : summary_t::unknown();
				state_t ret = st;
				apply_summary(ret, s);
				res.summary.add_return(ret);
				return;
			}
			if (to == pfn->start_ea) {
				return; // loop to the entry: the entry state is symbolic, keep it
			}
			auto it = res.in_states.find(to);
			if (it == res.in_states.end()) {
				res.in_states[to] = st;
				work.push_back(to);
			}
			else {
				state_t joined = it->second;
				joined.join_with(st);
				if (!(joined == it->second)) {
					it->second = joined;
					work.push_back(to);
				}
			}
		};

		xrefblk_t xb;
		for (bool ok = xb.first_from(ea, XREF_CODE); ok; ok = xb.next_from()) {
			if (xb.type == fl_F || xb.type == fl_JN || xb.type == fl_JF) {
				propagate(xb.to);
			}
		}
	}

	in_progress[pfn->start_ea] = false;
	return results[pfn->start_ea] = std::move(res);
}

size_t propagator_t::store() {
	size_t changed = 0;

	auto update = [&](ea_t ea, uchar tag, const val_t& v, uint16_t mask) {
		uint16_t cur;
		known_reg_src_t src;
		bool has = ea_get_known_reg(ea, tag, &cur, &src);
		if (has && src != KRS_STATIC) {
			return; // CDL / manual values are never overwritten
		}
		if (v.kind == VK_CONST) {
			if (!has || cur != (v.v & mask)) {
				ea_set_known_reg(ea, tag, v.v & mask, KRS_STATIC);
				plan_ea(ea);
				changed++;
			}
		}
		else if (has) {
			ea_del_known_reg(ea, tag);
			plan_ea(ea);
			changed++;
		}
	};

	std::set<ea_t> visited;
	for (auto& fr : results) {
		for (auto& is : fr.second.in_states) {
			visited.insert(is.first);
			update(is.first, DATA_BANK_TAG, is.second.db, 0xFF);
			update(is.first, DIRECT_PAGE_TAG, is.second.d, 0xFFFF);
			update(is.first, PROGRAM_BANK_TAG, is.second.pb, 0xFF);
		}
	}

	// derived values of code that is no longer reached (undefined, moved out of functions...)
	for (uchar tag : { DATA_BANK_TAG, DIRECT_PAGE_TAG, PROGRAM_BANK_TAG }) {
		std::vector<ea_t> stale;
		for (nodeidx_t idx = helper.altfirst(tag); idx != BADNODE; idx = helper.altnext(idx, tag)) {
			ea_t ea = node2ea(idx);
			uint16_t v;
			known_reg_src_t src;
			if (visited.count(ea) == 0 && ea_get_known_reg(ea, tag, &v, &src) && src == KRS_STATIC) {
				stale.push_back(ea);
			}
		}
		for (ea_t ea : stale) {
			ea_del_known_reg(ea, tag);
			if (is_code(get_flags(ea))) {
				plan_ea(ea);
			}
			changed++;
		}
	}
	return changed;
}

} // namespace

// Reset handler, when nothing else in the code jumps/calls to it (a soft reset could run it with other values)
static ea_t get_reset_entry() {
	ea_t entry = get_reset_vector_target();
	func_t* pfn = get_func(entry);
	if (pfn == nullptr || pfn->start_ea != entry || !is_reset_entry(entry)) {
		return BADADDR;
	}
	return entry;
}

// Handlers of the interrupt / reset vectors ($00:FFE4-$00:FFFF): the CPU runs them in bank $00.
// Only when nothing else in the code jumps/calls to them.
static std::set<ea_t> get_vector_entries() {
	static const uint16_t vectors[] = { 0xFFE4, 0xFFE6, 0xFFE8, 0xFFEA, 0xFFEE, 0xFFF4, 0xFFF8, 0xFFFA, 0xFFFC, 0xFFFE };
	std::set<ea_t> result;
	for (uint16_t vector : vectors) {
		ea_t vec = use_mapping(vector);
		if (!is_mapped(vec) || !is_mapped(vec + 1)) {
			continue;
		}
		ea_t entry = use_mapping(get_word(vec));
		func_t* pfn = get_func(entry);
		xrefblk_t xb;
		if (pfn != nullptr && pfn->start_ea == entry && !xb.first_to(entry, XREF_CODE)) {
			result.insert(entry);
		}
	}
	return result;
}

size_t propagate_known_regs() {
	propagator_t prop;
	prop.reset_entry = get_reset_entry();
	prop.vector_entries = get_vector_entries();
	size_t qty = get_func_qty();
	for (size_t i = 0; i < qty; i++) {
		func_t* pfn = getn_func(i);
		if (pfn != nullptr) {
			prop.analyze(pfn);
		}
	}
	return prop.store();
}
