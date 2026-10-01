#pragma once

#include <idaidp.hpp>
#include <xref.hpp>
#include <offset.hpp>
#include "ins.hpp"
#include <set>

#define BANK_PREFIX "BANK"

enum class m65816_mode : uint8_t {// 
	Im8, // #$00 - one byte
	Imm, // #$00/00 - depend on m
	Imx, // #$00/00 - depend on x
	Sr,   // $00,S - by stack
	Dp,   // $00 - direct page reg
	Dps,  // ($00) - by stack, direct page reg
	Dpx,  // $00,X - direct page reg
	Dpy,  // $00,Y - direct page reg
	Idp,  // ($00) - direct page reg
	Idx,  // ($00,X) - direct page reg
	Idy,  // ($00),Y - direct page reg
	Idl,  // [$00] - direct page reg
	Idly, // [$00],Y - direct page reg
	Isy,  // ($00,S),Y - by stack
	Absd,  // $0000 - by DBR for data
	Absp,  // $0000 - by PBR for jumps
	Abx,  // $0000,X - by DBR for data
	Aby,  // $0000,Y - by DBR for data
	Ablp,  // $000000 - absolute jump
	Abld,  // $000000 - absolute ref
	Alx,  // $000000,X - absolute
	Ind,  // ($0000) - Uses Zero bank
	Iax,  // ($0000,X) - Uses Program bank
	Ial,  // [$000000] - absolute
	Rel,  // $0000 (8 bits PC-relative)
	Rell, // $0000 (16 bits PC-relative)
	Bm,   // $00,$00
	Stk,  // no args
	Regs,  // no args
	Last,
};

typedef m65816_mode M;
const m65816_mode m65816_OpMode[256] = {
	// 0        1       2        3       4        5       6       7        8        9       A        B        C        D        E        F 
	M::Im8,  M::Idx, M::Im8,  M::Sr,  M::Dp,   M::Dp,  M::Dp,  M::Idl,  M::Stk,  M::Imm, M::Regs, M::Stk,  M::Absd, M::Absd, M::Absd, M::Abld, // 0
	M::Rel,  M::Idy, M::Idp,  M::Isy, M::Dp,   M::Dpx, M::Dpx, M::Idly, M::Regs, M::Aby, M::Regs, M::Regs, M::Absd, M::Abx,  M::Abx,  M::Alx,  // 1
	M::Absp, M::Idx, M::Ablp, M::Sr,  M::Dp,   M::Dp,  M::Dp,  M::Idl,  M::Stk,  M::Imm, M::Regs, M::Stk,  M::Absd, M::Absd, M::Absd, M::Abld, // 2
	M::Rel,  M::Idy, M::Idp,  M::Isy, M::Dpx,  M::Dpx, M::Dpx, M::Idly, M::Regs, M::Aby, M::Regs, M::Regs, M::Abx,  M::Abx,  M::Abx,  M::Alx,  // 3
	M::Stk,  M::Idx, M::Im8,  M::Sr,  M::Bm,   M::Dp,  M::Dp,  M::Idl,  M::Stk,  M::Imm, M::Regs, M::Stk,  M::Absp, M::Absd, M::Absd, M::Abld, // 4
	M::Rel,  M::Idy, M::Idp,  M::Isy, M::Bm,   M::Dpx, M::Dpx, M::Idly, M::Regs, M::Aby, M::Stk,  M::Regs, M::Ablp, M::Abx,  M::Abx,  M::Alx,  // 5
	M::Stk,  M::Idx, M::Rell, M::Sr,  M::Dp,   M::Dp,  M::Dp,  M::Idl,  M::Stk,  M::Imm, M::Regs, M::Stk,  M::Ind,  M::Absd, M::Absd, M::Abld, // 6
	M::Rel,  M::Idy, M::Idp,  M::Isy, M::Dpx,  M::Dpx, M::Dpx, M::Idly, M::Regs, M::Aby, M::Stk,  M::Regs, M::Iax,  M::Abx,  M::Abx,  M::Alx,  // 7
	M::Rel,  M::Idx, M::Rell, M::Sr,  M::Dp,   M::Dp,  M::Dp,  M::Idl,  M::Regs, M::Imm, M::Regs, M::Stk,  M::Absd, M::Absd, M::Absd, M::Abld, // 8
	M::Rel,  M::Idy, M::Idp,  M::Isy, M::Dpx,  M::Dpx, M::Dpy, M::Idly, M::Regs, M::Aby, M::Regs, M::Regs, M::Absd, M::Abx,  M::Abx,  M::Alx,  // 9
	M::Imx,  M::Idx, M::Imx,  M::Sr,  M::Dp,   M::Dp,  M::Dp,  M::Idl,  M::Regs, M::Imm, M::Regs, M::Stk,  M::Absd, M::Absd, M::Absd, M::Abld, // A
	M::Rel,  M::Idy, M::Idp,  M::Isy, M::Dpx,  M::Dpx, M::Dpy, M::Idly, M::Regs, M::Aby, M::Regs, M::Regs, M::Abx,  M::Abx,  M::Aby,  M::Alx,  // B
	M::Imx,  M::Idx, M::Im8,  M::Sr,  M::Dp,   M::Dp,  M::Dp,  M::Idl,  M::Regs, M::Imm, M::Regs, M::Regs, M::Absd, M::Absd, M::Absd, M::Abld, // C
	M::Rel,  M::Idy, M::Idp,  M::Isy, M::Dps,  M::Dpx, M::Dpx, M::Idly, M::Regs, M::Aby, M::Stk,  M::Regs, M::Ial,  M::Abx,  M::Abx,  M::Alx,  // D
	M::Imx,  M::Idx, M::Im8,  M::Sr,  M::Dp,   M::Dp,  M::Dp,  M::Idl,  M::Regs, M::Imm, M::Regs, M::Regs, M::Absd, M::Absd, M::Absd, M::Abld, // E
	M::Rel,  M::Idy, M::Idp,  M::Isy, M::Absd, M::Dpx, M::Dpx, M::Idly, M::Regs, M::Aby, M::Stk,  M::Regs, M::Iax,  M::Abx,  M::Abx,  M::Alx   // F
};

const uint8_t m65816_OpSize[] = {
	2, // Im8
	0, // Imm
	0, // Imx
	2, // Sr
	2, // Dp
	2, // Dps
	2, // Dpx
	2, // Dpy
	2, // Idp
	2, // Idx
	2, // Idy
	2, // Idl
	2, // Idly
	2, // Isy
	3, // Absd
	3, // Absp
	3, // Abx
	3, // Aby
	4, // Ablp
	4, // Abld
	4, // Alx
	3, // Ind
	3, // Iax
	3, // Ial
	2, // Rel
	3, // Rell
	3, // Bm
	1, // Stk
	1, // Regs
};

CASSERT(static_cast<int>(M::Last) == qnumber(m65816_OpSize));

enum m65816_regs : int {
	rA, rX, rY, rSP, rPC, rD, rDB, rP,
	rVcs, rVds
};

enum m65816_flags : uint8_t {
	Carry = 0x01,
	Zero = 0x02,
	IrqDisable = 0x04,
	Decimal = 0x08,

	/* Use 8-bit operations on indexes */
	IndexMode8 = 0x10,

	/* Use 8-bit operations on memory accesses and accumulator */
	MemoryMode8 = 0x20,

	Overflow = 0x40,
	Negative = 0x80
};

static const char  switch_bitmode_action_name[] = "65816:switch_bitmode";
static const char set_cur_offset_bank_action_name[] = "65816:set_cur_offset_bank";
static const char set_sel_offset_bank_action_name[] = "65816:set_sel_offset_bank";
static const char set_wram_offset_bank_action_name[] = "65816:set_wram_offset_bank";
static const char set_zero_offset_bank_action_name[] = "65816:set_zero_offset_bank";
static const char set_cust_offset_bank_action_name[] = "65816:set_cust_offset_bank";

extern netnode helper;
extern bool can_change_mem_mode(ea_t ea);
extern bool can_change_idx_mode(ea_t ea);

#define FLAGS_BITMODE_TAG ('P')
#define MANUAL_BITMODE_TAG ('O')
#define MANUAL_BASE_TAG ('R')

inline void ea_set_flags(ea_t ea, uint8_t flags) {
	helper.charset_ea(ea, flags, FLAGS_BITMODE_TAG);
}

// MANUAL_BITMODE_TAG: 1 = M/X set by the user, 2 = set by the M/X conflict fix (mxfix.cpp), which may move it later.
// Both stop the flags from being inherited from the code flow.
inline void ea_set_manual_bitmode(ea_t ea, bool manual) {
	helper.charset_ea(ea, manual ? 1 : 0, MANUAL_BITMODE_TAG);
}

inline void ea_set_auto_bitmode(ea_t ea) {
	helper.charset_ea(ea, 2, MANUAL_BITMODE_TAG);
}

inline bool ea_is_manual_bitmode(ea_t ea) {
	uint8_t res = helper.charval_ea(ea, MANUAL_BITMODE_TAG);
	return res == 1 || res == 2;
}

inline bool ea_is_user_bitmode(ea_t ea) {
	return helper.charval_ea(ea, MANUAL_BITMODE_TAG) == 1;
}

inline bool ea_is_auto_bitmode(ea_t ea) {
	return helper.charval_ea(ea, MANUAL_BITMODE_TAG) == 2;
}

inline uint8_t ea_get_flags(ea_t ea) {
	uint8_t res = helper.charval_ea(ea, FLAGS_BITMODE_TAG);

	if (res == 0xFF) {
		res = 0;
	}

	return res;
}

inline uint8_t ea_set_mem_bitmode(ea_t ea, bool clear) {
	uint8_t prev = ea_get_flags(ea);

	if (clear) {
		prev &= ~m65816_flags::MemoryMode8;
	}
	else {
		prev |= m65816_flags::MemoryMode8;
	}

	helper.charset_ea(ea, prev, FLAGS_BITMODE_TAG);
	return prev;
}

inline uint8_t ea_set_idx_bitmode(ea_t ea, bool clear) {
	uint8_t prev = ea_get_flags(ea);

	if (clear) {
		prev &= ~m65816_flags::IndexMode8;
	}
	else {
		prev |= m65816_flags::IndexMode8;
	}

	helper.charset_ea(ea, prev, FLAGS_BITMODE_TAG);
	return prev;
}

inline void ea_del_flags(ea_t ea) {
	helper.chardel_ea(ea, FLAGS_BITMODE_TAG);
}

// The bank of an offset operand (O, or Ctrl+R) is the base of its IDA reference info: the operand value is added to it.
// The target and the target delta of the reference info (Ctrl+R) are used too: "loc_C01B0E-1".
inline ea_t ea_get_bank(ea_t ea) {
	refinfo_t ri;
	if (!is_off(get_flags(ea), 0) || !get_refinfo(&ri, ea, 0) || ri.base == BADADDR) {
		return BADADDR;
	}
	return ri.base;
}

// size: operand size in bytes
inline void ea_set_bank(ea_t ea, int n, ea_t bank, int size) {
	reftype_t type = size == 1 ? REF_OFF8 : size == 2 ? REF_OFF16 : REF_OFF32;
	op_offset(ea, n, type, BADADDR, bank, 0);
}

inline void ea_clr_bank(ea_t ea) {
	refinfo_t ri;
	if (get_refinfo(&ri, ea, 0)) {
		del_refinfo(ea, 0);
	}
}

// Indexed operand: the instruction accesses the address + X/Y, the address itself may never be accessed
// (a table indexed from 1, a field of a structure), so nothing is known about the data there
inline bool is_indexed_operand(const insn_t& insn) {
	switch (static_cast<M>(insn.insnpref)) {
	case M::Abx:
	case M::Aby:
	case M::Alx:
	case M::Dpx:
	case M::Dpy:
	case M::Idx:
		return true;
	default:
		return false;
	}
}

// Full address of an operand: the operand value with the bank of an offset added (the value itself stays as encoded,
// so that IDA's reference info base + value gives the address, as Ctrl+R shows it)
inline ea_t op_full_addr(const insn_t& insn, const op_t& x) {
	ea_t bank = ea_get_bank(insn.ea);
	return bank == BADADDR ? x.addr : (x.addr | bank);
}

// The target of an offset: the address the operand value points to (value), unless the reference info names another
// target or a target delta (Ctrl+R); then the operand is shown as "target + difference"
inline ea_t op_ref_target(ea_t ea, int n, ea_t value) {
	refinfo_t ri;
	if (!is_off(get_flags(ea), n) || !get_refinfo(&ri, ea, n)) {
		return value;
	}
	if (ri.target != BADADDR) {
		return ri.target;
	}
	return value - ri.tdelta;
}

// 24-bit data (reg.cpp): custom data type "d24" and its "number" / "offset" formats
extern int data24_id;
extern int data24_num_fid;
extern int data24_off_fid;
bool toggle_data24_offset(ea_t ea);
bool create_data24_offset(ea_t ea);
bool search_immediate_action(const char* name);

// C (emu.cpp): the code created from the cursor is followed through addresses IDA marked as "not code"
// when code was undefined there (U) before
void note_user_code(ea_t ea);
bool toggle_data24_type_member(const til_type_ref_t* ref);

// !!! problems TODO:
// C18A1A (C18A4F)

enum class set_offset_bank_mode_t : uint8_t {
	SOB_CURRENT,
	SOB_SELECT,
	SOB_WRAM,
	SOB_ZERO,
	SOB_CUSTOM,
};

struct set_offset_bank_action_t : public action_handler_t {
private:
	set_offset_bank_mode_t _mode;
public:
	set_offset_bank_action_t(set_offset_bank_mode_t mode) : _mode(mode) {}

	virtual int idaapi activate(action_activation_ctx_t* ctx) {
		if (ctx->type_ref != nullptr) {
			// a type listing (Local Types): only data24_t fields are handled here
			toggle_data24_type_member(ctx->type_ref);
			return 1;
		}
		if (toggle_data24_offset(ctx->cur_ea)) {
			return 1; // d24: number <-> offset
		}
		if (create_data24_offset(ctx->cur_ea)) {
			return 1; // unexplored bytes: d24 offset
		}
		ea_clr_bank(ctx->cur_ea);

		int opnum = get_opnum();

		if (opnum == -1) {
			return 1;
		}

		insn_t insn;

		ea_t op_addr = 0;
		ea_t start_ea = BADADDR;
		set_offset_bank_mode_t mode = _mode;

		if (is_code(get_flags(ctx->cur_ea)) && decode_insn(&insn, ctx->cur_ea)) {
			M addrMode = static_cast<M>(insn.insnpref);

			switch (addrMode) {
			case M::Alx: // $000000,X - absolute (opcodes: $FF/SBC, $DF/CMP, $BF/LDA, $9F/STA, $7F/ADC, $5F/EOR, $3F/AND, $1F/ORA)
			case M::Abld: // $000000 - absolute ref (opcodes: $EF/SBC, $CF/CMP, $AF/LDA, $8F/STA, $6F/ADC, $4F/EOR, $2F/AND, $0F/ORA)
			case M::Ablp: // $000000 - absolute jump (opcodes: $5C/JML-JMP, $22/JSL)
			case M::Ial: { // [$000000] - absolute (opcodes: $DC/JML-JMP)
				mode = set_offset_bank_mode_t::SOB_ZERO;
			} break;
			}
		}

		switch (mode) {
		case set_offset_bank_mode_t::SOB_CURRENT: {
			start_ea = ctx->cur_ea & 0xFF0000;

			if (!is_mapped(start_ea)) {
				segment_t* seg = getseg(ctx->cur_ea);
				start_ea = (seg != nullptr) ? seg->start_ea : BADADDR;
			}
		} break;
		case set_offset_bank_mode_t::SOB_SELECT: {
			qstring title;
			title.sprnt("Choose Bank for offset %a at %a", ctx->cur_value, ctx->cur_ea);

			start_ea = ctx->cur_ea & 0xFF0000;

			if (!is_mapped(start_ea)) {
				segment_t* seg = getseg(ctx->cur_ea);
				start_ea = (seg != nullptr) ? seg->start_ea : BADADDR;
			}

			segment_t* seg = choose_segm(title.c_str(), start_ea);
			start_ea = (seg != nullptr) ? seg->start_ea : BADADDR;
		} break;
		case set_offset_bank_mode_t::SOB_ZERO: {
			segment_t* seg = getseg(0);
			start_ea = (seg != nullptr) ? seg->start_ea : BADADDR;
		} break;
		case set_offset_bank_mode_t::SOB_CUSTOM: {
			ea_t asked_addr = BADADDR;
			if (ask_addr(&asked_addr, "Enter specific value offset") && asked_addr != BADADDR && is_mapped(asked_addr)) {
				start_ea = asked_addr;
			}
		} break;
		default: { // WRAM
			segment_t* seg = getseg(use_mapping(0)); // by default it points to zero page
			start_ea = (seg != nullptr) ? seg->start_ea : BADADDR;
		} break;
		}

		//if (is_data(get_flags32(ctx->cur_ea)) || !decode_insn(&insn, ctx->cur_ea)) {
		//	show = true;
		//}
		//else {
		//	op_t op = insn.ops[opnum];
		//	op_addr = op.addr;

		//	switch (op.type) {
		//	case o_mem: {
		//		M addrMode = static_cast<M>(insn.insnpref);

		//		switch (addrMode) {
		//		case M::Dp:
		//		case M::Dpx:
		//		case M::Dpy:
		//		case M::Idp:
		//		case M::Idx:
		//		case M::Idy:
		//		case M::Idl:
		//		case M::Idly: { // Uses Direct Page Reg
		//		} break;
		//		case M::Abx:
		//		case M::Aby: { // Uses Data Bank Reg
		//			show = true;
		//		} break;
		//		}
		//	}
		//	case o_near: {
		//		show = true;
		//	} break;
		//	case o_imm: {
		//		show = true;
		//	} break;
		//	}
		//}

		if (start_ea != BADADDR) {
			// the operand size: of the operand of an instruction, or of the data item
			int size = get_item_size(ctx->cur_ea);
			if (is_code(get_flags(ctx->cur_ea)) && decode_insn(&insn, ctx->cur_ea)) {
				size = insn.size - insn.ops[opnum].offb;
			}
			ea_set_bank(ctx->cur_ea, opnum, start_ea, size);
			plan_ea(ctx->cur_ea);
		}

		return 1;
	}

	virtual action_state_t idaapi update(action_update_ctx_t* ctx) {
		return AST_ENABLE_ALWAYS;
	}
};

struct set_cur_offset_bank_action_t : public set_offset_bank_action_t {
	set_cur_offset_bank_action_t() : set_offset_bank_action_t(set_offset_bank_mode_t::SOB_CURRENT) {}
};

struct set_sel_offset_bank_action_t : public set_offset_bank_action_t {
	set_sel_offset_bank_action_t() : set_offset_bank_action_t(set_offset_bank_mode_t::SOB_SELECT) {}
};

struct set_wram_offset_bank_action_t : public set_offset_bank_action_t {
	set_wram_offset_bank_action_t() : set_offset_bank_action_t(set_offset_bank_mode_t::SOB_WRAM) {}
};

struct set_zero_offset_bank_action_t : public set_offset_bank_action_t {
	set_zero_offset_bank_action_t() : set_offset_bank_action_t(set_offset_bank_mode_t::SOB_ZERO) {}
};

struct set_cust_offset_bank_action_t : public set_offset_bank_action_t {
	set_cust_offset_bank_action_t() : set_offset_bank_action_t(set_offset_bank_mode_t::SOB_CUSTOM) {}
};

// Reset handler (target of the vector at $00:FFFC), or BADADDR.
// After a reset the CPU runs it in emulation mode (M = X = 1) with DB = $00, D = $0000.
inline ea_t get_reset_vector_target() {
	ea_t vec = use_mapping(0xFFFC);
	if (!is_mapped(vec) || !is_mapped(vec + 1)) {
		return BADADDR;
	}
	return use_mapping(get_word(vec));
}

// The reset state is only certain when no code jumps/calls to the handler (a soft reset could run it in another state)
inline bool is_reset_entry(ea_t ea) {
	if (ea != get_reset_vector_target()) {
		return false;
	}
	xrefblk_t xb;
	return !xb.first_to(ea, XREF_CODE);
}

// Known data bank (DB) / direct page (D) register values per instruction (value at the start of the instruction).
// Stored as (source << 24) | (value + 1); 0 = unknown.
#define DATA_BANK_TAG ('b')
#define DIRECT_PAGE_TAG ('D')
#define PROGRAM_BANK_TAG ('k')

enum known_reg_src_t : uint8_t {
	KRS_NONE = 0,
	KRS_STATIC = 1, // derived from the code by propagate_known_regs()
	KRS_CDL = 2,    // Mesen CDL: the instruction always ran with this value
	KRS_MANUAL = 3, // set by the user (Shift+X)
	KRS_CDL_SAME_TARGET = 4, // Mesen CDL: DB varied, but every observed value gives the same address for this operand
	                         // (e.g. $00/$80); used for this instruction only, never propagated
};

inline bool ea_get_known_reg(ea_t ea, uchar tag, uint16_t* value, known_reg_src_t* src = nullptr) {
	nodeidx_t v = helper.altval_ea(ea, tag);
	if (v == 0) {
		return false;
	}
	*value = (uint16_t)((v & 0xFFFFFF) - 1);
	if (src != nullptr) {
		uint8_t s = (uint8_t)(v >> 24);
		*src = (s == KRS_NONE) ? KRS_CDL : (known_reg_src_t)s; // values written without a source came from the CDL plugin
	}
	return true;
}

inline void ea_set_known_reg(ea_t ea, uchar tag, uint16_t value, known_reg_src_t src) {
	helper.altset_ea(ea, ((nodeidx_t)src << 24) | ((nodeidx_t)value + 1), tag);
}

inline void ea_del_known_reg(ea_t ea, uchar tag) {
	helper.altdel_ea(ea, tag);
}

enum : uint8_t {
	EKR_DB = 1,
	EKR_D = 2,
	EKR_PB = 4,
};

// Which of DB / D / PB the operand of an instruction depends on (for the reference that is created from it)
inline uint8_t insn_known_regs_used(ea_t ea) {
	insn_t insn;
	if (!is_code(get_flags(ea)) || decode_insn(&insn, ea) <= 0) {
		return 0;
	}
	switch (static_cast<M>(insn.insnpref)) {
	case M::Absd:
	case M::Abx:
	case M::Aby:
		return insn.itype == M65816_pea ? 0 : EKR_DB;
	case M::Dp:
	case M::Dps:
	case M::Dpx:
	case M::Dpy:
	case M::Idp:
	case M::Idx:
	case M::Idy:
	case M::Idl:
	case M::Idly:
		return EKR_D; // the operand is the direct page location (a pointer for the indirect modes)
	case M::Absp:
	case M::Iax:
		return EKR_PB; // JMP/JSR abs, JMP/JSR (abs,X)
	default:
		return 0;
	}
}

// decodes the code from ea again along the ordinary flow, after its M/X flags changed (mxfix.cpp)
void redecode_flow_from(ea_t ea);

// Known DB / D / PB values of an instruction (or of every instruction of a range) edited in one dialog.
// regs: which fields are shown (EKR_DB / EKR_D / EKR_PB).
// Values are used from there on along the code flow until the register changes.
// An empty field clears the manual value. Returns true when something changed.
// For a single instruction the M and X flags are edited too: a changed flag is set manually (the flags are no longer
// inherited from the code flow there), both fields empty make the instruction inherit them again.
inline bool edit_known_regs(ea_t start, ea_t end, bool is_range, uint8_t regs) {
	struct field_t {
		uchar tag;
		uint8_t reg;
		const char* name;
		const char* label;
		uint32_t max;
		qstring text;
		qstring orig;
		bool changed = false;
		bool clear = false;
		bool suggested = false;
		qstring orig_suggestion;
		uint16_t value = 0;
	};
	field_t fields[] = {
		{ DATA_BANK_TAG, EKR_DB, "DB", "<~D~ata bank (DB)    :q:4:6::>\n", 0xFF },
		{ DIRECT_PAGE_TAG, EKR_D, "D", "<Direct ~p~age (D)   :q:6:6::>\n", 0xFFFF },
		{ PROGRAM_BANK_TAG, EKR_PB, "PB", "<Pro~g~ram bank (PB) :q:4:6::>\n", 0xFF },
	};

	qstring info, inputs;
	qvector<qstring*> args;
	for (field_t& f : fields) {
		if ((regs & f.reg) == 0) {
			continue;
		}
		uint16_t v;
		known_reg_src_t src;
		if (ea_get_known_reg(start, f.tag, &v, &src)) {
			f.text.sprnt(f.max == 0xFF ? "%02X" : "%04X", v);
			info.cat_sprnt("%s=%s: %s\n", f.name, f.text.c_str(),
				src == KRS_STATIC ? "derived from the code" : src == KRS_CDL ? "Mesen CDL" : src == KRS_MANUAL ? "set manually" :
				src == KRS_CDL_SAME_TARGET ? "Mesen CDL (varied, same address)" : "");
		}
		f.orig = f.text;
		// unknown register the operand depends on (every register for a selection): suggest DB = $00, D = $0000,
		// PB = the bank of the instruction; confirming sets it manually
		if (f.text.empty() && (is_range || (insn_known_regs_used(start) & f.reg) != 0)) {
			f.suggested = true;
			if (f.reg == EKR_PB) {
				f.text.sprnt("%02X", (uint32)((start >> 16) & 0xFF));
			}
			else {
				f.text = (f.max == 0xFF) ? "00" : "0000";
			}
			f.orig_suggestion = f.text;
		}
		inputs.append(f.label);
		args.push_back(&f.text);
	}

	// M / X of a single instruction
	uint8_t old_flags = ea_get_flags(start);
	bool old_manual = ea_is_manual_bitmode(start);
	qstring m_text, x_text;
	if (!is_range) {
		m_text = (old_flags & m65816_flags::MemoryMode8) ? "1" : "0";
		x_text = (old_flags & m65816_flags::IndexMode8) ? "1" : "0";
		info.cat_sprnt("M=%s, X=%s: %s\n", m_text.c_str(), x_text.c_str(),
			old_manual ? "set manually" : "from the code flow");
		inputs.append("<~M~ (1 = 8-bit A)     :q:2:6::>\n");
		inputs.append("<~X~ (1 = 8-bit X, Y)  :q:2:6::>\n");
		args.push_back(&m_text);
		args.push_back(&x_text);
	}
	if (args.empty()) {
		return false;
	}
	qstring m_orig = m_text, x_orig = x_text;

	// field widths include the terminating zero; an optional '$' prefix is accepted
	qstring form;
	form.sprnt(
		"Known register values\n"
		"\n"
		"%s, hex. Used from there on until the register changes.\n"
		"Empty = no manual value%s.\n"
		"%s"
		"\n"
		"%s"
		"\n",
		is_range ? "For every instruction of the selection" : "At this instruction",
		is_range ? "" : " (M and X both empty: inherit them from the code flow)",
		info.c_str(),
		inputs.c_str());
	int res = 0;
	switch (args.size()) {
	case 1: res = ask_form(form.c_str(), args[0]); break;
	case 2: res = ask_form(form.c_str(), args[0], args[1]); break;
	case 3: res = ask_form(form.c_str(), args[0], args[1], args[2]); break;
	case 4: res = ask_form(form.c_str(), args[0], args[1], args[2], args[3]); break;
	default: res = ask_form(form.c_str(), args[0], args[1], args[2], args[3], args[4]); break;
	}
	if (res != 1) {
		return false;
	}

	// M / X: parsed before anything is changed
	bool mx_changed = false;
	bool mx_inherit = false;
	uint8_t new_flags = old_flags;
	if (!is_range) {
		m_text.trim2();
		x_text.trim2();
		if (m_text.empty() && x_text.empty()) {
			mx_inherit = old_manual;
			mx_changed = old_manual;
		}
		else if (m_text != m_orig || x_text != x_orig) {
			struct { qstring* text; uint8_t bit; const char* name; } mx[] = {
				{ &m_text, m65816_flags::MemoryMode8, "M" },
				{ &x_text, m65816_flags::IndexMode8, "X" },
			};
			for (auto& f : mx) {
				if (f.text->empty()) {
					continue; // keeps the current value
				}
				if (*f.text != "0" && *f.text != "1") {
					warning("Invalid %s value: %s (0 or 1)", f.name, f.text->c_str());
					return false;
				}
				new_flags = (*f.text == "1") ? (new_flags | f.bit) : (new_flags & ~f.bit);
			}
			mx_changed = new_flags != old_flags || !old_manual;
		}
	}

	for (field_t& f : fields) {
		if ((regs & f.reg) == 0) {
			continue;
		}
		f.text.trim2();
		if (f.text == f.orig) {
			continue; // untouched: keep whatever the instruction has (CDL / derived values stay as they are)
		}
		if (f.suggested && mx_changed && f.text == f.orig_suggestion) {
			continue; // only M / X were edited: the suggested value is not confirmed
		}
		f.changed = true;
		f.clear = f.text.empty();
		if (!f.clear) {
			const char* p = f.text.c_str();
			if (*p == '$') {
				p++;
			}
			char* endp = nullptr;
			uint64 value = strtoull(p, &endp, 16);
			if (endp == p || *endp != '\0' || value > f.max) {
				warning("Invalid %s value: %s", f.name, f.text.c_str());
				return false;
			}
			f.value = (uint16_t)value;
		}
	}

	size_t count = 0;
	for (ea_t ea = start; ea < end && ea != BADADDR; ea = next_head(ea, end)) {
		if (!is_code(get_flags(ea))) {
			continue;
		}
		count++;
		uint8_t used = insn_known_regs_used(ea);
		bool reset_repr = false;
		for (field_t& f : fields) {
			if (!f.changed) {
				continue;
			}
			if (f.clear) {
				uint16_t v;
				known_reg_src_t src;
				if (ea_get_known_reg(ea, f.tag, &v, &src) && src == KRS_MANUAL) {
					ea_del_known_reg(ea, f.tag);
				}
			}
			else {
				ea_set_known_reg(ea, f.tag, f.value, KRS_MANUAL);
				reset_repr |= (used & f.reg) != 0;
			}
		}
		// the register the operand depends on was set explicitly: the reference comes from it, so a representation
		// chosen before (O, Q, #...) and the bank of O are dropped
		if (reset_repr) {
			if (is_defarg(get_flags(ea), 0)) {
				clr_op_type(ea, 0);
			}
			ea_clr_bank(ea);
		}
		plan_ea(ea);
	}

	bool changed = false;
	if (mx_changed) {
		changed = true;
		if (mx_inherit) {
			ea_set_manual_bitmode(start, false);
			msg("M/X at %a: inherited from the code flow again\n", start);
		}
		else {
			ea_set_flags(start, new_flags);
			ea_set_manual_bitmode(start, true);
			msg("M/X at %a: M=%d, X=%d set manually\n", start,
				(new_flags & m65816_flags::MemoryMode8) ? 1 : 0, (new_flags & m65816_flags::IndexMode8) ? 1 : 0);
		}
		redecode_flow_from(start);
	}
	for (field_t& f : fields) {
		if (!f.changed) {
			continue;
		}
		changed = true;
		if (f.clear) {
			msg("%s: manual value cleared on %u instruction(s) at %a\n", f.name, (unsigned)count, start);
		}
		else {
			msg(f.max == 0xFF ? "%s: $%02X set on %u instruction(s) at %a\n" : "%s: $%04X set on %u instruction(s) at %a\n",
				f.name, (unsigned)f.value, (unsigned)count, start);
		}
	}
	return changed;
}

// Shift+X: switches the operand size of an immediate operand that depends on M/X,
// otherwise edits the known DB / D / PB values and M / X of the instruction (DB / D / PB of every instruction of the selection).
struct switch_bitmode_action_t : public action_handler_t {
	bool* dirty = nullptr;

	virtual int idaapi activate(action_activation_ctx_t* ctx) {
		ea_t start = ctx->cur_ea;
		ea_t end = BADADDR;
		// read_range_selection() alone is not enough: without a selection it may still return an (empty) range
		bool has_range = ctx->has_flag(ACF_HAS_SELECTION) && ctx->widget != nullptr
			&& read_range_selection(ctx->widget, &start, &end) && start != BADADDR && start < end;
		if (!has_range) {
			start = ctx->cur_ea;
			end = get_item_end(start);
		}
		if (start == BADADDR) {
			return 1;
		}

		if (!has_range) {
			int can_change_mode = 0;
			can_change_mode |= can_change_mem_mode(start) ? 1 : 0;
			can_change_mode |= can_change_idx_mode(start) ? 2 : 0;

			if (can_change_mode != 0) {
				uint8_t flags = ea_get_flags(start);
				if (can_change_mode & 1) {
					flags ^= m65816_flags::MemoryMode8;
				}
				else {
					flags ^= m65816_flags::IndexMode8;
				}
				ea_set_flags(start, flags);
				ea_set_manual_bitmode(start, true);
				return 1;
			}
		}

		// only the register the operand depends on; all of them for other instructions and for a selection
		uint8_t regs = has_range ? 0 : insn_known_regs_used(start);
		if (regs == 0) {
			regs = EKR_DB | EKR_D | EKR_PB;
		}
		if (edit_known_regs(start, end, has_range, regs) && dirty != nullptr) {
			*dirty = true;
		}
		return 1;
	}

	virtual action_state_t idaapi update(action_update_ctx_t* ctx) {
		return AST_ENABLE_ALWAYS;
	}
};

// Register info of an instruction (out.cpp): short lines for the listing, long lines for the hint
void describe_insn(const insn_t& insn, qstrvec_t* listing, qstrvec_t* hint);

// Hint with the register info when the mouse is over an instruction in the disassembly.
// IDA's own hint (e.g. for a name under the mouse) is kept below it.
struct reg_hint_listener_t : public event_listener_t {
	virtual ssize_t idaapi on_event(ssize_t code, va_list va) override {
		if (code == ui_preprocess_action) {
			const char* name = va_arg(va, const char*);
			if (name != nullptr && strcmp(name, "MakeCode") == 0) {
				note_user_code(get_screen_ea());
				return 0;
			}
			// Alt+I / Ctrl+I: any 3 bytes forming the value are searched too (reg.cpp)
			return search_immediate_action(name) ? 1 : 0;
		}
		if (code != ui_get_custom_viewer_hint) {
			return 0;
		}
		qstring* hint = va_arg(va, qstring*);
		TWidget* viewer = va_arg(va, TWidget*);
		place_t* place = va_arg(va, place_t*);
		int* important_lines = va_arg(va, int*);
		if (hint == nullptr || place == nullptr || important_lines == nullptr || get_widget_type(viewer) != BWN_DISASM) {
			return 0;
		}

		ea_t ea = place->toea();
		insn_t insn;
		if (!is_code(get_flags(ea)) || get_item_head(ea) != ea || decode_insn(&insn, ea) <= 0) {
			return 0;
		}

		qstrvec_t lines;
		describe_insn(insn, nullptr, &lines);
		if (lines.empty()) {
			return 0;
		}

		for (const qstring& line : lines) {
			hint->append(line);
			hint->append('\n');
			(*important_lines)++;
		}
		if (hint->find(REG_HINTS_MARKER) == qstring::npos) {
			hint->append(REG_HINTS_MARKER);
		}
		return 0;
	}
};

// Static DB/D propagation (dbdp.cpp). Returns the number of instructions whose derived values changed.
size_t propagate_known_regs();

// M/X corrections when the code flow runs into an opcode the ROM doesn't use (mxfix.cpp).
// Returns true when the code was changed.
bool fix_mx_conflicts(std::set<ea_t>& conflicts, ushort idpflags);

struct m65816_t;

// Work done when the auto-analysis queues are empty (m65816_t::on_auto_idle): resolves the M/X conflicts found
// meanwhile, then runs the DB/D propagation if the code changed since the last run. Changed instructions are
// reanalysed and this runs again after that analysis, until nothing changes anymore.
// Triggered by idb_event::auto_empty (initial analysis) and by a UI timer (any later change).
struct known_regs_listener_t : public event_listener_t {
	m65816_t* pm = nullptr;

	virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

int idaapi known_regs_timer_cb(void* ud);

struct m65816_t : public procmod_t {
#define ROM_NO_BRK 0x01
#define ROM_NO_COP 0x02
#define ROM_NO_WDM 0x04
#define SHOW_REG_CMTS 0x08 // register info as listing comments (it is always available as a hint)
	ushort idpflags = ROM_NO_BRK | ROM_NO_COP | ROM_NO_WDM;

	bool in_data24_repr = false; // guards against the events caused by apply_data24_repr()
	void ensure_data24_typedef();
	std::set<ea_t> new_tbytes; // 3-byte tbytes just created (D): turned into d24 when the analysis is idle
	void convert_new_tbytes();
	void setup_data_carousel();
	void apply_data24_repr(const char* udtname);

	switch_bitmode_action_t switch_bitmode;
	set_cur_offset_bank_action_t set_cur_offset_bank;
	set_sel_offset_bank_action_t set_sel_offset_bank;
	set_wram_offset_bank_action_t set_wram_offset_bank;
	set_zero_offset_bank_action_t set_zero_offset_bank;
	set_cust_offset_bank_action_t set_cust_offset_bank;

	action_desc_t switch_bitmode_action = ACTION_DESC_LITERAL_PROCMOD(switch_bitmode_action_name, "Switch flag / set DB, D, PB, M, X", &switch_bitmode, this, "Shift+X", NULL, -1);
	action_desc_t set_cur_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_cur_offset_bank_action_name, "Change bank to current", &set_cur_offset_bank, this, "O", NULL, -1);
	action_desc_t set_sel_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_sel_offset_bank_action_name, "Change bank to selected", &set_sel_offset_bank, this, "Ctrl+O", NULL, -1);
	action_desc_t set_wram_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_wram_offset_bank_action_name, "Change bank to WRAM", &set_wram_offset_bank, this, "Shift+O", NULL, -1);
	action_desc_t set_zero_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_zero_offset_bank_action_name, "Change bank to ZERO", &set_zero_offset_bank, this, "Ctrl+Shift+O", NULL, -1);
	action_desc_t set_cust_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_cust_offset_bank_action_name, "Change bank to custom", &set_cust_offset_bank, this, "Ctrl+Alt+O", NULL, -1);


	// set when code changed since the last DB/D propagation
	bool known_regs_dirty = true;
	known_regs_listener_t known_regs_listener;
	// instructions the code flow reached but which are opcodes the ROM doesn't use (see mxfix.cpp)
	std::set<ea_t> mx_conflicts;
	void note_mx_conflict(ea_t ea);
	// functions that couldn't be created because their code ran into undefined bytes (often the result of an
	// M/X conflict): created again once the flags are fixed; value = attempts left
	std::map<ea_t, int> failed_funcs;
	bool retry_failed_funcs = false;
	qtimer_t idle_timer = nullptr;
	void on_auto_idle();
	reg_hint_listener_t reg_hint_listener;

	bool recurse_ana = false;
	
	const char* idaapi set_idp_options(const char* keyword, int value_type, const void* value, bool idb_loaded);

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
  int idaapi ana(insn_t* _insn);
  int idaapi emu(const insn_t& insn);
  void handle_operand(const op_t& x, bool read_access, const insn_t& insn);
  void m65816_data(outctx_t& ctx, bool analyze_only);
	void out_banked_val(outctx_t& ctx, bool analyze_only);

	// bit 15 marks that the options were saved (altval returns 0 when nothing was stored)
	void save_idpflags() { helper.altset(-1, idpflags | 0x8000); }
	void load_from_idb() {
		nodeidx_t v = helper.altval(-1);
		if (v & 0x8000) {
			idpflags = (ushort)(v & ~0x8000);
		}
	}
};

// Bank + 16-bit address -> ea of the accessed memory, or BADADDR
inline ea_t get_data_target(uint32_t bank, uint32_t addr) {
	bool system_bank = bank < 0x40 || (bank >= 0x80 && bank < 0xC0);
	if (system_bank && addr < 0x2000) {
		ea_t ea = 0x7E0000 + addr; // first 8 KB of WRAM, mirrored in every system bank
		return is_mapped(ea) ? ea : BADADDR;
	}
	ea_t ea = use_mapping((ea_t)((bank << 16) | addr));
	return is_mapped(ea) ? ea : BADADDR;
}

// Size of the data an o_mem operand refers to: the value read/written (by M, or by X for LDX/LDY/STX/STY/CPX/CPY),
// or the pointer for the indirect modes (2 bytes, 3 for [dp]; tbyte is 3 bytes for this processor)
inline op_dtype_t get_data_dtype(uint16_t itype, M mode, uint8_t flags) {
	switch (mode) {
	case M::Idp: case M::Idx: case M::Idy: case M::Isy: case M::Dps:
		return dt_word;
	case M::Idl: case M::Idly:
		return dt_tbyte;
	default:
		break;
	}
	if (itype == M65816_pea) {
		return dt_word;
	}
	bool index_reg = itype == M65816_ldx || itype == M65816_ldy || itype == M65816_stx || itype == M65816_sty
		|| itype == M65816_cpx || itype == M65816_cpy;
	bool is8 = (flags & (index_reg ? m65816_flags::IndexMode8 : m65816_flags::MemoryMode8)) != 0;
	return is8 ? dt_byte : dt_word;
}

// 16-bit code address used with the program bank (JMP/JSR abs, JMP/JSR (abs,X)): the target depends on the bank the
// code runs from. With a known PB it is certain; otherwise it is certain only when it is the same for every CPU bank
// the code can run from (its own bank and the mirrors mapped to it), e.g. HiROM code at $C0:D257 also runs as
// $80:D257, where "JSR $00CF" calls WRAM $7E:00CF instead of $C0:00CF.
enum pb_target_t {
	PBT_CERTAIN,   // *target is the ea of the target
	PBT_UNMAPPED,  // certain, but nothing is mapped there
	PBT_AMBIGUOUS, // depends on the unknown program bank
};

inline pb_target_t get_pb_target(ea_t insn_ea, uint32_t addr16, ea_t* target) {
	uint16_t pb;
	if (ea_get_known_reg(insn_ea, PROGRAM_BANK_TAG, &pb)) {
		*target = get_data_target(pb & 0xFF, addr16);
		return *target != BADADDR ? PBT_CERTAIN : PBT_UNMAPPED;
	}

	uint32_t low = (uint32_t)(insn_ea & 0xFFFF);
	bool first = true;
	ea_t result = BADADDR;
	for (uint32_t bank = 0; bank < 0x100; bank++) {
		ea_t cpu = (ea_t)((bank << 16) | low);
		if (cpu != insn_ea && use_mapping(cpu) != insn_ea) {
			continue; // the code can't run from this bank
		}
		ea_t t = get_data_target(bank, addr16);
		if (first) {
			result = t;
			first = false;
		}
		else if (t != result) {
			return PBT_AMBIGUOUS;
		}
	}
	*target = result;
	return result != BADADDR ? PBT_CERTAIN : PBT_UNMAPPED;
}

// Data operand referenced automatically, without pressing O - only when the accessed address is certain:
//  - abs/abs,X/abs,Y: the data bank is known for the instruction (DB tag: CDL, manual or derived from the code)
//  - direct page modes: the direct page register is known (D tag)
//  - long addresses: always (the address is complete)
// An explicit bank (O) or a representation chosen by the user (offset, number...) wins.
inline bool get_auto_data_ref(const insn_t& insn, const op_t& x, ea_t* target) {
	if (x.type != o_mem || is_defarg(get_flags(insn.ea), x.n) || ea_get_bank(insn.ea) != BADADDR) {
		return false;
	}

	ea_t ea = BADADDR;
	uint16_t v;
	M addrMode = static_cast<M>(insn.insnpref);
	switch (addrMode) {
	case M::Absd:
	case M::Abx:
	case M::Aby: {
		if (insn.itype == M65816_pea || !ea_get_known_reg(insn.ea, DATA_BANK_TAG, &v)) {
			return false;
		}
		ea = get_data_target(v & 0xFF, (uint32_t)x.addr & 0xFFFF);
	} break;
	case M::Dp:
	case M::Dps:
	case M::Dpx:
	case M::Dpy:
	case M::Idp:
	case M::Idx:
	case M::Idy:
	case M::Idl:
	case M::Idly: {
		if (!ea_get_known_reg(insn.ea, DIRECT_PAGE_TAG, &v)) {
			return false;
		}
		ea = get_data_target(0, (uint16_t)(v + (x.addr & 0xFF)));
	} break;
	case M::Abld:
	case M::Alx: {
		ea = get_data_target((uint32_t)(x.addr >> 16) & 0xFF, (uint32_t)x.addr & 0xFFFF);
	} break;
	default:
		return false;
	}

	if (ea == BADADDR) {
		return false;
	}
	*target = ea;
	return true;
}

inline void add_op_possible_dref(ea_t addr, const op_t& x, const insn_t& insn, bool ref_anyway) {
	ea_t ea = use_mapping(addr);

	if (ref_anyway || op_adds_xrefs(get_flags32(insn.ea), x.n)) {
		if (is_mapped(ea)) {
			ea_t target = op_ref_target(insn.ea, x.n, ea);
			insn.add_dref(target, x.offb, dr_O);
			// data of the accessed size only for a memory operand: an immediate value (#) is just an address,
			// what is there is unknown (it may be code, as the pointer to a routine)
			if (target == ea && x.type == o_mem && !is_indexed_operand(insn)) {
				insn.create_op_data(ea, x);
			}
		}
	}
	else {
		ea_clr_bank(insn.ea);
		del_dref(insn.ea, ea);
	}
}

inline void add_op_cref(ea_t addr, const op_t& x, const insn_t& insn) {
	bool is_call = has_insn_feature(insn.itype, CF_CALL);
	ea_t ea = use_mapping(addr);

	if (is_mapped(ea)) {
		insn.add_cref(ea, x.offb, is_call ? fl_CN : fl_JN);
	}
	else {
		del_cref(insn.ea, ea, true);
	}
}

