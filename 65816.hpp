#pragma once

#include <idaidp.hpp>
#include <xref.hpp>
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

extern netnode helper;
extern bool can_change_mem_mode(ea_t ea);
extern bool can_change_idx_mode(ea_t ea);

#define FLAGS_BITMODE_TAG ('P')
#define MANUAL_BITMODE_TAG ('O')
#define MANUAL_BASE_TAG ('R')

inline void ea_set_flags(ea_t ea, uint8_t flags) {
	helper.charset_ea(ea, flags, FLAGS_BITMODE_TAG);
}

inline void ea_set_manual_bitmode(ea_t ea, bool manual) {
	helper.charset_ea(ea, manual ? 1 : 0, MANUAL_BITMODE_TAG);
}

inline bool ea_is_manual_bitmode(ea_t ea) {
	uint8_t res = helper.charval_ea(ea, MANUAL_BITMODE_TAG);

	if (res == 0xFF) {
		res = 0;
	}

	return res == 1;
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

struct switch_bitmode_action_t : public action_handler_t {
	virtual int idaapi activate(action_activation_ctx_t* ctx) {
		int can_change_mode = 0;
		can_change_mode |= can_change_mem_mode(ctx->cur_ea) ? 1 : 0;
		can_change_mode |= can_change_idx_mode(ctx->cur_ea) ? 2 : 0;

		if (can_change_mode == 0) {
			return 1;
		}

		uint8_t flags = ea_get_flags(ctx->cur_ea);
		
		if (can_change_mode & 1) {
			flags ^= m65816_flags::MemoryMode8;
		}
		else if (can_change_mode & 2) {
			flags ^= m65816_flags::IndexMode8;
		}

		ea_set_flags(ctx->cur_ea, flags);
		ea_set_manual_bitmode(ctx->cur_ea, true);

		return 1;
	}

	virtual action_state_t idaapi update(action_update_ctx_t* ctx) {
		return AST_ENABLE_ALWAYS;
	}
};

#define BANK_TAG ('B')

inline ea_t ea_get_bank(ea_t ea) {
	return helper.eaget(ea, BANK_TAG);
}

inline void ea_set_bank(ea_t ea, ea_t bank) {
	helper.easet(ea, bank, BANK_TAG);
}

inline void ea_clr_bank(ea_t ea) {
	helper.easet(ea, BADADDR, BANK_TAG);
}

// !!! problems TODO:
// C18A1A (C18A4F)

enum class set_offset_bank_mode_t : uint8_t {
	SOB_CURRENT,
	SOB_SELECT,
	SOB_WRAM,
	SOB_ZERO,
};

struct set_offset_bank_action_t : public action_handler_t {
private:
	set_offset_bank_mode_t _mode;
public:
	set_offset_bank_action_t(set_offset_bank_mode_t mode) : _mode(mode) {}

	virtual int idaapi activate(action_activation_ctx_t* ctx) {
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
			ea_set_bank(ctx->cur_ea, start_ea);
			set_op_type(ctx->cur_ea, off_flag(), opnum);
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

struct m65816_t : public procmod_t {
#define ROM_NO_BRK 0x01
#define ROM_NO_COP 0x02
#define ROM_NO_WDM 0x04
	ushort idpflags = ROM_NO_BRK | ROM_NO_COP | ROM_NO_WDM;

	int addr24_id, addr24_fid;

	switch_bitmode_action_t switch_bitmode;
	set_cur_offset_bank_action_t set_cur_offset_bank;
	set_sel_offset_bank_action_t set_sel_offset_bank;
	set_wram_offset_bank_action_t set_wram_offset_bank;
	set_zero_offset_bank_action_t set_zero_offset_bank;

	action_desc_t switch_bitmode_action = ACTION_DESC_LITERAL_PROCMOD(switch_bitmode_action_name, "Switch flag", &switch_bitmode, this, "Shift+X", NULL, -1);
	action_desc_t set_cur_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_cur_offset_bank_action_name, "Change bank to current", &set_cur_offset_bank, this, "O", NULL, -1);
	action_desc_t set_sel_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_sel_offset_bank_action_name, "Change bank to selected", &set_sel_offset_bank, this, "Ctrl+O", NULL, -1);
	action_desc_t set_wram_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_wram_offset_bank_action_name, "Change bank to WRAM", &set_wram_offset_bank, this, "Shift+O", NULL, -1);
	action_desc_t set_zero_offset_bank_action = ACTION_DESC_LITERAL_PROCMOD(set_zero_offset_bank_action_name, "Change bank to ZERO", &set_zero_offset_bank, this, "Ctrl+Shift+O", NULL, -1);

	bool recurse_ana = false;
	
	const char* idaapi set_idp_options(const char* keyword, int value_type, const void* value, bool idb_loaded);

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
  int idaapi ana(insn_t* _insn);
  int idaapi emu(const insn_t& insn);
  void handle_operand(const op_t& x, bool read_access, const insn_t& insn);
  void m65816_data(outctx_t& ctx, bool analyze_only);
	void out_banked_val(outctx_t& ctx, bool analyze_only);

	void save_idpflags() { helper.altset(-1, idpflags); }
	void load_from_idb() { (ushort)helper.altval(-1); }
};

inline void add_op_possible_dref(ea_t addr, const op_t& x, const insn_t& insn, bool ref_anyway) {
	ea_t ea = use_mapping(addr);

	if (ref_anyway || op_adds_xrefs(get_flags32(insn.ea), x.n)) {
		if (is_mapped(ea)) {
			insn.add_dref(ea, x.offb, dr_O);
			insn.create_op_data(ea, x);
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

