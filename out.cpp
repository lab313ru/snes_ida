#include "65816.hpp"

class out_m65816_t : public outctx_t {
  out_m65816_t(void) = delete;
  m65816_t& pm() { return *static_cast<m65816_t*>(procmod); }
public:
  void out_byte_word(const op_t& x, bool is_byte);
  void out_byte_or_off(const op_t& x, bool can_be_imm);
  void out_byteword_or_off(const op_t& x, bool can_be_imm);
  void out_word_or_off(const op_t& x, bool can_be_imm);
  void out_24bit_or_off(const op_t& x, bool can_be_imm);
  bool out_operand(const op_t& x);
  void out_insn(void);
  void out_proc_mnem(void);
};
CASSERT(sizeof(out_m65816_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS(out_m65816_t);

void out_m65816_t::out_byte_word(const op_t& x, bool is_byte) {
  out_value(x, is_byte ? OOFW_8 : OOFW_16);
}

void out_m65816_t::out_byte_or_off(const op_t& x, bool can_be_imm) {
  if (can_be_imm && !op_adds_xrefs(F, x.n)) {
    out_byte_word(x, true);
  }
  else {
    out_name_expr(x, use_mapping(x.addr));
  }
}

void out_m65816_t::out_byteword_or_off(const op_t& x, bool can_be_imm) {
  bool is_byte = (insn.size == 2);

  if (can_be_imm && !op_adds_xrefs(F, x.n)) {
    out_byte_word(x, is_byte);
  }
  else {
    out_name_expr(x, use_mapping(x.addr));
  }
}

void out_m65816_t::out_word_or_off(const op_t& x, bool can_be_imm) {
  if (can_be_imm && !op_adds_xrefs(F, x.n)) {
    out_byte_word(x, false);
  }
  else {
    out_name_expr(x, use_mapping(x.addr));
  }
}

void out_m65816_t::out_24bit_or_off(const op_t& x, bool can_be_imm) {
  if (can_be_imm && !op_adds_xrefs(F, x.n)) {
    out_value(x, OOFW_24);
  }
  else {
    out_name_expr(x, use_mapping(x.addr));
  }
}

bool out_m65816_t::out_operand(const op_t& x) {
  M addrMode = static_cast<M>(insn.insnpref);

  switch (addrMode) {
  case M::Im8: // #$00 - one byte (opcodes: $E2/SEP, $C2/REP, $42/WDM, $02/COP, $00/BRK)
  case M::Imm: // #$00/00 - depend on m (opcodes: $E9/SBC, $C9/CMP, $A9/LDA, $89/STA, $69/ADC, $49/EOR, $29/AND, $09/ORA
  case M::Imx: { // #$00/00 - depend on x (opcodes: $E0/CPX, $C0/CPY, $A0/LDY, $A2/LDX)
    out_symbol('#');

    if (addrMode == M::Im8) {
      out_byte_word(x, true);
    }
    else {
      out_byteword_or_off(x, true);
    }
  } break;
  case M::Sr: { // $00,S - by stack (opcodes: $E3/SBC, $C3/CMP, $A3/LDA, $83/STA, $63/ADC, $43/EOR, $23/AND, $03/ORA)
    out_byte_or_off(x, true);
    out_symbol(',');
    out_register("S");
  } break;
  case M::Dp: { // $00 - direct page reg (opcodes: $E4/CPX, $C4/CPY, $A4/LDY, $84/STY, $64/STZ, $24/BIT, $14/TRB, $04/TSB, $E5/SBC, $C5/CMP, $A5/LDA, $85/STA, $65/ADC, $45/EOR, $25/AND, $05/ORA, $E6/INC, $C6/DEC, $A6/LDX, $86/STX, $66/ROR, $46/LSR, $26/ROL, $06/ASL)
    out_byte_or_off(x, true);
  } break;
  case M::Dps: { // ($00) - by stack, direct page reg (opcodes: $D4/PEI)
    out_symbol('(');
    out_byte_or_off(x, true);
    out_symbol(')');
  } break;
  case M::Dpx: { // $00,X - direct page reg
    out_byte_or_off(x, true);
    out_symbol(',');
    out_register("X");
  } break;
  case M::Dpy: { // $00,Y - direct page reg (opcodes: $B6/LDX, $96/STX)
    out_byte_or_off(x, true);
    out_symbol(',');
    out_register("Y");
  } break;
  case M::Idp: { // ($00) - direct page reg
    out_symbol('(');
    out_byte_or_off(x, true);
    out_symbol(')');
  } break;
  case M::Idx: { // ($00,X) - direct page reg
    out_symbol('(');
    out_byte_or_off(x, true);
    out_symbol(',');
    out_register("X");
    out_symbol(')');
  } break;
  case M::Idy: { // ($00),Y - direct page reg
    out_symbol('(');
    out_byte_or_off(x, true);
    out_symbol(')');
    out_symbol(',');
    out_register("Y");
  } break;
  case M::Idl: { // [$00] - direct page reg
    out_symbol('[');
    out_byte_or_off(x, true);
    out_symbol(']');
  } break;
  case M::Idly: { // [$00],Y - direct page reg (opcodes: $F7/SBC, $D7/CMP, $B7/LDA, $97/STA, $77/ADC, $57/EOR, $37/AND, $17/ORA, $07/ORA)
    out_symbol('[');
    out_byte_or_off(x, true);
    out_symbol(']');
    out_symbol(',');
    out_register("Y");
  } break;
  case M::Isy: { // ($00,S),Y - by stack (opcodes: $F3/SBC, $D3/CMP, $B3/LDA, $93/STA, $73/ADC, $53/EOR, $33/AND, $13/ORA, $03/ORA)
    out_symbol('(');
    out_byte_or_off(x, true);
    out_symbol(',');
    out_register("S");
    out_symbol(')');
    out_symbol(',');
    out_register("Y");
  } break;
  case M::Absd: { // $0000 - Uses Data bank (opcodes: $EC/CPX, $CC/CPY, $AC/LDY, $$9C/STZ, $8C/STY, $2C/BIT, $1C/TRB, $0C/TSB, $ED/SBC, $CD/CMP, $AD/LDA, $8D/STA, $6D/ADC, $4D/EOR, $2D/AND, $0D/ORA, $EE/INC, $CE/DEC, $AE/LDX, $8E/STX, $6E/ROR, $4E/LSR, $2E/ROL, $0E/ASL)
    out_word_or_off(x, false);
  } break;
  case M::Absp: { // $0000 - Uses Program bank for jumps (opcodes: $4C/JMP, $20/JSR)
    out_word_or_off(x, false);
  } break;
  case M::Abx: // $0000,X - Uses Data bank (opcodes: $BC/LDY, $3C/BIT, $FD/SBC, $DD/CMP, $BD/LDA, $9D/STA, $7D/ADC, $5D/EOR, $3D/AND, $1D/ORA, $FE/INC, $DE/DEC, $9E/STZ, $7E/ROR, $5E/LSR, $3E/ROL, $1E/ASL)
  case M::Aby: { // $0000,Y - Uses Data bank (opcodes: $BE/LDX, $F9/SBC, $D9/CMP, $B9/LDA, $99/STA, $79/ADC, $59/EOR, $39/AND, $19/ORA)
    out_word_or_off(x, false);
    out_symbol(',');
    out_register((addrMode == M::Abx) ? "X" : "Y");
  } break;
  case M::Ablp: { // $000000 - absolute jump (opcodes: $5C/JML-JMP, $22/JSL)
    out_24bit_or_off(x, false);
  } break;
  case M::Abld: { // $000000 - absolute ref (opcodes: $EF/SBC, $CF/CMP, $AF/LDA, $8F/STA, $6F/ADC, $4F/EOR, $2F/AND, $0F/ORA)
    out_24bit_or_off(x, false);
  } break;
  case M::Alx: { // $000000,X - absolute (opcodes: $FF/SBC, $DF/CMP, $BF/LDA, $9F/STA, $7F/ADC, $5F/EOR, $3F/AND, $1F/ORA)
    out_24bit_or_off(x, false);
    out_symbol(',');
    out_register("X");
  } break;
  case M::Ind: { // ($0000) - Uses Program bank (opcodes: $6C/JMP)
    out_symbol('(');
    out_word_or_off(x, false);
    out_symbol(')');
  } break;
  case M::Iax: { // ($0000,X) - uses Program bank (opcodes: $FC/JSR, $7C/JMP)
    out_symbol('(');
    out_word_or_off(x, false);
    out_symbol(',');
    out_register("X");
    out_symbol(')');
  } break;
  case M::Ial: { // [$000000] - absolute (opcodes: $DC/JML-JMP)
    out_symbol('[');
    out_24bit_or_off(x, false);
    out_symbol(']');
  } break;
  case M::Rel: // $0000 (8 bits PC-relative) (opcodes: $F0/BEQ, $D0/BNE, $B0/BCS, $90/BCC, $80/BRA, $70/BVS, $50/BVC, $30/BMI, $10/BPL)
  case M::Rell: { // $0000 (16 bits PC-relative) (opcodes: $82/BRL, $62/PER)
    out_word_or_off(x, false);
  } break;
  case M::Bm: { // $00,$00 (opcodes: $44/MVP, $54/MVN)
    out_byte_or_off(x, true);
  } break;
  case M::Stk: { // no args

  } break;
  case M::Regs: { // no args

  } break;
  default:
    return false;
  }

  return true;
}

void out_m65816_t::out_proc_mnem(void) {
  char postfix[3];
  postfix[0] = '\0';

  M addrMode = static_cast<M>(insn.insnpref);

  switch (addrMode) {
  case M::Rel:
  case M::Rell:
  case M::Im8:
  case M::Regs:
  case M::Stk:
  case M::Bm:
    break;
  default:
    switch (insn.size) {
    case 2: {
      qstrncpy(postfix, ".B", sizeof(postfix));
    } break;
    case 3: {
      qstrncpy(postfix, ".W", sizeof(postfix));
    } break;
    case 4: {
      qstrncpy(postfix, ".L", sizeof(postfix));
    } break;
    }
  }

  out_mnem(8, postfix);
}

void out_m65816_t::out_insn(void) {
  out_mnemonic();
  out_one_operand(0);

  if (insn.Op2.type != o_void) {
    out_symbol(',');
    out_one_operand(1);
  }

  char buf[64];

  switch (insn.itype) {
  case M65816_sep:
  case M65816_rep: {
    int val = (insn.itype == M65816_rep) ? 0 : 1;
    uint8_t flags = (uint8_t)insn.Op1.value;

    int change_mode = 0;
    change_mode |= (flags & m65816_flags::MemoryMode8) ? 1 : 0;
    change_mode |= (flags & m65816_flags::IndexMode8) ? 2 : 0;

    if (change_mode == 1) {
      qsnprintf(buf, sizeof(buf), COLSTR(" %s P.m=>%d", SCOLOR_AUTOCMT), ash.cmnt, val);
      out_line(buf);
    }
    else if (change_mode == 2) {
      qsnprintf(buf, sizeof(buf), COLSTR(" %s P.x=>%d", SCOLOR_AUTOCMT), ash.cmnt, val);
      out_line(buf);
    }
    else if (change_mode == 3) {
      qsnprintf(buf, sizeof(buf), COLSTR(" %s P.m=>%d, P.x=>%d", SCOLOR_AUTOCMT), ash.cmnt, val, val);
      out_line(buf);
    }
  } break;
  default: {
    if (has_cmt(F)) {
      break;
    }

    if (can_change_idx_mode(insn.ea)) {
      uint8_t flags = ea_get_flags(insn.ea);
      qsnprintf(buf, sizeof(buf),
        COLSTR(" %s P.x=%d (press Shift+X to change)", SCOLOR_AUTOCMT), ash.cmnt, (flags & m65816_flags::IndexMode8) ? 1 : 0
      );
      out_line(buf);
    }
    else if (can_change_mem_mode(insn.ea)) {
      uint8_t flags = ea_get_flags(insn.ea);
      qsnprintf(buf, sizeof(buf),
        COLSTR(" %s P.m=%d (press Shift+X to change)", SCOLOR_AUTOCMT), ash.cmnt, (flags & m65816_flags::MemoryMode8) ? 1 : 0
      );
      out_line(buf);
    }
    else {
      switch (insn.itype) {
      case M65816_plb: {
        qsnprintf(buf, sizeof(buf), COLSTR(" %s Stack -> Data Bank Reg", SCOLOR_AUTOCMT), ash.cmnt);
        out_line(buf);
      } break;
      case M65816_pld: {
        qsnprintf(buf, sizeof(buf), COLSTR(" %s Stack -> Direct Page Reg", SCOLOR_AUTOCMT), ash.cmnt);
        out_line(buf);
      } break;
      case M65816_tcd: {
        qsnprintf(buf, sizeof(buf), COLSTR(" %s ACC -> Direct Page Reg", SCOLOR_AUTOCMT), ash.cmnt);
        out_line(buf);
      } break;
      default: {
        M addrMode = static_cast<M>(insn.insnpref);

        switch (addrMode) {
        case M::Dp:
        case M::Dpx:
        case M::Dpy:
        case M::Idp:
        case M::Idx:
        case M::Idy:
        case M::Idl:
        case M::Idly: {
          qsnprintf(buf, sizeof(buf), COLSTR(" %s Uses Direct Page Reg", SCOLOR_AUTOCMT), ash.cmnt);
          out_line(buf);
        } break;
        case M::Absd:
        case M::Abx:
        case M::Aby: {
          qsnprintf(buf, sizeof(buf), COLSTR(" %s Uses Data Bank Reg", SCOLOR_AUTOCMT), ash.cmnt);
          out_line(buf);
        } break;
        case M::Bm: {
          qsnprintf(buf, sizeof(buf), COLSTR(" %s Src(X),Dst(Y) [ACC.W]", SCOLOR_AUTOCMT), ash.cmnt);
          out_line(buf);
        } break;
        }
      } break;
      }
    }
  } break;
  }

  flush_outbuf();
}

void m65816_t::out_banked_val(outctx_t& ctx, bool analyze_only) {
  flags64_t F = ctx.F;

  if (!is_unknown(F)) {
    uint16_t i = 0;
    uint32_t value = 0;

    if (is_byte(F)) {
      i = 1;
      value = get_byte(ctx.insn_ea);
    }
    else if (is_word(F)) {
      i = 2;
      value = get_word(ctx.insn_ea);
    }
    else if (is_dword(F)) {
      i = 4;
      value = get_dword(ctx.insn_ea);
    }

    ea_t ea_bank = ea_get_bank(ctx.insn_ea);

    if (ea_bank != BADADDR) {
      value |= (uint32_t)ea_bank;
    }

    value = use_mapping(value);

    if (!is_mapped(value)) {
      ctx.out_data(analyze_only);
      return;
    }

    qstring name;

    ssize_t ln = get_name_expr(&name, ctx.insn_ea, 0, value, BADADDR);
    if (ln <= 0) {
      ctx.out_long(value, 16);
      ctx.flush_outbuf();
      return;
    }

    switch (i) {
    case 1: {
      ctx.out_keyword(ASH.a_byte);
    } break;
    case 2: {
      ctx.out_keyword(ASH.a_word);
    } break;
    case 4: {
      ctx.out_keyword(ASH.a_dword);
    } break;
    default: {
      ctx.out_data(analyze_only);
      return;
    } break;
    }

    ctx.out_char(' ');

    ctx.out_line(name.c_str(), COLOR_DREF);
    ctx.flush_outbuf();

    add_dref(ctx.insn_ea, value, dr_O);
  }
}

void m65816_t::m65816_data(outctx_t& ctx, bool analyze_only) {
  flags64_t F = ctx.F;

  if (!is_tbyte(F)) {
    if (op_adds_xrefs(F, 0)) {
      out_banked_val(ctx, analyze_only);
    }
    else {
      ea_clr_bank(ctx.insn_ea);
      ctx.out_data(analyze_only);
    }
    return;
  }
  
  uint8_t b3[3];
  ssize_t res = get_bytes(b3, 3, ctx.insn_ea);

  if (res != 3) {
    ctx.out_data(analyze_only);
    return;
  }

  ctx.out_line(ash.a_tbyte, COLOR_KEYWORD);
  ctx.out_char(' ');

  uint32_t val = (b3[2] << 16) | (b3[1] << 8) | (b3[0] << 0);

  op_t op = {};
  op.n = 0;
  op.dtype = dt_dword;
  op.type = o_mem;
  op.addr = val;

  if (!is_off0(F)) {
    ctx.out_long(val, 16);
    ctx.flush_outbuf();
    return;
  }

  qstring name;
  ssize_t ln = get_name_expr(&name, ctx.insn_ea, 0, val, BADADDR);
  if (ln <= 0) {
    ctx.out_long(val, 16);
    ctx.flush_outbuf();
    return;
  }

  ctx.out_line(name.c_str(), COLOR_DREF);
  ctx.flush_outbuf();
}