#include "65816.hpp"

void m65816_t::handle_operand(const op_t& x, bool read_access, const insn_t& insn) {
  switch (x.type) {
  case o_void:
  case o_reg: {

  } break;
  case o_mem: {
    M addrMode = static_cast<M>(insn.insnpref);

    switch (addrMode) {
    case M::Sr: // $00,S - by stack (opcodes: $E3/SBC, $C3/CMP, $A3/LDA, $83/STA, $63/ADC, $43/EOR, $23/AND, $03/ORA)
    case M::Dpx: // $00,X - direct page reg
    case M::Dpy: // $00,Y - direct page reg (opcodes: $B6/LDX, $96/STX)
    case M::Idx: // ($00,X) - direct page reg
    case M::Idy: // ($00),Y - direct page reg
    case M::Idly: // [$00],Y - direct page reg (opcodes: $F7/SBC, $D7/CMP, $B7/LDA, $97/STA, $77/ADC, $57/EOR, $37/AND, $17/ORA, $07/ORA)
    case M::Isy: // ($00,S),Y - by stack (opcodes: $F3/SBC, $D3/CMP, $B3/LDA, $93/STA, $73/ADC, $53/EOR, $33/AND, $13/ORA, $03/ORA)
    case M::Dp: // $00 - direct page reg (opcodes: $E4/CPX, $C4/CPY, $A4/LDY, $84/STY, $64/STZ, $24/BIT, $14/TRB, $04/TSB, $E5/SBC, $C5/CMP, $A5/LDA, $85/STA, $65/ADC, $45/EOR, $25/AND, $05/ORA, $E6/INC, $C6/DEC, $A6/LDX, $86/STX, $66/ROR, $46/LSR, $26/ROL, $06/ASL)
    case M::Dps: // ($00) - by stack, direct page reg (opcodes: $D4/PEI)
    case M::Idp: // ($00) - direct page reg
    case M::Idl: { // [$00] - direct page reg
      add_op_possible_dref(x.addr, x, insn, false);
    } break;
    case M::Abx: // $0000,X - Uses Data bank (opcodes: $BC/LDY, $3C/BIT, $FD/SBC, $DD/CMP, $BD/LDA, $9D/STA, $7D/ADC, $5D/EOR, $3D/AND, $1D/ORA, $FE/INC, $DE/DEC, $9E/STZ, $7E/ROR, $5E/LSR, $3E/ROL, $1E/ASL)
    case M::Aby: // $0000,Y - Uses Data bank (opcodes: $BE/LDX, $F9/SBC, $D9/CMP, $B9/LDA, $99/STA, $79/ADC, $59/EOR, $39/AND, $19/ORA)
    case M::Alx: // $000000,X - absolute (opcodes: $FF/SBC, $DF/CMP, $BF/LDA, $9F/STA, $7F/ADC, $5F/EOR, $3F/AND, $1F/ORA)
    case M::Absd: // $0000 - Uses Data bank (opcodes: $EC/CPX, $CC/CPY, $AC/LDY, $$9C/STZ, $8C/STY, $2C/BIT, $1C/TRB, $0C/TSB, $ED/SBC, $CD/CMP, $AD/LDA, $8D/STA, $6D/ADC, $4D/EOR, $2D/AND, $0D/ORA, $EE/INC, $CE/DEC, $AE/LDX, $8E/STX, $6E/ROR, $4E/LSR, $2E/ROL, $0E/ASL)
    case M::Abld: { // $000000 - absolute ref (opcodes: $EF/SBC, $CF/CMP, $AF/LDA, $8F/STA, $6F/ADC, $4F/EOR, $2F/AND, $0F/ORA)
      add_op_possible_dref(x.addr, x, insn, read_access);
    } break;
    }
  } break;
  case o_near: {
    add_op_cref(x.addr, x, insn);
  } break;
  case o_imm: {
    set_immd(insn.ea);
    add_op_possible_dref(x.addr, x, insn, false);
  } break;
  }
}

int m65816_t::emu(const insn_t& insn) {
  uint32_t feature = insn.get_canon_feature(ph);

  if (feature & CF_USE1) {
    handle_operand(insn.Op1, true, insn);
  }
  if (feature & CF_USE2) {
    handle_operand(insn.Op2, true, insn);
  }
  if (feature & CF_CHG1) {
    handle_operand(insn.Op1, false, insn);
  }
  if (feature & CF_CHG2) {
    handle_operand(insn.Op2, false, insn);
  }

  if ((feature & CF_STOP) == 0) {
    add_cref(insn.ea, insn.ea + insn.size, fl_F);
  }

  switch (insn.itype) {
  case M65816_plb: {
    remember_problem(PR_ATTN, insn.ea, "Data Bank Change");
  } break;
  case M65816_pld:
  case M65816_tcd: {
    remember_problem(PR_ATTN, insn.ea, "Direct Page Reg Change");
  } break;
  case M65816_nop: {
    remember_problem(PR_ATTN, insn.ea, "Rare instruction");
  } break;
  }

  return 1;
}
