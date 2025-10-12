#include "65816.hpp"
#include <ida.hpp>

static const m65816_opcode itype2opcode[256] = {
  //0         1           2           3           4           5           6           7           8           9           a           b           c           d           e           f
  M65816_brk, M65816_ora, M65816_cop, M65816_ora, M65816_tsb, M65816_ora, M65816_asl, M65816_ora, M65816_php, M65816_ora, M65816_asl, M65816_phd, M65816_tsb, M65816_ora, M65816_asl, M65816_ora, // 0
  M65816_bpl, M65816_ora, M65816_ora, M65816_ora, M65816_trb, M65816_ora, M65816_asl, M65816_ora, M65816_clc, M65816_ora, M65816_inc, M65816_tcs, M65816_trb, M65816_ora, M65816_asl, M65816_ora, // 1
  M65816_jsr, M65816_and, M65816_jsl, M65816_and, M65816_bit, M65816_and, M65816_rol, M65816_and, M65816_plp, M65816_and, M65816_rol, M65816_pld, M65816_bit, M65816_and, M65816_rol, M65816_and, // 2
  M65816_bmi, M65816_and, M65816_and, M65816_and, M65816_bit, M65816_and, M65816_rol, M65816_and, M65816_sec, M65816_and, M65816_dec, M65816_tsc, M65816_bit, M65816_and, M65816_rol, M65816_and, // 3
  M65816_rti, M65816_eor, M65816_wdm, M65816_eor, M65816_mvp, M65816_eor, M65816_lsr, M65816_eor, M65816_pha, M65816_eor, M65816_lsr, M65816_phk, M65816_jmp, M65816_eor, M65816_lsr, M65816_eor, // 4
  M65816_bvc, M65816_eor, M65816_eor, M65816_eor, M65816_mvn, M65816_eor, M65816_lsr, M65816_eor, M65816_cli, M65816_eor, M65816_phy, M65816_tcd, M65816_jml, M65816_eor, M65816_lsr, M65816_eor, // 5
  M65816_rts, M65816_adc, M65816_per, M65816_adc, M65816_stz, M65816_adc, M65816_ror, M65816_adc, M65816_pla, M65816_adc, M65816_ror, M65816_rtl, M65816_jmp, M65816_adc, M65816_ror, M65816_adc, // 6
  M65816_bvs, M65816_adc, M65816_adc, M65816_adc, M65816_stz, M65816_adc, M65816_ror, M65816_adc, M65816_sei, M65816_adc, M65816_ply, M65816_tdc, M65816_jmp, M65816_adc, M65816_ror, M65816_adc, // 7
  M65816_bra, M65816_sta, M65816_brl, M65816_sta, M65816_sty, M65816_sta, M65816_stx, M65816_sta, M65816_dey, M65816_bit, M65816_txa, M65816_phb, M65816_sty, M65816_sta, M65816_stx, M65816_sta, // 8
  M65816_bcc, M65816_sta, M65816_sta, M65816_sta, M65816_sty, M65816_sta, M65816_stx, M65816_sta, M65816_tya, M65816_sta, M65816_txs, M65816_txy, M65816_stz, M65816_sta, M65816_stz, M65816_sta, // 9
  M65816_ldy, M65816_lda, M65816_ldx, M65816_lda, M65816_ldy, M65816_lda, M65816_ldx, M65816_lda, M65816_tay, M65816_lda, M65816_tax, M65816_plb, M65816_ldy, M65816_lda, M65816_ldx, M65816_lda, // a
  M65816_bcs, M65816_lda, M65816_lda, M65816_lda, M65816_ldy, M65816_lda, M65816_ldx, M65816_lda, M65816_clv, M65816_lda, M65816_tsx, M65816_tyx, M65816_ldy, M65816_lda, M65816_ldx, M65816_lda, // b
  M65816_cpy, M65816_cmp, M65816_rep, M65816_cmp, M65816_cpy, M65816_cmp, M65816_dec, M65816_cmp, M65816_iny, M65816_cmp, M65816_dex, M65816_wai, M65816_cpy, M65816_cmp, M65816_dec, M65816_cmp, // c
  M65816_bne, M65816_cmp, M65816_cmp, M65816_cmp, M65816_pei, M65816_cmp, M65816_dec, M65816_cmp, M65816_cld, M65816_cmp, M65816_phx, M65816_stp, M65816_jml, M65816_cmp, M65816_dec, M65816_cmp, // d
  M65816_cpx, M65816_sbc, M65816_sep, M65816_sbc, M65816_cpx, M65816_sbc, M65816_inc, M65816_sbc, M65816_inx, M65816_sbc, M65816_nop, M65816_xba, M65816_cpx, M65816_sbc, M65816_inc, M65816_sbc, // e
  M65816_beq, M65816_sbc, M65816_sbc, M65816_sbc, M65816_pea, M65816_sbc, M65816_inc, M65816_sbc, M65816_sed, M65816_sbc, M65816_plx, M65816_xce, M65816_jsr, M65816_sbc, M65816_inc, M65816_sbc  // f
};

static uint8_t get_op_size(M addrMode, uint8_t flags) {
  if (addrMode == M::Imx) {
    return (flags & m65816_flags::IndexMode8) ? 2 : 3;
  }
  else if (addrMode == M::Imm) {
    return (flags & m65816_flags::MemoryMode8) ? 2 : 3;
  }

  return m65816_OpSize[static_cast<int>(addrMode)];
}

bool can_change_mem_mode(ea_t ea) {
  uint8_t opCode = get_byte(ea);
  M addrMode = m65816_OpMode[opCode];
  return (addrMode == M::Imm);
}

bool can_change_idx_mode(ea_t ea) {
  uint8_t opCode = get_byte(ea);
  M addrMode = m65816_OpMode[opCode];
  return (addrMode == M::Imx);
}

static uint32_t get_operand_address(insn_t* _insn, uint8_t opSize, M addrMode, ea_t memoryAddr) {
  uint32_t opAddr = 0;

  if (opSize == 2) {
    opAddr = _insn->get_next_byte();
  }
  else if (opSize == 3) {
    opAddr = _insn->get_next_byte();
    opAddr |= (_insn->get_next_byte() << 8);
  }
  else if (opSize == 4) {
    opAddr = _insn->get_next_byte();
    opAddr |= (_insn->get_next_byte() << 8);
    opAddr |= (_insn->get_next_byte() << 16);
  }

  if (addrMode == M::Rel || addrMode == M::Rell) {
    if (opSize == 2) {
      opAddr = (memoryAddr & 0xFF0000) | (((int8_t)opAddr + memoryAddr + 2) & 0xFFFF);
    }
    else {
      opAddr = (memoryAddr & 0xFF0000) | (((int16_t)opAddr + memoryAddr + 3) & 0xFFFF);
    }
  }

  return opAddr;
}

static bool is_cref_itype(const insn_t& insn) {
  switch (insn.itype) {
  case M65816_bcc:    // Branch if carry clear
  case M65816_bcs:    // Branch if carry set
  case M65816_beq:    // Branch if equal
  case M65816_bmi:    // Branch if minus
  case M65816_bne:    // Branch if not equal
  case M65816_bpl:    // Branch if plus
  case M65816_bra:    // Branch always
    //case M65816_brk:    // Software break
  case M65816_brl:    // Branch always long
  case M65816_bvc:    // Branch if overflow clear
  case M65816_bvs:    // Branch if overflow set
  case M65816_jml:    // Jump long (inter-bank)
  case M65816_jmp:    // Jump
  case M65816_jsl:    // Jump to subroutine long (inter-bank)
  case M65816_jsr:    // Jump to subroutine
    return true;
  default:
    return false;
  }
}

int idaapi m65816_t::ana(insn_t* _insn) { // SnesDisUtils.cpp / Mesen2
  if (_insn == NULL) {
    return 0;
  }

  insn_t& insn = *_insn;
  insn.size = 0;
  uint8_t opCode = insn.get_next_byte();

  if ((idpflags & ROM_NO_BRK) && (opCode == 0x00)) {
    forget_problem(PR_DISASM, insn.ea);
    return 0;
  }

  if ((idpflags & ROM_NO_COP) && (opCode == 0x02)) {
    forget_problem(PR_DISASM, insn.ea);
    return 0;
  }

  if ((idpflags & ROM_NO_WDM) && (opCode == 0x42)) {
    forget_problem(PR_DISASM, insn.ea);
    return 0;
  }

  M addrMode = m65816_OpMode[opCode];

  int can_change_mode = 0;
  can_change_mode |= can_change_mem_mode(insn.ea) ? 1 : 0;
  can_change_mode |= can_change_idx_mode(insn.ea) ? 2 : 0;

  uint8_t flags = ea_get_flags(insn.ea);
  uint8_t opSize = get_op_size(addrMode, flags);
  uint32_t opAddr = get_operand_address(_insn, opSize, addrMode, insn.ea);

  insn.itype = itype2opcode[opCode];
  insn.Op1.offb = 1;
  insn.insnpref = static_cast<char>(addrMode);

  //uint8_t argsSize = opSize >= 1 ? (opSize - 1) : 0;

  op_dtype_t dtype = dt_byte;

  /*if (argsSize > 0) {
    switch (argsSize) {
    case 2: dtype = dt_word; break;
    case 3: dtype = dt_dword; break;
    }
  }*/

  ea_t ea_bank = ea_get_bank(insn.ea);

  if (ea_bank != BADADDR) {
    opAddr |= (uint32_t)ea_bank;
  }

  switch (addrMode) {
  case M::Im8: // #$00 - one byte (opcodes: $E2/SEP, $C2/REP, $42/WDM, $02/COP, $00/BRK)
  case M::Imm: // #$00/00 - depend on m (opcodes: $E9/SBC, $C9/CMP, $A9/LDA, $89/STA, $69/ADC, $49/EOR, $29/AND, $09/ORA
  case M::Imx: { // #$00/00 - depend on x (opcodes: $E0/CPX, $C0/CPY, $A0/LDY, $A2/LDX)
    insn.Op1.type = o_imm;
    insn.Op1.value = insn.Op1.addr = opAddr;
    insn.Op1.dtype = dtype;
  } break;
  case M::Sr: // $00,S - by stack (opcodes: $E3/SBC, $C3/CMP, $A3/LDA, $83/STA, $63/ADC, $43/EOR, $23/AND, $03/ORA)
  case M::Dpx: // $00,X - direct page reg
  case M::Dpy: // $00,Y - direct page reg (opcodes: $B6/LDX, $96/STX)
  case M::Idx: // ($00,X) - direct page reg
  case M::Idy: // ($00),Y - direct page reg
  case M::Idly: // [$00],Y - direct page reg (opcodes: $F7/SBC, $D7/CMP, $B7/LDA, $97/STA, $77/ADC, $57/EOR, $37/AND, $17/ORA, $07/ORA)
  case M::Isy: // ($00,S),Y - by stack (opcodes: $F3/SBC, $D3/CMP, $B3/LDA, $93/STA, $73/ADC, $53/EOR, $33/AND, $13/ORA, $03/ORA)
  case M::Abx: // $0000,X - Uses Data bank (opcodes: $BC/LDY, $3C/BIT, $FD/SBC, $DD/CMP, $BD/LDA, $9D/STA, $7D/ADC, $5D/EOR, $3D/AND, $1D/ORA, $FE/INC, $DE/DEC, $9E/STZ, $7E/ROR, $5E/LSR, $3E/ROL, $1E/ASL)
  case M::Aby: // $0000,Y - Uses Data bank (opcodes: $BE/LDX, $F9/SBC, $D9/CMP, $B9/LDA, $99/STA, $79/ADC, $59/EOR, $39/AND, $19/ORA)
  case M::Alx: // $000000,X - absolute (opcodes: $FF/SBC, $DF/CMP, $BF/LDA, $9F/STA, $7F/ADC, $5F/EOR, $3F/AND, $1F/ORA)
  case M::Dp: // $00 - direct page reg (opcodes: $E4/CPX, $C4/CPY, $A4/LDY, $84/STY, $64/STZ, $24/BIT, $14/TRB, $04/TSB, $E5/SBC, $C5/CMP, $A5/LDA, $85/STA, $65/ADC, $45/EOR, $25/AND, $05/ORA, $E6/INC, $C6/DEC, $A6/LDX, $86/STX, $66/ROR, $46/LSR, $26/ROL, $06/ASL)
  case M::Dps: // ($00) - by stack, direct page reg (opcodes: $D4/PEI)
  case M::Idp: // ($00) - direct page reg
  case M::Idl: // [$00] - direct page reg
  case M::Absd: // $0000 - Uses Data bank (opcodes: $EC/CPX, $CC/CPY, $AC/LDY, $$9C/STZ, $8C/STY, $2C/BIT, $1C/TRB, $0C/TSB, $ED/SBC, $CD/CMP, $AD/LDA, $8D/STA, $6D/ADC, $4D/EOR, $2D/AND, $0D/ORA, $EE/INC, $CE/DEC, $AE/LDX, $8E/STX, $6E/ROR, $4E/LSR, $2E/ROL, $0E/ASL)
  case M::Abld: { // $000000 - absolute ref (opcodes: $EF/SBC, $CF/CMP, $AF/LDA, $8F/STA, $6F/ADC, $4F/EOR, $2F/AND, $0F/ORA)
    insn.Op1.type = o_mem;
    insn.Op1.value = insn.Op1.addr = opAddr;
    insn.Op1.dtype = dtype;
  } break;
  case M::Iax: // ($0000,X) - uses Program bank (opcodes: $FC/JSR, $7C/JMP)
  case M::Ind: // ($0000) - Uses Program bank (opcodes: $6C/JMP)
  case M::Absp: {// $0000 - Uses Program bank for jumps (opcodes: $4C/JMP, $20/JSR)
    insn.Op1.type = o_near;
    insn.Op1.addr = insn.Op1.value = (insn.ea & 0xFF0000) | opAddr;
    insn.Op1.dtype = dtype;

    if (!is_mapped(use_mapping(insn.Op1.addr))) {
      return 0;
    }
  } break;
  case M::Ablp: // $000000 - absolute jump (opcodes: $5C/JML-JMP, $22/JSL)
  case M::Ial: // [$000000] - absolute (opcodes: $DC/JML-JMP)
  case M::Rel: // $0000 (8 bits PC-relative) (opcodes: $F0/BEQ, $D0/BNE, $B0/BCS, $90/BCC, $80/BRA, $70/BVS, $50/BVC, $30/BMI, $10/BPL)
  case M::Rell: { // $0000 (16 bits PC-relative) (opcodes: $82/BRL, $62/PER)
    insn.Op1.type = o_near;
    insn.Op1.addr = insn.Op1.value = opAddr;
    insn.Op1.dtype = dtype;
  } break;
  case M::Bm: { // $00,$00 (opcodes: $44/MVP, $54/MVN)
    insn.Op1.type = o_mem;
    insn.Op1.addr = insn.Op1.value = (opAddr >> 8) & 0xFF;
    insn.Op1.dtype = dt_byte;

    insn.Op2.type = o_mem;
    insn.Op2.addr = insn.Op2.value = (opAddr >> 0) & 0xFF;
    insn.Op2.dtype = dt_byte;
    insn.Op2.offb = 2;
  } break;
  case M::Stk: { // no args

  } break;
  case M::Regs: { // no args

  } break;
  }

  if (recurse_ana) {
    return insn.size;
  }

  switch (insn.itype) {
  case M65816_sep:
  case M65816_rep: {
    uint8_t val = (uint8_t)insn.Op1.value;
    bool is_zero = (insn.itype == M65816_rep);

    if (val & m65816_flags::MemoryMode8) {
      ea_set_mem_bitmode(insn.ea, is_zero);
    }
    if (val & m65816_flags::IndexMode8) {
      ea_set_idx_bitmode(insn.ea, is_zero);
    }
  } // break;
  default: { // any other instruction
    if (ea_is_manual_bitmode(insn.ea)) {
      break;
    }

    xrefblk_t xb;
    bool ok = xb.first_to(insn.ea, XREF_FLOW);

    if (ok && xb.iscode) {
      uint8_t flags = ea_get_flags(xb.from);
      ea_set_flags(insn.ea, flags);

      recurse_ana = true;
      ana(&insn);
      recurse_ana = false;
    }
  } break;
  }

  return insn.size;
}