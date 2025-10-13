#include "65816.hpp"

int data_id;

netnode helper;

const char* idaapi m65816_t::set_idp_options(const char* keyword, int value_type, const void* value, bool idb_loaded) {
  if (keyword == nullptr)
  {
    static const char form[] =
      "HELP\n"
      "ROM specific options\n"
      "\n"
      " BRK isn't used in this ROM\n"
      "\n"
      "       If this option is on, IDA won't accept BRK opcode as a valid one\n"
      "\n"
      " COP isn't used in this ROM\n"
      "\n"
      "       If this option is on, IDA won't accept COP opcode as a valid one\n"
      "\n"
      " WDM isn't used in this ROM\n"
      "\n"
      "       If this option is on, IDA won't accept WDM opcode as a valid one\n"
      "\n"
      "ENDHELP\n"
      "ROM specific options\n"
      "%*\n"
      " <~B~RK isn't used in this ROM:C>\n"
      " <~C~OP isn't used in this ROM:C>\n"
      " <~W~DM isn't used in this ROM:C>>\n"
      "\n"
      "\n";
    CASSERT(sizeof(idpflags) == sizeof(ushort));
    ask_form(form, this, &idpflags);

    if (idb_loaded) {
      save_idpflags();
    }
    return IDPOPT_OK;
  }
  else
  {
    if (value_type != IDPOPT_BIT) {
      return IDPOPT_BADTYPE;
    }

    if (streq(keyword, "ROM_NO_BRK")) {
      setflag(idpflags, ROM_NO_BRK, *(int*)value != 0);

      if (idb_loaded) {
        save_idpflags();
      }

      return IDPOPT_OK;
    } else if (streq(keyword, "ROM_NO_COP")) {
      setflag(idpflags, ROM_NO_COP, *(int*)value != 0);

      if (idb_loaded) {
        save_idpflags();
      }

      return IDPOPT_OK;
    } else if (streq(keyword, "ROM_NO_WDM")) {
      setflag(idpflags, ROM_NO_WDM, *(int*)value != 0);

      if (idb_loaded) {
        save_idpflags();
      }

      return IDPOPT_OK;
    }

    return IDPOPT_BADKEY;
  }
}

ssize_t idaapi m65816_t::on_event(ssize_t msgid, va_list va) {
  int retcode = 1;

  switch (msgid) {
  case processor_t::ev_init: {
    inf_set_be(false); // our vm uses little endian
    inf_set_gen_lzero(true); // we want to align every hex-value with zeroes

    inf_set_af(0
      //| AF_FIXUP //        0x0001          // Create offsets and segments using fixup info
      //| AF_MARKCODE  //     0x0002          // Mark typical code sequences as code
      | AF_UNK //          0x0004          // Delete instructions with no xrefs
      | AF_CODE //         0x0008          // Trace execution flow
      | AF_PROC //         0x0010          // Create functions if call is present
      | AF_USED //         0x0020          // Analyze and create all xrefs
      //| AF_FLIRT //        0x0040          // Use flirt signatures
      //| AF_PROCPTR //      0x0080          // Create function if data xref data->code32 exists
      | AF_JFUNC //        0x0100          // Rename jump functions as j_...
      | AF_NULLSUB //      0x0200          // Rename empty functions as nullsub_...
      //| AF_LVAR //         0x0400          // Create stack variables
      //| AF_TRACE //        0x0800          // Trace stack pointer
      //| AF_ASCII //        0x1000          // Create ascii string if data xref exists
      //| AF_IMMOFF //       0x2000          // Convert 32bit instruction operand to offset
      //AF_DREFOFF //      0x4000          // Create offset if data xref to seg32 exists
      //| AF_FINAL //       0x8000          // Final pass of analysis
      | AF_JUMPTBL  //    0x0001          // Locate and create jump tables
      | AF_STKARG  //     0x0008          // Propagate stack argument information
      | AF_REGARG  //     0x0010          // Propagate register argument information
      | AF_SIGMLT  //     0x0080          // Allow recognition of several copies of the same function
      //| AF_FTAIL  //      0x0100          // Create function tails
      //| AF_DATOFF  //     0x0200          // Automatically convert data to offsets
      //| AF_TRFUNC  //     0x2000          // Truncate functions upon code deletion
      //| AF_PURDAT  //     0x4000          // Control flow to data segment is ignored
    );
    inf_set_af2(0);

    bool exists = helper.create("$ 65816");

    update_action_state("OpOffset", action_state_t::AST_DISABLE_ALWAYS);
    update_action_state("OpOffsetCs", action_state_t::AST_DISABLE_ALWAYS);
    update_action_state("OpenXrefsTree", action_state_t::AST_DISABLE_ALWAYS);

    register_action(switch_bitmode_action);
    register_action(set_cur_offset_bank_action);
    register_action(set_sel_offset_bank_action);
    register_action(set_wram_offset_bank_action);
    register_action(set_zero_offset_bank_action);

    //hook_event_listener(HT_IDB, &idb_listener, &LPH);

    recurse_ana = false;
  } break;
  case processor_t::ev_term: {
    clr_module_data(data_id);

    unregister_action(switch_bitmode_action_name);
    unregister_action(set_cur_offset_bank_action_name);
    unregister_action(set_sel_offset_bank_action_name);
    unregister_action(set_wram_offset_bank_action_name);
    unregister_action(set_zero_offset_bank_action_name);

    update_action_state("OpOffset", action_state_t::AST_ENABLE_ALWAYS);
    update_action_state("OpOffsetCs", action_state_t::AST_ENABLE_ALWAYS);
    update_action_state("OpenXrefsTree", action_state_t::AST_ENABLE_ALWAYS);

    //unhook_event_listener(HT_IDB, &idb_listener);
  } break;
  case processor_t::ev_newfile: {
    auto* fname = va_arg(va, char*); // here we can load additional data from a current dir
  } break;
  case processor_t::ev_is_cond_insn: {
    const auto* insn = va_arg(va, const insn_t*);
    return (
      insn->itype == M65816_bpl ||
      insn->itype == M65816_bmi ||
      insn->itype == M65816_bvc ||
      insn->itype == M65816_bvs ||
      insn->itype == M65816_bcc ||
      insn->itype == M65816_bcs ||
      insn->itype == M65816_bne ||
      insn->itype == M65816_beq
      ) ? 1 : -1;
  } break;
  case processor_t::ev_is_ret_insn: {
    const auto* insn = va_arg(va, const insn_t*);
    return (
      insn->itype == M65816_rts ||
      insn->itype == M65816_rtl ||
      insn->itype == M65816_rti
      ) ? 1 : -1;
  } break;
  case processor_t::ev_is_call_insn: {
    const auto* insn = va_arg(va, const insn_t*);
    return (
      insn->itype == M65816_brk ||
      insn->itype == M65816_cop ||
      insn->itype == M65816_jsr ||
      insn->itype == M65816_jsl
      ) ? 1 : -1;
  } break;
  case processor_t::ev_ana_insn: {
    auto* out = va_arg(va, insn_t*);
    return ana(out);
  } break;
  case processor_t::ev_emu_insn: {
    const auto* insn = va_arg(va, const insn_t*);
    return emu(*insn);
  } break;
  case processor_t::ev_out_insn: {
    auto* ctx = va_arg(va, outctx_t*);
    out_insn(*ctx);
  } break;
  case processor_t::ev_out_mnem: {
    auto* ctx = va_arg(va, outctx_t*);
    out_mnem(*ctx);
  } break;
  case processor_t::ev_out_operand: {
    auto* ctx = va_arg(va, outctx_t*);
    const auto* op = va_arg(va, const op_t*);
    return out_opnd(*ctx, *op) ? 1 : -1;
  } break;
  case processor_t::ev_set_idp_options: {
    const char* keyword = va_arg(va, const char*);
    int value_type = va_arg(va, int);
    const char* value = va_arg(va, const char*);
    const char** errmsg = va_arg(va, const char**);
    bool idb_loaded = va_argi(va, bool);
    const char* ret = set_idp_options(keyword, value_type, value, idb_loaded);

    if (ret == IDPOPT_OK)
      return 1;
    if (errmsg != nullptr)
      *errmsg = ret;
    return -1;
  } break;
  case processor_t::ev_ending_undo:
  case processor_t::ev_oldfile: {
    load_from_idb();
  } break;
  case processor_t::ev_privrange_changed: {
    helper.create("$ 65816");
  } break;
  case processor_t::ev_out_data: {
    outctx_t* ctx = va_arg(va, outctx_t*);
    bool analyze_only = va_argi(va, bool);
    m65816_data(*ctx, analyze_only);

    return 1;
  } break;
  //case processor_t::ev_undefine: {
  //  ea_t ea = va_arg(va, ea_t);
  //  ea_clr_bank(ea);

  //  return 1;
  //} break;
  default:
    return 0;
  }

  return retcode;
}

static const char* const shnames[] = { "m65816", NULL };
static const char* const lnames[] = { "WD M65816", NULL };

static const asm_t ca65asm = {
  AS_COLON | ASH_HEXF4, // Assembler features
  0,                    // User-defined flags
  "CA65 ASSEMBLER",     // Name
  0,
  nullptr,                 // headers
  ".ORG",               // origin directive
  ".END",               // end directive

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "\\'",        // special symbols in char and string constants

  "db",      // ascii string directive
  "db",      // byte directive
  "dw",      // word directive
  "dl",      // dword directive
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  "dd"
};

static const asm_t* const asms[] = {
  &ca65asm,
  nullptr
};

extern int data_id;

ssize_t idaapi notify(void* user_data, int notification_code, va_list va) {
  if (notification_code == processor_t::ev_get_procmod) {
    data_id = 0;
    return size_t(SET_MODULE_DATA(m65816_t));
  }

  return 0;
}

static const char* const regnames[] = {
  "A",  // Accumulator
  "X",  // Index
  "Y",  // Index
  "SP",  // Stack
  "PC", // PC
  "D", // Direct page register
  "DB", // Data bank

  "P", // flags

  // virtual
  "cs", "ds"
};

static const uchar retcode_1[] = { 0x60 }; // RTS
static const uchar retcode_2[] = { 0x40 }; // RTI
static const uchar retcode_3[] = { 0x6b }; // RTL

static const bytes_t retcodes[] = {
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { 0, nullptr }
};

processor_t LPH = {
  IDP_INTERFACE_VERSION,
  PLFM_65C816, // 0x8000 + 889, // proc ID
  PRN_HEX | PR_BINMEM | PR_NO_SEGMOVE | PR_CNDINSNS, // flags
  PR2_MAPPINGS | PR2_IDP_OPTS, // flags2
  8, 8, // bits in a byte (code/data)
  shnames, // short processor names
  lnames, // long processor names
  asms, // assembler definitions

  notify, // callback to create our proc module instance

  regnames, // register names
  qnumber(regnames), // registers count

  rVcs, rVds, // number of first/last segment register
  0, // segment register size
  rVcs, rVds, // virtual code/data segment register

  NULL, // typical code start sequences
  retcodes, // return opcodes bytes

  0, M65816_last, // indices of first/last opcodes (in enum)
  Instructions, // array of instructions,

  3, // 24 bit imitation (tbyte)
};