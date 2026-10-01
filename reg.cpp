#include "65816.hpp"
#include <typeinf.hpp>
#include <search.hpp>
#include <algorithm>

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
      " Show register info as comments\n"
      "\n"
      "       Register sizes (a8/a16, i8/i16) and known DB/D values as listing\n"
      "       comments. They are always shown as a hint when the mouse is over\n"
      "       an instruction\n"
      "\n"
      "ENDHELP\n"
      "ROM specific options\n"
      "%*\n"
      " <~B~RK isn't used in this ROM:C>\n"
      " <~C~OP isn't used in this ROM:C>\n"
      " <~W~DM isn't used in this ROM:C>\n"
      " <~S~how register info as comments:C>>\n"
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
    } else if (streq(keyword, "SHOW_REG_CMTS")) {
      setflag(idpflags, SHOW_REG_CMTS, *(int*)value != 0);

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

void m65816_t::on_auto_idle() {
  if (!mx_conflicts.empty() && fix_mx_conflicts(mx_conflicts, idpflags)) {
    known_regs_dirty = true; // the code is decoded again; the propagation runs after that
    retry_failed_funcs = true;
    return;
  }
  if (retry_failed_funcs) {
    // the code decoded again: functions that failed because of it may be created now
    retry_failed_funcs = false;
    std::map<ea_t, int> todo;
    todo.swap(failed_funcs);
    for (auto& it : todo) {
      ea_t ea = it.first;
      if (!is_code(get_flags(ea)) || get_func(ea) != nullptr) {
        continue;
      }
      if (add_func(ea)) {
        msg("%a: function created after the M/X fix\n", ea);
      }
      else if (it.second > 1) {
        auto f = failed_funcs.find(ea); // failed again: noted again by ev_func_bounds
        if (f != failed_funcs.end()) {
          f->second = it.second - 1;
        }
      }
      else {
        failed_funcs.erase(ea);
      }
    }
  }
  if (known_regs_dirty) {
    known_regs_dirty = false;
    propagate_known_regs();
  }
}

// Data carousel (D): byte -> word -> 24-bit value. The 3-byte tbyte of this processor is in the carousel and every
// tbyte created as a data item becomes d24 (custom types can't be part of the carousel themselves).
// Only a carousel still at IDA's default (byte, word, dword, qword) is changed, a user's choice is kept.
static const uval_t DATA_CAROUSEL_DEFAULT = 0x17; // bits in the order of Options -> Setup data types
static const uval_t DATA_CAROUSEL_SNES = 0x43;    // byte, word, tbyte

void m65816_t::setup_data_carousel() {
  if (inf_get_datatypes() == DATA_CAROUSEL_DEFAULT) {
    inf_set_datatypes(DATA_CAROUSEL_SNES);
  }
}

void m65816_t::convert_new_tbytes() {
  std::set<ea_t> todo;
  todo.swap(new_tbytes);
  for (ea_t ea : todo) {
    flags64_t F = get_flags(ea);
    if (is_tbyte(F) && get_item_head(ea) == ea && get_item_size(ea) == 3 && data24_id > 0 && data24_num_fid > 0) {
      del_items(ea, DELIT_SIMPLE, 3);
      create_custdata(ea, 3, data24_id, data24_num_fid);
    }
  }
}

ssize_t idaapi known_regs_listener_t::on_event(ssize_t code, va_list va) {
  if (pm == nullptr) {
    return 0;
  }
  switch (code) {
  case idb_event::auto_empty:
    pm->on_auto_idle();
    break;
  case idb_event::make_data: {
    ea_t ea = va_arg(va, ea_t);
    flags64_t flags = va_arg(va, flags64_t);
    va_arg(va, tid_t);
    asize_t len = va_arg(va, asize_t);
    if (is_tbyte(flags) && len == 3) {
      pm->new_tbytes.insert(ea);
    }
  } break;
  case idb_event::lt_udm_created: {
    const char* udtname = va_arg(va, const char*);
    pm->apply_data24_repr(udtname);
  } break;
  case idb_event::lt_udm_changed: {
    const char* udtname = va_arg(va, const char*);
    pm->apply_data24_repr(udtname);
  } break;
  case idb_event::local_types_changed: {
    local_type_change_t ltc = (local_type_change_t)va_arg(va, int);
    va_arg(va, uint32);
    const char* name = va_arg(va, const char*);
    if (ltc == LTC_ADDED || ltc == LTC_EDITED) {
      pm->apply_data24_repr(name);
    }
  } break;
  default:
    break;
  }
  return 0;
}

int idaapi known_regs_timer_cb(void* ud) {
  m65816_t* pm = static_cast<m65816_t*>(ud);
  if (!pm->new_tbytes.empty()) {
    pm->convert_new_tbytes();
  }
  if ((pm->known_regs_dirty || !pm->mx_conflicts.empty() || pm->retry_failed_funcs) && auto_is_ok()) {
    pm->on_auto_idle();
  }
  return 500;
}

// 24-bit values stored in 3 bytes (little endian): the custom data type "d24" (the listing directive; "3" on a byte,
// or D). Two formats: "number" shows the value, "offset" shows the target name and creates a reference to it.
// O switches between them (for a structure field: in the structure, i.e. in all its instances).
// Structure fields use the "data24_t" type. It must be named differently from the custom data type: with the same
// name IDA's parser loses the format of "__custom(...)" when a structure is edited as text.
static const char data24_type_name[] = "d24";
static const char data24_num_name[] = "number";
static const char offset24_name[] = "offset";
static const char data24_typedef_name[] = "data24_t";

int data24_id = -1;
int data24_num_fid = -1;
int data24_off_fid = -1;

static const data_type_t data24_type = {
  sizeof(data_type_t), // size of this struct
  nullptr, // user defined data
  DTP_NODUP, // properties
  data24_type_name, // internal name of the data type
  "24-bit data", // menu name. If nullptr, the type won't be visible in the Edit menu
  "3", // hotkey
  "d24", // keyword to use in the assembly listing
  3, // value size
  nullptr, // may_create_at? nullptr means the type can be created anywhere
  nullptr, // calc exact size for varsize
};

static uint32_t data24_value(const uint8_t* b3) {
  return (b3[2] << 16) | (b3[1] << 8) | b3[0];
}

// canonical ea of the addressed memory (mirrors resolved), BADADDR when nothing is mapped there
static ea_t data24_target(uint32_t value) {
  return get_data_target((value >> 16) & 0xFF, value & 0xFFFF);
}

static bool idaapi print_data24(void* ud, qstring* out, const void* value, asize_t, ea_t current_ea, int operand_num, int) {
  if (out != nullptr) {
    out->cat_sprnt("$%06X", data24_value((const uint8_t*)value));
  }
  return true;
}

static bool idaapi print_offset24(void* ud, qstring* out, const void* value, asize_t, ea_t current_ea, int operand_num, int) {
  if (out != nullptr) {
    uint32_t val = data24_value((const uint8_t*)value);
    ea_t target = data24_target(val);

    qstring name;
    if (target != BADADDR && get_name_expr(&name, current_ea, operand_num, target, target) > 0) {
      out->append(name);
    }
    else {
      out->cat_sprnt("$%06X", val);
    }
  }
  return true;
}

// Creates the data references of an offset item: every element of a table, or the value at current_ea
// (e.g. a structure member). The value is read from the database, not kept from the output.
static void idaapi analyze_offset24(void* ud, ea_t current_ea, int operand_num) {
  if (current_ea == BADADDR) {
    return;
  }
  ea_t head = get_item_head(current_ea);
  ea_t start = current_ea;
  ea_t end = current_ea + 3;
  if (head == current_ea && is_custom(get_flags(head)) && get_item_size(head) % 3 == 0) {
    end = head + get_item_size(head); // table
  }

  for (ea_t ea = start; ea + 3 <= end; ea += 3) {
    uint8_t b3[3];
    if (get_bytes(b3, 3, ea) != 3) {
      break;
    }
    ea_t target = data24_target(data24_value(b3));
    if (target != BADADDR) {
      add_dref(head, target, dr_O);
    }
  }
}

static const data_format_t data24_format = {
  sizeof(data_format_t), // size of this struct
  nullptr, // user defined data
  0, // properties
  data24_num_name, // internal name of the data format
  "Number", // menu name
  nullptr, // hotkey
  3, // value size
  0, // text width of the value
  print_data24, // callback to render colored text for the data
  nullptr, // scan
  nullptr, // analyze: a number, no reference
};

static const data_format_t offset24_format = {
  sizeof(data_format_t), // size of this struct
  nullptr, // user defined data
  0, // properties
  offset24_name, // internal name of the data format
  "Offset", // menu name
  nullptr, // hotkey
  3, // value size
  0, // text width of the value
  print_offset24, // callback to render colored text for the data
  nullptr, // scan
  analyze_offset24, // analyze: creates the references
};

// switches a 3-byte _TBYTE member of a structure between the d24 number and offset representations
static bool toggle_data24_member(tinfo_t& tif, int idx, const udm_t& udm) {
  if (data24_id <= 0 || data24_num_fid <= 0 || data24_off_fid <= 0) {
    return false;
  }
  if (!udm.type.is_tbyte() || udm.type.get_size() != 3) {
    return false;
  }
  bool is_offset = udm.repr.get_vtype() == FRB_CUSTOM && udm.repr.cd.fid == data24_off_fid;
  value_repr_t repr;
  repr.set_vtype(FRB_CUSTOM);
  repr.cd.dtid = (int16)data24_id;
  repr.cd.fid = (int16)(is_offset ? data24_num_fid : data24_off_fid);
  if (tif.set_udm_repr(idx, repr) != TERR_OK) {
    return false;
  }
  qstring tname;
  tif.get_type_name(&tname);
  msg("%s.%s: %s (all instances)\n", tname.c_str(), udm.name.c_str(), is_offset ? "24-bit number" : "24-bit offset");
  return true;
}

// O on a data24_t field in a type listing (Local Types): switches it between number and offset
bool toggle_data24_type_member(const til_type_ref_t* ref) {
  if (ref == nullptr || !ref->is_udt() || !ref->on_member()) {
    return false;
  }
  tinfo_t tif;
  if (ref->ordinal == 0 || !tif.get_numbered_type(nullptr, ref->ordinal)) {
    tif = ref->tif;
  }
  udm_t udm;
  udm.offset = ref->udm.offset;
  int idx = tif.find_udm(&udm, STRMEM_OFFSET);
  if (idx < 0 || !toggle_data24_member(tif, idx, udm)) {
    return false;
  }
  // instances in the listing show the new representation
  request_refresh(IWID_DISASM);
  return true;
}

// O on a d24 item or on a data24_t field of a structure instance: switches between number and offset.
// Returns false when there is no such item at ea.
bool toggle_data24_offset(ea_t ea) {
  if (data24_id <= 0 || data24_num_fid <= 0 || data24_off_fid <= 0) {
    return false;
  }
  ea_t head = get_item_head(ea);
  flags64_t F = get_flags(head);

  if (is_custom(F)) {
    custom_data_type_ids_t cdis;
    if (get_custom_data_type_ids(&cdis, head) < 0 || cdis.dtid != data24_id) {
      return false;
    }
    int fid = (cdis.fids[0] == data24_off_fid) ? data24_num_fid : data24_off_fid;
    asize_t size = get_item_size(head);
    del_items(head, DELIT_SIMPLE, size);
    create_custdata(head, size, data24_id, fid);
    plan_range(head, head + size);
    msg("%a: %s\n", head, fid == data24_off_fid ? "24-bit offset" : "24-bit number");
    return true;
  }

  if (is_struct(F)) {
    // the structure of an instance is kept in its operand info, not always as the item type
    tinfo_t tif;
    opinfo_t oi;
    if (!(get_opinfo(&oi, head, 0, F) != nullptr && tif.get_type_by_tid(oi.tid)) && !get_tinfo(&tif, head)) {
      return false;
    }
    if (!tif.is_udt()) {
      return false;
    }
    udm_t udm;
    udm.offset = uint64(ea - head) * 8;
    int idx = tif.find_udm(&udm, STRMEM_OFFSET);
    if (idx < 0 || !toggle_data24_member(tif, idx, udm)) {
      return false;
    }
    plan_range(head, head + get_item_size(head));
    return true;
  }
  return false;
}

// O / Q on unexplored bytes: a d24 offset / number there (instead of IDA's 4-byte offset / nothing). Returns false
// when the 3 bytes at ea are not all unexplored.
bool create_data24(ea_t ea, bool offset) {
  int fid = offset ? data24_off_fid : data24_num_fid;
  if (data24_id <= 0 || fid <= 0) {
    return false;
  }
  for (ea_t a = ea; a < ea + 3; a++) {
    if (!is_mapped(a) || !is_unknown(get_flags(a))) {
      return false;
    }
  }
  if (!create_custdata(ea, 3, data24_id, fid)) {
    return false;
  }
  plan_range(ea, ea + 3);
  msg("%a: %s\n", ea, offset ? "24-bit offset" : "24-bit number");
  return true;
}

// Alt+I / Ctrl+I (search for an immediate value): IDA's find_imm() compares only the values of instructions and of
// standard data items (byte, word, dword, qword), so any 3 bytes forming the value (little endian) are searched too,
// whatever is defined there, and both results are merged. The value of another bank addressing the same memory
// (a mirror) is searched as well. A match inside an instruction is reported as the instruction.
static uval_t imm_value = 0;
static ushort imm_opts = 0; // 1: search up, 2: find all occurrences
static bool imm_valid = false;
static ea_t imm_last = BADADDR; // the last match: the next search continues from it when the cursor is still there

// the 3-byte patterns of the value: the value itself and its mirrors
static void imm_patterns(compiled_binpat_vec_t* pats, uval_t value) {
  if (value > 0xFFFFFF) {
    return;
  }
  ea_t canon = data24_target(uint32_t(value));
  for (uint32_t bank = 0; bank < 0x100; bank++) {
    uint32_t v = (bank << 16) | (value & 0xFFFF);
    if (v != value && (canon == BADADDR || data24_target(v) != canon)) {
      continue;
    }
    compiled_binpat_t& pat = pats->push_back();
    pat.bytes.push_back(uchar(v));
    pat.bytes.push_back(uchar(v >> 8));
    pat.bytes.push_back(uchar(v >> 16));
  }
}

// a byte match is reported as the instruction it is a part of
static ea_t imm_report_ea(ea_t ea) {
  ea_t head = get_item_head(ea);
  return is_code(get_flags(head)) ? head : ea;
}

// the next (or previous) 3 bytes forming the value after ea, BADADDR when there are none
static ea_t find_imm_bytes(ea_t ea, bool up, const compiled_binpat_vec_t& pats) {
  if (pats.empty()) {
    return BADADDR;
  }
  if (up) {
    ea_t found = bin_search(inf_get_min_ea(), ea, pats, BIN_SEARCH_BACKWARD | BIN_SEARCH_NOSHOW);
    return found == BADADDR ? BADADDR : imm_report_ea(found);
  }
  for (ea_t from = ea + 1; from < inf_get_max_ea(); ) {
    ea_t found = bin_search(from, inf_get_max_ea(), pats, BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW);
    if (found == BADADDR) {
      return BADADDR;
    }
    ea_t rep = imm_report_ea(found);
    if (rep > ea) {
      return rep;
    }
    from = found + 1; // in the instruction the search started from
  }
  return BADADDR;
}

// the next (or previous) match after ea: an IDA one or a 3-byte one, whichever is closer
static ea_t find_imm_next(ea_t ea, bool up, uval_t value) {
  compiled_binpat_vec_t pats;
  imm_patterns(&pats, value);
  ea_t ida = find_imm(ea, (up ? SEARCH_UP : SEARCH_DOWN) | SEARCH_NEXT | SEARCH_NOSHOW, value);
  ea_t bytes = find_imm_bytes(ea, up, pats);
  if (ida == BADADDR) {
    return bytes;
  }
  if (bytes == BADADDR) {
    return ida;
  }
  return up ? qmax(ida, bytes) : qmin(ida, bytes);
}

static const int imm_widths[] = { CHCOL_HEX | 10, 48 };
static const char* const imm_header[] = { "Address", "Instruction" };

struct imm_chooser_t : public chooser_t {
  eavec_t list;
  qstring title_str; // chooser_t keeps only the pointer

  imm_chooser_t(const qstring& title_) : chooser_t(0, qnumber(imm_widths), imm_widths, imm_header), title_str(title_) {
    title = title_str.c_str();
  }

  virtual const void* get_obj_id(size_t* len) const override {
    *len = strlen(title);
    return title;
  }
  virtual size_t idaapi get_count() const override { return list.size(); }
  virtual void idaapi get_row(qstrvec_t* cols, int*, chooser_item_attrs_t*, size_t n) const override {
    (*cols)[0].sprnt("%a", list[n]);
    generate_disasm_line(&(*cols)[1], list[n], GENDSM_REMOVE_TAGS);
  }
  virtual cbret_t idaapi enter(size_t n) override {
    if (n < list.size()) {
      jumpto(list[n]);
    }
    return cbret_t();
  }
  virtual ea_t idaapi get_ea(size_t n) const override {
    return n < list.size() ? list[n] : BADADDR;
  }
};

static void find_imm_all(uval_t value) {
  qstring title;
  title.sprnt("Occurrences of: %a", value);
  imm_chooser_t* ch = new imm_chooser_t(title);

  show_wait_box("Searching for the immediate value...");
  ea_t found = find_imm(inf_get_min_ea(), SEARCH_DOWN | SEARCH_NOSHOW, value);
  while (found != BADADDR && !user_cancelled()) {
    ch->list.push_back(found);
    found = find_imm(found, SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW, value);
  }
  compiled_binpat_vec_t pats;
  imm_patterns(&pats, value);
  if (!pats.empty()) {
    found = bin_search(inf_get_min_ea(), inf_get_max_ea(), pats, BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW);
    while (found != BADADDR && !user_cancelled()) {
      ch->list.push_back(imm_report_ea(found));
      found = bin_search(found + 1, inf_get_max_ea(), pats, BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW);
    }
  }
  hide_wait_box();

  if (ch->list.empty()) {
    delete ch;
    warning("Search failed.\nImmediate value %a not found", value);
    return;
  }
  std::sort(ch->list.begin(), ch->list.end());
  ch->list.erase(std::unique(ch->list.begin(), ch->list.end()), ch->list.end());
  ch->choose();
}

static void find_imm_from_screen() {
  bool up = (imm_opts & 1) != 0;
  ea_t ea = get_screen_ea();
  // the cursor is still on the item of the last match (e.g. a table): continue from the match itself
  if (imm_last != BADADDR && get_item_head(imm_last) == get_item_head(ea)) {
    ea = imm_last;
  }
  show_wait_box("Searching for the immediate value...");
  ea_t found = find_imm_next(ea, up, imm_value);
  hide_wait_box();
  if (found == BADADDR) {
    msg("Search failed: immediate value %a not found\n", imm_value);
    beep();
    return;
  }
  imm_last = found;
  jumpto(found);
}

// handles the action instead of IDA; returns true when it was handled
bool search_immediate_action(const char* name) {
  if (name == nullptr) {
    return false;
  }
  bool ask = strcmp(name, "AskNextImmediate") == 0;
  if (!ask && strcmp(name, "JumpImmediate") != 0) {
    return false;
  }
  if (ask || !imm_valid) {
    static const char form[] =
      "Search for immediate value\n"
      "\n"
      "<~V~alue to search:N::32::>\n"
      "<Search ~U~p:C>\n"
      "<~F~ind all occurrences:C>>\n";
    uval_t value = imm_value;
    ushort opts = imm_opts;
    if (ask_form(form, &value, &opts) <= 0) {
      return true;
    }
    imm_value = value;
    imm_opts = opts;
    imm_valid = true;
    imm_last = BADADDR;
    if (opts & 2) {
      find_imm_all(value);
      return true;
    }
  }
  find_imm_from_screen();
  return true;
}

// Local type "data24_t": a 3-byte _TBYTE (tbyte_size is 3 for this processor), so structure fields can be
// declared as "data24_t ptr;". IDA has no other 3-byte scalar type a field could be based on.
void m65816_t::ensure_data24_typedef() {
  tinfo_t tif;
  if (tif.get_named_type(nullptr, data24_typedef_name)) {
    return;
  }
  qstring name;
  if (parse_decl(&tif, &name, nullptr, "typedef _TBYTE data24_t;", PT_SIL | PT_TYP)) {
    tif.set_named_type(nullptr, data24_typedef_name);
  }
}

// 3-byte _TBYTE fields (created by the D carousel, or declared as _TBYTE) become data24_t, and fields without
// a representation get the number one: "data24_t ptr;" becomes "data24_t ptr __custom(d24,number);" (O on a field in an instance
// switches it to "__custom(d24,offset)").
void m65816_t::apply_data24_repr(const char* udtname) {
  if (udtname == nullptr || data24_id <= 0 || data24_num_fid <= 0 || in_data24_repr) {
    return;
  }
  tinfo_t tif;
  udt_type_data_t udt;
  if (!tif.get_named_type(nullptr, udtname) || !tif.is_udt() || !tif.get_udt_details(&udt)) {
    return;
  }

  tinfo_t data24;
  bool have_data24 = data24.get_named_type(nullptr, data24_typedef_name);

  in_data24_repr = true;
  for (size_t i = 0; i < udt.size(); i++) {
    const udm_t& udm = udt[i];
    if (!udm.type.is_tbyte() || udm.type.get_size() != 3) {
      continue;
    }
    value_repr_t repr = udm.repr;
    if (repr.get_vtype() == 0) {
      repr.set_vtype(FRB_CUSTOM);
      repr.cd.dtid = (int16)data24_id;
      repr.cd.fid = (int16)data24_num_fid;
    }
    // a plain _TBYTE (e.g. from the D carousel) becomes data24_t
    qstring tname;
    bool is_typedef = udm.type.is_typedef() && udm.type.get_type_name(&tname) && tname == data24_typedef_name;
    if (have_data24 && !is_typedef) {
      tif.set_udm_type(i, data24, 0, &repr);
    }
    else if (udm.repr.get_vtype() == 0) {
      tif.set_udm_repr(i, repr);
    }
  }
  in_data24_repr = false;
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
    register_action(set_cust_offset_bank_action);

    switch_bitmode.dirty = &known_regs_dirty;
    known_regs_dirty = true;
    known_regs_listener.pm = this;
    hook_event_listener(HT_IDB, &known_regs_listener, &LPH);
    idle_timer = register_timer(500, known_regs_timer_cb, this);
    hook_event_listener(HT_UI, &reg_hint_listener, &LPH);

    data24_id = register_custom_data_type(&data24_type);
    data24_num_fid = register_custom_data_format(&data24_format);
    data24_off_fid = register_custom_data_format(&offset24_format);
    attach_custom_data_format(data24_id, data24_num_fid); // the first one is the default
    attach_custom_data_format(data24_id, data24_off_fid);

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
    unregister_action(set_cust_offset_bank_action_name);
    unhook_event_listener(HT_IDB, &known_regs_listener);
    if (idle_timer != nullptr) {
      unregister_timer(idle_timer);
      idle_timer = nullptr;
    }
    unhook_event_listener(HT_UI, &reg_hint_listener);

    update_action_state("OpOffset", action_state_t::AST_ENABLE_ALWAYS);
    update_action_state("OpOffsetCs", action_state_t::AST_ENABLE_ALWAYS);
    update_action_state("OpenXrefsTree", action_state_t::AST_ENABLE_ALWAYS);

    if (data24_id > 0) {
      unregister_custom_data_type(data24_id);
      data24_id = -1;
    }
    if (data24_num_fid > 0) {
      unregister_custom_data_format(data24_num_fid);
      data24_num_fid = -1;
    }
    if (data24_off_fid > 0) {
      unregister_custom_data_format(data24_off_fid);
      data24_off_fid = -1;
    }

    //unhook_event_listener(HT_IDB, &idb_listener);
  } break;
  case processor_t::ev_newfile: {
    auto* fname = va_arg(va, char*); // here we can load additional data from a current dir
    ensure_data24_typedef();
    setup_data_carousel();
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
  case processor_t::ev_func_bounds: {
    int* code = va_arg(va, int*);
    func_t* pfn = va_arg(va, func_t*);
    if (code != nullptr && *code == FIND_FUNC_UNDEF && pfn != nullptr && failed_funcs.size() < 10000) {
      failed_funcs.emplace(pfn->start_ea, 3);
    }
    retcode = 0;
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
    ensure_data24_typedef();
    setup_data_carousel();
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

// "snes816" is unique, so the loader never ends up with IDA's stock m65816 module.
// "m65816" is kept only to open databases created before the rename.
static const char* const shnames[] = { "snes816", "m65816", NULL };
static const char* const lnames[] = { "WD 65816 (snes_ida)", "WD 65816 (snes_ida, legacy name)", NULL };

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
  PRN_HEX | PR_BINMEM | PR_NO_SEGMOVE | PR_CNDINSNS | PR_USE_TBYTE, // flags
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