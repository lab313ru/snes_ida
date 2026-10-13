// SNES graphics viewer: Shift+D shows the bytes starting at the cursor as SNES tiles
// (1/2/3/4/8 bpp planar, Mode 7), optionally with a BGR555 palette read from the database / debugged memory.
// A separate plugin and not a part of the processor module: it needs Qt, which idat / idalib don't load.

#include <QtWidgets/QtWidgets>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <netnode.hpp>
#include <dbg.hpp>

#undef wait

QT_USE_NAMESPACE

static const char tiles_title[] = "SNES tiles";
static const char tiles_action_name[] = "snes_ida:data_as_tiles";
static const char settings_node[] = "$ snes_ida tiles";

#define TILE_W 8
#define TILE_H 8
#define MAX_VIEW_BYTES 0x10000 // the view shows at most this much data after the cursor

struct tile_format_t {
  const char* name;
  int bpp;   // bits per pixel: 1 << bpp palette entries
  int bytes; // bytes per 8x8 tile
};

enum {
  FMT_1BPP, FMT_2BPP, FMT_3BPP, FMT_4BPP, FMT_8BPP, FMT_MODE7,
};

static const tile_format_t formats[] = {
  { "1bpp",                1,  8 },
  { "2bpp (BG modes 0-1)", 2, 16 },
  { "3bpp (packed in ROM)", 3, 24 },
  { "4bpp (BG / OBJ)",     4, 32 },
  { "8bpp (BG modes 3-4)", 8, 64 },
  { "Mode 7 (8bpp linear)", 8, 64 },
};

// Color index of pixel (x, y) of a tile.
// Planar formats store each row as bitplanes, bit 7 of a byte is the leftmost pixel. Planes go in pairs: 8 rows of
// (plane 0, plane 1) bytes, then 8 rows of (plane 2, plane 3)... 3bpp is 2bpp followed by 8 bytes of plane 2.
static int tile_pixel(int fmt, const uint8* tile, int x, int y) {
  if (fmt == FMT_MODE7) {
    return tile[y * TILE_W + x];
  }
  if (fmt == FMT_1BPP) {
    return (tile[y] >> (7 - x)) & 1;
  }

  int bpp = formats[fmt].bpp;
  int c = 0;
  for (int p = 0; p < bpp; ++p) {
    uint8 b = (fmt == FMT_3BPP && p == 2) ? tile[16 + y] : tile[(p >> 1) * 16 + y * 2 + (p & 1)];
    c |= ((b >> (7 - x)) & 1) << p;
  }
  return c;
}

// Debugged memory while a process runs, the database otherwise
static void read_mem(ea_t ea, uint8* buf, size_t size) {
  if (get_process_state() != DSTATE_NOTASK) {
    ssize_t ss = read_dbg_memory(ea, buf, size);
    if (ss == (ssize_t)size) {
      return;
    }
  }
  memset(buf, 0, size);
  get_bytes(buf, size, ea, GMB_READALL);
}

class TileCanvas : public QWidget {
public:
  QScrollBar* scroll = nullptr;
  QLabel* status = nullptr;

  int fmt = FMT_4BPP;
  int zoom = 3;
  bool use_pal = false;
  ea_t pal_ea = BADADDR;
  ea_t last_start = BADADDR;

  QRgb pal[256];

  TileCanvas() {
    setMouseTracking(true);
    setMinimumSize(TILE_W * 4, TILE_H * 4);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    load_settings();
    update_palette();
  }

  void load_settings() {
    netnode n(settings_node);
    if (n == BADNODE) {
      return;
    }
    nodeidx_t v = n.altval(0);
    if (v != 0 && v - 1 < qnumber(formats)) {
      fmt = (int)(v - 1);
    }
    v = n.altval(1);
    if (v >= 1 && v <= 16) {
      zoom = (int)v;
    }
    if (n.altval(2) != 0) {
      use_pal = true;
      pal_ea = (ea_t)(n.altval(3));
    }
  }

  void save_settings() {
    netnode n(settings_node, 0, true);
    n.altset(0, fmt + 1);
    n.altset(1, zoom);
    n.altset(2, use_pal ? 1 : 0);
    n.altset(3, use_pal ? pal_ea : 0);
  }

  int tile_px() const {
    return TILE_W * zoom;
  }

  int cols() const {
    return std::max(1, width() / tile_px());
  }

  int rows() const {
    return std::max(1, (height() + tile_px() - 1) / tile_px());
  }

  int full_rows() const {
    return std::max(1, height() / tile_px());
  }

  // [start, end) of the shown data: from the cursor till the end of its segment
  bool get_range(ea_t* start, ea_t* end) const {
    ea_t ea = get_screen_ea();
    segment_info_t s;
    if (ea == BADADDR || !get_segment_info(&s, ea)) {
      return false;
    }
    *start = ea;
    *end = std::min<ea_t>(s.end_ea, ea + MAX_VIEW_BYTES);
    return true;
  }

  int total_tiles(ea_t start, ea_t end) const {
    int tb = formats[fmt].bytes;
    return (int)((end - start + tb - 1) / tb);
  }

  // BGR555 palette from pal_ea, or a gray ramp with as many shades as the format has colors
  void update_palette() {
    int n = 1 << formats[fmt].bpp;

    if (use_pal && pal_ea != BADADDR) {
      uint8 raw[512];
      read_mem(pal_ea, raw, n * 2);
      for (int i = 0; i < n; ++i) {
        uint16 w = raw[i * 2] | (raw[i * 2 + 1] << 8);
        int r = (w >> 0) & 0x1F, g = (w >> 5) & 0x1F, b = (w >> 10) & 0x1F;
        pal[i] = qRgb((r << 3) | (r >> 2), (g << 3) | (g >> 2), (b << 3) | (b >> 2));
      }
    }
    else {
      for (int i = 0; i < n; ++i) {
        int v = i * 255 / (n - 1);
        pal[i] = qRgb(v, v, v);
      }
    }
  }

  void set_format(int f) {
    fmt = f;
    update_palette();
    save_settings();
    update();
  }

  void set_zoom(int z) {
    zoom = z;
    save_settings();
    update();
  }

  void set_palette_text(const QString& text) {
    QString t = text.trimmed();
    t.remove('$').remove(':');
    if (t.startsWith("0x", Qt::CaseInsensitive)) {
      t = t.mid(2);
    }
    bool ok = false;
    qulonglong v = t.toULongLong(&ok, 16);
    use_pal = ok && !t.isEmpty();
    pal_ea = use_pal ? (ea_t)v : BADADDR;
    update_palette();
    save_settings();
    update();
  }

  // tile under a widget point, or -1
  int tile_at(const QPoint& p, ea_t start, ea_t end) const {
    if (p.x() < 0 || p.y() < 0 || p.x() >= cols() * tile_px()) {
      return -1;
    }
    int i = (scroll->value() + p.y() / tile_px()) * cols() + p.x() / tile_px();
    return i < total_tiles(start, end) ? i : -1;
  }

protected:
  void paintEvent(QPaintEvent*) override {
    QPainter painter(this);
    painter.fillRect(rect(), QColor(48, 48, 48));

    ea_t start, end;
    if (!get_range(&start, &end)) {
      return;
    }

    if (start != last_start) {
      last_start = start;
      QSignalBlocker sb(scroll);
      scroll->setValue(0);
      if (use_pal) {
        update_palette(); // the palette may be in RAM that changed meanwhile
      }
    }

    int c = cols(), r = rows();
    int total = total_tiles(start, end);
    {
      QSignalBlocker sb(scroll);
      scroll->setMaximum(std::max(0, (total + c - 1) / c - full_rows()));
      scroll->setPageStep(full_rows());
    }

    int first = scroll->value() * c;
    int count = std::min(total - first, c * r);
    if (count <= 0) {
      return;
    }

    int tb = formats[fmt].bytes;
    ea_t from = start + (ea_t)first * tb;
    size_t avail = (size_t)(end - from);
    qvector<uint8> data;
    data.resize((size_t)count * tb, 0);
    read_mem(from, data.begin(), std::min(avail, data.size()));

    QImage img(c * TILE_W, r * TILE_H, QImage::Format_RGB32);
    img.fill(QColor(48, 48, 48));

    for (int i = 0; i < count; ++i) {
      const uint8* tile = &data[(size_t)i * tb];
      int tx = (i % c) * TILE_W, ty = (i / c) * TILE_H;
      bool partial = (size_t)(i + 1) * tb > avail; // the last tile, cut by the end of the segment

      for (int y = 0; y < TILE_H; ++y) {
        QRgb* line = (QRgb*)img.scanLine(ty + y);
        for (int x = 0; x < TILE_W; ++x) {
          line[tx + x] = partial ? qRgb(96, 0, 0) : pal[tile_pixel(fmt, tile, x, y)];
        }
      }
    }

    painter.drawImage(QRect(0, 0, img.width() * zoom, img.height() * zoom), img);
  }

  void mouseMoveEvent(QMouseEvent* e) override {
    ea_t start, end;
    int i = get_range(&start, &end) ? tile_at(e->pos(), start, end) : -1;
    if (i < 0) {
      status->clear();
      return;
    }
    qstring s;
    s.sprnt("Tile %d at $%06" FMT_EA "X (double click to jump)", i, start + (ea_t)i * formats[fmt].bytes);
    status->setText(s.c_str());
  }

  void mouseDoubleClickEvent(QMouseEvent* e) override {
    ea_t start, end;
    int i = get_range(&start, &end) ? tile_at(e->pos(), start, end) : -1;
    if (i >= 0) {
      jumpto(start + (ea_t)i * formats[fmt].bytes);
    }
  }

  void wheelEvent(QWheelEvent* e) override {
    QCoreApplication::sendEvent(scroll, e);
  }

  void resizeEvent(QResizeEvent*) override {
    update();
  }
};

struct plugin_ctx_t;

struct tiles_action_t : public action_handler_t {
  plugin_ctx_t& plug;
  tiles_action_t(plugin_ctx_t& _plug) : plug(_plug) {}

  virtual int idaapi activate(action_activation_ctx_t* ctx) override;

  virtual action_state_t idaapi update(action_update_ctx_t* ctx) override {
    return AST_ENABLE_ALWAYS;
  }
};

struct tiles_listener_t : public event_listener_t {
  plugin_ctx_t& plug;
  tiles_listener_t(plugin_ctx_t& _plug) : plug(_plug) {}

  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct plugin_ctx_t : public plugmod_t {
  TWidget* widget = nullptr;
  TileCanvas* canvas = nullptr;

  tiles_action_t tiles_action_handler = tiles_action_t(*this);
  tiles_listener_t ui_listener = tiles_listener_t(*this);
  tiles_listener_t view_listener = tiles_listener_t(*this);
  tiles_listener_t dbg_listener = tiles_listener_t(*this);

  action_desc_t tiles_action = ACTION_DESC_LITERAL_PLUGMOD(tiles_action_name, "Show data as SNES tiles", &tiles_action_handler, this, "Shift+D", NULL, -1);

  plugin_ctx_t() {
    register_action(tiles_action);
    hook_event_listener(HT_UI, &ui_listener);
    hook_event_listener(HT_VIEW, &view_listener);
    hook_event_listener(HT_DBG, &dbg_listener);
  }

  ~plugin_ctx_t() {
    // the widget's code lives in this module: it must not outlive it
    if (widget != nullptr) {
      close_widget(widget, 0);
      widget = nullptr;
      canvas = nullptr;
    }
    unhook_event_listener(HT_DBG, &dbg_listener);
    unhook_event_listener(HT_VIEW, &view_listener);
    unhook_event_listener(HT_UI, &ui_listener);
    unregister_action(tiles_action_name);
  }

  void build_widget(TWidget* w) {
    QWidget* qw = (QWidget*)w;

    QComboBox* fmt_box = new QComboBox();
    for (const auto& f : formats) {
      fmt_box->addItem(f.name);
    }

    QLineEdit* pal_addr = new QLineEdit();
    pal_addr->setPlaceholderText("none (grayscale)");
    pal_addr->setToolTip("Address of a BGR555 palette (2 bytes per color, as written to CGRAM), e.g. 7E2000 or C0:8000.\n"
      "Empty: shades of gray.");
    pal_addr->setValidator(new QRegularExpressionValidator(QRegularExpression("\\s*\\$?(0[xX])?[0-9a-fA-F:]{0,12}\\s*"), pal_addr));

    QSpinBox* zoom_box = new QSpinBox();
    zoom_box->setRange(1, 16);
    zoom_box->setSuffix("x");

    canvas = new TileCanvas();
    QScrollBar* sb = new QScrollBar(Qt::Vertical);
    QLabel* status = new QLabel();
    canvas->scroll = sb;
    canvas->status = status;

    fmt_box->setCurrentIndex(canvas->fmt);
    zoom_box->setValue(canvas->zoom);
    if (canvas->use_pal) {
      qstring s;
      s.sprnt("%" FMT_EA "X", canvas->pal_ea);
      pal_addr->setText(s.c_str());
    }

    QHBoxLayout* top = new QHBoxLayout();
    top->addWidget(new QLabel("Format:"));
    top->addWidget(fmt_box);
    top->addWidget(new QLabel("Palette:"));
    top->addWidget(pal_addr, 1);
    top->addWidget(new QLabel("Zoom:"));
    top->addWidget(zoom_box);

    QGridLayout* layout = new QGridLayout();
    layout->setContentsMargins(4, 4, 4, 4);
    layout->addLayout(top, 0, 0, 1, 2);
    layout->addWidget(canvas, 1, 0);
    layout->addWidget(sb, 1, 1);
    layout->addWidget(status, 2, 0, 1, 2);
    layout->setRowStretch(1, 1);
    qw->setLayout(layout);

    TileCanvas* c = canvas;
    QObject::connect(fmt_box, &QComboBox::currentIndexChanged, c, [c](int i) { c->set_format(i); });
    QObject::connect(zoom_box, &QSpinBox::valueChanged, c, [c](int z) { c->set_zoom(z); });
    QObject::connect(pal_addr, &QLineEdit::textChanged, c, [c](const QString& t) { c->set_palette_text(t); });
    QObject::connect(sb, &QScrollBar::valueChanged, c, [c](int) { c->update(); });
  }

  void show_tiles() {
    TWidget* w = find_widget(tiles_title);
    if (w != nullptr) {
      activate_widget(w, true);
      if (canvas != nullptr) {
        canvas->update();
      }
      return;
    }

    widget = create_empty_widget(tiles_title);
    if (widget == nullptr) {
      return;
    }
    build_widget(widget);
    display_widget(widget, WOPN_PERSIST | WOPN_DP_RIGHT);
  }

  void update_tiles() {
    if (canvas != nullptr) {
      canvas->update();
    }
  }

  virtual bool idaapi run(size_t) override {
    show_tiles();
    return true;
  }
};

int idaapi tiles_action_t::activate(action_activation_ctx_t*) {
  plug.show_tiles();
  return 1;
}

ssize_t idaapi tiles_listener_t::on_event(ssize_t code, va_list va) {
  if (this == &plug.view_listener) {
    if (code == view_loc_changed) {
      plug.update_tiles();
    }
    return 0;
  }
  if (this == &plug.dbg_listener) {
    if (code == dbg_suspend_process) { // memory of the debugged process changed
      plug.update_tiles();
    }
    return 0;
  }

  switch (code) {
  case ui_populating_widget_popup: {
    TWidget* w = va_arg(va, TWidget*);
    TPopupMenu* p = va_arg(va, TPopupMenu*);
    int type = get_widget_type(w);
    if (type == BWN_DISASM || type == BWN_HEXVIEW) {
      attach_action_to_popup(w, p, tiles_action_name);
    }
  } break;
  case ui_widget_invisible: {
    TWidget* w = va_arg(va, TWidget*);
    if (w == plug.widget) {
      plug.widget = nullptr;
      plug.canvas = nullptr;
    }
  } break;
  case ui_refreshmarked:
    plug.update_tiles();
    break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static plugmod_t* idaapi init() {
  if (!is_idaq()) {
    return nullptr;
  }
  qstring procname = inf_get_procname();
  if (procname != "snes816" && procname != "m65816") {
    return nullptr;
  }
  return new plugin_ctx_t;
}

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI | PLUGIN_PROC,
  init,
  nullptr,
  nullptr,
  "Shows data as SNES tiles (Shift+D)",
  "SNES graphics viewer\n"
  "Shift+D in the disassembly or hex view shows the bytes at the cursor as SNES tiles.",
  "SNES tiles",
  "",
};
