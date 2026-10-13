# Linux build of the processor module, loader and tile viewer plugin (the Windows build uses the .vcxproj files)
#   make IDA_SDK=/path/to/ida-sdk/src
#   make install IDA_DIR=/path/to/ida      (or copy build/*.so into ~/.idapro/procs and ~/.idapro/loaders)
IDA_SDK ?= $(HOME)/ida-sdk/src
IDA_DIR ?= $(HOME)/.idapro
# IDA installation: its Qt libraries are linked when the SDK has no Linux build of Qt
IDA_HOME ?= $(HOME)/ida-pro-9.4

CXX ?= g++
# -Wno-format: %a is IDA's address format, gcc takes it for a double (the SDK builds its modules with it too)
CXXFLAGS = -std=c++17 -O2 -shared -fPIC -Wno-format -D__LINUX__ -D__X64__ -D__EA64__ -I$(IDA_SDK)/include -I$(IDA_SDK)/module
# SDK 9.4: lib/x64_linux_64, older SDKs: lib/x64_linux_gcc_64
IDA_LIBDIR ?= $(firstword $(wildcard $(IDA_SDK)/lib/x64_linux_64 $(IDA_SDK)/lib/x64_linux_gcc_64))
LDFLAGS = -L$(IDA_LIBDIR) -lida

# the tile viewer plugin uses IDA's Qt (QT_NAMESPACE=QT): headers built by the SDK into build/qt-install,
# libraries from there or (when the SDK has only the Windows build of Qt) from the IDA installation.
# rpath: idat / idalib don't load Qt themselves; without IDA's directory the plugin installed into ~/.idapro/plugins
# would get the system Qt there, fail to load and print an error
QT_DIR ?= $(IDA_SDK)/build/qt-install
QT_LIBDIR ?= $(if $(wildcard $(QT_DIR)/lib/libQt6Core.so.6),$(QT_DIR)/lib,$(IDA_HOME))
QT_CXXFLAGS = -DQT_CORE_LIB -DQT_GUI_LIB -DQT_WIDGETS_LIB -DQT_NAMESPACE=QT -I$(QT_DIR)/include
QT_LDFLAGS = $(QT_LIBDIR)/libQt6Core.so.6 $(QT_LIBDIR)/libQt6Gui.so.6 $(QT_LIBDIR)/libQt6Widgets.so.6 -Wl,-rpath,'$$ORIGIN/..':$(abspath $(IDA_HOME))

PROC_SRC = ana.cpp dbdp.cpp emu.cpp ins.cpp mxfix.cpp out.cpp reg.cpp

all: build/snesproc.so build/snesldr.so build/snestiles.so

build/snesproc.so: $(PROC_SRC) 65816.hpp ins.hpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) $(PROC_SRC) $(LDFLAGS) -o $@

build/snesldr.so: snes_loader.cpp snes_cart.hpp 65816.hpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) snes_loader.cpp $(LDFLAGS) -o $@

build/snestiles.so: snes_tiles.cpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) $(QT_CXXFLAGS) snes_tiles.cpp $(LDFLAGS) $(QT_LDFLAGS) -o $@

# Files are replaced with mv, not overwritten: a running IDA keeps the old module mapped in memory,
# overwriting it in place would crash it. The new files are used after restarting IDA.
install: all
	mkdir -p $(IDA_DIR)/procs $(IDA_DIR)/loaders $(IDA_DIR)/plugins
	cp build/snesproc.so $(IDA_DIR)/procs/snesproc.so.new && mv -f $(IDA_DIR)/procs/snesproc.so.new $(IDA_DIR)/procs/snesproc.so
	cp build/snesldr.so $(IDA_DIR)/loaders/snesldr.so.new && mv -f $(IDA_DIR)/loaders/snesldr.so.new $(IDA_DIR)/loaders/snesldr.so
	cp build/snestiles.so $(IDA_DIR)/plugins/snestiles.so.new && mv -f $(IDA_DIR)/plugins/snestiles.so.new $(IDA_DIR)/plugins/snestiles.so
	cp ida_plugins/mesen_cdl.py $(IDA_DIR)/plugins/mesen_cdl.py.new && mv -f $(IDA_DIR)/plugins/mesen_cdl.py.new $(IDA_DIR)/plugins/mesen_cdl.py

clean:
	rm -rf build

.PHONY: all install clean
