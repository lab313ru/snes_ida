# Linux build of the processor module and loader (the Windows build uses the .vcxproj files)
#   make IDA_SDK=/path/to/ida-sdk/src
#   make install IDA_DIR=/path/to/ida      (or copy build/*.so into ~/.idapro/procs and ~/.idapro/loaders)
IDA_SDK ?= $(HOME)/ida-sdk/src
IDA_DIR ?= $(HOME)/.idapro

CXX ?= g++
CXXFLAGS = -std=c++17 -O2 -shared -fPIC -D__LINUX__ -D__X64__ -D__EA64__ -I$(IDA_SDK)/include -I$(IDA_SDK)/module
LDFLAGS = -L$(IDA_SDK)/lib/x64_linux_gcc_64 -lida

PROC_SRC = ana.cpp dbdp.cpp emu.cpp ins.cpp mxfix.cpp out.cpp reg.cpp

all: build/snesproc.so build/snesldr.so

build/snesproc.so: $(PROC_SRC) 65816.hpp ins.hpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) $(PROC_SRC) $(LDFLAGS) -o $@

build/snesldr.so: snes_loader.cpp snes_cart.hpp 65816.hpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) snes_loader.cpp $(LDFLAGS) -o $@

# Files are replaced with mv, not overwritten: a running IDA keeps the old module mapped in memory,
# overwriting it in place would crash it. The new files are used after restarting IDA.
install: all
	mkdir -p $(IDA_DIR)/procs $(IDA_DIR)/loaders $(IDA_DIR)/plugins
	cp build/snesproc.so $(IDA_DIR)/procs/snesproc.so.new && mv -f $(IDA_DIR)/procs/snesproc.so.new $(IDA_DIR)/procs/snesproc.so
	cp build/snesldr.so $(IDA_DIR)/loaders/snesldr.so.new && mv -f $(IDA_DIR)/loaders/snesldr.so.new $(IDA_DIR)/loaders/snesldr.so
	cp ida_plugins/mesen_cdl.py $(IDA_DIR)/plugins/mesen_cdl.py.new && mv -f $(IDA_DIR)/plugins/mesen_cdl.py.new $(IDA_DIR)/plugins/mesen_cdl.py

clean:
	rm -rf build

.PHONY: all install clean
