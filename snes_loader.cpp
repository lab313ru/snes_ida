#include <loader.hpp>
#include <idp.hpp>
#include <diskio.hpp>
#include <auto.hpp>
#include <name.hpp>
#include <segregs.hpp>
#include <vector>
#include <cmath>

#include "snes_cart.hpp"
#include "65816.hpp"

static int32_t GetHeaderScore(linput_t* li, uint32_t addr, uint32_t _prgRomSize) {
	//Try to figure out where the header is by using a scoring system
	if (_prgRomSize < addr + 0x7FFF) {
		return -1;
	}

	SnesCartInformation cartInfo;
	qlseek(li, addr + 0x7FB0, SEEK_SET);
	qlread(li, &cartInfo, sizeof(SnesCartInformation));

	uint32_t score = 0;
	uint8_t mode = (cartInfo.MapMode & ~0x10);
	if ((mode == 0x20 || mode == 0x22) && addr < 0x8000) {
		score++;
	}
	else if ((mode == 0x21 || mode == 0x25) && addr >= 0x8000) {
		score++;
	}

	if (cartInfo.RomType < 0x08) {
		score++;
	}
	if (cartInfo.RomSize < 0x10) {
		score++;
	}
	if (cartInfo.SramSize < 0x08) {
		score++;
	}

	uint16_t checksum = cartInfo.Checksum[0] | (cartInfo.Checksum[1] << 8);
	uint16_t complement = cartInfo.ChecksumComplement[0] | (cartInfo.ChecksumComplement[1] << 8);
	if (checksum + complement == 0xFFFF && checksum != 0 && complement != 0) {
		score += 8;
	}

	uint32_t resetVectorAddr = addr + 0x7FFC;
	uint8_t resetVectorAddr_bytes[2];
	qlseek(li, resetVectorAddr, SEEK_SET);
	qlread(li, &resetVectorAddr_bytes, sizeof(resetVectorAddr_bytes));
	uint32_t resetVector = resetVectorAddr_bytes[0] | (resetVectorAddr_bytes[1] << 8);
	if (resetVector < 0x8000) {
		return -1;
	}

	uint8_t op;
	qlseek(li, addr + (resetVector & 0x7FFF), SEEK_SET);
	qlread(li, &op, sizeof(op));

	if (op == 0x18 || op == 0x78 || op == 0x4C || op == 0x5C || op == 0x20 || op == 0x22 || op == 0x9C) {
		//CLI, SEI, JMP, JML, JSR, JSl, STZ
		score += 8;
	}
	else if (op == 0xC2 || op == 0xE2 || op == 0xA9 || op == 0xA2 || op == 0xA0) {
		//REP, SEP, LDA, LDX, LDY
		score += 4;
	}
	else if (op == 0x00 || op == 0xFF || op == 0xCC) {
		//BRK, SBC, CPY
		score -= 8;
	}

	return std::max<int32_t>(0, score);
}

static bool IsCorruptedHeader(const SnesCartInformation & _cartInfo) {
	int badHeaderCounter = 0;
	if (_cartInfo.SramSize & 0xF0) {
		badHeaderCounter++;
	}
	if (_cartInfo.RomType == 0xFF) {
		badHeaderCounter++;
	}
	if (_cartInfo.DestinationCode == 0xFF) {
		badHeaderCounter++;
	}
	if (_cartInfo.DeveloperId == 0xFF) {
		badHeaderCounter++;
	}
	if (_cartInfo.RomSize == 0xFF) {
		badHeaderCounter++;
	}
	if (_cartInfo.MapMode == 0xFF) {
		badHeaderCounter++;
	}
	return badHeaderCounter > 2;
}

static std::string GetGameCode(const SnesCartInformation& _cartInfo) {
	std::string code;
	if (_cartInfo.GameCode[0] > ' ') {
		code += _cartInfo.GameCode[0];
	}
	if (_cartInfo.GameCode[1] > ' ') {
		code += _cartInfo.GameCode[1];
	}
	if (_cartInfo.GameCode[2] > ' ') {
		code += _cartInfo.GameCode[2];
	}
	if (_cartInfo.GameCode[3] > ' ') {
		code += _cartInfo.GameCode[3];
	}
	return code;
}

static std::string GetString(const uint8_t* src, int maxLen) {
	for (int i = 0; i < maxLen; i++) {
		if (src[i] == 0) {
			return std::string(src, src + i);
		}
	}
	return std::string(src, src + maxLen);
}

static std::string GetString(const char* src, uint32_t maxLen) {
	return GetString((const uint8_t*)src, maxLen);
}

static std::string GetCartName(const SnesCartInformation& _cartInfo) {
	std::string name = GetString(_cartInfo.CartName, 21);

	size_t lastNonSpace = name.find_last_not_of(' ');
	if (lastNonSpace != std::string::npos) {
		return name.substr(0, lastNonSpace + 1);
	}
	else {
		return name;
	}
}

static CoprocessorType GetSt01xVersion(const SnesCartInformation& _cartInfo) {
	std::string cartName = GetCartName(_cartInfo);
	if (cartName == "2DAN MORITA SHOUGI") {
		return CoprocessorType::ST011;
	}

	return CoprocessorType::ST010;
}

static CoprocessorType GetDspVersion(const SnesCartInformation& _cartInfo) {
	std::string cartName = GetCartName(_cartInfo);
	if (cartName == "DUNGEON MASTER") {
		return CoprocessorType::DSP2;
	} if (cartName == "PILOTWINGS") {
		return CoprocessorType::DSP1;
	}
	else if (cartName == "SD\xB6\xDE\xDD\xC0\xDE\xD1GX") {
		//SD Gundam GX
		return CoprocessorType::DSP3;
	}
	else if (cartName == "PLANETS CHAMP TG3000" || cartName == "TOP GEAR 3000") {
		return CoprocessorType::DSP4;
	}

	//Default to DSP1B
	return CoprocessorType::DSP1B;
}

static CoprocessorType GetCoprocessorType(const SnesCartInformation& _cartInfo, bool *_hasBattery, bool *_hasRtc) {
	if ((_cartInfo.RomType & 0x0F) >= 0x03) {
		switch ((_cartInfo.RomType & 0xF0) >> 4) {
		case 0x00: return GetDspVersion(_cartInfo);
		case 0x01: return CoprocessorType::GSU;
		case 0x02: return CoprocessorType::OBC1;
		case 0x03: return CoprocessorType::SA1;
		case 0x04: return CoprocessorType::SDD1;
		case 0x05: return CoprocessorType::RTC;
		case 0x0E:
			switch (_cartInfo.RomType) {
			case 0xE3: return CoprocessorType::SGB;
			case 0xE5: return CoprocessorType::Satellaview;
			default: return CoprocessorType::None;
			}
			break;

		case 0x0F:
			switch (_cartInfo.CartridgeType) {
			case 0x00:
				*_hasBattery = true;
				*_hasRtc = (_cartInfo.RomType & 0x0F) == 0x09;
				return CoprocessorType::SPC7110;

			case 0x01:
				*_hasBattery = true;
				return GetSt01xVersion(_cartInfo);

			case 0x02:
				*_hasBattery = true;
				return CoprocessorType::ST018;

			case 0x10: return CoprocessorType::CX4;
			}
			break;
		}
	}
	else if (GetGameCode(_cartInfo) == "042J") {
		return CoprocessorType::SGB;
	}

	return CoprocessorType::None;
}

static void LoadEmbeddedFirmware(CoprocessorType _coprocessorType, uint8_t* _prgRom, uint32_t _prgRomSize, std::vector<uint8_t> & _embeddedFirmware) {
	//Attempt to detect/load the firmware from the end of the rom file, if it exists
	if ((_coprocessorType >= CoprocessorType::DSP1 && _coprocessorType <= CoprocessorType::DSP4) || (_coprocessorType >= CoprocessorType::ST010 && _coprocessorType <= CoprocessorType::ST011)) {
		uint32_t firmwareSize = 0;
		if ((_prgRomSize & 0x7FFF) == 0x2000) {
			firmwareSize = 0x2000;
		}
		else if ((_prgRomSize & 0xFFFF) == 0xD000) {
			firmwareSize = 0xD000;
		}

		_embeddedFirmware.resize(firmwareSize);
		memcpy(_embeddedFirmware.data(), _prgRom + (_prgRomSize - firmwareSize), firmwareSize);
		_prgRomSize -= firmwareSize;
	}
}

static void EnsureValidPrgRomSize(uint32_t& size, uint8_t*& rom) {
	if ((size & 0xFFF) != 0) {
		//Round up to the next 4kb size, to ensure we have access to all the rom's data
		//Memory mappings expect a multiple of 4kb to work properly
		uint32_t orgPrgSize = size;
		size = (size & ~0xFFF) + 0x1000;
		uint8_t* expandedPrgRom = new uint8_t[size];
		memset(expandedPrgRom, 0, size);
		memcpy(expandedPrgRom, rom, orgPrgSize);
		delete[] rom;
		rom = expandedPrgRom;
	}
}

static void create_segm(uint32_t bank, uint32_t startAddr, uint32_t endAddr, const char* seg_name, uchar seg_type, const char* seg_class, uchar seg_perm, eavec_t &mirrors, int mirror_idx) {
	segment_t s;
	s.start_ea = (ea_t)((bank << 16) + startAddr);
	s.end_ea = (ea_t)((bank << 16) + endAddr + 1);
	s.type = seg_type;
	s.bitness = 1;
	s.perm = seg_perm; // asCode ? (SEGPERM_EXEC | SEGPERM_READ) : SEGPERM_MAXVAL;

	if (mirror_idx == -1) {
		add_segm_ex(&s, seg_name, seg_class, ADDSEG_NOSREG | ADDSEG_OR_DIE);
		set_default_sreg_value(&s, m65816_regs::rVds, s.start_ea);

		mirrors.push_back(s.start_ea);
	}
	else {
		add_mapping(s.start_ea, mirrors[mirror_idx % mirrors.size()], s.end_ea - s.start_ea);
	}
}

static void RegisterHandlerPrg(const uint8_t *_prgRom, uint32_t _prgRomSize, uint8_t startBank, uint8_t endBank, uint16_t startAddr, uint16_t endAddr, uint16_t pageIncrement, uint16_t startPageNumber, uint32_t handlersSize, eavec_t& mirrors) {
	if ((startAddr & 0xFFF) != 0 || (endAddr & 0xFFF) != 0xFFF || startBank > endBank || startAddr > endAddr) {
		loader_failure("invalid start/end address\n");
	}

	startPageNumber %= handlersSize;
	uint32_t pageNumber = startPageNumber;

	bool no_mirrors = mirrors.empty();
	uint32_t bank;
	int idx;

	for (bank = startBank, idx = 0; bank <= endBank; bank++, idx++) {
		pageNumber += pageIncrement;

		uint32_t romOffset = pageNumber * 0x1000;

		if (romOffset < _prgRomSize) {
			char bank_name[16];
			qsnprintf(bank_name, sizeof(bank_name), BANK_PREFIX "%02X", bank);
			create_segm(bank, startAddr, endAddr, bank_name, SEG_CODE, "CODE", SEGPERM_EXEC | SEGPERM_READ, mirrors, no_mirrors ? -1 : idx);
		}

		for (uint32_t j = startAddr; j <= endAddr; j += 0x1000) {
			romOffset = pageNumber * 0x1000;

			if (romOffset < _prgRomSize) {
				ea_t start_ea = (ea_t)((bank << 16) + j);
				ea_t end_ea = start_ea + 0x1000;

				if (no_mirrors) {
					mem2base(&_prgRom[romOffset], start_ea, end_ea, romOffset);
				}
			}

			pageNumber++;

			if (pageNumber >= handlersSize) {
				pageNumber = 0;
			}
		}
	}
}

static void RegisterHandlerSram(uint8_t startBank, uint8_t endBank, uint16_t startAddr, uint16_t endAddr, eavec_t &mirrors) {
	if ((startAddr & 0xFFF) != 0 || (endAddr & 0xFFF) != 0xFFF || startBank > endBank || startAddr > endAddr) {
		loader_failure("invalid start/end address\n");
	}

	bool no_mirrors = mirrors.empty();
	uint32_t bank;
	int idx;

	for (bank = startBank, idx = 0; bank <= endBank; bank++, idx++) {
		char bank_name[16];
		qsnprintf(bank_name, sizeof(bank_name), "SRAM%02X", bank);

		create_segm(bank, startAddr, endAddr, bank_name, SEG_DATA, "DATA", SEGPERM_READ | SEGPERM_WRITE, mirrors, no_mirrors ? -1 : idx);
	}
}

static void RegisterHandlerWram(uint8_t startBank, uint8_t endBank, uint16_t startAddr, uint16_t endAddr, eavec_t &mirrors) {
	if ((startAddr & 0xFFF) != 0 || (endAddr & 0xFFF) != 0xFFF || startBank > endBank || startAddr > endAddr) {
		loader_failure("invalid start/end address\n");
	}

	bool no_mirrors = mirrors.empty();
	uint32_t bank;
	int idx;

	for (bank = startBank, idx = 0; bank <= endBank; bank++, idx++) {
		char bank_name[16];
		qsnprintf(bank_name, sizeof(bank_name), "WRAM%02X", bank);

		create_segm(bank, startAddr, endAddr, bank_name, SEG_DATA, "DATA", SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC, mirrors, no_mirrors ? -1 : idx);
	}
}

static void RegisterHandlerRegs(uint8_t startBank, uint8_t endBank, uint16_t startAddr, uint16_t endAddr, const char* regsName, eavec_t &mirrors) {
	if ((startAddr & 0xFFF) != 0 || (endAddr & 0xFFF) != 0xFFF || startBank > endBank || startAddr > endAddr) {
		loader_failure("invalid start/end address\n");
	}

	bool no_mirrors = mirrors.empty();
	uint32_t bank;
	int idx;

	for (bank = startBank, idx = 0; bank <= endBank; bank++, idx++) {
		char bank_name[16];
		qsnprintf(bank_name, sizeof(bank_name), "%s%02X", regsName, bank);

		create_segm(bank, startAddr, endAddr, bank_name, SEG_XTRN, "XTRN", SEGPERM_READ | SEGPERM_WRITE, mirrors, no_mirrors ? -1 : idx);
	}
}

static bool MapSpecificCarts(const uint8_t* _prgRom, uint32_t _prgRomSize, const SnesCartInformation& _cartInfo, uint32_t _saveRamSize, uint32_t handlersSize) {
	std::string name = GetCartName(_cartInfo);
	std::string code = GetGameCode(_cartInfo);

	eavec_t mirrors = {};

	//if (_sufamiTurbo) {
	//	_sufamiTurbo->InitializeMappings(mm, _prgRomHandlers, _saveRamHandlers);
	//	return true;
	//}
	//else
	if (GetCartName(_cartInfo) == "DEZAEMON") {
		//LOROM with mirrored SRAM?
		mirrors.clear();
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x00, 0x7D, 0x8000, 0xFFFF, 0, 0, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x80, 0xFF, 0x8000, 0xFFFF, 0, 0, handlersSize, mirrors);

		mirrors.clear();
		RegisterHandlerSram(0x70, 0x7D, 0x0000, 0x7FFF, mirrors);
		RegisterHandlerSram(0x70, 0x7D, 0x8000, 0xFFFF, mirrors);

		mirrors.clear();
		RegisterHandlerSram(0xF0, 0xFF, 0x8000, 0xFFFF, mirrors);
		RegisterHandlerSram(0xF0, 0xFF, 0x0000, 0x7FFF, mirrors);

		return true;
	}
	else if (code == "ZDBJ" || code == "ZR2J" || code == "ZSNJ") {
		//BSC-1A5M-02, BSC-1A7M-01
		//Games: Sound Novel Tsukuuru, RPG Tsukuuru, Derby Stallion 96
		mirrors.clear();
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x00, 0x3F, 0x8000, 0xFFFF, 0, 0, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x80, 0x9F, 0x8000, 0xFFFF, 0, 0x200, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0xA0, 0xBF, 0x8000, 0xFFFF, 0, 0x100, handlersSize, mirrors);

		if (_saveRamSize > 0) {
			mirrors.clear();
			RegisterHandlerSram(0x70, 0x7D, 0x0000, 0x7FFF, mirrors);
			RegisterHandlerSram(0xF0, 0xFF, 0x0000, 0x7FFF, mirrors);
		}
		return true;
	}
	return false;
}

static void RegisterHandlers(const uint8_t* _prgRom, const SnesCartInformation& _cartInfo, CoprocessorType _coprocessorType, CartFlags::CartFlags _flags, uint32_t _prgRomSize, uint32_t _saveRamSize, uint32_t handlersSize) {
	if (MapSpecificCarts(_prgRom, _prgRomSize, _cartInfo, _saveRamSize, handlersSize) || _coprocessorType == CoprocessorType::GSU || _coprocessorType == CoprocessorType::SDD1 || _coprocessorType == CoprocessorType::SPC7110 || _coprocessorType == CoprocessorType::CX4) {
		// MapBsxMemoryPack(mm);
		return;
	}

	bool mapSram = _coprocessorType != CoprocessorType::SA1;

	eavec_t mirrors = {};

	if (_flags & CartFlags::LoRom) {
		mirrors.clear();
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x00, 0x7D, 0x8000, 0xFFFF, 0, 0, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x80, 0xFF, 0x8000, 0xFFFF, 0, 0, handlersSize, mirrors);

		if (mapSram && _saveRamSize > 0) {
			if (_prgRomSize >= 1024 * 1024 * 2) {
				//For games >= 2mb in size, put ROM at 70-7D/F0-FF:0000-7FFF (e.g: Fire Emblem: Thracia 776) 
				mirrors.clear();
				RegisterHandlerSram(0x70, 0x7D, 0x0000, 0x7FFF, mirrors);
				RegisterHandlerSram(0xF0, 0xFF, 0x0000, 0x7FFF, mirrors);
			}
			else {
				//For games < 2mb in size, put save RAM at 70-7D/F0-FF:0000-FFFF (e.g: Wanderers from Ys)
				mirrors.clear();
				RegisterHandlerSram(0x70, 0x7D, 0x0000, 0xFFFF, mirrors);
				RegisterHandlerSram(0xF0, 0xFF, 0x0000, 0xFFFF, mirrors);
			}
		}
	}
	else if (_flags & CartFlags::HiRom) {
		mirrors.clear();
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x00, 0x3F, 0x8000, 0xFFFF, 8, 0, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x40, 0x7D, 0x0000, 0xFFFF, 0, 0, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x80, 0xBF, 0x8000, 0xFFFF, 8, 0, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0xC0, 0xFF, 0x0000, 0xFFFF, 0, 0, handlersSize, mirrors);

		if (mapSram) {
			mirrors.clear();
			RegisterHandlerSram(0x20, 0x3F, 0x6000, 0x7FFF, mirrors);
			RegisterHandlerSram(0xA0, 0xBF, 0x6000, 0x7FFF, mirrors);
		}
	}
	else if (_flags & CartFlags::ExHiRom) {
		//First half is at the end
		mirrors.clear();
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0xC0, 0xFF, 0x0000, 0xFFFF, 0, 0, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x80, 0xBF, 0x8000, 0xFFFF, 8, 0, handlersSize, mirrors); //mirror

		//Last part of the ROM is at the start
		mirrors.clear();
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x40, 0x7D, 0x0000, 0xFFFF, 0, 0x400, handlersSize, mirrors);
		RegisterHandlerPrg(_prgRom, _prgRomSize, 0x00, 0x3F, 0x8000, 0xFFFF, 8, 0x400, handlersSize, mirrors); //mirror

		//Save RAM
		if (mapSram) {
			//if (!_emu->GetSettings()->GetSnesConfig().EnableStrictBoardMappings) {
				//This shouldn't be mapped on ExHiROM boards, but some old romhacks seem to depend on this
			mirrors.clear();
			RegisterHandlerSram(0x20, 0x3F, 0x6000, 0x7FFF, mirrors);
			//}
			RegisterHandlerSram(0x80, 0xBF, 0x6000, 0x7FFF, mirrors);
		}
	}

	// MapBsxMemoryPack(mm);
}

static void RegisterHandlerWrams() {
	eavec_t mirrors;
	RegisterHandlerWram(0x7E, 0x7F, 0x0000, 0xFFFF, mirrors);
	RegisterHandlerWram(0x00, 0x3F, 0x0000, 0x0FFF, mirrors);
	RegisterHandlerWram(0x80, 0xBF, 0x0000, 0x0FFF, mirrors);

	RegisterHandlerWram(0x00, 0x3F, 0x1000, 0x1FFF, mirrors);
	RegisterHandlerWram(0x80, 0xBF, 0x1000, 0x1FFF, mirrors);

	mirrors.clear();
	RegisterHandlerRegs(0x00, 0x3F, 0x2000, 0x2FFF, "REGB", mirrors);
	RegisterHandlerRegs(0x80, 0xBF, 0x2000, 0x2FFF, "REGB", mirrors);

	mirrors.clear();
	RegisterHandlerRegs(0x00, 0x3F, 0x4000, 0x4FFF, "REGA", mirrors);
	RegisterHandlerRegs(0x80, 0xBF, 0x4000, 0x4FFF, "REGA", mirrors);
}

static uint32_t CalcHandlersSize(uint32_t _prgRomSize) {
	uint32_t handlersSize = 0;

	for(uint32_t i = 0; i < _prgRomSize; i += 0x1000) {
		handlersSize += 1;
	}

	uint32_t power = (uint32_t)std::log2(_prgRomSize);
	if(_prgRomSize >(1u << power)) {
		//If size isn't a power of 2, mirror the part above the nearest (lower) power of 2 until the size reaches the next power of 2.
		uint32_t halfSize = 1 << power;
		uint32_t fullSize = 1 << (power + 1);
		uint32_t extraHandlers = std::max<uint32_t>((_prgRomSize - halfSize) / 0x1000, 1);

		while(handlersSize < fullSize / 0x1000) {
			for(uint32_t i = 0; i < extraHandlers; i += 0x1000) {
				handlersSize += 1;
			}
		}
	}

	return handlersSize;
}

static int check_or_load(linput_t* li, bool load) {
	uint32_t _prgRomSize = (uint32_t)qlsize(li);

	if (_prgRomSize < 0x8000) {
		return 0;
	}

	std::vector<uint32_t> baseAddresses = { 0, 0x200, 0x8000, 0x8200, 0x408000, 0x408200 };
	int32_t bestScore = -1;
	bool hasHeader = false;
	bool isLoRom = true;
	bool isExRom = true;

	SnesCartInformation _cartInfo = {};
	uint32_t _headerOffset = 0;

	for (uint32_t baseAddress : baseAddresses) {
		int32_t score = GetHeaderScore(li, baseAddress, _prgRomSize);

		if (score >= 0 && score >= bestScore) {
			bestScore = score;
			isLoRom = (baseAddress & 0x8000) == 0;
			isExRom = (baseAddress & 0x400000) != 0;
			hasHeader = (baseAddress & 0x200) != 0;

			uint32_t headerOffset = std::min(baseAddress + 0x7FB0, (uint32_t)(_prgRomSize - sizeof(SnesCartInformation)));
			qlseek(li, headerOffset, SEEK_SET);
			qlread(li, &_cartInfo, sizeof(SnesCartInformation));
			_headerOffset = headerOffset;
		}
	}

	if (bestScore < 9) {
		return 0;
	}

	if (!load) {
		return 1;
	}

	uint8_t* _prgRom = new uint8_t[_prgRomSize];
	qlseek(li, 0, SEEK_SET);
	qlread(li, _prgRom, _prgRomSize);

	bool corruptedHeader = IsCorruptedHeader(_cartInfo);

	uint32_t flags = 0;
	if (hasHeader) {
		flags |= CartFlags::CopierHeader;
	}

	if (isLoRom) {
		flags |= CartFlags::LoRom;
	}
	else {
		flags |= isExRom ? CartFlags::ExHiRom : CartFlags::HiRom;
	}

	if (flags & CartFlags::CopierHeader) {
		//Remove the copier header
		memmove(_prgRom, _prgRom + 512, _prgRomSize - 512);
		_prgRomSize -= 512;
		_headerOffset -= 512;
	}

	if ((flags & CartFlags::HiRom) && (_cartInfo.MapMode & 0x27) == 0x25) {
		flags |= CartFlags::ExHiRom;
	}
	else if ((flags & CartFlags::LoRom) && (_cartInfo.MapMode & 0x27) == 0x22) {
		flags |= CartFlags::ExLoRom;
	}

	if (_cartInfo.MapMode & 0x10) {
		flags |= CartFlags::FastRom;
	}
	CartFlags::CartFlags _flags = (CartFlags::CartFlags)flags;

	bool _hasBattery = (_cartInfo.RomType & 0x0F) == 0x02 || (_cartInfo.RomType & 0x0F) == 0x05 || (_cartInfo.RomType & 0x0F) == 0x06 || (_cartInfo.RomType & 0x0F) == 0x09 || (_cartInfo.RomType & 0x0F) == 0x0A;
	bool _hasRtc = false;

	CoprocessorType _coprocessorType;
	uint32_t _coprocessorRamSize = 0;
	std::vector<uint8_t> _embeddedFirmware;

	if (corruptedHeader) {
		_coprocessorType = CoprocessorType::None;
	}
	else {
		_coprocessorType = GetCoprocessorType(_cartInfo, &_hasBattery, &_hasRtc);

		if (_coprocessorType == CoprocessorType::SGB) {
			//Only allow SGB when a game boy rom is loaded
			_coprocessorType = CoprocessorType::None;
		}

		if (_coprocessorType != CoprocessorType::None && _cartInfo.ExpansionRamSize > 0 && _cartInfo.ExpansionRamSize <= 7) {
			_coprocessorRamSize = _cartInfo.ExpansionRamSize > 0 ? 1024 * (1 << _cartInfo.ExpansionRamSize) : 0;
		}

		if (_coprocessorType == CoprocessorType::GSU && _coprocessorRamSize == 0) {
			//Use a min of 64kb by default for GSU games
			_coprocessorRamSize = 0x10000;
		}

		LoadEmbeddedFirmware(_coprocessorType, _prgRom, _prgRomSize, _embeddedFirmware);
	}

	uint8_t rawSramSize = std::min(_cartInfo.SramSize & 0x0F, 8);
	uint32_t _saveRamSize = rawSramSize > 0 ? 1024 * (1 << rawSramSize) : 0;
	uint8_t* _saveRam = new uint8_t[_saveRamSize];

	EnsureValidPrgRomSize(_prgRomSize, _prgRom);

	// add rom mappings
	uint32_t handlersSize = CalcHandlersSize(_prgRomSize);
	RegisterHandlers(_prgRom, _cartInfo, _coprocessorType, _flags, _prgRomSize, _saveRamSize, handlersSize);

	RegisterHandlerWrams();

	delete[] _prgRom;
	delete[] _saveRam;

	return 1;
}

int idaapi accept_file(qstring* fileformatname, qstring* processor, linput_t* li, const char* filename) {
	int res = check_or_load(li, false);

	if (res) {
		*fileformatname = "SNES ROM";
		*processor = "m65816";

		return 1;
	}

	return 0;
}

void idaapi load_file(linput_t* li, ushort neflags, const char* fileformatname) {
	set_processor_type("m65816", SETPROC_LOADER);
	inf_set_app_bitness(32);

	inf_set_af(0
		| AF_FIXUP //        0x0001          // Create offsets and segments using fixup info
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
		| AF_IMMOFF //       0x2000          // Convert 32bit instruction operand to offset
		//AF_DREFOFF //      0x4000          // Create offset if data xref to seg32 exists
		| AF_FINAL //       0x8000          // Final pass of analysis
		| AF_JUMPTBL  //    0x0001          // Locate and create jump tables
		| AF_STKARG  //     0x0008          // Propagate stack argument information
		| AF_REGARG  //     0x0010          // Propagate register argument information
		| AF_SIGMLT  //     0x0080          // Allow recognition of several copies of the same function
		//| AF_FTAIL  //      0x0100          // Create function tails
		| AF_DATOFF  //     0x0200          // Automatically convert data to offsets
		//| AF_TRFUNC  //     0x2000          // Truncate functions upon code deletion
		//| AF_PURDAT  //     0x4000          // Control flow to data segment is ignored
	);
	inf_set_af2(0);

	int res = check_or_load(li, true);

	uint32_t reset_vector = get_16bit(0xFFFC);
	set_name(reset_vector, "start", SN_PUBLIC);
	auto_make_proc(reset_vector);

	jumpto(reset_vector);
}

idaman loader_t  ida_module_data LDSC = {
  IDP_INTERFACE_VERSION,
  LDRF_RELOAD,
  accept_file,
  load_file,
  nullptr,
  nullptr,
  nullptr
};