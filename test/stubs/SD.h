#pragma once
#include "FS.h"
#include "SPI.h"
constexpr int CARD_NONE = 0, FILE_WRITE = 1;
class FakeSd {
public:
    bool begin(int, SPIClass&, int) { return mock::sdPresent; }
    int cardType() { return mock::sdPresent ? 1 : CARD_NONE; }
    bool exists(const char* path) { return mock::sdPresent && mock::files.count(path); }
    bool mkdir(const char* path) { mock::files[path] = {}; return mock::sdPresent; }
    fs::File open(const char* path, int) { return mock::sdPresent ? fs::File(&mock::files[path], path) : fs::File(); }
    bool rename(const char* src, const char* dst) {
        if (!mock::sdPresent || mock::failRename || dst == mock::failRenamePath || !exists(src) || exists(dst)) return false;
        mock::files[dst] = mock::files[src]; mock::files.erase(src); return true;
    }
};
inline FakeSd SD;
