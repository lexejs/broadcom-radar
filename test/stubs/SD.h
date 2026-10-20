#pragma once
#include "FS.h"
#include "SPI.h"
constexpr int CARD_NONE = 0, FILE_READ = 0, FILE_WRITE = 1;
class FakeSd {
public:
    bool mounted=false, needsReinit=false;
    unsigned endCalls=0, existsCalls=0;
    bool begin(int, SPIClass&, int) {
        if (mounted) return true; // Arduino SD caches an existing mount, even after a media fault.
        if (!mock::sdPresent) return false;
        mounted=true; needsReinit=false; return true;
    }
    void end() { ++endCalls; mounted=false; }
    int cardType() { return mounted ? 1 : CARD_NONE; }
    bool exists(const char* path) { ++existsCalls; return mock::sdPresent && !needsReinit && mock::files.count(path); }
    bool mkdir(const char* path) { mock::files[path] = {}; return mock::sdPresent && !needsReinit; }
    fs::File open(const char* path, int mode=FILE_READ) {
        if (!mock::sdPresent || needsReinit) return {};
        if (mode==FILE_READ && std::string(path)=="/broadcom-radar" && mock::files.count(path)) return fs::File(path);
        if (mode==FILE_READ && !mock::files.count(path)) return {};
        return fs::File(&mock::files[path],path);
    }
    bool rename(const char* src, const char* dst) {
        if (!mock::sdPresent || mock::failRename || dst == mock::failRenamePath || !exists(src) || exists(dst)) return false;
        mock::files[dst] = mock::files[src]; mock::files.erase(src); return true;
    }
};
inline FakeSd SD;
