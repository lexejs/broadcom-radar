#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
namespace mock {
inline bool sdPresent = true, failWrite = false, failRename = false;
inline std::string failWritePath, failRenamePath;
inline std::map<std::string, std::vector<uint8_t>> files;
}
namespace fs {
class File {
public:
    File() = default;
    explicit File(std::vector<uint8_t>* data, const char* path) : data_(data), path_(path) {}
    explicit operator bool() const { return data_ && mock::sdPresent; }
    size_t write(const uint8_t* bytes, size_t n) {
        if (!*this || mock::failWrite || path_ == mock::failWritePath) { error_ = 1; return 0; }
        data_->insert(data_->end(), bytes, bytes + n); return n;
    }
    void flush() {}
    int getWriteError() const { return error_; }
    void close() { data_ = nullptr; }
private:
    std::vector<uint8_t>* data_ = nullptr;
    std::string path_;
    int error_ = 0;
};
}
constexpr int OUTPUT = 1, HIGH = 1;
inline void pinMode(int, int) {}
inline void digitalWrite(int, int) {}
