#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
namespace mock {
inline bool sdPresent = true, failWrite = false, failRename = false;
inline std::string failWritePath, failRenamePath;
inline std::map<std::string, std::vector<uint8_t>> files;
inline unsigned directoryReads = 0;
}
namespace fs {
class File {
public:
    File() = default;
    explicit File(std::vector<uint8_t>* data, const char* path) : data_(data), path_(path) {}
    explicit File(const char* directory) : path_(directory), directory_(true) {}
    explicit operator bool() const { return (data_ || directory_) && mock::sdPresent; }
    bool isDirectory() const { return directory_; }
    std::string getNextFileName(bool* isDirectory = nullptr) {
        ++mock::directoryReads;
        if (!*this || !directory_) return {};
        const std::string prefix=path_+"/";
        auto next=cursor_.empty() ? mock::files.lower_bound(prefix) : mock::files.upper_bound(cursor_);
        if (next==mock::files.end() || next->first.compare(0,prefix.size(),prefix)) return {};
        cursor_=next->first;
        if (isDirectory) *isDirectory=false;
        return cursor_;
    }
    size_t write(const uint8_t* bytes, size_t n) {
        if (!*this || !data_ || mock::failWrite || path_ == mock::failWritePath) { error_ = 1; return 0; }
        data_->insert(data_->end(), bytes, bytes + n); return n;
    }
    void flush() {}
    int getWriteError() const { return error_; }
    void close() { data_ = nullptr; directory_ = false; }
private:
    std::vector<uint8_t>* data_ = nullptr;
    std::string path_;
    std::string cursor_;
    bool directory_ = false;
    int error_ = 0;
};
}
constexpr int OUTPUT = 1, HIGH = 1;
inline void pinMode(int, int) {}
inline void digitalWrite(int, int) {}
