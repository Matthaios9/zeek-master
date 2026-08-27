

#pragma once

#include <cstdio>
#include <string>

#ifdef _WIN32
#include <cstdint>
#include <istream>
#include <memory>
#else
#include <sys/types.h>
#include <fstream>
#endif

namespace zeek::input::reader::detail {

#ifdef _WIN32



using file_ino_t = uint64_t;

class WinShareDeleteBuf;









class InputFile : public std::istream {
public:
    InputFile();
    explicit InputFile(const std::string& path, std::ios_base::openmode mode = std::ios_base::in);
    ~InputFile();

    InputFile(const InputFile&) = delete;
    InputFile& operator=(const InputFile&) = delete;

    void open(const std::string& path, std::ios_base::openmode mode = std::ios_base::in);
    bool is_open() const;
    void close();

private:
    std::unique_ptr<WinShareDeleteBuf> buf_;
};

#else

using InputFile = std::ifstream;


using file_ino_t = ino_t;

#endif



inline bool is_absolute_path(const std::string& p) {
    if ( p.empty() )
        return false;
    if ( p.front() == '/' )
        return true;
#ifdef _WIN32
    if ( p.size() >= 3 && std::isalpha(static_cast<unsigned char>(p[0])) && p[1] == ':' &&
         (p[2] == '/' || p[2] == '\\') )
        return true;
#endif
    return false;
}




FILE* fopen_with_share_delete(const char* path, const char* mode);




file_ino_t reliable_inode(const char* path, file_ino_t stat_ino);

}
