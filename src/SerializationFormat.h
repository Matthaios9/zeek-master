



#pragma once

#include <cstdint>
#include <string>

struct in_addr;
struct in6_addr;

namespace zeek {

class IPAddr;
class IPPrefix;

namespace detail {


class SerializationFormat {
public:
    SerializationFormat() = default;
    virtual ~SerializationFormat();


    virtual void StartRead(const char* data, uint32_t len);
    virtual void EndRead();

    virtual bool Read(int* v, const char* tag) = 0;
    virtual bool Read(uint16_t* v, const char* tag) = 0;
    virtual bool Read(uint32_t* v, const char* tag) = 0;
    virtual bool Read(int64_t* v, const char* tag) = 0;
    virtual bool Read(uint64_t* v, const char* tag) = 0;
    virtual bool Read(char* v, const char* tag) = 0;
    virtual bool Read(bool* v, const char* tag) = 0;
    virtual bool Read(double* d, const char* tag) = 0;
    virtual bool Read(std::string* s, const char* tag) = 0;
    virtual bool Read(IPAddr* addr, const char* tag) = 0;
    virtual bool Read(IPPrefix* prefix, const char* tag) = 0;
    virtual bool Read(in_addr* addr, const char* tag) = 0;
    virtual bool Read(in6_addr* addr, const char* tag) = 0;


    int BytesRead() const { return bytes_read; }


    virtual bool Read(char** str, int* len, const char* tag) = 0;


    virtual void StartWrite();








    virtual size_t EndWrite(char** data);

    virtual bool Write(int v, const char* tag) = 0;
    virtual bool Write(uint16_t v, const char* tag) = 0;
    virtual bool Write(uint32_t v, const char* tag) = 0;
    virtual bool Write(int64_t v, const char* tag) = 0;
    virtual bool Write(uint64_t v, const char* tag) = 0;
    virtual bool Write(char v, const char* tag) = 0;
    virtual bool Write(bool v, const char* tag) = 0;
    virtual bool Write(double d, const char* tag) = 0;
    virtual bool Write(const char* s, const char* tag) = 0;
    virtual bool Write(const char* buf, int len, const char* tag) = 0;
    virtual bool Write(const std::string& s, const char* tag) = 0;
    virtual bool Write(const IPAddr& addr, const char* tag) = 0;
    virtual bool Write(const IPPrefix& prefix, const char* tag) = 0;
    virtual bool Write(const in_addr& addr, const char* tag) = 0;
    virtual bool Write(const in6_addr& addr, const char* tag) = 0;

    virtual bool WriteOpenTag(const char* tag) = 0;
    virtual bool WriteCloseTag(const char* tag) = 0;
    virtual bool WriteSeparator() = 0;


    size_t BytesWritten() const { return bytes_written; }

protected:
    bool ReadData(void* buf, size_t count);
    bool WriteData(const void* buf, size_t count);

    static const uint32_t INITIAL_SIZE = 65536;
    static const float GROWTH_FACTOR;
    char* output = nullptr;
    size_t output_size = 0;
    size_t output_pos = 0;

    const char* input = nullptr;
    size_t input_len = 0;
    size_t input_pos = 0;

    size_t bytes_written = 0;
    size_t bytes_read = 0;
};

class BinarySerializationFormat final : public SerializationFormat {
public:
    BinarySerializationFormat() = default;

    bool Read(int* v, const char* tag) override;
    bool Read(uint16_t* v, const char* tag) override;
    bool Read(uint32_t* v, const char* tag) override;
    bool Read(int64_t* v, const char* tag) override;
    bool Read(uint64_t* v, const char* tag) override;
    bool Read(char* v, const char* tag) override;
    bool Read(bool* v, const char* tag) override;
    bool Read(double* d, const char* tag) override;
    bool Read(char** str, int* len, const char* tag) override;
    bool Read(std::string* s, const char* tag) override;
    bool Read(IPAddr* addr, const char* tag) override;
    bool Read(IPPrefix* prefix, const char* tag) override;
    bool Read(in_addr* addr, const char* tag) override;
    bool Read(in6_addr* addr, const char* tag) override;
    bool Write(int v, const char* tag) override;
    bool Write(uint16_t v, const char* tag) override;
    bool Write(uint32_t v, const char* tag) override;
    bool Write(int64_t v, const char* tag) override;
    bool Write(uint64_t v, const char* tag) override;
    bool Write(char v, const char* tag) override;
    bool Write(bool v, const char* tag) override;
    bool Write(double d, const char* tag) override;
    bool Write(const char* s, const char* tag) override;
    bool Write(const char* buf, int len, const char* tag) override;
    bool Write(const std::string& s, const char* tag) override;
    bool Write(const IPAddr& addr, const char* tag) override;
    bool Write(const IPPrefix& prefix, const char* tag) override;
    bool Write(const in_addr& addr, const char* tag) override;
    bool Write(const in6_addr& addr, const char* tag) override;
    bool WriteOpenTag(const char* tag) override;
    bool WriteCloseTag(const char* tag) override;
    bool WriteSeparator() override;
};

}
}
