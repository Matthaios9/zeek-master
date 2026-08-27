

#pragma once

#include <string>

namespace zeek {

class String;
class Connection;

namespace detail {


class Base64Converter {
public:





    explicit Base64Converter(Connection* conn, const std::string& alphabet = "", bool silent = false);
    ~Base64Converter();











    int Decode(int len, const char* data, int* blen, char** buf);
    void Encode(int len, const unsigned char* data, int* blen, char** buf);

    int Done(int* pblen, char** pbuf);
    bool HasData() const { return base64_group_next != 0; }


    int Errored() const { return errored; }

    const char* ErrorMsg() const { return error_msg; }
    void IllegalEncoding(const char* msg);

protected:
    char error_msg[256];

protected:
    static const std::string default_alphabet;
    std::string alphabet;

    static int* InitBase64Table(const std::string& alphabet);
    static int default_base64_table[256];
    char base64_group[4];
    int base64_group_next;
    int base64_padding;
    int base64_after_padding;
    int* base64_table;
    int errored;
    Connection* conn;
    bool silent;
};

String* decode_base64(const String* s, const String* a = nullptr, Connection* conn = nullptr);
String* encode_base64(const String* s, const String* a = nullptr, Connection* conn = nullptr);
bool is_valid_base64(const String* s, const String* a = nullptr);

}
}
