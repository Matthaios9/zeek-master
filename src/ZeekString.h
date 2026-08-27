

#pragma once

#include <sys/types.h>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace zeek {




class VectorVal;

using byte_vec = u_char*;







class String {
public:
    using Vec = std::vector<String*>;
    using VecIt = Vec::iterator;
    using VecCIt = Vec::const_iterator;

    using CVec = std::vector<const String*>;
    using CVecIt = Vec::iterator;
    using CVecCIt = Vec::const_iterator;


    using IdxVec = std::vector<int>;
    using IdxVecIt = IdxVec::iterator;
    using IdxVecCIt = IdxVec::const_iterator;


    String(const u_char* str, int arg_n, bool add_NUL);
    String(std::string_view str);
    String(const String& bs);


    String(bool arg_final_NUL, byte_vec str, int arg_n);


    String(String&& s) noexcept;

    String();
    ~String() { Reset(); }

    const String& operator=(const String& bs);
    String& operator=(String&& bs) noexcept;
    bool operator==(const String& bs) const;
    bool operator<(const String& bs) const;
    bool operator==(std::string_view s) const;
    bool operator!=(std::string_view s) const;

    byte_vec Bytes() const { return b; }
    int Len() const { return n; }





    void Adopt(byte_vec bytes, int len);





    void Set(const u_char* str, int len, bool add_NUL = true);
    void Set(std::string_view str);
    void Set(const String& str);

    void SetUseFreeToDelete(int use_it) { use_free_to_delete = use_it; }








    const char* CheckString() const;




    std::pair<const char*, size_t> CheckStringWithSize() const;





    std::string ToStdString() const;




    std::string_view ToStdStringView() const;

    enum render_style : uint8_t {
        ESC_NONE = 0,
        ESC_ESC = (1 << 1),
        ESC_QUOT = (1 << 2),
        ESC_HEX = (1 << 3),
        ESC_DOT = (1 << 4),


        ESC_SER = (1 << 7),
    };

    static constexpr int EXPANDED_STRING =
        ESC_HEX;

    static constexpr int ZEEK_STRING_LITERAL =
        ESC_ESC | ESC_QUOT | ESC_HEX;









    char* Render(int format = EXPANDED_STRING, int* len = nullptr) const;





    std::ostream& Render(std::ostream& os, int format = ESC_SER) const;





    std::istream& Read(std::istream& is, int format = ESC_SER);



    void ToUpper();






    String* GetSubstring(int start, int length) const;




    int FindSubstring(const String* s) const;






    Vec* Split(const IdxVec& indices) const;

protected:
    void Reset();

    byte_vec b;
    int n;
    bool final_NUL;
    bool use_free_to_delete;
};





class StringLenCmp {
public:
    explicit StringLenCmp(bool increasing = true) { _increasing = increasing; }
    bool operator()(String* const& bst1, String* const& bst2);

private:
    unsigned int _increasing;
};


std::ostream& operator<<(std::ostream& os, const String& bs);

extern int Bstr_eq(const String* s1, const String* s2);
extern int Bstr_cmp(const String* s1, const String* s2);








struct data_chunk_t {
    int length;
    const char* data;
};

extern String* concatenate(std::vector<data_chunk_t>& v);
extern String* concatenate(String::Vec& v);
extern String* concatenate(String::CVec& v);
extern void delete_strings(std::vector<const String*>& v);

}
