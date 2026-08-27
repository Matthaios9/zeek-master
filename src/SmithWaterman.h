

#pragma once

#include <map>
#include <string>
#include <vector>

#include "zeek/ZeekString.h"

namespace zeek::detail {







class Substring : public String {
public:
    using Vec = std::vector<Substring*>;



    struct BSSAlign {
        BSSAlign(const String* string, int index) {
            this->string = string;
            this->index = index;
        }



        const String* string;




        int index;
    };

    using BSSAlignVec = std::vector<BSSAlign>;

    Substring() = delete;

    explicit Substring(const std::string& string) : String(string), _num(), _new(false) {}

    explicit Substring(const String& string) : String(string), _num(), _new(false) {}

    Substring(const Substring& bst);

    const Substring& operator=(const Substring& bst);






    bool DoesCover(const Substring* bst) const;

    void AddAlignment(const String* string, int index);
    const BSSAlignVec& GetAlignments() const { return _aligns; }
    unsigned int GetNumAlignments() const { return _aligns.size(); }

    void SetNum(int num) { _num = num; }
    int GetNum() const { return _num; }

    void MarkNewAlignment(bool mark) { _new = mark; }
    bool IsNewAlignment() { return _new; }



    static VectorVal* VecToPolicy(Vec* vec);
    static Vec* VecFromPolicy(VectorVal* vec);
    static char* VecToString(Vec* vec);
    static String::IdxVec* GetOffsetsVec(const Vec* vec, unsigned int index);

private:
    using DataMap = std::map<std::string, void*>;


    BSSAlignVec _aligns;


    int _num;


    bool _new;
};




class SubstringCmp {
public:
    explicit SubstringCmp(unsigned int index) { _index = index; }
    bool operator()(const Substring* bst1, const Substring* bst2) const;

private:
    unsigned int _index;
};








enum SWVariant : uint8_t {
    SW_SINGLE = 0,
    SW_MULTIPLE = 1,
};



struct SWParams {
    explicit SWParams(unsigned int min_toklen = 3, SWVariant sw_variant = SW_SINGLE) {
        _min_toklen = min_toklen;
        _sw_variant = sw_variant;
    }



    unsigned int _min_toklen;

    SWVariant _sw_variant;
};


















extern Substring::Vec* smith_waterman(const String* s1, const String* s2, SWParams& params);

}
