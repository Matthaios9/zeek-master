

#ifndef pac_embedded_h
#define pac_embedded_h

#include "pac_common.h"

class EmbeddedCodeSegment {
public:
    explicit EmbeddedCodeSegment(string s);
    explicit EmbeddedCodeSegment(PacPrimitive* primitive);
    ~EmbeddedCodeSegment();

    string ToCode(Env* env);

private:
    string s_;
    PacPrimitive* primitive_;
};

using EmbeddedCodeSegmentList = vector<EmbeddedCodeSegment*>;

class EmbeddedCode : public Object {
public:
    EmbeddedCode();
    ~EmbeddedCode() override;


    void Append(int atom);
    void Append(const char* str);


    void Append(PacPrimitive* primitive);

    void GenCode(Output* out, Env* env);

private:
    string current_segment_;
    EmbeddedCodeSegmentList* segments_;
};

#endif
