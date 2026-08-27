

#ifndef pac_ctype_h
#define pac_ctype_h

#include "pac_common.h"


class CType {
public:
    CType(const string& name);

    string name() const { return name_; }

    string DeclareInstance(const string& var) const;
    string DeclareConstReference(const string& var) const;
    string DeclareConstPointer(const string& var) const;
    string DeclarePointer(const string& var) const;

protected:
    string name_;
};

#endif
