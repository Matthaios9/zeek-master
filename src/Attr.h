

#pragma once

#include <string>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/Traverse.h"
#include "zeek/ZeekList.h"





namespace zeek {

class Type;
using TypePtr = IntrusivePtr<Type>;

namespace detail {

class Expr;
using ExprPtr = IntrusivePtr<Expr>;

enum AttrTag : uint8_t {
    ATTR_OPTIONAL,
    ATTR_DEFAULT,
    ATTR_DEFAULT_INSERT,
    ATTR_REDEF,
    ATTR_ADD_FUNC,
    ATTR_DEL_FUNC,
    ATTR_EXPIRE_FUNC,
    ATTR_EXPIRE_READ,
    ATTR_EXPIRE_WRITE,
    ATTR_EXPIRE_CREATE,
    ATTR_RAW_OUTPUT,
    ATTR_PRIORITY,
    ATTR_GROUP,
    ATTR_LOG,
    ATTR_ERROR_HANDLER,
    ATTR_TYPE_COLUMN,
    ATTR_TRACKED,
    ATTR_ON_CHANGE,
    ATTR_PUBLISH_ON_CHANGE,
    ATTR_BROKER_STORE,
    ATTR_BROKER_STORE_ALLOW_COMPLEX,
    ATTR_BACKEND,
    ATTR_DEPRECATED,
    ATTR_IS_ASSIGNED,
    ATTR_IS_USED,
    ATTR_ORDERED,
    ATTR_NO_ZAM_OPT,
    ATTR_NO_CPP_OPT,
    NUM_ATTRS
};

class Attr;
using AttrPtr = IntrusivePtr<Attr>;
class Attributes;
using AttributesPtr = IntrusivePtr<Attributes>;

class Attr final : public Obj {
public:
    static inline const AttrPtr nil;

    Attr(AttrTag t, ExprPtr e);
    explicit Attr(AttrTag t);

    AttrTag Tag() const { return tag; }

    const ExprPtr& GetExpr() const { return expr; }

    void SetAttrExpr(ExprPtr e);

    void Describe(ODesc* d) const override;
    void DescribeReST(ODesc* d, bool shorten = false) const;





    std::string DeprecationMessage() const;

    bool operator==(const Attr& other) const {
        if ( tag != other.tag )
            return false;

        if ( expr || other.expr )




            return expr && other.expr;

        return true;
    }

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const;

protected:
    void AddTag(ODesc* d) const;

    AttrTag tag;
    ExprPtr expr;
};


class Attributes final : public Obj {
public:
    Attributes(std::vector<AttrPtr> a, TypePtr t, bool in_record, bool is_global, bool is_param);

    Attributes(TypePtr t, bool in_record, bool is_global)
        : Attributes(std::vector<AttrPtr>{}, std::move(t), in_record, is_global, false) {}

    Attributes(std::vector<AttrPtr> a, TypePtr t, bool in_record, bool is_global)
        : Attributes(std::move(a), std::move(t), in_record, is_global, false) {}


    void AddAttr(AttrPtr a, bool is_redef = false);

    void AddAttrs(const AttributesPtr& a, bool is_redef = false);

    const AttrPtr& Find(AttrTag t) const;

    void RemoveAttr(AttrTag t);

    void Describe(ODesc* d) const override;
    void DescribeReST(ODesc* d, bool shorten = false) const;

    const std::vector<AttrPtr>& GetAttrs() const { return attrs; }

    bool operator==(const Attributes& other) const;

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const;

protected:

    bool CheckAttr(Attr* attr, const TypePtr& attrs_t);


    bool AttrError(const char* msg);

    TypePtr type;
    std::vector<AttrPtr> attrs;

    bool in_record;
    bool global_var;
    bool is_param;
};









extern bool check_default_attr(Attr* a, const TypePtr& type, bool global_var, bool in_record, std::string& err_msg);


extern const char* attr_name(AttrTag t);

}
}
