

#pragma once

#include <memory>

#include "zeek/IntrusivePtr.h"
#include "zeek/session/Key.h"

namespace zeek {

class Packet;

class RecordVal;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;




class ConnKey {
public:
    virtual ~ConnKey() = default;






    void Init(const Packet& pkt) { DoInit(pkt); }

















    void PopulateConnIdVal(RecordVal& conn_id, RecordVal& ctx) { DoPopulateConnIdVal(conn_id, ctx); };










    zeek::session::detail::Key SessionKey() const { return DoSessionKey(); }

protected:















    virtual void DoInit(const Packet& pkt) {};

















    virtual void DoPopulateConnIdVal(RecordVal& conn_id, RecordVal& ctx) {}






    virtual session::detail::Key DoSessionKey() const = 0;
};

using ConnKeyPtr = std::unique_ptr<ConnKey>;

}
