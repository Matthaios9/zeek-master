

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::rpc {
namespace detail {

enum : uint8_t {
    RPC_CALL = 0,
    RPC_REPLY = 1,
};

enum : uint8_t {
    RPC_MSG_ACCEPTED = 0,
    RPC_MSG_DENIED = 1,
};

enum : uint8_t {
    RPC_SUCCESS = 0,
    RPC_PROG_UNAVAIL = 1,
    RPC_PROG_MISMATCH = 2,
    RPC_PROC_UNAVAIL = 3,
    RPC_GARBAGE_ARGS = 4,
    RPC_SYSTEM_ERR = 5,
};

enum : uint8_t {
    RPC_MISMATCH = 0,
    RPC_AUTH_ERROR = 1,
};

enum : uint8_t {
    RPC_AUTH_BADCRED = 1,
    RPC_AUTH_REJECTEDCRED = 2,
    RPC_AUTH_BADVERF = 3,
    RPC_AUTH_REJECTEDVERF = 4,
    RPC_AUTH_TOOWEAK = 5,
};

enum : uint8_t {
    RPC_AUTH_NULL = 0,
    RPC_AUTH_UNIX = 1,
    RPC_AUTH_SHORT = 2,
    RPC_AUTH_DES = 3,
};

class RPC_CallInfo {
public:
    RPC_CallInfo(uint32_t xid, const u_char*& buf, int& n, double start_time, double last_time, int rpc_len);
    ~RPC_CallInfo();

    void AddVal(ValPtr arg_v) { v = std::move(arg_v); }
    const ValPtr& RequestVal() const { return v; }
    ValPtr TakeRequestVal() {
        auto rv = std::move(v);
        return rv;
    }

    bool CompareRexmit(const u_char* buf, int n) const;

    uint32_t Program() const { return prog; }
    uint32_t Version() const { return vers; }
    uint32_t Proc() const { return proc; }
    uint32_t Uid() const { return uid; }
    uint32_t Gid() const { return gid; }
    uint32_t Stamp() const { return stamp; }
    const std::string& MachineName() const { return machinename; }
    const std::vector<int>& AuxGIDs() const { return auxgids; }

    double StartTime() const { return start_time; }
    void SetStartTime(double t) { start_time = t; }
    double LastTime() const { return last_time; }
    void SetLastTime(double t) { last_time = t; }
    int CallLen() const { return call_n; }
    int RPCLen() const { return rpc_len; }
    int HeaderLen() const { return header_len; }

    uint32_t XID() const { return xid; }

    void SetValidCall() { valid_call = true; }
    bool IsValidCall() const { return valid_call; }

protected:
    uint32_t xid, rpc_version, prog, vers, proc;
    uint32_t cred_flavor, stamp;
    uint32_t uid, gid;
    std::vector<int> auxgids;
    uint32_t verf_flavor = 0;
    u_char* call_buf;
    std::string machinename;
    double start_time;
    double last_time;
    int rpc_len = 0;
    int call_n = 0;
    int header_len = 0;
    bool valid_call = true;

    ValPtr v;
};

class RPC_Interpreter {
public:
    explicit RPC_Interpreter(analyzer::Analyzer* analyzer);
    virtual ~RPC_Interpreter();




    int DeliverRPC(const u_char* data, int len, int caplen, bool is_orig, double start_time, double last_time);

    void Timeout();

protected:
    virtual bool RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) = 0;
    virtual bool RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status success, const u_char*& buf, int& n,
                                double start_time, double last_time, int reply_len) = 0;

    void Event_RPC_Dialogue(RPC_CallInfo* c, BifEnum::rpc_status status, int reply_len);
    void Event_RPC_Call(RPC_CallInfo* c);
    void Event_RPC_Reply(uint32_t xid, BifEnum::rpc_status status, int reply_len);

    void Weird(const char* name, const char* addl = "");

    std::map<uint32_t, RPC_CallInfo*> calls;
    analyzer::Analyzer* analyzer;
};


















class RPC_Reasm_Buffer {
public:
    RPC_Reasm_Buffer() {
        maxsize = expected = 0;
        fill = processed = 0;
        buf = nullptr;
    };

    ~RPC_Reasm_Buffer() {
        if ( buf )
            delete[] buf;
    }

    void Init(int64_t arg_maxsize, int64_t arg_expected);

    const u_char* GetBuf() { return buf; }
    int64_t GetFill() { return fill; }
    int64_t GetSkipped() { return processed - fill; }
    int64_t GetExpected() { return expected; }
    int64_t GetProcessed() { return processed; }




    bool AddToExpected(int64_t delta) {
        expected += delta;
        return ! (expected > maxsize);
    }





    bool ConsumeChunk(const u_char*& data, int& len);

protected:
    int64_t fill;
    int64_t maxsize;
    int64_t processed;
    int64_t expected;
    u_char* buf;
};

}


class Contents_RPC final : public analyzer::tcp::TCP_SupportAnalyzer {
public:
    Contents_RPC(Connection* conn, bool orig, detail::RPC_Interpreter* interp);

protected:
    enum state_t : uint8_t {
        WAIT_FOR_MESSAGE,
        WAIT_FOR_MARKER,
        WAIT_FOR_DATA,
        WAIT_FOR_LAST_DATA,
    };

    enum resync_state_t : uint8_t {
        NEED_RESYNC,
        RESYNC_WAIT_FOR_MSG_START,
        RESYNC_WAIT_FOR_FULL_MSG,
        RESYNC_HAD_FULL_MSG,
        INSYNC,
        RESYNC_INIT,
    };

    void Init() override;
    bool CheckResync(int& len, const u_char*& data, bool orig);
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;

    void NeedResync() {
        resync_state = NEED_RESYNC;
        resync_toskip = 0;
        state = WAIT_FOR_MESSAGE;
    }

    detail::RPC_Interpreter* interp;

    detail::RPC_Reasm_Buffer marker_buf;
    detail::RPC_Reasm_Buffer msg_buf;
    state_t state;

    double start_time;
    double last_time;

    resync_state_t resync_state;
    int resync_toskip;
};

class RPC_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    RPC_Analyzer(const char* name, Connection* conn, detail::RPC_Interpreter* arg_interp);
    ~RPC_Analyzer() override;

    void Done() override;

protected:
    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;

    void ExpireTimer(double t);

    detail::RPC_Interpreter* interp;

    Contents_RPC* orig_rpc = nullptr;
    Contents_RPC* resp_rpc = nullptr;
};

}
