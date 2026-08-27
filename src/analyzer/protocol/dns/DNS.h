

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::dns {
namespace detail {

enum DNS_Opcode : uint8_t {
    DNS_OP_QUERY = 0,
    DNS_OP_IQUERY = 1,



    DNS_OP_SERVER_STATUS = 2,

    DNS_OP_NOTIFY = 4,
    DNS_OP_DYNAMIC_UPDATE = 5,
    DNS_OP_DSO = 6,


    NETBIOS_REGISTRATION = 5,
    NETBIOS_RELEASE = 6,
    NETBIOS_WACK = 7,
    NETBIOS_REFRESH = 8,
};

enum DNS_Code : uint16_t {
    DNS_CODE_OK = 0,
    DNS_CODE_FORMAT_ERR = 1,
    DNS_CODE_SERVER_FAIL = 2,
    DNS_CODE_NAME_ERR = 3,
    DNS_CODE_NOT_IMPL = 4,
    DNS_CODE_REFUSED = 5,
    DNS_CODE_YXDOMAIN = 6,
    DNS_CODE_YXRRSET = 7,
    DNS_CODE_NXRRSET = 8,
    DNS_CODE_NOTAUTH = 9,
    DNS_CODE_NOT_ZONE = 10,
    DNS_CODE_RESERVED = 65535,
};

enum RR_Type : uint16_t {
    TYPE_A = 1,
    TYPE_NS = 2,
    TYPE_CNAME = 5,
    TYPE_SOA = 6,
    TYPE_WKS = 11,
    TYPE_PTR = 12,
    TYPE_HINFO = 13,
    TYPE_MX = 15,
    TYPE_TXT = 16,
    TYPE_SIG = 24,
    TYPE_KEY = 25,
    TYPE_PX = 26,
    TYPE_AAAA = 28,
    TYPE_LOC = 29,
    TYPE_NBS = 32,
    TYPE_SRV = 33,
    TYPE_NAPTR = 35,
    TYPE_KX = 36,
    TYPE_CERT = 37,
    TYPE_A6 = 38,
    TYPE_DNAME = 39,
    TYPE_EDNS = 41,
    TYPE_SSHFP = 44,
    TYPE_TKEY = 249,
    TYPE_TSIG = 250,
    TYPE_CAA = 257,

    TYPE_RRSIG = 46,
    TYPE_NSEC = 47,
    TYPE_DNSKEY = 48,
    TYPE_DS = 43,
    TYPE_NSEC3 = 50,
    TYPE_NSEC3PARAM = 51,
    TYPE_SVCB = 64,

    TYPE_HTTPS = 65,

    TYPE_SPF = 99,


    TYPE_AXFR = 252,
    TYPE_ALL = 255,
    TYPE_WINS = 65281,
    TYPE_WINSR = 65282,

    TYPE_BINDS = 65534,
};

enum DNS_Class : uint16_t {
    DNS_CLASS_IN = 1,
    DNS_CLASS_NONE = 254,
    DNS_CLASS_ANY = 255,
    DNS_CLASS_RESERVED = 65535,
};

enum DNS_AnswerType : uint8_t {
    DNS_QUESTION,
    DNS_ANSWER,
    DNS_AUTHORITY,
    DNS_ADDITIONAL,
    DNS_PREREQUISITES,
    DNS_UPDATES,
};



enum EDNS_OPT_Type : uint16_t {
    TYPE_LLQ = 1,
    TYPE_UL = 2,
    TYPE_NSID = 3,
    TYPE_DAU = 5,
    TYPE_DHU = 6,
    TYPE_N3U = 7,
    TYPE_ECS = 8,
    TYPE_EXPIRE = 9,
    TYPE_COOKIE = 10,
    TYPE_TCP_KA = 11,
    TYPE_PAD = 12,
    TYPE_CHAIN = 13,
    TYPE_KEY_TAG = 14,
    TYPE_ERROR = 15,
    TYPE_CLIENT_TAG = 16,
    TYPE_SERVER_TAG = 17,
    TYPE_DEVICE_ID = 26946
};

enum DNSSEC_Algo : uint8_t {
    reserved0 = 0,
    RSA_MD5 = 1,
    Diffie_Hellman = 2,
    DSA_SHA1 = 3,
    Elliptic_Curve = 4,
    RSA_SHA1 = 5,
    DSA_NSEC3_SHA1 = 6,
    RSA_SHA1_NSEC3_SHA1 = 7,
    RSA_SHA256 = 8,
    RSA_SHA512 = 10,
    GOST_R_34_10_2001 = 12,
    ECDSA_curveP256withSHA256 = 13,
    ECDSA_curveP384withSHA384 = 14,
    Ed25519 = 15,
    Ed448 = 16,
    Indirect = 252,
    PrivateDNS = 253,
    PrivateOID = 254,
    reserved255 = 255,
};

enum DNSSEC_Digest : uint8_t {
    reserved = 0,
    SHA1 = 1,
    SHA256 = 2,
    GOST_R_34_11_94 = 3,
    SHA384 = 4,
};




enum SVCPARAM_Key : uint8_t {
    mandatory = 0,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
};

struct DNS_RawMsgHdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_zo_count;
    uint16_t an_pr_count;
    uint16_t ns_up_count;
    uint16_t arcount;
};

struct EDNS_ADDITIONAL {
    uint16_t name;
    uint16_t type;
    uint16_t payload_size;
    uint8_t extended_rcode;
    uint8_t version;
    uint16_t z;
    uint16_t rdata_len;
};

struct EDNS_ECS {
    StringValPtr ecs_family;
    uint16_t ecs_src_pfx_len;
    uint16_t ecs_scp_pfx_len;
    IntrusivePtr<AddrVal> ecs_addr;
};

struct EDNS_TCP_KEEPALIVE {
    bool keepalive_timeout_omitted;
    uint16_t keepalive_timeout;
};

struct EDNS_COOKIE {
    zeek::String* client_cookie;
    zeek::String* server_cookie;
};

struct TKEY_DATA {
    String* alg_name;
    uint32_t inception;
    uint32_t expiration;
    uint16_t mode;
    uint16_t error;
    String* key;
};

struct TSIG_DATA {
    String* alg_name;
    uint32_t time_s;
    uint16_t time_ms;
    String* sig;
    uint16_t fudge;
    uint16_t orig_id;
    uint16_t rr_error;
};

struct RRSIG_DATA {
    uint16_t type_covered;
    uint8_t algorithm;
    uint8_t labels;
    uint32_t orig_ttl;
    uint32_t sig_exp;
    uint32_t sig_incep;
    uint16_t key_tag;
    String* signer_name;
    String* signature;
};

struct DNSKEY_DATA {
    uint16_t dflags;
    uint8_t dalgorithm;
    uint8_t dprotocol;
    String* public_key;
};

struct NSEC3_DATA {
    uint16_t nsec_flags;
    uint16_t nsec_hash_algo;
    uint16_t nsec_iter;
    uint16_t nsec_salt_len;
    String* nsec_salt;
    uint16_t nsec_hlen;
    String* nsec_hash;
    VectorValPtr bitmaps;
};

struct NSEC3PARAM_DATA {
    uint8_t nsec_flags;
    uint8_t nsec_hash_algo;
    uint16_t nsec_iter;
    uint8_t nsec_salt_len;
    String* nsec_salt;
};

struct DS_DATA {
    uint16_t key_tag;
    uint8_t algorithm;
    uint8_t digest_type;
    String* digest_val;
};

struct BINDS_DATA {
    uint8_t algorithm;
    uint8_t removal_flag;
    uint16_t key_id;
    uint8_t complete_flag;
};

struct LOC_DATA {
    uint8_t version;
    uint8_t size;
    uint8_t horiz_pre;
    uint8_t vert_pre;
    uint32_t latitude;
    uint32_t longitude;
    uint32_t altitude;
};

struct SVCB_DATA {
    uint16_t svc_priority;
    StringValPtr target_name;
    VectorValPtr svc_params;
};

class DNS_MsgInfo final {
public:
    DNS_MsgInfo(DNS_RawMsgHdr* hdr, bool is_query, bool is_netbios);

    RecordValPtr BuildHdrVal();
    RecordValPtr BuildAnswerVal();
    RecordValPtr BuildEDNS_Val();
    RecordValPtr BuildEDNS_ECS_Val(struct EDNS_ECS*);
    RecordValPtr BuildEDNS_TCP_KA_Val(struct EDNS_TCP_KEEPALIVE*);
    RecordValPtr BuildEDNS_COOKIE_Val(struct EDNS_COOKIE*);
    RecordValPtr BuildTKEY_Val(struct TKEY_DATA*);
    RecordValPtr BuildTSIG_Val(struct TSIG_DATA*);
    RecordValPtr BuildRRSIG_Val(struct RRSIG_DATA*);
    RecordValPtr BuildDNSKEY_Val(struct DNSKEY_DATA*);
    RecordValPtr BuildNSEC3_Val(struct NSEC3_DATA*);
    RecordValPtr BuildNSEC3PARAM_Val(struct NSEC3PARAM_DATA*);
    RecordValPtr BuildDS_Val(struct DS_DATA*);
    RecordValPtr BuildBINDS_Val(struct BINDS_DATA*);
    RecordValPtr BuildLOC_Val(struct LOC_DATA*);
    RecordValPtr BuildSVCB_Val(const struct SVCB_DATA&);

    uint16_t id;
    uint8_t opcode;
    uint16_t rcode;
    bool QR;
    bool AA;
    bool TC;
    bool RD;
    bool RA;
    uint8_t Z;
    bool AD;
    bool CD;
    uint16_t qd_zo_count;
    uint16_t an_pr_count;
    uint16_t ns_up_count;
    uint16_t arcount;
    bool is_query = false;
    bool skip_event = false;
    bool is_dynamic_update = false;
    bool is_netbios = false;

    StringValPtr query_name;
    RR_Type atype = TYPE_ALL;
    uint16_t aclass = 0;
    uint32_t ttl = 0;
    uint16_t zclass = 0;

    DNS_AnswerType answer_type = DNS_QUESTION;
};

class DNS_Interpreter final {
public:
    explicit DNS_Interpreter(analyzer::Analyzer* analyzer);

    void ParseMessage(const u_char* data, int len, int is_query);

    void Timeout() {}

private:
    enum class LabelParseState : uint8_t {
        Continue,
        EndOfName,
        ParseError,
    };

    void EndMessage(detail::DNS_MsgInfo* msg);

    bool ParseQuestions(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* start);
    bool ParseAnswers(detail::DNS_MsgInfo* msg, int n, detail::DNS_AnswerType answer_type, const u_char*& data,
                      int& len, const u_char* start);

    bool ParseQuestion(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* start);
    bool ParseAnswerHeader(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* msg_start);
    bool ParseAnswer(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, const u_char* start);

    u_char* ExtractName(const u_char*& data, int& len, u_char* label, int label_len, const u_char* msg_start,
                        bool downcase = true, int compression_depth = 0);
    LabelParseState ExtractLabel(const u_char*& data, int& len, u_char*& label, int& label_len, const u_char* msg_start,
                                 int compression_depth = 0);

    uint8_t ExtractByte(const u_char*& data, int& len);
    uint16_t ExtractShort(const u_char*& data, int& len);
    uint32_t ExtractLong(const u_char*& data, int& len);
    void ExtractOctets(const u_char*& data, int& len, String** p);

    String* ExtractStream(const u_char*& data, int& len, int sig_len);

    VectorValPtr Parse_SvcParams(const u_char*& data, int& len, int svc_params_len);

    bool ParseRR_Name(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SOA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_MX(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NBS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SRV(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NAPTR(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_EDNS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_EDNS_ECS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                          const u_char* msg_start);
    bool ParseRR_A(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength);
    bool ParseRR_AAAA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength);
    bool ParseRR_WKS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength);
    bool ParseRR_HINFO(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength);
    bool ParseRR_TXT(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SPF(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_CAA(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_TKEY(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_TSIG(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_RRSIG(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_DNSKEY(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NSEC(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NSEC3(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_NSEC3PARAM(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength,
                            const u_char* msg_start);
    bool ParseRR_DS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_BINDS(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SSHFP(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_LOC(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start);
    bool ParseRR_SVCB(detail::DNS_MsgInfo* msg, const u_char*& data, int& len, int rdlength, const u_char* msg_start,
                      const RR_Type& svcb_type);
    void SendReplyOrRejectEvent(detail::DNS_MsgInfo* msg, EventHandlerPtr event, const u_char*& data, int& len,
                                String* question_name, String* original_name);

    analyzer::Analyzer* analyzer = nullptr;
    bool first_message = true;
    bool is_netbios = false;
};

enum TCP_DNS_state : uint8_t {
    DNS_LEN_HI,
    DNS_LEN_LO,
    DNS_MESSAGE_BUFFER,
};

}



class Contents_DNS final : public analyzer::tcp::TCP_SupportAnalyzer {
public:
    Contents_DNS(Connection* c, bool orig, detail::DNS_Interpreter* interp);
    ~Contents_DNS() override;

    void Flush();

    detail::TCP_DNS_state State() const { return state; }

protected:
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void ProcessChunk(int& len, const u_char*& data, bool orig);

    detail::DNS_Interpreter* interp;

    u_char* msg_buf;
    int buf_n;
    int buf_len;
    int msg_size;
    detail::TCP_DNS_state state;
};


class DNS_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit DNS_Analyzer(Connection* conn);
    ~DNS_Analyzer() override;

    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;

    void Done() override;
    void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                          bool gen_event) override;
    void ExpireTimer(double t);

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new DNS_Analyzer(conn); }

protected:
    detail::DNS_Interpreter* interp;
    Contents_DNS* contents_dns_orig;
    Contents_DNS* contents_dns_resp;
};

}
