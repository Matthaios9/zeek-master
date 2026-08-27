

#pragma once

#include "zeek/zeek-config.h"

#include <arpa/nameser.h>
#include <netdb.h>
#include <list>
#include <map>
#include <utility>
#include <variant>

#include "zeek/EventHandler.h"
#include "zeek/IPAddr.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/util.h"



struct ares_channeldata;
using ares_channel = struct ares_channeldata*;



#ifdef T_PTR

#undef T_PTR
#endif

#ifdef T_TXT

#undef T_TXT
#endif

[[deprecated("Remove in v9.1. Use ns_t_ptr from arpa/nameser.h instead.")]]
constexpr int T_PTR = ns_t_ptr;

[[deprecated("Remove in v9.1. Use ns_t_txt from arpa/nameser.h instead.")]]
constexpr int T_TXT = ns_t_txt;

namespace zeek {
class Val;
class ListVal;
class TableVal;
class StringVal;
class RecordVal;

template<class T>
class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;
using ListValPtr = IntrusivePtr<ListVal>;
using TableValPtr = IntrusivePtr<TableVal>;
using StringValPtr = IntrusivePtr<StringVal>;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace telemetry {
class Gauge;
class Counter;
using GaugePtr = std::shared_ptr<Gauge>;
using CounterPtr = std::shared_ptr<Counter>;
}

}

namespace zeek::detail {
class DNS_Mapping;
using DNS_MappingPtr = std::shared_ptr<DNS_Mapping>;
class DNS_Request;

enum DNS_MgrMode : uint8_t {
    DNS_PRIME,
    DNS_FORCE,
    DNS_DEFAULT,
    DNS_FAKE,
};

class DNS_Mgr : public iosource::IOSource {
public:



    class LookupCallback {
    public:
        virtual ~LookupCallback() = default;






        virtual void Resolved(const std::string& name) {};






        virtual void Resolved(TableValPtr addrs) {};






        virtual void Resolved(ValPtr data, int request_type) {}




        virtual void Timeout() = 0;
    };

    explicit DNS_Mgr(DNS_MgrMode mode);
    ~DNS_Mgr() override;




    void Done() override;





    void InitPostScript();





    void Flush();










    TableValPtr LookupHost(const std::string& host);









    StringValPtr LookupAddr(const IPAddr& addr);













    ValPtr Lookup(const std::string& name, int request_type);









    void LookupHost(const std::string& host, LookupCallback* callback);









    void LookupAddr(const IPAddr& addr, LookupCallback* callback);










    void LookupText(const std::string& host, LookupCallback* callback) { Lookup(host, ns_t_txt, callback); }














    void Lookup(const std::string& name, int request_type, LookupCallback* callback);




    void SetDir(const std::string& arg_dir) { dir = arg_dir; }





    void Resolve();




    bool Save();

    struct CachedStats {
        unsigned long hosts = 0;
        unsigned long addresses = 0;
        unsigned long texts = 0;
        unsigned long total = 0;
    };

    struct Stats {
        unsigned long requests = 0;
        unsigned long successful = 0;
        unsigned long failed = 0;
        unsigned long pending = 0;
        CachedStats cached;
    };






    void GetStats(Stats* stats);












    void AddResult(DNS_Request* dr, struct hostent* h, uint32_t ttl, bool merge = false);





    static TableValPtr empty_addr_set();




    std::string CacheFile() const { return cache_name; }




    void RegisterSocket(int fd, bool read, bool write);

    ares_channel& GetChannel() { return channel; }

protected:
    friend class LookupCallback;
    friend class DNS_Request;

    StringValPtr LookupAddrInCache(const IPAddr& addr, bool cleanup_expired = false, bool check_failed = false);
    TableValPtr LookupNameInCache(const std::string& name, bool cleanup_expired = false, bool check_failed = false);
    StringValPtr LookupOtherInCache(const std::string& name, int request_type, bool cleanup_expired = false);



    void CheckAsyncAddrRequest(const IPAddr& addr, bool timeout);
    void CheckAsyncHostRequest(const std::string& host, bool timeout);
    void CheckAsyncOtherRequest(const std::string& host, bool timeout, int request_type);

    void Event(EventHandlerPtr e, const DNS_MappingPtr& dm);
    void Event(EventHandlerPtr e, const DNS_MappingPtr& dm, ListValPtr l1, ListValPtr l2);
    void Event(EventHandlerPtr e, const DNS_MappingPtr& old_dm, DNS_MappingPtr new_dm);

    RecordValPtr BuildMappingVal(const DNS_MappingPtr& dm);

    void CompareMappings(const DNS_MappingPtr& prev_dm, const DNS_MappingPtr& new_dm);
    ListValPtr AddrListDelta(ListValPtr al1, ListValPtr al2);

    using MappingKey = std::variant<IPAddr, std::pair<int, std::string>>;
    using MappingMap = std::map<MappingKey, DNS_MappingPtr>;
    void LoadCache(const std::string& path);
    void Save(FILE* f, const MappingMap& m);


    void IssueAsyncRequests();


    void Process() override;
    void ProcessFd(int fd, int flags) override;
    void InitSource() override;
    const char* Tag() override { return "DNS_Mgr"; }
    double GetNextTimeout() override;

    void UpdateCachedStats(bool force);

    DNS_MgrMode mode;

    MappingMap all_mappings;

    std::string cache_name;
    std::string dir;

    bool did_init = false;

    RecordTypePtr dm_rec;

    ares_channel channel{};

    using CallbackList = std::list<LookupCallback*>;

    struct AsyncRequest {
        double time = 0.0;
        IPAddr addr;
        std::string host;
        CallbackList callbacks;
        int type = 0;
        bool processed = false;

        AsyncRequest(std::string host, int request_type) : host(std::move(host)), type(request_type) {}
        AsyncRequest(const IPAddr& addr);

        void Resolved(const std::string& name);
        void Resolved(TableValPtr addrs);
        void Timeout();
    };

    struct AsyncRequestCompare {
        bool operator()(const AsyncRequest* a, const AsyncRequest* b) { return a->time > b->time; }
    };

    using AsyncRequestMap = std::map<MappingKey, AsyncRequest*>;
    AsyncRequestMap asyncs;

    using QueuedList = std::list<AsyncRequest*>;
    QueuedList asyncs_queued;

    telemetry::CounterPtr num_requests_metric;
    telemetry::CounterPtr successful_metric;
    telemetry::CounterPtr failed_metric;
    telemetry::GaugePtr asyncs_pending_metric;

    telemetry::GaugePtr cached_hosts_metric;
    telemetry::GaugePtr cached_addresses_metric;
    telemetry::GaugePtr cached_texts_metric;

    double last_cached_stats_update = 0;
    CachedStats last_cached_stats;

    int asyncs_pending = 0;

    std::set<int> socket_fds;
    std::set<int> write_socket_fds;

    bool shutting_down = false;
};

ZEEK_EXTERN_DATA DNS_Mgr* dns_mgr;

}
