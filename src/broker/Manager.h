

#pragma once

#include "zeek/zeek-config.h"

#include <broker/backend.hh>
#include <broker/backend_options.hh>
#include <broker/detail/hash.hh>
#include <broker/endpoint_info.hh>
#include <broker/hub.hh>
#include <broker/peer_info.hh>
#include <broker/store.hh>
#include <broker/zeek.hh>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "zeek/IntrusivePtr.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/Backend.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/logging/Types.h"
#include "zeek/logging/WriterBackend.h"

namespace broker {

class data;
class error;
class endpoint;

}

namespace zeek {

class Func;
class VectorType;
class TableVal;
using VectorTypePtr = IntrusivePtr<VectorType>;
using TableValPtr = IntrusivePtr<TableVal>;

namespace telemetry {
class Gauge;
class Counter;
using GaugePtr = std::shared_ptr<Gauge>;
using CounterPtr = std::shared_ptr<Counter>;
}

namespace detail {
class Frame;
}

namespace Broker {

namespace detail {
class StoreHandleVal;
class StoreQueryCallback;
};

class BrokerState;




struct Stats {

    size_t num_peers = 0;

    size_t num_stores = 0;

    size_t num_pending_queries = 0;

    size_t num_events_incoming = 0;

    size_t num_events_outgoing = 0;

    size_t num_logs_incoming = 0;

    size_t num_logs_outgoing = 0;

    size_t num_ids_incoming = 0;

    size_t num_ids_outgoing = 0;
};





class Manager : public zeek::cluster::Backend, public iosource::IOSource {
public:
    static const broker::endpoint_info NoPeer;




    Manager(bool use_real_time);




    bool Active();





    void AdvanceTime(double seconds_since_unix_epoch);











    uint16_t Listen(const std::string& addr, uint16_t port);









    void Peer(const std::string& addr, uint16_t port, double retry = 10.0);







    void PeerNoRetry(const std::string& addr, uint16_t port);






    void Unpeer(const std::string& addr, uint16_t port);







    bool IsOutboundPeering(const std::string& addr, uint16_t port) const;






    bool IsOutboundPeering(const broker::network_info& ni) const;




    std::vector<broker::peer_info> Peers() const;







    bool PublishIdentifier(std::string topic, std::string id);











    bool PublishEvent(std::string topic, const std::string& name, const broker::vector& args,
                      double ts = run_state::network_time);




    bool PublishEvent(std::string topic, const std::string& name, BrokerData args,
                      double ts = run_state::network_time) {
        if ( ! args.AsView().IsList() )
            return false;
        return PublishEvent(std::move(topic), name, broker::get<broker::vector>(args.value_), ts);
    }

    using cluster::Backend::PublishEvent;











    bool PublishEvent(std::string topic, RecordVal* ev);














    bool PublishLogCreate(EnumVal* stream, EnumVal* writer, const logging::WriterBackend::WriterInfo& info,
                          int num_fields, const threading::Field* const* fields,
                          const broker::endpoint_info& peer = NoPeer);










    bool PublishLogWrite(EnumVal* stream, EnumVal* writer, const std::string& path,
                         const logging::detail::LogRecord& rec);

    using ArgsSpan = std::span<const ValPtr>;








    zeek::RecordValPtr MakeEvent(ArgsSpan args, zeek::detail::Frame* frame);










    bool Forward(std::string topic_prefix);








    detail::StoreHandleVal* MakeMaster(const std::string& name, broker::backend type, broker::backend_options opts);



















    detail::StoreHandleVal* MakeClone(const std::string& name, double resync_interval = 10.0,
                                      double stale_interval = 300.0, double mutation_buffer_interval = 120.0);






    detail::StoreHandleVal* LookupStore(const std::string& name);









    bool AddForwardedStore(const std::string& name, TableValPtr table);







    bool CloseStore(const std::string& name);






    bool TrackStoreQuery(detail::StoreHandleVal* handle, broker::request_id id, detail::StoreQueryCallback* cb);





    size_t FlushLogBuffers();




    void ClearStores();




    const Stats& GetStatistics();







    TableValPtr GetPeeringStatsTable();






    struct ScriptScopeGuard {
        ScriptScopeGuard() { ++script_scope; }
        ~ScriptScopeGuard() { --script_scope; }
    };

private:

    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override;


    bool DoUnsubscribe(const std::string& topic_prefix) override;



    void DoInitPostScript() override;


    bool DoInit() override { return true; }


    void DoTerminate() override;


    bool DoPublishEvent(const std::string& topic, cluster::Event& event) override;



    bool DoPublishEvent(const std::string& topic, const std::string& format, const byte_buffer& buf) override {
        throw std::logic_error("not implemented");
    }





    bool DoPublishLogWrites(const logging::detail::LogWriteHeader& header,
                            std::span<logging::detail::LogRecord> records) override {

        throw std::logic_error("not implemented");
    }

    bool DoPublishLogWrites(const logging::detail::LogWriteHeader& header, const std::string& format,
                            byte_buffer& buf) override {

        throw std::logic_error("not implemented");
    }


    void ProcessStoreEvent(const broker::data& msg);

    void ProcessStoreEventInsertUpdate(const TableValPtr& table, const std::string& store_id, const broker::data& key,
                                       const broker::data& data, const broker::data& old_value, bool insert);
    void ProcessMessage(std::string_view topic, broker::zeek::Batch& ev);
    void ProcessMessage(std::string_view topic, broker::zeek::Event& ev);
    void ProcessMessage(std::string_view topic, broker::zeek::Invalid& ev);
    bool ProcessMessage(std::string_view topic, broker::zeek::LogCreate& lc);
    bool ProcessMessage(std::string_view topic, broker::zeek::LogWrite& lw);
    bool ProcessMessage(std::string_view topic, broker::zeek::IdentifierUpdate& iu);
    void ProcessStatus(broker::status& stat);
    void ProcessError(broker::error& err);
    void ProcessStoreResponse(detail::StoreHandleVal*, broker::store::response response);
    void FlushPendingQueries();

    void InitializeBrokerStoreForwarding();

    void PrepareForwarding(const std::string& name);


    void BrokerStoreToZeekTable(const std::string& name, const detail::StoreHandleVal* handle);

    void Error(const char* format, ...) __attribute__((format(printf, 2, 3)));


    void ProcessMessages();


    void ProcessLogEvents();


    void ProcessDataStore(detail::StoreHandleVal* store);


    void ProcessDataStores();


    void ProcessFd(int fd, int flags) override;
    void Process() override;
    const char* Tag() override { return "Broker::Manager"; }
    double GetNextTimeout() override;



    friend class WebSocketState;


    broker::hub MakeHub();


    void DestroyHub(broker::hub&& hub);

    struct LogBuffer {

        std::unordered_map<std::string, broker::zeek::BatchBuilder> msgs;
        size_t message_count;

        size_t Flush(broker::endpoint& endpoint, size_t batch_size);
    };


    using query_id = std::pair<broker::request_id, detail::StoreHandleVal*>;

    struct query_id_hasher {
        size_t operator()(const query_id& qid) const {
            size_t rval = 0;
            broker::detail::hash_combine(rval, qid.first);
            broker::detail::hash_combine(rval, qid.second);
            return rval;
        }
    };

    std::vector<LogBuffer> log_buffers;
    std::string default_log_topic_prefix;
    std::shared_ptr<BrokerState> bstate;
    std::unordered_map<std::string, detail::StoreHandleVal*> data_stores;
    std::unordered_map<std::string, TableValPtr> forwarded_stores;
    std::unordered_map<query_id, detail::StoreQueryCallback*, query_id_hasher> pending_queries;
    std::vector<std::string> forwarded_prefixes;

    Stats statistics;

    uint16_t bound_port;
    bool use_real_time;
    int peer_count;
    int hub_count;

    size_t log_batch_size;
    Func* log_topic_func;
    VectorTypePtr vector_of_data_type;
    EnumType* log_id_type;
    EnumType* writer_id_type;
    bool zeek_table_manager = false;
    std::string zeek_table_db_directory;

    static int script_scope;

    telemetry::GaugePtr num_peers_metric;
    telemetry::GaugePtr num_stores_metric;
    telemetry::GaugePtr num_pending_queries_metric;
    telemetry::CounterPtr num_events_incoming_metric;
    telemetry::CounterPtr num_events_outgoing_metric;
    telemetry::CounterPtr num_logs_incoming_metric;
    telemetry::CounterPtr num_logs_outgoing_metric;
    telemetry::CounterPtr num_ids_incoming_metric;
    telemetry::CounterPtr num_ids_outgoing_metric;
};

}

ZEEK_EXTERN_DATA Broker::Manager* broker_mgr;

}
