

#pragma once

#include "zeek/zeek-config.h"

#include <memory>

#include "zeek/OpaqueVal.h"
#include "zeek/Tag.h"
#include "zeek/Val.h"
#include "zeek/storage/Serializer.h"

namespace zeek::detail::trigger {
class Trigger;
using TriggerPtr = IntrusivePtr<Trigger>;
}

namespace zeek::telemetry {
class Counter;
using CounterPtr = std::shared_ptr<Counter>;
class CounterFamily;
using CounterFamilyPtr = std::shared_ptr<CounterFamily>;
class Histogram;
using HistogramPtr = std::shared_ptr<Histogram>;
class HistogramFamily;
using HistogramFamilyPtr = std::shared_ptr<HistogramFamily>;
}

namespace zeek::storage {

namespace detail {
struct OperationMetrics {
    telemetry::CounterPtr success;
    telemetry::CounterPtr fail;
    telemetry::CounterPtr error;
    telemetry::CounterPtr timeouts;
    telemetry::HistogramPtr latency;

    OperationMetrics(const telemetry::CounterFamilyPtr& results_family,
                     const telemetry::HistogramFamilyPtr& latency_family, std::string_view operation_type,
                     std::string_view backend_type, std::string_view backend_config);
};
}

class Manager;





struct OperationResult {






    EnumValPtr code;




    std::string err_str;





    ValPtr value;





    RecordValPtr BuildVal();





    static RecordValPtr MakeVal(EnumValPtr code, std::string_view err_str = "", ValPtr value = nullptr);
};




class ResultCallback {
public:
    ResultCallback() = default;
    ResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc);
    virtual ~ResultCallback() = default;





    void Timeout();





    bool IsSyncCallback() const { return ! trigger; }





    virtual void Complete(OperationResult res);

    OperationResult Result() const { return result; }






    void Init(detail::OperationMetrics* m);




    void UpdateOperationMetrics(EnumValPtr c);






    void AddDataTransferredSize(size_t size) { transferred_size += size; }




    size_t GetDataTransferredSize() const { return transferred_size; }

protected:
    zeek::detail::trigger::TriggerPtr trigger;
    const void* assoc = nullptr;
    OperationResult result;
    detail::OperationMetrics* operation_metrics = nullptr;
    double start_time = 0.0;
    size_t transferred_size = 0;
};

class OpenResultCallback;





enum SupportedModes : uint8_t { SYNC = 0x01, ASYNC = 0x02 };

class Backend : public zeek::Obj {
public:



    const char* Tag() const { return tag_str.c_str(); }















    OperationResult Put(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite = true,
                        double expiration_time = 0);










    OperationResult Get(ResultCallback* cb, ValPtr key);










    OperationResult Erase(ResultCallback* cb, ValPtr key);




    virtual bool IsOpen() = 0;

    bool SupportsSync() const { return (modes & SupportedModes::SYNC) == SupportedModes::SYNC; }
    bool SupportsAsync() const { return (modes & SupportedModes::ASYNC) == SupportedModes::ASYNC; }





    void Poll() { DoPoll(); }





    const RecordValPtr& Options() const { return backend_options; }




    bool IsForcedSync() const { return forced_sync; }

protected:

    friend class storage::Manager;


    friend class storage::OpenResultCallback;










    Backend(uint8_t modes, std::string_view tag_name);














    OperationResult Open(OpenResultCallback* cb, RecordValPtr options, TypePtr kt, TypePtr vt);









    OperationResult Close(ResultCallback* cb);








    void Expire(double current_network_time) { DoExpire(current_network_time); }





    void EnqueueBackendOpened();






    void EnqueueBackendLost(std::string_view reason);






    void CompleteCallback(ResultCallback* cb, const OperationResult& data) const;





    std::string GetConfigMetricsLabel() const { return DoGetConfigMetricsLabel(); }






    void IncBytesWrittenMetric(size_t written);






    void IncBytesReadMetric(size_t read);







    void IncExpiredEntriesMetric(size_t expired);

    TypePtr key_type;
    TypePtr val_type;
    RecordValPtr backend_options;

    zeek::Tag tag;
    std::string tag_str;
    std::unique_ptr<Serializer> serializer;

private:




    virtual OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) = 0;





    virtual OperationResult DoClose(ResultCallback* cb) = 0;





    virtual OperationResult DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                                  double expiration_time) = 0;





    virtual OperationResult DoGet(ResultCallback* cb, ValPtr key) = 0;





    virtual OperationResult DoErase(ResultCallback* cb, ValPtr key) = 0;






    virtual void DoPoll() {}









    virtual void DoExpire(double current_network_time) {}





    virtual std::string DoGetConfigMetricsLabel() const = 0;




    void InitMetrics();

    uint8_t modes;
    bool forced_sync = false;
    bool metrics_initialized = false;



    std::unique_ptr<detail::OperationMetrics> put_metrics;
    std::unique_ptr<detail::OperationMetrics> get_metrics;
    std::unique_ptr<detail::OperationMetrics> erase_metrics;

    telemetry::CounterPtr bytes_written_metric;
    telemetry::CounterPtr bytes_read_metric;
    telemetry::CounterPtr backends_opened_metric;
    telemetry::CounterPtr expired_entries_metric;
};

using BackendPtr = zeek::IntrusivePtr<Backend>;

namespace detail {

ZEEK_EXTERN_DATA OpaqueTypePtr backend_opaque;




class BackendHandleVal : public OpaqueVal {
public:
    BackendHandleVal() : OpaqueVal(detail::backend_opaque) {}
    BackendHandleVal(BackendPtr backend) : OpaqueVal(detail::backend_opaque), backend(std::move(backend)) {}









    static zeek::expected<storage::detail::BackendHandleVal*, OperationResult> CastFromAny(Val*);

    BackendPtr backend;

protected:
    IntrusivePtr<Val> DoClone(CloneState* state) override { return {NewRef{}, this}; }

    DECLARE_OPAQUE_VALUE_DATA(BackendHandleVal)
};

}





class OpenResultCallback : public ResultCallback {
public:
    OpenResultCallback(IntrusivePtr<detail::BackendHandleVal> backend);
    OpenResultCallback(zeek::detail::trigger::TriggerPtr trigger, const void* assoc,
                       IntrusivePtr<detail::BackendHandleVal> backend);
    void Complete(OperationResult res) override;

    IntrusivePtr<detail::BackendHandleVal> Backend() const { return backend; }

private:
    IntrusivePtr<detail::BackendHandleVal> backend;
};

}
