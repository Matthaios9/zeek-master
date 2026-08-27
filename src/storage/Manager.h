

#pragma once

#include "zeek/zeek-config.h"

#include <mutex>





#if defined(__APPLE__) || ! defined(__cpp_lib_jthread)
#include "zeek/3rdparty/jthread.hpp"
namespace zeek {
using jthread = nonstd::jthread;
}
#else
#include <thread>
namespace zeek {
using jthread = std::jthread;
}
#endif

#include "zeek/Timer.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/storage/Backend.h"
#include "zeek/storage/Component.h"
#include "zeek/storage/Serializer.h"

namespace zeek::storage {

namespace detail {

class ExpirationTimer final : public zeek::detail::Timer {
public:
    ExpirationTimer(double t) : zeek::detail::Timer(t, zeek::detail::TIMER_STORAGE_EXPIRE) {}
    void Dispatch(double t, bool is_expire) override;
};

}

class Manager final {
public:
    Manager();
    ~Manager();





    void InitPostScript();









    zeek::expected<BackendPtr, std::string> InstantiateBackend(const Tag& type);








    zeek::expected<std::unique_ptr<Serializer>, std::string> InstantiateSerializer(const Tag& type);















    OperationResult OpenBackend(BackendPtr backend, OpenResultCallback* cb, RecordValPtr options, TypePtr key_type,
                                TypePtr val_type);










    OperationResult CloseBackend(BackendPtr backend, ResultCallback* cb);








    void Expire(double t);

    plugin::ComponentManager<BackendComponent>& BackendMgr() { return backend_mgr; }
    plugin::ComponentManager<SerializerComponent>& SerializerMgr() { return serializer_mgr; }

protected:
    friend class storage::detail::ExpirationTimer;
    void RunExpireThread();
    void StartExpirationTimer();
    size_t BackendCount();
    zeek::jthread expiration_thread;

    friend class storage::OpenResultCallback;
    void RegisterBackend(BackendPtr backend);

private:
    std::vector<BackendPtr> backends;
    std::mutex backends_mtx;

    plugin::ComponentManager<BackendComponent> backend_mgr;
    plugin::ComponentManager<SerializerComponent> serializer_mgr;
};

}

namespace zeek {

ZEEK_EXTERN_DATA storage::Manager* storage_mgr;

}
