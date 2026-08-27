

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <list>
#include <mutex>
#include <thread>

#include "zeek/Flare.h"
#include "zeek/Reporter.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/Manager.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/util-types.h"

namespace zeek::detail {




enum class QueueFlag : uint8_t {
    Block = 0x0,
    DontBlock = 0x1,
    Force = 0x2,
};

constexpr QueueFlag operator&(QueueFlag x, QueueFlag y) {
    return static_cast<QueueFlag>(static_cast<uint8_t>(x) & static_cast<uint8_t>(y));
};

















template<class Proc, class Work>
class OnLoopProcess : public zeek::iosource::IOSource {
public:









    OnLoopProcess(Proc* proc, std::string_view tag, size_t max_queue_size = 250,
                  std::chrono::microseconds cond_timeout = std::chrono::microseconds(100000),
                  std::thread::id main_thread_id = std::this_thread::get_id())
        : cond_timeout(cond_timeout),
          max_queue_size(max_queue_size),
          proc(proc),
          tag(tag),
          main_thread_id(main_thread_id),
          total_queue_blocks_metric(
              zeek::telemetry_mgr
                  ->CounterFamily(
                      "zeek", "cluster_onloop_queue_blocks", {"tag"},
                      "Increased whenever a cluster backend thread is blocked due to the OnLoop queue being full.")
                  ->GetOrAdd({{"tag", this->tag}})) {}









    void Register(bool dont_count = true) {
        zeek::iosource_mgr->Register(this, dont_count, true);

        if ( ! zeek::iosource_mgr->RegisterFd(flare.FD(), this) )
            zeek::reporter->InternalError("Failed to register IO source FD %d for OnLoopProcess %s", flare.FD(),
                                          tag.c_str());
    }




    void Close() {
        if ( std::this_thread::get_id() != main_thread_id ) {
            fprintf(stderr, "OnLoopProcess::Close() not called by main thread!");
            abort();
        }

        zeek::iosource_mgr->UnregisterFd(flare.FD(), this);


        proc = nullptr;

        {


            std::scoped_lock lock(mtx);
            SetClosed(true);


            cond.notify_all();
        }


        while ( queuers > 0 )
            std::this_thread::sleep_for(std::chrono::microseconds(10));
    }






    void Process() override {
        std::list<Work> to_process;
        bool notify = false;
        {
            std::scoped_lock lock(mtx);
            if ( max_queue_size > 0 && queue.size() >= max_queue_size )
                notify = true;

            to_process.splice(to_process.end(), queue);
            flare.Extinguish();
        }



        if ( notify )
            cond.notify_one();




        if ( ! IsOpen() )
            return;

        for ( auto& work : to_process )
            proc->Process(std::move(work));
    }




    const char* Tag() override { return tag.c_str(); }




    double GetNextTimeout() override { return -1; };





















    bool QueueForProcessing(Work&& work, QueueFlag flags = QueueFlag::Block) {
        if ( std::this_thread::get_id() == main_thread_id ) {
            fprintf(stderr, "OnLoopProcess::QueueForProcessing() called by main thread!");
            abort();
        }

        ++queuers;
        auto defer = util::Deferred([this] { --queuers; });
        bool fire = false;

        {
            std::unique_lock lock(mtx);


            while ( IsOpen() && max_queue_size > 0 && queue.size() >= max_queue_size ) {
                if ( (flags & QueueFlag::Force) == QueueFlag::Force )
                    break;

                if ( (flags & QueueFlag::DontBlock) == QueueFlag::DontBlock )
                    return false;

                total_queue_blocks_metric->Inc();
                cond.wait_for(lock, cond_timeout);
            }

            if ( IsOpen() ) {
                std::list<Work> to_queue{std::move(work)};
                queue.splice(queue.end(), to_queue);
                assert(to_queue.empty());
                fire = queue.size() == 1;
            }
            else {

                fire = false;
            }
        }

        if ( fire )
            flare.Fire();

        return true;
    }

private:

    zeek::detail::Flare flare;


    std::mutex mtx;
    std::condition_variable cond;
    std::chrono::microseconds cond_timeout;

    std::list<Work> queue;
    size_t max_queue_size;

    Proc* proc;
    std::string tag;
    std::atomic<int> queuers = 0;
    std::thread::id main_thread_id;


    telemetry::CounterPtr total_queue_blocks_metric;
};


}
