

#pragma once

#include <sys/time.h>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>

#include "zeek/Reporter.h"
#include "zeek/threading/BasicThread.h"

#undef Queue

namespace zeek::threading {












template<typename T>
class Queue {
public:







    Queue(BasicThread* arg_reader, BasicThread* arg_writer);




    ~Queue();






    T Get();




    void Put(T data);




    bool Ready();










    bool MaybeReady() { return (num_reads != num_writes); }





    void WakeUp();




    uint64_t Size();




    struct Stats {
        uint64_t num_reads;
        uint64_t num_writes;
    };







    void GetStats(Stats* stats);

private:
    static const int NUM_QUEUES = 8;

    std::vector<std::unique_lock<std::mutex>> LocksForAllQueues();

    std::mutex mutex[NUM_QUEUES];
    std::condition_variable has_data[NUM_QUEUES];
    std::queue<T> messages[NUM_QUEUES];

    int read_ptr;
    int write_ptr;

    BasicThread* reader;
    BasicThread* writer;


    uint64_t num_reads;
    uint64_t num_writes;
};

inline static std::unique_lock<std::mutex> acquire_lock(std::mutex& m) {
    try {
        return std::unique_lock<std::mutex>(m);
    } catch ( const std::system_error& e ) {
        reporter->FatalErrorWithCore("cannot lock mutex: %s", e.what());

        throw std::exception();
    }
}

template<typename T>
inline Queue<T>::Queue(BasicThread* arg_reader, BasicThread* arg_writer) {
    read_ptr = 0;
    write_ptr = 0;
    num_reads = num_writes = 0;
    reader = arg_reader;
    writer = arg_writer;
}

template<typename T>
inline Queue<T>::~Queue() = default;

template<typename T>
inline T Queue<T>::Get() {
    auto lock = acquire_lock(mutex[read_ptr]);

    int old_read_ptr = read_ptr;

    if ( messages[read_ptr].empty() && ! ((reader && reader->Killed()) || (writer && writer->Killed())) ) {
        if ( has_data[read_ptr].wait_for(lock, std::chrono::seconds(5)) == std::cv_status::timeout )
            return nullptr;
    }

    if ( messages[read_ptr].empty() )
        return nullptr;

    T data = messages[read_ptr].front();
    messages[read_ptr].pop();

    read_ptr = (read_ptr + 1) % NUM_QUEUES;
    ++num_reads;

    return data;
}

template<typename T>
inline void Queue<T>::Put(T data) {
    auto lock = acquire_lock(mutex[write_ptr]);

    int old_write_ptr = write_ptr;

    bool need_signal = messages[write_ptr].empty();

    messages[write_ptr].push(data);

    write_ptr = (write_ptr + 1) % NUM_QUEUES;
    ++num_writes;

    if ( need_signal ) {
        lock.unlock();
        has_data[old_write_ptr].notify_one();
    }
}

template<typename T>
inline bool Queue<T>::Ready() {
    auto lock = acquire_lock(mutex[read_ptr]);

    return ! messages[read_ptr].empty();
}

template<typename T>
inline std::vector<std::unique_lock<std::mutex>> Queue<T>::LocksForAllQueues() {
    std::vector<std::unique_lock<std::mutex>> locks;

    try {

        for ( int i = 0; i < NUM_QUEUES; i++ )
            locks.emplace_back(std::unique_lock<std::mutex>(mutex[i]));
    }

    catch ( const std::system_error& e ) {
        reporter->FatalErrorWithCore("cannot lock all mutexes: %s", e.what());

        throw std::exception();
    }

    return locks;
}

template<typename T>
inline uint64_t Queue<T>::Size() {

    auto locks = LocksForAllQueues();

    uint64_t size = 0;


    for ( int i = 0; i < NUM_QUEUES; i++ )
        size += messages[i].size();

    return size;
}

template<typename T>
inline void Queue<T>::GetStats(Stats* stats) {


    auto locks = LocksForAllQueues();

    stats->num_reads = num_reads;
    stats->num_writes = num_writes;
}

template<typename T>
inline void Queue<T>::WakeUp() {
    for ( int i = 0; i < NUM_QUEUES; i++ ) {
        auto lock = acquire_lock(mutex[i]);
        has_data[i].notify_all();
    }
}

}
