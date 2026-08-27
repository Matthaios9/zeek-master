

#pragma once

#include <deque>
#include <mutex>

#include "zeek/iosource/IOSource.h"
#include "zeek/storage/Backend.h"


struct redisAsyncContext;
struct redisReply;
struct redisPollEvents;

namespace zeek::storage::backend::redis {
class Redis final : public Backend, public iosource::IOSource {
public:
    Redis() : Backend(SupportedModes::ASYNC, "REDIS"), IOSource(true) {}

    static BackendPtr Instantiate();







    const char* Tag() override { return Backend::Tag(); }


    double GetNextTimeout() override { return -1; }
    void Process() override {}
    void ProcessFd(int fd, int flags) override;


    void OnConnect(int status);
    void OnDisconnect(int status);

    void HandlePutResult(redisReply* reply, ResultCallback* callback);
    void HandleGetResult(redisReply* reply, ResultCallback* callback);
    void HandleEraseResult(redisReply* reply, ResultCallback* callback);
    void HandleGeneric(redisReply* reply);
    void HandleInfoResult(redisReply* reply);
    void HandleAuthResult(redisReply* reply);




    bool IsOpen() override { return connected; }

    bool ExpireRunning() const { return expire_running.load(); }

private:
    OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) override;
    OperationResult DoClose(ResultCallback* cb) override;
    OperationResult DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                          double expiration_time) override;
    OperationResult DoGet(ResultCallback* cb, ValPtr key) override;
    OperationResult DoErase(ResultCallback* cb, ValPtr key) override;
    void DoExpire(double current_network_time) override;
    void DoPoll() override;
    std::string DoGetConfigMetricsLabel() const override;

    OperationResult ParseReplyError(std::string_view op_str, std::string_view reply_err_str) const;
    OperationResult CheckServerVersion();

    void SendInfoRequest();

    redisAsyncContext* async_ctx = nullptr;




    std::deque<redisReply*> reply_queue;

    OpenResultCallback* open_cb = nullptr;
    ResultCallback* close_cb = nullptr;
    std::mutex expire_mutex;

    std::string server_addr;
    std::string key_prefix;
    std::string disconnect_reason;
    std::string username;
    std::string password;

    std::atomic<bool> connected = false;
    std::atomic<bool> expire_running = false;
    std::atomic<int> active_ops = 0;
};

}
