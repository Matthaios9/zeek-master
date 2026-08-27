

#pragma once

#include <string>
#include <thread>
#include <zmq.hpp>

#include "zeek/cluster/backend/zeromq/ZeroMQ-ZAP.h"
#include "zeek/cluster/backend/zeromq/ZeroMQ.h"




namespace zeek::cluster::zeromq {
class ProxyThread {
public:











    ProxyThread(std::string xpub_endpoint, std::string xsub_endpoint, zmq::socket_t&& control, int ipv6,
                int xpub_nodrop, int io_threads, CurveConfig curve_config)
        : xpub_endpoint(std::move(xpub_endpoint)),
          xsub_endpoint(std::move(xsub_endpoint)),
          control(std::move(control)),
          ipv6(ipv6),
          xpub_nodrop(xpub_nodrop),
          io_threads(io_threads),
          curve_config(std::move(curve_config)) {}


    ~ProxyThread() { Shutdown(); }




    struct Args {
        zmq::socket_t xpub;
        zmq::socket_t xsub;
        zmq::socket_t control;
    };




    bool Start();




    void Shutdown();

private:
    zmq::context_t ctx;
    std::thread thread;
    Args args;
    std::thread zap_thread;
    ZapArgs zap_args;
    std::string xpub_endpoint;
    std::string xsub_endpoint;
    zmq::socket_t control;
    int ipv6 = 1;
    int xpub_nodrop = 1;
    int io_threads = 2;
    CurveConfig curve_config;
};
}
