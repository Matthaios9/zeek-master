

#include "zeek/cluster/backend/zeromq/ZeroMQ-Proxy.h"

#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "zeek/Reporter.h"
#include "zeek/cluster/backend/zeromq/ZeroMQ-ZAP.h"
#include "zeek/util.h"


using namespace zeek::cluster::zeromq;

namespace {






void thread_fun(ProxyThread::Args* args) {
    zeek::util::detail::set_thread_name("zmq-proxy-thread");

    bool done = false;

    while ( ! done ) {
        try {
            zmq::proxy_steerable(args->xsub, args->xpub, zmq::socket_ref{}, args->control);
        } catch ( zmq::error_t& err ) {
            if ( err.num() == EINTR )
                continue;

            done = true;
            args->xsub.close();
            args->xpub.close();
            args->control.close();

            if ( err.num() != ETERM ) {
                std::fprintf(stderr, "[zeromq] unexpected zmq_proxy() error: %s (%d)", err.what(), err.num());
                throw;
            }
        }
    }
}

}

bool ProxyThread::Start() {
    ctx.set(zmq::ctxopt::io_threads, io_threads);


    ctx.set(zmq::ctxopt::ipv6, ipv6);

    zmq::socket_t xpub(ctx, zmq::socket_type::xpub);
    zmq::socket_t xsub(ctx, zmq::socket_type::xsub);






    xpub.set(zmq::sockopt::xpub_verboser, 1);

    xpub.set(zmq::sockopt::xpub_nodrop, xpub_nodrop);








    if ( curve_config.IsServerEnabled() ) {
        curve_config.ConfigureServerCurveSockOpts(xpub);
        curve_config.ConfigureServerCurveSockOpts(xsub);

        curve_config.InitZap(ctx, zap_args);
        zap_thread = std::thread(zeek::cluster::zeromq::zap_thread_fun, &zap_args);
    }

    try {
        xpub.bind(xpub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to bind xpub socket %s: %s (%d)", xpub_endpoint.c_str(), err.what(),
                              err.num());
        return false;
    }

    try {
        xsub.bind(xsub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to bind xsub socket %s: %s (%d)", xsub_endpoint.c_str(), err.what(),
                              err.num());
        return false;
    }

    args = {.xpub = std::move(xpub), .xsub = std::move(xsub), .control = std::move(control)};

    thread = std::thread(thread_fun, &args);

    return true;
}

void ProxyThread::Shutdown() {
    ctx.shutdown();

    if ( thread.joinable() )
        thread.join();

    if ( zap_thread.joinable() )
        zap_thread.join();

    ctx.close();
}
