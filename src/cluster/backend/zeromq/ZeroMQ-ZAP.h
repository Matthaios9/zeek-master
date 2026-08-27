

#pragma once

#include <set>
#include <string>
#include <zmq.hpp>
#include <zmq_addon.hpp>

namespace zeek::cluster::zeromq {

























struct ZapArgs {

    zmq::socket_t zap_rep;




    std::set<std::string> allowed_publickeys;
};




void zap_thread_fun(ZapArgs* zap_args);

}
