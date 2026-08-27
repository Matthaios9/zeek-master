

if (MSVC AND NOT ZeroMQ_LIBRARIES)
    set(ZeroMQ_LIBRARIES libzmq-static)
endif ()

zeek_add_plugin(
    Zeek Cluster_Backend_ZeroMQ
    INCLUDE_DIRS ${ZeroMQ_INCLUDE_DIRS}
    DEPENDENCIES ${ZeroMQ_LIBRARIES}
    SOURCES Plugin.cc ZeroMQ-Proxy.cc ZeroMQ-ZAP.cc ZeroMQ.cc
    BIFS cluster_backend_zeromq.bif)
