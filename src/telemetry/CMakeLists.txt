zeek_add_subdir_library(
    telemetry
    SOURCES
    Counter.cc
    Gauge.cc
    Histogram.cc
    Manager.cc
    Opaques.cc
    ProcessStats.cc
    Utils.cc)






target_include_directories(
    zeek_telemetry_obj BEFORE
    PUBLIC ${PROJECT_SOURCE_DIR}/auxil/prometheus-cpp/3rdparty/civetweb/include)
