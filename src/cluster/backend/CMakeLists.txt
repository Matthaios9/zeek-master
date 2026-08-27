

option(ENABLE_CLUSTER_BACKEND_ZEROMQ "Enable the ZeroMQ cluster backend" ON)

if (ENABLE_CLUSTER_BACKEND_ZEROMQ)

    if (MSVC)
        find_package(ZeroMQ CONFIG REQUIRED)
    else ()
        list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/zeromq/cmake")



        find_package(ZeroMQ 4.3.0 REQUIRED)
    endif ()

    add_subdirectory(zeromq)
endif ()

add_subdirectory(none)
