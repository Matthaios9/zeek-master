list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Hiredis)





option(ENABLE_STORAGE_BACKEND_REDIS "Enable the Redis storage backend" ${HIREDIS_FOUND})

if (ENABLE_STORAGE_BACKEND_REDIS)
    if (NOT HIREDIS_FOUND)
        message(STATUS "ENABLE_STORAGE_BACKEND_REDIS set, but hiredis library not available.")
    endif ()

    zeek_add_plugin(
        Zeek Storage_Backend_Redis
        INCLUDE_DIRS ${HIREDIS_INCLUDE_DIRS}
        DEPENDENCIES ${HIREDIS_LIBRARIES}
        SOURCES Plugin.cc Redis.cc)

endif ()
