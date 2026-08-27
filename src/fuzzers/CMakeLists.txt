


if (NOT ZEEK_ENABLE_FUZZERS)
    return()
endif ()

if (NOT DEFINED ZEEK_FUZZING_ENGINE AND DEFINED ENV{LIB_FUZZING_ENGINE})
    if ("$ENV{LIB_FUZZING_ENGINE}" STREQUAL "")

        set(ZEEK_FUZZING_ENGINE "-fsanitize=fuzzer" CACHE INTERNAL "" FORCE)
    else ()
        string(SUBSTRING "$ENV{LIB_FUZZING_ENGINE}" 0 1 _first_char)

        if ("${_first_char}" STREQUAL "-" OR EXISTS "$ENV{LIB_FUZZING_ENGINE}")

            set(ZEEK_FUZZING_ENGINE "$ENV{LIB_FUZZING_ENGINE}" CACHE INTERNAL "" FORCE)
        else ()
            message(WARNING "$ENV{LIB_FUZZING_ENGINE} does not exist, assume libFuzzer")
            set(ZEEK_FUZZING_ENGINE "-fsanitize=fuzzer" CACHE INTERNAL "" FORCE)
        endif ()
    endif ()
endif ()






string(REGEX MATCH ".*\\.a$" _have_static_bind_lib "${BIND_LIBRARY}")

macro (SETUP_FUZZ_TARGET _fuzz_target _fuzz_source)
    add_executable(${_fuzz_target} ${_fuzz_source} ${ARGN})
    target_compile_features(${_fuzz_target} PRIVATE "${ZEEK_CXX_STD}")
    set_target_properties(${_fuzz_target} PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(${_fuzz_target} zeek_fuzzer_shared)

    if (_have_static_bind_lib)
        target_link_libraries(${_fuzz_target} ${BIND_LIBRARY})
    endif ()

    target_link_libraries(${_fuzz_target} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

    if (DEFINED ZEEK_FUZZING_ENGINE)
        target_link_libraries(${_fuzz_target} ${ZEEK_FUZZING_ENGINE})
    else ()
        target_link_libraries(${_fuzz_target} $<TARGET_OBJECTS:zeek_fuzzer_standalone>)
    endif ()
endmacro ()

macro (ADD_FUZZ_TARGET _name)
    set(_fuzz_target zeek-${_name}-fuzzer)
    set(_fuzz_source ${_name}-fuzzer.cc)
    setup_fuzz_target(${_fuzz_target} ${_fuzz_source})
endmacro ()

macro (ADD_GENERIC_ANALYZER_FUZZ_TARGET _name)
    set(_transport "tcp")
    set(extra_args "${ARGN}")
    list(LENGTH extra_args extra_args_n)
    if (${extra_args_n} GREATER 0)
        list(GET extra_args 0 _transport)
    endif ()

    set(_fuzz_target zeek-${_name}-fuzzer)
    set(_fuzz_source generic-analyzer-fuzzer.cc)
    setup_fuzz_target(${_fuzz_target} ${_fuzz_source})
    target_compile_definitions(${_fuzz_target} PUBLIC ZEEK_FUZZ_ANALYZER=${_name})
    target_compile_definitions(${_fuzz_target} PUBLIC ZEEK_FUZZ_ANALYZER_TRANSPORT=${_transport})
endmacro ()

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR})

add_library(zeek_fuzzer_standalone OBJECT standalone-driver.cc)
target_compile_features(zeek_fuzzer_standalone PRIVATE "${ZEEK_CXX_STD}")
set_target_properties(zeek_fuzzer_standalone PROPERTIES CXX_EXTENSIONS OFF)

target_sources(zeek_fuzzer_shared PRIVATE FuzzBuffer.cc)

set(zeek_fuzzer_shared_deps)

foreach (_dep ${zeekdeps})
    if ("${_dep}" STREQUAL "${BIND_LIBRARY}")
        if (NOT _have_static_bind_lib)
            set(zeek_fuzzer_shared_deps ${zeek_fuzzer_shared_deps} ${_dep})
        endif ()
    else ()
        set(zeek_fuzzer_shared_deps ${zeek_fuzzer_shared_deps} ${_dep})
    endif ()
endforeach ()

target_link_libraries(zeek_fuzzer_shared PUBLIC ${zeek_fuzzer_shared_deps}
                                                ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

add_fuzz_target(packet)
add_fuzz_target(dns)
add_fuzz_target(websocket)

add_generic_analyzer_fuzz_target(ftp)
add_generic_analyzer_fuzz_target(http)
add_generic_analyzer_fuzz_target(imap)
add_generic_analyzer_fuzz_target(pop3)
add_generic_analyzer_fuzz_target(smtp)

add_generic_analyzer_fuzz_target(dce_rpc)
add_generic_analyzer_fuzz_target(dhcp udp)
add_generic_analyzer_fuzz_target(dnp3_tcp)
add_generic_analyzer_fuzz_target(dtls udp)
add_generic_analyzer_fuzz_target(irc)
add_generic_analyzer_fuzz_target(ldap_udp udp)
add_generic_analyzer_fuzz_target(ldap_tcp tcp)
add_generic_analyzer_fuzz_target(modbus)
add_generic_analyzer_fuzz_target(mqtt)
add_generic_analyzer_fuzz_target(mysql)
add_generic_analyzer_fuzz_target(ncp)
add_generic_analyzer_fuzz_target(ntp udp)
add_generic_analyzer_fuzz_target(radius udp)
add_generic_analyzer_fuzz_target(rdp)
add_generic_analyzer_fuzz_target(rdpeudp udp)
add_generic_analyzer_fuzz_target(rfb)

add_generic_analyzer_fuzz_target(mount)
add_generic_analyzer_fuzz_target(nfs)
add_generic_analyzer_fuzz_target(portmapper)
add_generic_analyzer_fuzz_target(sip udp)
add_generic_analyzer_fuzz_target(smb)
add_generic_analyzer_fuzz_target(snmp udp)
add_generic_analyzer_fuzz_target(ssh)
add_generic_analyzer_fuzz_target(ssl)
add_generic_analyzer_fuzz_target(syslog udp)
