spicy_add_analyzer(
    NAME QUIC
    PACKAGE_NAME QUIC
    SOURCES QUIC.spicy QUIC.evt decrypt_crypto.cc)


if (TARGET spicy_QUIC)


    target_include_directories(spicy_QUIC PRIVATE "${OPENSSL_INCLUDE_DIR}")
endif ()
