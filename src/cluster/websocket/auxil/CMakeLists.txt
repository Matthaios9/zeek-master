option(IXWEBSOCKET_INSTALL "Install IXWebSocket" OFF)

set(BUILD_SHARED_LIBS OFF)
set(USE_TLS ON)
set(USE_OPEN_SSL ON)

add_subdirectory(IXWebSocket)



target_compile_options(ixwebsocket PRIVATE "-w")


set_target_properties(ixwebsocket PROPERTIES CXX_INCLUDE_WHAT_YOU_USE "")
set_target_properties(ixwebsocket PROPERTIES CXX_CLANG_TIDY "")
