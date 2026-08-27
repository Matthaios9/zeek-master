

#include "zeek-version.h"

#include "zeek/zeek-version.h"

using namespace zeek::spicy;

int configuration::ZeekVersionNumber() { return ZEEK_VERSION_NUMBER; }

const char* configuration::ZeekVersionString() { return VERSION; }
