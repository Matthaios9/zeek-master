

#pragma once

#include <sys/stat.h>

#include "zeek/Val.h"

namespace zeek {

#ifdef USE_GEOIP

#include <maxminddb.h>











class MMDB {
public:
    MMDB();
    virtual ~MMDB();




    virtual bool OpenFromScriptConfig() = 0;


    virtual std::string_view Description() = 0;



    bool OpenFile(const std::string& filename);



    void Close();


    bool IsOpen() const { return mmdb.filename != nullptr; }









    bool EnsureLoaded();



    bool Lookup(const zeek::IPAddr& addr, MMDB_lookup_result_s& result);

private:
    bool IsStaleDB();

    std::string filename;
    MMDB_s mmdb;
    struct stat file_info;
    bool reported_error = false;
    double last_check;
};

class LocDB : public MMDB {
public:
    bool OpenFromScriptConfig() override;
    std::string_view Description() override { return "GeoIP location database"; }
};

class AsnDB : public MMDB {
public:
    bool OpenFromScriptConfig() override;
    std::string_view Description() override { return "GeoIP ASN database"; }
};

#endif

ValPtr mmdb_open_location_db(const StringValPtr& filename);
ValPtr mmdb_open_asn_db(const StringValPtr& filename);

RecordValPtr mmdb_lookup_location(const AddrValPtr& addr);
RecordValPtr mmdb_lookup_autonomous_system(const AddrValPtr& addr);

}
