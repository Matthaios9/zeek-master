




#pragma once

#include "zeek/zeek-config.h"

#include <openssl/asn1.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>

#include "zeek/file_analysis/Analyzer.h"

namespace zeek {

class EventHandlerPtr;
class Reporter;
class StringVal;
template<class T>
class IntrusivePtr;
using StringValPtr = IntrusivePtr<StringVal>;

namespace file_analysis {

class File;

namespace detail {

static_assert(ZEEK_OPENSSL_VERSION_MAJOR == OPENSSL_VERSION_MAJOR,
              "OpenSSL major version mismatch: Zeek was configured with a different "
              "OpenSSL major version than the headers being compiled against.");






#if ZEEK_OPENSSL_VERSION_MAJOR >= 4
using openssl_x509_ext_t = const X509_EXTENSION;
using openssl_asn1_obj_t = const ASN1_OBJECT;
#else
using openssl_x509_ext_t = X509_EXTENSION;
using openssl_asn1_obj_t = ASN1_OBJECT;
#endif

class X509Common : public file_analysis::Analyzer {
public:











    static StringValPtr GetExtensionFromBIO(BIO* bio, file_analysis::File* f = nullptr);

    static double GetTimeFromAsn1(const ASN1_TIME* atime, file_analysis::File* f, Reporter* reporter);

protected:
    X509Common(const zeek::Tag& arg_tag, RecordValPtr arg_args, file_analysis::File* arg_file);

    void ParseExtension(openssl_x509_ext_t* ex, const EventHandlerPtr& h, bool global);
    void ParseSignedCertificateTimestamps(openssl_x509_ext_t* ext);
    virtual void ParseExtensionsSpecific(openssl_x509_ext_t* ex, bool, openssl_asn1_obj_t*, const char*) = 0;
};

}
}
}
