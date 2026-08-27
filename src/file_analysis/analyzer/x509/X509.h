

#pragma once

#include <map>
#include <string>

#include "zeek/Func.h"
#include "zeek/OpaqueVal.h"
#include "zeek/file_analysis/analyzer/x509/X509Common.h"

namespace zeek::file_analysis::detail {

class X509Val;

class X509 : public file_analysis::detail::X509Common {
public:
    bool DeliverStream(const u_char* data, uint64_t len) override;
    bool Undelivered(uint64_t offset, uint64_t len) override;
    bool EndOfFile() override;














    static RecordValPtr ParseCertificate(X509Val* cert_val, file_analysis::File* file = nullptr);

    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file) {
        return new X509(std::move(args), file);
    }











    static X509_STORE* GetRootStore(TableVal* root_certs);









    static void FreeRootStore();




    static void SetCertificateCache(TableValPtr cache) { certificate_cache = std::move(cache); }




    static void SetCertificateCacheHitCallback(FuncPtr func) { cache_hit_callback = std::move(func); }

protected:
    X509(RecordValPtr args, file_analysis::File* file);

private:
    void ParseBasicConstraints(openssl_x509_ext_t* ex);
    void ParseSAN(openssl_x509_ext_t* ex);
    void ParseExtensionsSpecific(openssl_x509_ext_t* ex, bool, openssl_asn1_obj_t*, const char*) override;

    std::string cert_data;


    static StringValPtr KeyCurve(EVP_PKEY* key);
    static unsigned int KeyLength(EVP_PKEY* key);

    inline static std::map<Val*, X509_STORE*> x509_stores = std::map<Val*, X509_STORE*>();
    inline static TableValPtr certificate_cache = nullptr;
    inline static FuncPtr cache_hit_callback = nullptr;
};








class X509Val : public OpaqueVal {
public:







    explicit X509Val(::X509* certificate);








    ValPtr DoClone(CloneState* state) override;




    ~X509Val() override;







    ::X509* GetCertificate() const;

protected:



    X509Val();

    DECLARE_OPAQUE_VALUE_DATA(X509Val)
private:
    ::X509* certificate;
};

}
