
#pragma once

#include <set>

#include "zeek/Tag.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/session/Session.h"

namespace zeek::packet_analysis {
class Analyzer;
using AnalyzerPtr = std::shared_ptr<Analyzer>;




class Analyzer {
public:
    static inline AnalyzerPtr nil = nullptr;










    explicit Analyzer(const std::string& name, bool report_unknown_protocols = true);







    explicit Analyzer(const zeek::Tag& tag);




    virtual ~Analyzer() = default;








    virtual void Initialize();




    zeek::Tag GetAnalyzerTag() const;






    const char* GetAnalyzerName() const;








    bool IsAnalyzer(const char* name);






    bool IsEnabled() const { return enabled; }















    virtual bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) = 0;




    void DumpDebug() const;








    void RegisterProtocol(uint64_t identifier, AnalyzerPtr child);








    void RegisterProtocolDetection(AnalyzerPtr child) { analyzers_to_detect.insert(child); }
















    virtual bool DetectProtocol(size_t len, const uint8_t* data, Packet* packet) { return false; }












    virtual void AnalyzerConfirmation(session::Session* session, zeek::Tag tag = zeek::Tag());
















    virtual void AnalyzerViolation(const char* reason, session::Session* session, const char* data = nullptr,
                                   int len = 0, zeek::Tag tag = zeek::Tag());





    bool AnalyzerConfirmed(session::Session* session) const {
        return session->AnalyzerState(GetAnalyzerTag()) == session::AnalyzerConfirmationState::CONFIRMED;
    }
    bool AnalyzerViolated(session::Session* session) const {
        return session->AnalyzerState(GetAnalyzerTag()) == session::AnalyzerConfirmationState::VIOLATED;
    }











    void Weird(const char* name, Packet* packet = nullptr, const char* addl = "") const;

protected:
    friend class Component;
    friend class Manager;









    const AnalyzerPtr& Lookup(uint64_t identifier) const;







    AnalyzerPtr LoadAnalyzer(const std::string& name);







    void SetEnabled(bool value) { enabled = value; }






    std::string GetModuleName() const { return util::fmt("PacketAnalyzer::%s::", GetAnalyzerName()); };












    bool ForwardPacket(size_t len, const uint8_t* data, Packet* packet, uint64_t identifier) const;











    bool ForwardPacket(size_t len, const uint8_t* data, Packet* packet) const;




    bool report_unknown_protocols = true;

private:

    void EnqueueAnalyzerConfirmationInfo(session::Session* session, const zeek::Tag& arg_tag);


    void EnqueueAnalyzerViolationInfo(session::Session* session, const char* reason, const char* data, int len,
                                      const zeek::Tag& arg_tag);


    const AnalyzerPtr& FindInnerAnalyzer(size_t len, const uint8_t* data, Packet* packet, uint64_t identifier) const;
    const AnalyzerPtr& FindInnerAnalyzer(size_t len, const uint8_t* data, Packet* packet) const;
    const AnalyzerPtr& DetectInnerAnalyzer(size_t len, const uint8_t* data, Packet* packet) const;

    zeek::Tag tag;
    detail::Dispatcher dispatcher;
    AnalyzerPtr default_analyzer = nullptr;
    bool enabled = true;

    std::set<AnalyzerPtr> analyzers_to_detect;

    void Init(const zeek::Tag& tag);
};
}
