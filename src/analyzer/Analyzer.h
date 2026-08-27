

#pragma once

#include <sys/types.h>
#include <list>
#include <tuple>
#include <type_traits>
#include <vector>

#include "zeek/EventHandler.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Tag.h"
#include "zeek/Timer.h"

namespace zeek {

class Connection;
class IP_Hdr;
class File;
using FilePtr = zeek::IntrusivePtr<File>;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;

namespace detail {
class Rule;
}
namespace packet_analysis::IP {
class IPBasedAnalyzer;
}

}

namespace zeek::analyzer {

namespace tcp {
class TCP_ApplicationAnalyzer;
}
namespace pia {
class PIA;
}

class Analyzer;
class AnalyzerTimer;
class SupportAnalyzer;
class OutputHandler;






using analyzer_list = std::list<Analyzer*>;
using ID = uint32_t;
using analyzer_timer_func = void (Analyzer::*)(double t);




class OutputHandler {
public:



    virtual ~OutputHandler() = default;





    virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) {}





    virtual void DeliverStream(int len, const u_char* data, bool orig) {}





    virtual void Undelivered(uint64_t seq, int len, bool orig) {}
};












class Analyzer {
public:








    Analyzer(const char* name, Connection* conn);









    Analyzer(const zeek::Tag& tag, Connection* conn);








    explicit Analyzer(Connection* conn);




    virtual ~Analyzer();




    virtual void Init();




    virtual void Done();
























    void NextPacket(int len, const u_char* data, bool is_orig, uint64_t seq = -1, const IP_Hdr* ip = nullptr,
                    int caplen = 0);
















    void NextStream(int len, const u_char* data, bool is_orig);












    void NextUndelivered(uint64_t seq, int len, bool is_orig);











    void NextEndOfData(bool is_orig);








    virtual void ForwardPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen);








    virtual void ForwardStream(int len, const u_char* data, bool orig);






    virtual void ForwardUndelivered(uint64_t seq, int len, bool orig);






    virtual void ForwardEndOfData(bool orig);






    virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen);






    virtual void DeliverStream(int len, const u_char* data, bool orig);






    virtual void Undelivered(uint64_t seq, int len, bool orig);






    virtual void EndOfData(bool is_orig);









    virtual void FlipRoles();






    ID GetID() const { return id; }




    Connection* Conn() const { return conn; }





    OutputHandler* GetOutputHandler() const { return output_handler; }






    void SetOutputHandler(OutputHandler* handler) { output_handler = handler; }





    const zeek::detail::Rule* Signature() const { return signature; }






    void SetSignature(const zeek::detail::Rule* sig) { signature = sig; }







    void SetSkip(bool do_skip) { skip = do_skip; }





    bool Skipping() const { return skip; }




    bool IsFinished() const { return finished; }





    bool Removing() const { return removing; }




    zeek::Tag GetAnalyzerTag() const {
        assert(tag);
        return tag;
    }







    void SetAnalyzerTag(const zeek::Tag& tag);






    const char* GetAnalyzerName() const;








    bool IsAnalyzer(const char* name);









    bool AddChildAnalyzer(Analyzer* analyzer) { return AddChildAnalyzer(analyzer, true); }









    Analyzer* AddChildAnalyzer(const zeek::Tag& tag);










    bool RemoveChildAnalyzer(Analyzer* analyzer) { return RemoveChildAnalyzer(analyzer->GetID()); }










    virtual bool RemoveChildAnalyzer(ID id);






    void PreventChildren(const zeek::Tag& tag);









    bool IsPreventedChildAnalyzer(const zeek::Tag& tag) const;






    bool HasChildAnalyzer(const zeek::Tag& tag) const;











    Analyzer* GetChildAnalyzer(const zeek::Tag& tag) const;












    Analyzer* GetChildAnalyzer(const std::string& name) const;










    virtual Analyzer* FindChild(ID id);










    virtual Analyzer* FindChild(zeek::Tag tag);











    Analyzer* FindChild(const char* name);








    const analyzer_list& GetChildren() { return children; }






    void CleanupChildren();





    Analyzer* Parent() const { return parent; }






    void SetParent(Analyzer* p) { parent = p; }







    bool Remove();






    void AddSupportAnalyzer(SupportAnalyzer* analyzer);







    void RemoveSupportAnalyzer(SupportAnalyzer* analyzer);












    virtual void AnalyzerConfirmation(zeek::Tag tag = zeek::Tag());



















    virtual void AnalyzerViolation(const char* reason, const char* data = nullptr, int len = 0,
                                   zeek::Tag tag = zeek::Tag());





    bool AnalyzerConfirmed() const { return analyzer_confirmed; }












    virtual void UpdateConnVal(RecordVal* conn_val);





    const RecordValPtr& ConnVal();





    void Event(EventHandlerPtr f, const char* name = nullptr);





    void EnqueueConnEvent(EventHandlerPtr f, Args args);




    template<class... Args>
        requires std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>
    void EnqueueConnEvent(EventHandlerPtr h, Args&&... args) {
        return EnqueueConnEvent(h, zeek::Args{std::forward<Args>(args)...});
    }





    void Weird(const char* name, const char* addl = "");













    void LimitReachedWeird(const char* name, size_t limit, size_t limit_max = 0);

protected:
    friend class AnalyzerTimer;
    friend class Manager;
    friend class zeek::Connection;
    friend class zeek::analyzer::tcp::TCP_ApplicationAnalyzer;
    friend class zeek::packet_analysis::IP::IPBasedAnalyzer;





    static std::string fmt_analyzer(const Analyzer* a) {
        return std::string(a->GetAnalyzerName()) + util::fmt("[%d]", a->GetID());
    }







    void SetConnection(Connection* c) { conn = c; }














    void AddTimer(analyzer_timer_func timer, double t, bool do_expire, detail::TimerType type);




    void CancelTimers();





    void RemoveTimer(detail::Timer* t);








    bool HasSupportAnalyzer(const zeek::Tag& tag, bool orig);







    SupportAnalyzer* FirstSupportAnalyzer(bool orig);










    bool AddChildAnalyzer(Analyzer* analyzer, bool init);




    void InitChildren();




    void AppendNewChildren();





    bool RemoveChild(const analyzer_list& children, ID id);

private:



    analyzer_list::iterator DeleteChild(analyzer_list::iterator i);


    void CtorInit(const zeek::Tag& tag, Connection* conn);


    void EnqueueAnalyzerConfirmationInfo(const zeek::Tag& arg_tag);


    void EnqueueAnalyzerViolationInfo(const char* reason, const char* data, int len, const zeek::Tag& arg_tag);

    zeek::Tag tag;
    ID id;

    bool skip;
    bool finished;
    bool removing;
    bool timers_canceled;
    TimerPList timers;

    Connection* conn;
    Analyzer* parent;
    const zeek::detail::Rule* signature;
    OutputHandler* output_handler;

    analyzer_list children;
    SupportAnalyzer* orig_supporters;
    SupportAnalyzer* resp_supporters;

    analyzer_list new_children;
    std::vector<zeek::Tag> prevented;

    bool protocol_confirmed;
    bool analyzer_confirmed;

    uint64_t analyzer_violations = 0;

    static ID id_counter;
};






#define ADD_ANALYZER_TIMER(timer, t, do_expire, type)                                                                  \
    AddTimer(zeek::analyzer::analyzer_timer_func(timer), (t), (do_expire), (type))




#define LOOP_OVER_CHILDREN(var) for ( auto(var) = children.begin(); (var) != children.end(); ++(var) )





#define LOOP_OVER_CONST_CHILDREN(var) for ( auto(var) = children.cbegin(); (var) != children.cend(); ++(var) )




#define LOOP_OVER_GIVEN_CHILDREN(var, the_kids)                                                                        \
    for ( auto(var) = (the_kids).begin(); (var) != (the_kids).end(); ++(var) )





#define LOOP_OVER_GIVEN_CONST_CHILDREN(var, the_kids)                                                                  \
    for ( auto(var) = (the_kids).cbegin(); (var) != (the_kids).cend(); ++(var) )









class SupportAnalyzer : public Analyzer {
public:











    SupportAnalyzer(const char* name, Connection* conn, bool arg_orig) : Analyzer(name, conn) {
        orig = arg_orig;
        sibling = nullptr;
    }





    bool IsOrig() const { return orig; }







    SupportAnalyzer* Sibling(bool only_active = false) const;









    void ForwardPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;









    void ForwardStream(int len, const u_char* data, bool orig) override;









    void ForwardUndelivered(uint64_t seq, int len, bool orig) override;





    void FlipRoles() override { orig = ! orig; }

protected:
    friend class Analyzer;

private:
    bool orig;



    SupportAnalyzer* sibling;
};


constexpr int CONTENTS_NONE = 0;
constexpr int CONTENTS_ORIG = 1;
constexpr int CONTENTS_RESP = 2;
constexpr int CONTENTS_BOTH = 3;

}
