

#pragma once

#include <sys/types.h>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "zeek/CCL.h"
#include "zeek/RE.h"
#include "zeek/Rule.h"
#include "zeek/ScannedFile.h"
#include "zeek/ZeekString.h"





extern void rules_error(const char* msg);
extern void rules_error(const char* msg, const char* addl);
extern void rules_error(zeek::detail::Rule* id, const char* msg);
extern int rules_lex();
extern int rules_parse();
extern "C" int rules_wrap();
extern int rules_line_number;
extern const char* current_rule_file;

namespace zeek {

class File;
class IP_Hdr;
class IPPrefix;
class Val;

namespace analyzer {
class Analyzer;
}
namespace analyzer::pia {
class PIA;
}

namespace detail {

class RE_Match_State;
class Specific_RE_Matcher;
class RuleMatcher;
class IntSet;

extern RuleMatcher* rule_matcher;





struct Range {
    uint32_t offset;
    uint32_t len;
};

struct MaskedValue {
    uint32_t val;
    uint32_t mask;
};

using maskedvalue_list = PList<MaskedValue>;
using string_list = PList<char>;
using bstr_list = PList<String>;


extern void id_to_maskedvallist(const char* id, maskedvalue_list* append_to,
                                std::vector<IPPrefix>* prefix_vector = nullptr);
extern char* id_to_str(const char* id);
extern uint32_t id_to_uint(const char* id);

class RuleHdrTest {
public:

    enum Comp : uint8_t { LE, GE, LT, GT, EQ, NE };
    enum Prot : uint8_t { NOPROT, IP, IPv6, ICMP, ICMPv6, TCP, UDP, NEXT, IPSrc, IPDst };

    RuleHdrTest(Prot arg_prot, uint32_t arg_offset, uint32_t arg_size, Comp arg_comp, maskedvalue_list* arg_vals);
    RuleHdrTest(Prot arg_prot, Comp arg_comp, std::vector<IPPrefix> arg_v);
    ~RuleHdrTest();

    void PrintDebug() const;

private:


    RuleHdrTest(RuleHdrTest& h);



    bool operator==(const RuleHdrTest& h) const;

    Prot prot;
    Comp comp;
    maskedvalue_list* vals;
    std::vector<IPPrefix> prefix_vals;
    uint32_t offset;
    uint32_t size;

    uint32_t id;
    static uint32_t idcounter;
    int32_t level;


    friend class RuleMatcher;

    struct PatternSet {




        Specific_RE_Matcher* re = nullptr;


        string_list patterns;
        int_list ids;
    };

    using pattern_set_list = PList<PatternSet>;
    pattern_set_list psets[Rule::TYPES];


    Rule* pattern_rules;
    Rule* pure_rules;

    IntSet* ruleset;


    RuleHdrTest* sibling;
    RuleHdrTest* child;
};

using rule_hdr_test_list = PList<RuleHdrTest>;



class RuleEndpointState {
public:
    ~RuleEndpointState();

    analyzer::Analyzer* GetAnalyzer() const { return analyzer; }
    bool IsOrig() { return is_orig; }


    void FlipIsOrig() { is_orig = ! is_orig; }





    int PayloadSize() { return payload_size; }

    analyzer::pia::PIA* PIA() const { return pia; }

private:
    friend class RuleMatcher;
    friend class RuleActionEvent;



    RuleEndpointState(analyzer::Analyzer* arg_analyzer, bool arg_is_orig, RuleEndpointState* arg_opposite,
                      analyzer::pia::PIA* arg_PIA);


    struct RulePatternMatch {
        RulePatternMatch(Rule* rule, const u_char* data, int data_len, MatchPos end_of_match)
            : rule(rule), text(data, data_len, false), end_of_match(end_of_match) {}

        RulePatternMatch(RulePatternMatch&& other) noexcept
            : rule(other.rule), text(std::move(other.text)), end_of_match(other.end_of_match) {
            other.rule = nullptr;
            other.end_of_match = 0;
        }

        RulePatternMatch(const RulePatternMatch&) = delete;
        RulePatternMatch& operator=(const RulePatternMatch&) = delete;

        Rule* rule = nullptr;
        String text;
        MatchPos end_of_match = 0;
    };




    const RulePatternMatch* FindRulePatternMatch(const Rule* r) const;
    void AddRulePatternMatch(Rule* r, const u_char* data, int data_len, MatchPos end_of_match);

    struct Matcher {
        RE_Match_State* state;
        Rule::PatternType type;
    };

    using matcher_list = PList<Matcher>;
    using match_offset_list = std::vector<MatchPos>;

    analyzer::Analyzer* analyzer;
    RuleEndpointState* opposite;
    analyzer::pia::PIA* pia;

    matcher_list matchers;
    rule_hdr_test_list hdr_tests;



    std::vector<RulePatternMatch> pattern_matches;

    int payload_size;
    size_t current_pos;
    bool is_orig;

    int_list matched_rules;
};




class RuleFileMagicState {
    friend class RuleMatcher;

public:
    ~RuleFileMagicState();

private:


    RuleFileMagicState() = default;

    struct Matcher {
        RE_Match_State* state;
    };

    using matcher_list = PList<Matcher>;
    matcher_list matchers;
};




class RuleMatcher {
public:


    RuleMatcher(int RE_level = 4);
    ~RuleMatcher();


    bool ReadFiles(const std::vector<SignatureFile>& files);






    RuleFileMagicState* InitFileMagic() const;






    using MIME_Matches = std::map<int, std::set<std::string>, std::greater<>>;













    MIME_Matches* Match(RuleFileMagicState* state, const u_char* data, uint64_t len,
                        MIME_Matches* matches = nullptr) const;





    void ClearFileMagicState(RuleFileMagicState* state) const;





    RuleEndpointState* InitEndpoint(analyzer::Analyzer* analyzer, const IP_Hdr* ip, int caplen,
                                    RuleEndpointState* opposite, bool is_orig, analyzer::pia::PIA* pia);


    void FinishEndpoint(RuleEndpointState* state);




    void Match(RuleEndpointState* state, Rule::PatternType type, const u_char* data, int data_len, bool bol, bool eol,
               bool clear);


    void ClearEndpointState(RuleEndpointState* state);

    void PrintDebug() const;


    void AddRule(Rule* rule);
    void SetParseError() { parse_error = true; }

    bool HasNonFileMagicRule() const { return has_non_file_magic_rule; }


    struct Stats {
        unsigned int matchers;


        unsigned int nfa_states;


        unsigned int dfa_states;
        unsigned int computed;
        unsigned int mem;


        unsigned int hits;
        unsigned int misses;
    };

    Val* BuildRuleStateValue(const Rule* rule, const RuleEndpointState* state) const;

    void GetStats(Stats* stats, RuleHdrTest* hdr_test = nullptr) const;
    void DumpStats(File* f) const;

private:

    void Delete(RuleHdrTest* node);


    void BuildRulesTree();


    void InsertRuleIntoTree(Rule* r, int testnr, RuleHdrTest* dest, int level);


    void BuildRegEx(RuleHdrTest* hdr_test, string_list* exprs, int_list* ids);


    void BuildPatternSets(RuleHdrTest::pattern_set_list* dst, const string_list& exprs, const int_list& ids);



    void ExecRule(Rule* rule, RuleEndpointState* state, bool eos);


    void ExecPureRules(RuleEndpointState* state, bool eos);




    bool ExecRulePurely(Rule* r, const String* s, RuleEndpointState* state, bool eos);


    void ExecRuleActions(Rule* r, RuleEndpointState* state, const u_char* data, int len, bool eos);


    bool EvalRuleConditions(Rule* r, RuleEndpointState* state, const u_char* data, int len, bool eos);

    void PrintTreeDebug(RuleHdrTest* node) const;

    void DumpStateStats(File* f, RuleHdrTest* hdr_test) const;

    static bool AllRulePatternsMatched(const Rule* r, MatchPos matchpos, const AcceptingMatchSet& ams);

    int RE_level;
    bool has_non_file_magic_rule;
    bool parse_error;
    RuleHdrTest* root;
    rule_list rules;
    rule_dict rules_by_id;
};


class RuleMatcherState {
public:
    RuleMatcherState() { orig_match_state = resp_match_state = nullptr; }
    virtual ~RuleMatcherState() {
        delete orig_match_state;
        delete resp_match_state;
    }


    void InitEndpointMatcher(analyzer::Analyzer* analyzer, const IP_Hdr* ip, int caplen, bool from_orig,
                             analyzer::pia::PIA* pia = nullptr);



    virtual void Match(Rule::PatternType type, const u_char* data, int data_len, bool from_orig, bool bol, bool eol,
                       bool clear_state);

    void FinishEndpointMatcher();
    void ClearMatchState(bool orig);

    bool MatcherInitialized(bool orig) { return orig ? orig_match_state : resp_match_state; }

private:
    RuleEndpointState* orig_match_state;
    RuleEndpointState* resp_match_state;
};

}
}
