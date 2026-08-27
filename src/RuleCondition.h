

#pragma once

#include <sys/types.h>
#include <cstdint>

namespace zeek::detail {

class RuleEndpointState;
class Rule;
class ID;


class RuleCondition {
public:
    RuleCondition() = default;
    virtual ~RuleCondition() = default;

    virtual bool DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len) = 0;

    virtual void PrintDebug() = 0;
};

enum RuleStateKind : uint8_t {
    RULE_STATE_ESTABLISHED = 1,
    RULE_STATE_ORIG = 2,
    RULE_STATE_RESP = 4,
    RULE_STATE_STATELESS = 8
};


class RuleConditionTCPState : public RuleCondition {
public:
    explicit RuleConditionTCPState(int arg_tcpstates) { tcpstates = arg_tcpstates; }

    bool DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;

private:
    int tcpstates;
};


class RuleConditionUDPState : public RuleCondition {
public:
    explicit RuleConditionUDPState(int arg_states) { states = arg_states; }

    bool DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;

private:
    int states;
};


class RuleConditionIPOptions : public RuleCondition {
public:
    enum Options : uint8_t {
        OPT_LSRR = 1,
        OPT_LSRRE = 2,
        OPT_RR = 4,
        OPT_SSRR = 8,
    };

    explicit RuleConditionIPOptions(int arg_options) { options = arg_options; }

    bool DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;

private:
    int options;
};


class RuleConditionSameIP : public RuleCondition {
public:
    RuleConditionSameIP() = default;

    bool DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;
};


class RuleConditionPayloadSize : public RuleCondition {
public:
    enum Comp : uint8_t { RULE_LE, RULE_GE, RULE_LT, RULE_GT, RULE_EQ, RULE_NE };

    RuleConditionPayloadSize(uint32_t arg_val, Comp arg_comp) {
        val = arg_val;
        comp = arg_comp;
    }

    bool DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;

private:
    uint32_t val;
    Comp comp;
};


class RuleConditionEval : public RuleCondition {
public:
    explicit RuleConditionEval(const char* func);

    bool DoMatch(Rule* rule, RuleEndpointState* state, const u_char* data, int len) override;

    void PrintDebug() override;

private:
    ID* id;
};

}
