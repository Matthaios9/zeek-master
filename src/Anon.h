











#pragma once

#include <cstdint>
#include <map>
#include <vector>

namespace zeek::detail {



enum ip_addr_anonymization_class_t : uint8_t {
    ORIG_ADDR,
    RESP_ADDR,
    OTHER_ADDR,
    NUM_ADDR_ANONYMIZATION_CLASSES,
};

enum ip_addr_anonymization_method_t : uint8_t {
    KEEP_ORIG_ADDR,
    SEQUENTIALLY_NUMBERED,
    PREFIX_PRESERVING_A50,
    RANDOM_MD5 [[deprecated("Remove in v9.1. Use the A50 or SHA256 anonymizers instead.")]],
    PREFIX_PRESERVING_MD5 [[deprecated("Remove in v9.1. Use the A50 or SHA256 anonymizers instead.")]],
    RANDOM_SHA256,
    PREFIX_PRESERVING_SHA256,
    NUM_ADDR_ANONYMIZATION_METHODS,
};

using ipaddr32_t = uint32_t;




class AnonymizeIPAddr {
public:
    virtual ~AnonymizeIPAddr() = default;

    ipaddr32_t Anonymize(ipaddr32_t addr);

    virtual bool PreservePrefix(ipaddr32_t input, int num_bits);

    virtual ipaddr32_t anonymize(ipaddr32_t addr) = 0;

    bool PreserveNet(ipaddr32_t input);

protected:
    std::map<ipaddr32_t, ipaddr32_t> mapping;
};

class AnonymizeIPAddr_Seq : public AnonymizeIPAddr {
public:
    AnonymizeIPAddr_Seq() { seq = 1; }
    ipaddr32_t anonymize(ipaddr32_t addr) override;

protected:
    ipaddr32_t seq;
};

class [[deprecated("Remove in v9.1. Use the A50 or SHA256 anonymizers instead.")]] AnonymizeIPAddr_RandomMD5
    : public AnonymizeIPAddr {
public:
    ipaddr32_t anonymize(ipaddr32_t addr) override;
};

class [[deprecated("Remove in v9.1. Use the A50 or SHA256 anonymizers instead.")]] AnonymizeIPAddr_PrefixMD5
    : public AnonymizeIPAddr {
public:
    ipaddr32_t anonymize(ipaddr32_t addr) override;

protected:
    struct anon_prefix {
        int len;
        ipaddr32_t prefix;
    } prefix;
};

class AnonymizeIPAddr_RandomSHA256 : public AnonymizeIPAddr {
public:
    ipaddr32_t anonymize(ipaddr32_t addr) override;
};

class AnonymizeIPAddr_PrefixSHA256 : public AnonymizeIPAddr {
public:
    ipaddr32_t anonymize(ipaddr32_t addr) override;

protected:
    struct anon_prefix {
        int len;
        ipaddr32_t prefix;
    } prefix;
};

class AnonymizeIPAddr_A50 : public AnonymizeIPAddr {
public:
    AnonymizeIPAddr_A50() { init(); }
    ~AnonymizeIPAddr_A50() override;

    ipaddr32_t anonymize(ipaddr32_t addr) override;
    bool PreservePrefix(ipaddr32_t input, int num_bits) override;

protected:
    struct Node {
        ipaddr32_t input;
        ipaddr32_t output;
        Node* child[2];
    };

    bool before_anonymization = true;
    bool new_mapping = false;


    Node* root = nullptr;


    Node* next_free_node = nullptr;
    std::vector<Node*> blocks;


    Node special_nodes[2];

    void init();

    Node* new_node();
    Node* new_node_block();
    void free_node(Node*);

    ipaddr32_t make_output(ipaddr32_t, int) const;
    Node* make_peer(ipaddr32_t, Node*);
    Node* find_node(ipaddr32_t);
};


extern AnonymizeIPAddr* ip_anonymizer[NUM_ADDR_ANONYMIZATION_METHODS];

void init_ip_addr_anonymizers();
ipaddr32_t anonymize_ip(ipaddr32_t ip, enum ip_addr_anonymization_class_t cl);

#define LOG_ANONYMIZATION_MAPPING
void log_anonymization_mapping(ipaddr32_t input, ipaddr32_t output);

}
