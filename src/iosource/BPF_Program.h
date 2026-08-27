

#pragma once

#include <cstdint>
#include <string>

#include "zeek/util-types.h"

extern "C" {
#include <pcap.h>
}

namespace zeek::iosource {

enum class FilterState : uint8_t {
    OK,
    FATAL,
    WARNING
};

namespace detail {





class BPF_Program {
public:



    BPF_Program();
    ~BPF_Program();







    bool Compile(pcap_t* pcap, const char* filter, uint32_t netmask, bool optimize = true);







    bool Compile(zeek_uint_t snaplen, int linktype, const char* filter, uint32_t netmask, bool optimize = true);




    bool IsCompiled() { return m_compiled; }





    bool MatchesAnything() { return m_matches_anything; }




    bpf_program* GetProgram();




    FilterState GetState() const { return state; }




    std::string GetStateMessage() const { return state_message; }

protected:
    void FreeCode();

    FilterState GetStateFromMessage(const std::string& err);



    bool m_compiled = false;
    bool m_matches_anything = false;
    struct bpf_program m_program;

    FilterState state = FilterState::OK;
    std::string state_message;
};

}
}
