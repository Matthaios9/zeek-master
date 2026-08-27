






#pragma once

#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/backtrace.h>
#include <hilti/rt/types/optional.h>

#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"

namespace zeek::spicy::rt {

namespace cookie {


struct FileState {
    FileState(std::string fid) : fid(std::move(fid)) {}
    std::string fid;
    hilti::rt::Optional<std::string> mime_type;
};








class FileStateStack {
public:





    FileStateStack(std::string analyzer_id) : _analyzer_id(std::move(analyzer_id)) {}






    FileState* push(hilti::rt::Optional<std::string> fid = {});


    bool isEmpty() const { return _stack.empty(); }






    void remove(const std::string& fid);





    const FileState* current() const {
        assert(! _stack.empty());
        return &_stack.back();
    }







    const FileState* find(const std::string& fid) const;

private:
    std::vector<FileState> _stack;
    std::string _analyzer_id;
    uint64_t _id_counter = 0;
};


struct ProtocolAnalyzer {
    analyzer::Analyzer* analyzer = nullptr;
    bool is_orig = false;
    uint64_t num_packets = 0;
    FileStateStack fstate_orig;
    FileStateStack fstate_resp;
    std::shared_ptr<packet_analysis::TCP::TCPSessionAdapter> fake_tcp;
};


struct FileAnalyzer {
    file_analysis::Analyzer* analyzer = nullptr;
    uint64_t depth = 0;
    FileStateStack fstate;
};


struct PacketAnalyzer {
    packet_analysis::Analyzer* analyzer = nullptr;
    Packet* packet = nullptr;
    ValPtr packet_val = nullptr;
    std::optional<uint32_t> next_analyzer;
};

}





struct Cookie {



    cookie::ProtocolAnalyzer* protocol = nullptr;
    cookie::FileAnalyzer* file = nullptr;
    cookie::PacketAnalyzer* packet = nullptr;

    Cookie(cookie::ProtocolAnalyzer&& c) : data(std::move(c)) { protocol = &data.protocol; }
    Cookie(cookie::FileAnalyzer&& c) : data(std::move(c)) { file = &data.file; }
    Cookie(cookie::PacketAnalyzer&& c) : data(std::move(c)) { packet = &data.packet; }

    Cookie(Cookie&& other) noexcept
        : data(
              [&]() {
                  try {
                      return other.tag();
                  } catch ( const std::exception& e ) {
                      auto type = hilti::rt::demangle(typeid(e).name());
                      reporter->FatalError("terminating with uncaught exception of type %s: %s", type.c_str(),
                                           e.what());
                  }
              }(),
              std::move(other.data)) {
        _initLike(other);
    }

    ~Cookie() { _delete(); }

    Cookie& operator=(Cookie&& other) noexcept try {
        if ( this == &other )
            return *this;

        _delete();
        _initLike(other);

        new (&data) Data(tag(), std::move(other.data));
        return *this;
    } catch ( const std::exception& e ) {
        auto type = hilti::rt::demangle(typeid(e).name());
        reporter->FatalError("terminating with uncaught exception of type %s: %s", type.c_str(), e.what());
    }


    struct {
        ValPtr conn = nullptr;
        ValPtr is_orig = nullptr;
        bool confirmed = false;
    } cache;

    enum Tag : uint8_t { Protocol, File, Packet };


    Tag tag() const {
        if ( protocol )
            return Tag::Protocol;
        else if ( file )
            return Tag::File;
        else if ( packet )
            return Tag::Packet;
        else
            throw std::runtime_error("invalid cookie");
    }

    Cookie(const Cookie& other) = delete;
    Cookie& operator=(const Cookie& other) = delete;

private:
    union Data {
        cookie::ProtocolAnalyzer protocol;
        cookie::FileAnalyzer file;
        cookie::PacketAnalyzer packet;

        Data(cookie::ProtocolAnalyzer&& protocol) : protocol(std::move(protocol)) {}
        Data(cookie::FileAnalyzer&& file) : file(std::move(file)) {}
        Data(cookie::PacketAnalyzer&& packet) : packet(std::move(packet)) {}
        Data(Tag tag, Data&& other) {
            switch ( tag ) {
                case Tag::Protocol: new (&protocol) cookie::ProtocolAnalyzer(std::move(other.protocol)); break;
                case Tag::File: new (&file) cookie::FileAnalyzer(std::move(other.file)); break;
                case Tag::Packet: new (&packet) cookie::PacketAnalyzer(std::move(other.packet)); break;
            }
        }

        ~Data() {

        }

        Data(const Data& other) = delete;
        Data& operator=(const Data& other) = delete;
        Data& operator=(Data&& other) = delete;
    } data;

    void _delete() {
        if ( protocol ) {
            data.protocol.~ProtocolAnalyzer();
            protocol = nullptr;
            cache.conn = nullptr;
            cache.is_orig = nullptr;
            cache.confirmed = false;
        }
        else if ( file ) {
            data.file.~FileAnalyzer();
            file = nullptr;
        }
        else if ( packet ) {
            data.packet.~PacketAnalyzer();
            packet = nullptr;
        }
    }

    void _initLike(const Cookie& other) {
        if ( other.protocol ) {
            protocol = &data.protocol;
            cache.confirmed = other.cache.confirmed;
        }

        else if ( other.file )
            file = &data.file;

        else if ( other.packet )
            packet = &data.packet;
    }

    friend inline void swap(Cookie& lhs, Cookie& rhs) noexcept {
        Cookie tmp = std::move(lhs);
        lhs = std::move(rhs);
        rhs = std::move(tmp);
    }
};

}
