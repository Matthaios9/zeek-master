

#pragma once

#include <sys/types.h>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "zeek/Obj.h"
#include "zeek/input/InputFile.h"
#include "zeek/input/ReaderBackend.h"
#include "zeek/threading/Formatter.h"

namespace zeek::input::reader::detail {



struct FieldMapping {
    std::string name;
    TypeTag type;
    TypeTag subtype;
    int position = -1;
    int secondary_position = -1;
    bool present = false;

    FieldMapping(std::string arg_name, const TypeTag& arg_type, int arg_position);
    FieldMapping(std::string arg_name, const TypeTag& arg_type, const TypeTag& arg_subtype, int arg_position);

    FieldMapping(const FieldMapping& arg);
    FieldMapping() = default;

    FieldMapping& operator=(const FieldMapping& arg);

    FieldMapping subType();
};




class Ascii : public ReaderBackend {
public:
    explicit Ascii(ReaderFrontend* frontend);


    Ascii(const Ascii&) = delete;
    Ascii(Ascii&&) = delete;
    Ascii& operator=(const Ascii&) = delete;
    Ascii& operator=(Ascii&&) = delete;

    static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Ascii(frontend); }

protected:
    bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
    void DoClose() override;
    bool DoUpdate() override;
    bool DoHeartbeat(double network_time, double current_time) override;

    const zeek::detail::Location* GetLocationInfo() const override { return read_location.get(); }

private:
    bool ReadHeader(bool useCached);
    bool GetLine(std::string& str);
    bool OpenFile();

    InputFile file;
    time_t mtime;
    file_ino_t ino;




    std::string fname;


    std::vector<FieldMapping> columnMap;


    std::string headerline;


    std::string separator;
    std::string set_separator;
    std::string empty_field;
    std::string unset_field;
    bool fail_on_invalid_lines;
    bool fail_on_file_problem;
    std::string path_prefix;

    std::unique_ptr<threading::Formatter> formatter;




    struct LocationDeleter {
        void operator()(zeek::detail::Location* loc) const {
            delete[] loc->FileName();
            delete loc;
        }
    };

    using LocationPtr = std::unique_ptr<zeek::detail::Location, LocationDeleter>;
    LocationPtr read_location;
};

}
