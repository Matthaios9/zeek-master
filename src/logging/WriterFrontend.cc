

#include "zeek/logging/WriterFrontend.h"

#include <span>

#include "zeek/RunState.h"
#include "zeek/broker/Manager.h"
#include "zeek/cluster/Backend.h"
#include "zeek/logging/Manager.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/threading/SerialTypes.h"

using zeek::threading::Field;
using zeek::threading::Value;

namespace zeek::logging {



class InitMessage final : public threading::InputMessage<WriterBackend> {
public:
    InitMessage(WriterBackend* backend, const int num_fields, const Field* const* fields)
        : threading::InputMessage<WriterBackend>("Init", backend), num_fields(num_fields), fields(fields) {}

    bool Process() override { return Object()->Init(num_fields, fields); }

private:
    const int num_fields;
    const Field* const* fields;
};

class RotateMessage final : public threading::InputMessage<WriterBackend> {
public:
    RotateMessage(WriterBackend* backend, WriterFrontend* frontend, const char* rotated_path, const double open,
                  const double close, const bool terminating)
        : threading::InputMessage<WriterBackend>("Rotate", backend),
          frontend(frontend),
          rotated_path(util::copy_string(rotated_path)),
          open(open),
          close(close),
          terminating(terminating) {}

    ~RotateMessage() override { delete[] rotated_path; }

    bool Process() override { return Object()->Rotate(rotated_path, open, close, terminating); }

private:
    WriterFrontend* frontend;
    const char* rotated_path;
    const double open;
    const double close;
    const bool terminating;
};

class WriteMessage final : public threading::InputMessage<WriterBackend> {
public:
    WriteMessage(WriterBackend* backend, int num_fields, std::vector<detail::LogRecord>&& records)
        : threading::InputMessage<WriterBackend>("Write", backend),
          num_fields(num_fields),
          records(std::move(records)) {}

    bool Process() override { return Object()->Write(num_fields, std::span{records}); }

private:
    int num_fields;
    std::vector<detail::LogRecord> records;
};

class SetBufMessage final : public threading::InputMessage<WriterBackend> {
public:
    SetBufMessage(WriterBackend* backend, const bool enabled)
        : threading::InputMessage<WriterBackend>("SetBuf", backend), enabled(enabled) {}

    bool Process() override { return Object()->SetBuf(enabled); }

private:
    const bool enabled;
};

class FlushMessage final : public threading::InputMessage<WriterBackend> {
public:
    FlushMessage(WriterBackend* backend, double network_time)
        : threading::InputMessage<WriterBackend>("Flush", backend), network_time(network_time) {}

    bool Process() override { return Object()->Flush(network_time); }

private:
    double network_time;
};



WriterFrontend::WriterFrontend(const WriterBackend::WriterInfo& arg_info, EnumVal* arg_stream, EnumVal* arg_writer,
                               bool arg_local, bool arg_remote)
    : write_buffer(detail::WriteBuffer(BifConst::Log::write_buffer_size)) {

    header = detail::LogWriteHeader{{zeek::NewRef{}, arg_stream},
                                    {zeek::NewRef{}, arg_writer},
                                    arg_info.filter_name,
                                    arg_info.path};

    disabled = initialized = false;
    buf = true;
    local = arg_local;
    remote = arg_remote;
    info = new WriterBackend::WriterInfo(arg_info);

    const char* w = arg_writer->GetType()->AsEnumType()->Lookup(arg_writer->InternalInt());
    name = util::copy_string(util::fmt("%s/%s", arg_info.path, w));

    if ( local ) {
        backend = log_mgr->CreateBackend(this, header.writer_id.get());

        if ( backend )
            backend->Start();
    }

    else
        backend = nullptr;
}

WriterFrontend::~WriterFrontend() {
    delete info;
    delete[] name;
}

void WriterFrontend::Stop() {
    if ( disabled ) {
        return;
    }

    FlushWriteBuffer();
    SetDisable();

    if ( backend ) {
        backend->SignalStop();
        backend = nullptr;
    }
}

void WriterFrontend::Init(int arg_num_fields, const Field* const* arg_fields) {
    if ( disabled )
        return;

    if ( initialized )
        reporter->InternalError("writer initialize twice");

    initialized = true;


    header.fields.reserve(arg_num_fields);
    for ( int i = 0; i < arg_num_fields; i++ )
        header.fields.emplace_back(*arg_fields[i]);


    header.field_pointers.reserve(arg_num_fields);
    for ( int i = 0; i < arg_num_fields; i++ )
        header.field_pointers.emplace_back(&header.fields[i]);

    if ( remote ) {
        broker_mgr->PublishLogCreate(header.stream_id.get(), header.writer_id.get(), *info, arg_num_fields, arg_fields);
    }

    if ( backend )


        backend->SendIn(new InitMessage(backend, arg_num_fields, arg_fields));
    else {
        for ( int i = 0; i < arg_num_fields; i++ )
            delete arg_fields[i];
        delete[] arg_fields;
    }
}

void WriterFrontend::Write(detail::LogRecord&& arg_vals) {
    std::vector<threading::Value> vals = std::move(arg_vals);

    if ( disabled )
        return;

    if ( vals.size() != header.fields.size() ) {
        reporter->Warning("WriterFrontend %s expected %zu fields in write, got %zu. Skipping line.", name,
                          header.fields.size(), vals.size());
        return;
    }







    const bool broker_is_cluster_backend = zeek::cluster::backend == zeek::broker_mgr;

    if ( remote ) {
        if ( broker_is_cluster_backend ) {
            zeek::broker_mgr->PublishLogWrite(header.stream_id.get(), header.writer_id.get(), info->path, vals);

            if ( ! backend )
                return;
        }
    }
    else if ( ! backend ) {
        assert(! remote);

        return;
    }


    assert(backend || (remote && ! broker_is_cluster_backend));

    write_buffer.WriteRecord(std::move(vals));

    if ( write_buffer.Full() || ! buf || run_state::terminating )

        FlushWriteBuffer();
}

void WriterFrontend::FlushWriteBuffer() {
    if ( disabled )
        return;

    if ( write_buffer.Empty() )

        return;

    auto records = std::move(write_buffer).TakeRecords();



    const bool broker_is_cluster_backend = zeek::cluster::backend == zeek::broker_mgr;
    if ( remote && ! broker_is_cluster_backend )
        zeek::cluster::backend->PublishLogWrites(header, std::span{records});

    if ( backend )
        backend->SendIn(new WriteMessage(backend, header.fields.size(), std::move(records)));
}

void WriterFrontend::SetBuf(bool enabled) {
    if ( disabled )
        return;

    buf = enabled;

    if ( backend )
        backend->SendIn(new SetBufMessage(backend, enabled));

    if ( ! buf )

        FlushWriteBuffer();
}

void WriterFrontend::Flush(double network_time) {
    if ( disabled )
        return;

    FlushWriteBuffer();

    if ( backend )
        backend->SendIn(new FlushMessage(backend, network_time));
}

void WriterFrontend::Rotate(const char* rotated_path, double open, double close, bool terminating) {
    if ( disabled )
        return;

    FlushWriteBuffer();

    if ( backend )
        backend->SendIn(new RotateMessage(backend, this, rotated_path, open, close, terminating));
    else

        log_mgr->FinishedRotation(this, nullptr, nullptr, 0, 0, false, terminating);
}

}
