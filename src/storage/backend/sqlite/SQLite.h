

#pragma once

#include <chrono>

#include "zeek/storage/Backend.h"


struct sqlite3;
struct sqlite3_stmt;

namespace zeek::storage::backend::sqlite {

class SQLite final : public Backend {
public:
    SQLite() : Backend(SupportedModes::SYNC, "SQLITE") {}

    static BackendPtr Instantiate();




    bool IsOpen() override { return db != nullptr; }

private:
    using StepResultParser = std::function<OperationResult(sqlite3_stmt*)>;

    OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) override;
    OperationResult DoClose(ResultCallback* cb) override;
    OperationResult DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                          double expiration_time) override;
    OperationResult DoGet(ResultCallback* cb, ValPtr key) override;
    OperationResult DoErase(ResultCallback* cb, ValPtr key) override;
    void DoExpire(double current_network_time) override;
    std::string DoGetConfigMetricsLabel() const override;







    OperationResult CheckError(int code);





    OperationResult Step(sqlite3_stmt* stmt, const StepResultParser& parser, bool is_pragma = false);




    OperationResult RunPragma(std::string_view name, std::optional<std::string_view> value = std::nullopt,
                              const StepResultParser& value_parser = nullptr);

    sqlite3* db = nullptr;
    sqlite3* expire_db = nullptr;

    using sqlite_stmt_func = std::function<void(sqlite3_stmt*)>;
    using unique_stmt_ptr = std::unique_ptr<sqlite3_stmt, sqlite_stmt_func>;

    unique_stmt_ptr put_stmt;
    unique_stmt_ptr put_update_stmt;
    unique_stmt_ptr get_stmt;
    unique_stmt_ptr erase_stmt;

    unique_stmt_ptr check_expire_stmt;
    unique_stmt_ptr expire_stmt;
    unique_stmt_ptr get_expiry_last_run_stmt;
    unique_stmt_ptr update_expiry_last_run_stmt;

    std::string full_path;
    std::string table_name;
    std::chrono::milliseconds pragma_timeout = {};
    std::chrono::milliseconds pragma_wait_on_busy = {};

    telemetry::GaugePtr page_count_metric;
    telemetry::GaugePtr file_size_metric;

    double last_page_count_value = 0.0;
    double last_file_size_value = 0.0;
};

}
