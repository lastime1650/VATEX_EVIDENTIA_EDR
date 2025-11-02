#ifndef SQLITE_MANAGER_HPP
#define SQLITE_MANAGER_HPP

#include "sqlite_modern_cpp.h"
#include "../json.hpp"
using namespace nlohmann;

#include <string>
#include <map>

namespace EDR
{
    namespace Util
    {
        namespace Sqlite
        {
            class SqliteManager
            {
                public:
                    SqliteManager(std::string db_path)
                    : db_path(db_path), DatabaseObj(db_path)
                    {
                        this->DatabaseObj << "PRAGMA busy_timeout = 3000;"; // 락 걸렸을 때 3초 대기
                    }
                    ~SqliteManager() = default;

                    bool Query(std::string  query, json::array_t& result)
                    {

                        sqlite3_stmt* stmt = nullptr;
                        int rc = sqlite3_prepare_v2(DatabaseObj.connection().get(), query.c_str(), -1, &stmt, nullptr);

                        if (rc != SQLITE_OK) {
                            std::cerr << "Prepare error: " << sqlite3_errmsg(DatabaseObj.connection().get()) << std::endl;
                            return false;
                        }

                        int columnCount = sqlite3_column_count(stmt);

                        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                            json row;
                            for (int i = 0; i < columnCount; ++i) {
                                std::string colName = sqlite3_column_name(stmt, i);

                                switch (sqlite3_column_type(stmt, i)) {
                                    case SQLITE_INTEGER:
                                        row[colName] = sqlite3_column_int64(stmt, i);
                                        break;
                                    case SQLITE_FLOAT:
                                        row[colName] = sqlite3_column_double(stmt, i);
                                        break;
                                    case SQLITE_TEXT:
                                        row[colName] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                                        break;
                                    case SQLITE_NULL:
                                        row[colName] = nullptr;
                                        break;
                                    default:
                                        row[colName] = "UNSUPPORTED";
                                }
                            }
                            result.push_back(row);
                        }

                        if (rc != SQLITE_DONE) {
                            std::cerr << "SQLite step error: " << sqlite3_errmsg(DatabaseObj.connection().get()) << std::endl;
                            sqlite3_finalize(stmt);
                            return false;
                        }

                        sqlite3_finalize(stmt);
                        return true;  // pretty-print JSON
                    }

                    bool Execute(const std::string& query)
                    {   

                        sqlite3_stmt* stmt = nullptr;
                        sqlite3* raw = DatabaseObj.connection().get();

                        int rc = sqlite3_prepare_v2(raw, query.c_str(), -1, &stmt, nullptr);
                        if (rc != SQLITE_OK) {
                            std::cerr << "SQLite prepare error: " << sqlite3_errmsg(raw) << std::endl;
                            return false;
                        }

                        rc = sqlite3_step(stmt);
                        if (rc != SQLITE_DONE) {  // SELECT가 아닌 경우 정상 완료는 SQLITE_DONE
                            std::cerr << "SQLite execute error: " << sqlite3_errmsg(raw) << std::endl;
                            sqlite3_finalize(stmt);
                            return false;
                        }

                        sqlite3_finalize(stmt);
                        return true;
                    }

                    

                private:
                    std::string db_path; 
                    sqlite::database DatabaseObj;
            };
        }
    }
}

#endif