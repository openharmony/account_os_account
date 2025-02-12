/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ACCOUNT_SQLITE_ADAPTER_IMPL_H
#define ACCOUNT_SQLITE_ADAPTER_IMPL_H
#include <map>
#include <string>

#include "database_adapter_interface.h"
#include "rwlock.h"
#include "sqlite_helper.h"

namespace OHOS {
namespace AccountSA {
// This sqlite cannot use in distributed devices
struct SqliteTable {
public:
    std::string tableName_;
    std::vector<std::string> tableColumnNames_;
};

enum DataType {
    ACCOUNT_INFO_DATA_TYPE,
};

class AppAccountSqliteHelper : public SqliteHelper {
public:
    static std::shared_ptr<AppAccountSqliteHelper> GetInstance();
    AppAccountSqliteHelper();
    ~AppAccountSqliteHelper();
    
    std::string CheckDataType(const DataType type);
    void OnCreate() override;
    void OnUpdate(int32_t version) override;
private:
    DbAdapterStatus CreateAppAccountTable();
    inline static constexpr const char* ACCOUNT_INFO_TABLE_NAME = "account_info";
    inline static constexpr const char* DATABASE_NAME = "account.db";
    inline static constexpr const char* DATABASE_PATH = "/data/service/el2/100/account/app_account/";
    static const int32_t DATABASE_VERSION = DataBaseVersion::VERISION_1;
    std::map<DataType, SqliteTable> dataTypeToSqlTable_;
};

class DbAdapterSqlite : public IDbAdapterSingleStore {
public:
    DbAdapterSqlite();
    ~DbAdapterSqlite() = default;

    DbAdapterStatus CheckOrOpenDb();
    DbAdapterStatus Get(const std::string &keyStr, std::string &valueStr) override;
    DbAdapterStatus Delete(const std::string &keyStr) override;
    DbAdapterStatus Put(const std::string &keyStr, const std::string &valueStr) override;
    DbAdapterStatus GetEntries(const std::string subId,
        std::vector<DbAdapterEntry> &allEntries) override;

private:
    std::string GenerateGetSql(const DataType type);
    std::string GenerateDeleteSql(const DataType type);
    std::string GeneratePutSql(const DataType type);
    std::string GenerateGetEntriesSql(const DataType type);

    std::shared_ptr<AppAccountSqliteHelper> appAccountDb_ = nullptr;
};

class SqliteAdapterDataManager : public IDbAdapterDataManager {
public:
    SqliteAdapterDataManager() = default;
    ~SqliteAdapterDataManager() = default;

    DbAdapterStatus CloseKvStore(const std::string appIdStr,
        std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr) override;
    DbAdapterStatus GetSingleKvStore(const DbAdapterOptions &options, const std::string &appIdStr,
        const std::string &storeIdStr, std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr) override;
private:
    std::shared_ptr<DbAdapterSqlite> sqliteShareHandler_ = nullptr;
};

extern "C" {
    IDbAdapterDataManager* __attribute__((visibility("default"))) CreateDataManager();
    void __attribute__((visibility("default"))) DestroyDataManager(IDbAdapterDataManager* ptr);
};
}
}
#endif // ACCOUNT_SQLITE_ADAPTER_IMPL_H