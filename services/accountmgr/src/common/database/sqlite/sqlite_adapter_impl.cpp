/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "sqlite_adapter_impl.h"

#include <memory>
#include "account_log_wrapper.h"
#include "generic_values.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string ACCOUNT_INFO_TABLE_KEY = "key";
const std::string ACCOUNT_INFO_TABLE_VALUE = "value";
constexpr const char* CREATE_TABLE_STR = "create table if not exists ";
constexpr const char* TEXT_STR = " text not null,";
static OHOS::Utils::RWLock DATABASE_RWLOCK;
};

std::shared_ptr<AppAccountSqliteHelper> AppAccountSqliteHelper::GetInstance()
{
    static std::shared_ptr<AppAccountSqliteHelper> instance = std::make_shared<AppAccountSqliteHelper>();
    return instance;
}

AppAccountSqliteHelper::AppAccountSqliteHelper() : SqliteHelper(DATABASE_NAME, DATABASE_PATH, DATABASE_VERSION)
{
    SqliteTable appAccountTable;
    appAccountTable.tableName_ = ACCOUNT_INFO_TABLE_NAME;
    appAccountTable.tableColumnNames_ = {
        ACCOUNT_INFO_TABLE_KEY,
        ACCOUNT_INFO_TABLE_VALUE,
    };
    dataTypeToSqlTable_[DataType::ACCOUNT_INFO_DATA_TYPE] = appAccountTable;
}

AppAccountSqliteHelper::~AppAccountSqliteHelper()
{
    Utils::UniqueWriteGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    this->Close();
}

void AppAccountSqliteHelper::OnCreate()
{
    CreateAppAccountTable();
}

void AppAccountSqliteHelper::OnUpdate(int32_t version)
{
    // No need to update database.
    return;
}

DbAdapterStatus AppAccountSqliteHelper::CreateAppAccountTable()
{
    ACCOUNT_LOGI("Create Table");
    auto it = dataTypeToSqlTable_.find(DataType::ACCOUNT_INFO_DATA_TYPE);
    if (it == dataTypeToSqlTable_.end()) {
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    std::string sql = CREATE_TABLE_STR;
    sql.append(it->second.tableName_ + " (")
        .append(ACCOUNT_INFO_TABLE_KEY)
        .append(TEXT_STR)
        .append(ACCOUNT_INFO_TABLE_VALUE)
        .append(TEXT_STR)
        .append("primary key(")
        .append(ACCOUNT_INFO_TABLE_KEY)
        .append("))");
    int32_t ret = ExecuteSql(sql);
    if (ret != SQLITE_OK) {
        ACCOUNT_LOGE("CreateTable failed, ret = %{public}d", ret);
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    return DbAdapterStatus::SUCCESS;
}

std::string AppAccountSqliteHelper::CheckDataType(const DataType type)
{
    auto it = dataTypeToSqlTable_.find(DataType::ACCOUNT_INFO_DATA_TYPE);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    return it->second.tableName_;
}

DbAdapterSqlite::DbAdapterSqlite()
{
    appAccountDb_ = AppAccountSqliteHelper::GetInstance();
}

DbAdapterStatus DbAdapterSqlite::CheckOrOpenDb()
{
    bool isReady = false;
    {
        Utils::UniqueReadGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
        isReady = appAccountDb_->CheckReady();
    }
    if (isReady) {
        return DbAdapterStatus::SUCCESS;
    }
    Utils::UniqueWriteGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    if (appAccountDb_ == nullptr) {
        appAccountDb_ = AppAccountSqliteHelper::GetInstance();
    }
    appAccountDb_->Open();
    isReady = appAccountDb_->CheckReady();
    if (!isReady) {
        ACCOUNT_LOGE("database is not ready with two tries.");
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    return DbAdapterStatus::SUCCESS;
}

std::string DbAdapterSqlite::GenerateGetSql(const DataType type)
{
    std::string tableName = appAccountDb_->CheckDataType(type);
    if (tableName.empty()) {
        ACCOUNT_LOGE("Input invalid datatype %{public}d.", type);
        return tableName;
    }
    std::string sql = "select * from " + tableName + " where 1=1";
    sql.append(" and ");
    sql.append(ACCOUNT_INFO_TABLE_KEY + "=:" + ACCOUNT_INFO_TABLE_KEY);
    return sql;
}

DbAdapterStatus DbAdapterSqlite::Get(const std::string &keyStr, std::string &valueStr)
{
    valueStr.clear();
    DbAdapterStatus status = CheckOrOpenDb();
    if (status != DbAdapterStatus::SUCCESS) {
        ACCOUNT_LOGE("Check sqlite db failed.");
        return status;
    }
    std::string sql = GenerateGetSql(DataType::ACCOUNT_INFO_DATA_TYPE);
    Utils::UniqueReadGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    Statement statement = appAccountDb_->Prepare(sql);
    VariantValue searchKey(keyStr);
    statement.Bind(ACCOUNT_INFO_TABLE_KEY, searchKey);
    std::vector<GenericValues> results;
    while (statement.Step() == Statement::State::ROW) {
        int columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int32_t i = 0; i < columnCount; i++) {
            value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
        }
        results.emplace_back(value);
    }
    size_t resSize = results.size();
    if (resSize == 0) {
        return DbAdapterStatus::KEY_NOT_EXIST;
    } else if (resSize == 1) {
        valueStr = results[0].GetString(ACCOUNT_INFO_TABLE_VALUE);
    } else {
        ACCOUNT_LOGE("Receive size error, expect one, get %{public}zu", resSize);
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    return DbAdapterStatus::SUCCESS;
}

std::string DbAdapterSqlite::GenerateDeleteSql(const DataType type)
{
    std::string tableName = appAccountDb_->CheckDataType(type);
    if (tableName.empty()) {
        ACCOUNT_LOGE("Input invalid datatype %{public}d.", type);
        return tableName;
    }
    std::string sql = "delete from " + tableName + " where 1=1";
    sql.append(" and ");
    sql.append(ACCOUNT_INFO_TABLE_KEY + "=:" + ACCOUNT_INFO_TABLE_KEY);
    return sql;
}

DbAdapterStatus DbAdapterSqlite::Delete(const std::string &keyStr)
{
    DbAdapterStatus status = CheckOrOpenDb();
    if (status != DbAdapterStatus::SUCCESS) {
        ACCOUNT_LOGE("Check sqlite db failed.");
        return status;
    }
    std::string sql = GenerateDeleteSql(DataType::ACCOUNT_INFO_DATA_TYPE);
    Utils::UniqueWriteGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    Statement statement = appAccountDb_->Prepare(sql);
    VariantValue deleteKey(keyStr);
    statement.Bind(ACCOUNT_INFO_TABLE_KEY, deleteKey);
    int32_t ret = statement.Step();
    if (ret != Statement::State::DONE) {
        ACCOUNT_LOGE("Remove error, ret %{public}d", ret);
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    return DbAdapterStatus::SUCCESS;
}

std::string DbAdapterSqlite::GeneratePutSql(const DataType type)
{
    std::string tableName = appAccountDb_->CheckDataType(type);
    if (tableName.empty()) {
        ACCOUNT_LOGE("Input invalid datatype %{public}d.", type);
        return tableName;
    }
    std::string sql = "insert or replace into " + tableName + " values(";
    sql.append(":" + ACCOUNT_INFO_TABLE_KEY);
    sql.append(",");
    sql.append(":" + ACCOUNT_INFO_TABLE_VALUE);
    sql.append(")");
    return sql;
}

DbAdapterStatus DbAdapterSqlite::Put(const std::string &keyStr, const std::string &valueStr)
{
    DbAdapterStatus status = CheckOrOpenDb();
    if (status != DbAdapterStatus::SUCCESS) {
        ACCOUNT_LOGE("Check sqlite db failed.");
        return status;
    }
    std::string sql = GeneratePutSql(DataType::ACCOUNT_INFO_DATA_TYPE);
    Utils::UniqueWriteGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    Statement statement = appAccountDb_->Prepare(sql);
    VariantValue insertKey(keyStr);
    statement.Bind(ACCOUNT_INFO_TABLE_KEY, insertKey);
    VariantValue insertValue(valueStr);
    statement.Bind(ACCOUNT_INFO_TABLE_VALUE, insertValue);
    int32_t ret = statement.Step();
    if (ret != Statement::State::DONE) {
        ACCOUNT_LOGE("Insert error, ret %{public}d", ret);
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    return DbAdapterStatus::SUCCESS;
}

std::string DbAdapterSqlite::GenerateGetEntriesSql(const DataType type)
{
    std::string tableName = appAccountDb_->CheckDataType(type);
    if (tableName.empty()) {
        ACCOUNT_LOGE("Input invalid datatype %{public}d.", type);
        return tableName;
    }
    std::string sql = "select * from " + tableName + " where 1=1";
    sql.append(" and ");
    sql.append(ACCOUNT_INFO_TABLE_KEY + " like :" + ACCOUNT_INFO_TABLE_KEY);
    return sql;
}

DbAdapterStatus DbAdapterSqlite::GetEntries(const std::string subId,
    std::vector<DbAdapterEntry> &allEntries)
{
    DbAdapterStatus status = CheckOrOpenDb();
    if (status != DbAdapterStatus::SUCCESS) {
        ACCOUNT_LOGE("Check sqlite db failed.");
        return status;
    }
    allEntries.clear();
    std::string sql = GenerateGetEntriesSql(DataType::ACCOUNT_INFO_DATA_TYPE);
    Utils::UniqueReadGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    Statement statement = appAccountDb_->Prepare(sql);
    VariantValue searchKey(subId + "\%");
    statement.Bind(ACCOUNT_INFO_TABLE_KEY, searchKey);
    std::vector<GenericValues> results;
    while (statement.Step() == Statement::State::ROW) {
        int columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int32_t i = 0; i < columnCount; i++) {
            value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
        }
        results.emplace_back(value);
    }
    for (const GenericValues &result : results) {
        DbAdapterEntry entry;
        entry.key = result.GetString(ACCOUNT_INFO_TABLE_KEY);
        entry.value = result.GetString(ACCOUNT_INFO_TABLE_VALUE);
        allEntries.emplace_back(entry);
    }
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus DbAdapterSqlite::Commit()
{
    Utils::UniqueWriteGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    if (appAccountDb_->CommitTransaction() != SQLITE_HELPER_SUCCESS) {
        ACCOUNT_LOGE("Commit transaction failed.");
        return DbAdapterStatus::INTERNAL_ERROR;
    } else {
        return DbAdapterStatus::SUCCESS;
    }
}

DbAdapterStatus DbAdapterSqlite::Rollback()
{
    Utils::UniqueWriteGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    if (appAccountDb_->RollbackTransaction() != SQLITE_HELPER_SUCCESS) {
        ACCOUNT_LOGE("Rollback transaction failed.");
        return DbAdapterStatus::INTERNAL_ERROR;
    } else {
        return DbAdapterStatus::SUCCESS;
    }
}

DbAdapterStatus DbAdapterSqlite::StartTransaction()
{
    Utils::UniqueWriteGuard<Utils::RWLock> lock(DATABASE_RWLOCK);
    if (appAccountDb_->BeginTransaction() != SQLITE_HELPER_SUCCESS) {
        ACCOUNT_LOGE("Start transaction failed.");
        return DbAdapterStatus::INTERNAL_ERROR;
    } else {
        return DbAdapterStatus::SUCCESS;
    }
}

DbAdapterStatus DbAdapterSqlite::PutBatch(const std::vector<DbAdapterEntry> &entries)
{
    //No need to batch put
    ACCOUNT_LOGI("Sqlite PutBatch not enabled.");
    return DbAdapterStatus::NOT_SUPPORT;
}

DbAdapterStatus SqliteAdapterDataManager::CloseKvStore(const std::string appIdStr,
    std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr)
{
    // No need to close
    kvStorePtr = nullptr;
    ACCOUNT_LOGI("Sqlite CloseKvStore not enabled.");
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus SqliteAdapterDataManager::GetSingleKvStore(const DbAdapterOptions &options, const std::string &appIdStr,
    const std::string &storeIdStr, std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr)
{
    std::shared_ptr<DbAdapterSqlite> storeImpl = std::make_shared<DbAdapterSqlite>();
    if ((storeImpl == nullptr) || (storeImpl->CheckOrOpenDb())) {
        return DbAdapterStatus::INTERNAL_ERROR;
    }
    kvStorePtr = std::dynamic_pointer_cast<IDbAdapterSingleStore>(storeImpl);
    return DbAdapterStatus::SUCCESS;
}

DbAdapterStatus SqliteAdapterDataManager::DeleteKvStore(const std::string &appIdStr,
    const std::string &storeIdStr, const std::string &baseDir)
{
    // delete not enabled
    ACCOUNT_LOGI("Sqlite DeleteKvStore not enabled.");
    return DbAdapterStatus::NOT_SUPPORT;
}

DbAdapterStatus SqliteAdapterDataManager::GetAllKvStoreId(const std::string &appIdStr,
    std::vector<std::string> &storeIdList)
{
    // No need to get all kv store id
    ACCOUNT_LOGI("Sqlite GetAllKvStoreId not enabled.");
    return DbAdapterStatus::NOT_SUPPORT;
}

bool SqliteAdapterDataManager::IsKvStore()
{
    return false;
}

extern "C" {
IDbAdapterDataManager* CreateDataManager()
{
    return reinterpret_cast<IDbAdapterDataManager*>(new SqliteAdapterDataManager());
}

void DestroyDataManager(IDbAdapterDataManager* ptr)
{
    delete reinterpret_cast<SqliteAdapterDataManager*>(ptr);
}
};
} // AccountSA
} // OHOS
