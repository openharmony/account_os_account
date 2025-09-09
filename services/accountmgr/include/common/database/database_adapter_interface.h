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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DATABASE_ADAPTER_INTERFACE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DATABASE_ADAPTER_INTERFACE_H

#include <errors.h>
#include <string>

namespace OHOS {
namespace AccountSA {
enum DbAdapterSecurityLevel : int32_t {
    INVALID_LABEL = -1,
    NO_LABEL,
    S0,
    S1,
    S2,
    S3_EX,
    S3,
    S4,
};

enum DbAdapterArea : int32_t {
    INVALID_AREA = -1,
    EL0,
    EL1,
    EL2,
    EL3,
    EL4
};

enum DbAdapterStatus : int32_t {
    SUCCESS = ERR_OK,
    IPC_ERROR,
    INTERNAL_ERROR,
    KEY_NOT_EXIST,
    NOT_SUPPORT,
};

struct DbAdapterOptions {
    bool encrypt = false;
    bool autoSync = false;
    DbAdapterSecurityLevel securityLevel = DbAdapterSecurityLevel::S1;
    DbAdapterArea area = DbAdapterArea::EL1;
    std::string baseDir;
};

struct DbAdapterEntry {
    std::string key;
    std::string value;
};

class IDbAdapterSingleStore {
public:
    virtual ~IDbAdapterSingleStore() = default;
    virtual DbAdapterStatus Get(const std::string &keyStr, std::string &valueStr) = 0;
    virtual DbAdapterStatus Delete(const std::string &keyStr) = 0;
    virtual DbAdapterStatus Put(const std::string &keyStr, const std::string &valueStr) = 0;
    virtual DbAdapterStatus GetEntries(const std::string subId,
        std::vector<DbAdapterEntry> &allEntries) = 0;
    virtual DbAdapterStatus PutBatch(const std::vector<DbAdapterEntry> &entries) = 0;
    virtual DbAdapterStatus Commit() = 0;
    virtual DbAdapterStatus Rollback() = 0;
    virtual DbAdapterStatus StartTransaction() = 0;
};

class IDbAdapterDataManager {
public:
    virtual ~IDbAdapterDataManager() = default;
    virtual DbAdapterStatus CloseKvStore(const std::string appIdStr,
        std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr) = 0;
    virtual DbAdapterStatus GetSingleKvStore(const DbAdapterOptions &options, const std::string &appIdStr,
        const std::string &storeIdStr, std::shared_ptr<IDbAdapterSingleStore> &kvStorePtr) = 0;
    virtual DbAdapterStatus DeleteKvStore(const std::string &appIdStr, const std::string &storeIdStr,
        const std::string &baseDir) = 0;
    virtual DbAdapterStatus GetAllKvStoreId(const std::string &appIdStr, std::vector<std::string> &storeIdList) = 0;
    virtual bool IsKvStore() = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DATABASE_ADAPTER_INTERFACE_H
