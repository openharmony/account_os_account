/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "os_account_info_json_parser.h"
#include <string>
#include "json_utils.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
CJsonUnique ToJson(const OsAccountInfo &accountInfo)
{
    auto jsonObject = CreateJson();

    AddIntToJson(jsonObject, LOCAL_ID, accountInfo.localId_);
    AddStringToJson(jsonObject, LOCAL_NAME, accountInfo.localName_);
    AddStringToJson(jsonObject, SHORT_NAME, accountInfo.shortName_);
    AddIntToJson(jsonObject, TYPE, static_cast<int32_t>(accountInfo.type_));
    AddVectorStringToJson(jsonObject, CONSTRAINTS, accountInfo.constraints_);
    AddBoolToJson(jsonObject, IS_OS_ACCOUNT_VERIFIED, accountInfo.isVerified_);
    AddStringToJson(jsonObject, PHOTO, accountInfo.photo_);
    AddInt64ToJson(jsonObject, CREATE_TIME, accountInfo.createTime_);
    AddInt64ToJson(jsonObject, LAST_LOGGED_IN_TIME, accountInfo.lastLoginTime_);
    AddInt64ToJson(jsonObject, SERIAL_NUMBER, accountInfo.serialNumber_);

    AddBoolToJson(jsonObject, IS_ACTIVATED, accountInfo.isActivated_);
    AddBoolToJson(jsonObject, IS_ACCOUNT_COMPLETED, accountInfo.isCreateCompleted_);
    AddBoolToJson(jsonObject, TO_BE_REMOVED, accountInfo.toBeRemoved_);
    AddUint64ToJson(jsonObject, CREDENTIAL_ID, accountInfo.credentialId_);
    AddUint64ToJson(jsonObject, DISPLAY_ID, accountInfo.displayId_);
    AddBoolToJson(jsonObject, IS_FOREGROUND, accountInfo.isForeground_);
    AddBoolToJson(jsonObject, IS_LOGGED_IN, accountInfo.isLoggedIn_);
    AddBoolToJson(jsonObject, IS_DATA_REMOVABLE, accountInfo.isDataRemovable_);
    AddIntToJson(jsonObject, CREATOR_TYPE, accountInfo.creatorType_);

    auto domainInfoObject = CreateJson();
    AddStringToJson(domainInfoObject, DOMAIN_NAME, accountInfo.domainInfo_.domain_);
    AddStringToJson(domainInfoObject, DOMAIN_ACCOUNT_NAME, accountInfo.domainInfo_.accountName_);
    AddStringToJson(domainInfoObject, DOMAIN_ACCOUNT_ID, accountInfo.domainInfo_.accountId_);
    AddIntToJson(domainInfoObject, DOMAIN_ACCOUNT_STATUS, static_cast<int>(accountInfo.domainInfo_.status_));
    AddStringToJson(domainInfoObject, DOMAIN_ACCOUNT_CONFIG, accountInfo.domainInfo_.serverConfigId_);
    AddObjToJson(jsonObject, DOMAIN_INFO, domainInfoObject);

    return jsonObject;
}

bool FromJson(cJSON *jsonObject, OsAccountInfo &accountInfo)
{
    if (jsonObject == nullptr) {
        return false;
    }
    bool parseSuccess = GetDataByType<int>(jsonObject, LOCAL_ID, accountInfo.localId_);
    GetDataByType<std::string>(jsonObject, LOCAL_NAME, accountInfo.localName_);
    GetDataByType<std::string>(jsonObject, SHORT_NAME, accountInfo.shortName_);
    GetDataByType<OsAccountType>(jsonObject, TYPE, accountInfo.type_);
    GetDataByType<std::vector<std::string>>(jsonObject, CONSTRAINTS, accountInfo.constraints_);
    GetDataByType<bool>(jsonObject, IS_OS_ACCOUNT_VERIFIED, accountInfo.isVerified_);
    GetDataByType<std::string>(jsonObject, PHOTO, accountInfo.photo_);
    GetDataByType<int64_t>(jsonObject, CREATE_TIME, accountInfo.createTime_);
    GetDataByType<int64_t>(jsonObject, LAST_LOGGED_IN_TIME, accountInfo.lastLoginTime_);
    GetDataByType<int64_t>(jsonObject, SERIAL_NUMBER, accountInfo.serialNumber_);
    GetDataByType<bool>(jsonObject, IS_ACTIVATED, accountInfo.isActivated_);
    parseSuccess =
        parseSuccess && GetDataByType<bool>(jsonObject, IS_ACCOUNT_COMPLETED, accountInfo.isCreateCompleted_);
    GetDataByType<bool>(jsonObject, TO_BE_REMOVED, accountInfo.toBeRemoved_);
    GetDataByType<uint64_t>(jsonObject, CREDENTIAL_ID, accountInfo.credentialId_);
    GetDataByType<uint64_t>(jsonObject, DISPLAY_ID, accountInfo.displayId_);
    GetDataByType<bool>(jsonObject, IS_FOREGROUND, accountInfo.isForeground_);
    GetDataByType<bool>(jsonObject, IS_LOGGED_IN, accountInfo.isLoggedIn_);
    GetDataByType<bool>(jsonObject, IS_DATA_REMOVABLE, accountInfo.isDataRemovable_);
    GetDataByType<int32_t>(jsonObject, CREATOR_TYPE, accountInfo.creatorType_);

    CJson *typeJson = nullptr;
    GetDataByType<CJson *>(jsonObject, DOMAIN_INFO, typeJson);
    if (typeJson != nullptr) {
        GetDataByType<std::string>(typeJson, DOMAIN_NAME, accountInfo.domainInfo_.domain_);
        GetDataByType<std::string>(typeJson, DOMAIN_ACCOUNT_NAME, accountInfo.domainInfo_.accountName_);
        GetDataByType<std::string>(typeJson, DOMAIN_ACCOUNT_ID, accountInfo.domainInfo_.accountId_);
        GetDataByType<DomainAccountStatus>(typeJson, DOMAIN_ACCOUNT_STATUS, accountInfo.domainInfo_.status_);
        GetDataByType<std::string>(typeJson, DOMAIN_ACCOUNT_CONFIG, accountInfo.domainInfo_.serverConfigId_);
    }
    return parseSuccess;
}

CJsonUnique ToJson(const DomainAccountInfo &domainInfo)
{
    auto domainInfoObject = CreateJson();
    AddStringToJson(domainInfoObject, DOMAIN_NAME, domainInfo.domain_);
    AddStringToJson(domainInfoObject, DOMAIN_ACCOUNT_NAME, domainInfo.accountName_);
    AddStringToJson(domainInfoObject, DOMAIN_ACCOUNT_ID, domainInfo.accountId_);
    AddIntToJson(domainInfoObject, DOMAIN_ACCOUNT_STATUS, static_cast<int>(domainInfo.status_));
    AddStringToJson(domainInfoObject, DOMAIN_ACCOUNT_CONFIG, domainInfo.serverConfigId_);
    return domainInfoObject;
}

bool FromJson(cJSON *jsonObject, DomainAccountInfo &domainInfo)
{
    if (jsonObject == nullptr) {
        return false;
    }
    bool result = true;
    result &= GetDataByType<std::string>(jsonObject, DOMAIN_NAME, domainInfo.domain_);
    result &= GetDataByType<std::string>(jsonObject, DOMAIN_ACCOUNT_NAME, domainInfo.accountName_);
    result &= GetDataByType<std::string>(jsonObject, DOMAIN_ACCOUNT_ID, domainInfo.accountId_);
    result &= GetDataByType<DomainAccountStatus>(jsonObject, DOMAIN_ACCOUNT_STATUS, domainInfo.status_);
    result &= GetDataByType<std::string>(jsonObject, DOMAIN_ACCOUNT_CONFIG, domainInfo.serverConfigId_);
    return result;
}
} // namespace AccountSA
} // namespace OHOS