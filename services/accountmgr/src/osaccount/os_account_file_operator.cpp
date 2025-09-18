/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "os_account_file_operator.h"

#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include "account_hisysevent_adapter.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char KEY_TYPE_TO_CONSTRAINTS[] = "Type2Constraints";
const char KEY_CONSTRAINTS_LIST[] = "constraints";
const char IS_ALLOWED_CREATE_ADMIN[] = "IsAllowedCreateAdmin";
}

OsAccountFileOperator::OsAccountFileOperator()
{
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
}
OsAccountFileOperator::~OsAccountFileOperator()
{}

ErrCode OsAccountFileOperator::GetConstraintsByType(const int type, std::vector<std::string> &constraints)
{
    ACCOUNT_LOGD("Start");
    constraints.clear();
    std::string str;
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::OS_ACCOUNT_CONSTRAINT_CONFIG_PATH, str);
    if (errCode != ERR_OK) {
        return errCode;
    }
    auto configJson = CreateJsonFromString(str);
    CJson *typeJson = nullptr;
    bool ret = GetDataByType<CJson *>(configJson, KEY_TYPE_TO_CONSTRAINTS, typeJson);
    if (!ret) {
        ACCOUNT_LOGE("Failed to parse %{public}s", KEY_TYPE_TO_CONSTRAINTS);
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    GetDataByType<std::vector<std::string>>(typeJson, std::to_string(type), constraints);
    ACCOUNT_LOGD("End");
    return ERR_OK;
}

ErrCode OsAccountFileOperator::GetBaseOAConstraintsList(const int id, std::vector<std::string> &constraints)
{
    auto baseOsAccountConstraintsConfig = CreateJson();
    if (accountFileOperator_->IsExistFile(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        std::string baseUserConstraintsConfigStr;
        accountFileOperator_->GetFileContentByPath(
            Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, baseUserConstraintsConfigStr);
        baseOsAccountConstraintsConfig = CreateJsonFromString(baseUserConstraintsConfigStr);
        if (baseOsAccountConstraintsConfig == nullptr) {
            return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY;
        }
    }
    if (GetItemNum(baseOsAccountConstraintsConfig) == 0) {
        ACCOUNT_LOGE("BaseOsAccountConstraints data is empty");
        return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY;
    }
    GetDataByType<std::vector<std::string>>(baseOsAccountConstraintsConfig, std::to_string(id), constraints);
    return ERR_OK;
}

ErrCode OsAccountFileOperator::GetGlobalOAConstraintsList(std::vector<std::string> &constraints)
{
    auto globalOsAccountConstraintsConfig = CreateJson();
    if (accountFileOperator_->IsExistFile(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        std::string globalOsAccountConstraintsConfigStr;
        accountFileOperator_->GetFileContentByPath(
            Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, globalOsAccountConstraintsConfigStr);
        globalOsAccountConstraintsConfig = CreateJsonFromString(globalOsAccountConstraintsConfigStr);
        if (globalOsAccountConstraintsConfig == nullptr) {
            ACCOUNT_LOGE("GlobalOsAccountConstraints config is empty");
            REPORT_OS_ACCOUNT_FAIL(0, Constants::OPERATION_CONSTRAINT,
                ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_GLOBAL_CONSTRAINTS_FILE_EMPTY,
                "Global constraints config is empty");
            return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_GLOBAL_CONSTRAINTS_FILE_EMPTY;
        }
    }

    if (GetItemNum(globalOsAccountConstraintsConfig) == 0) {
        ACCOUNT_LOGE("GlobalOsAccountConstraints data is empty");
        REPORT_OS_ACCOUNT_FAIL(0, Constants::OPERATION_CONSTRAINT,
            ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_GLOBAL_CONSTRAINTS_FILE_EMPTY,
            "Global constraints data is empty");
        return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_GLOBAL_CONSTRAINTS_FILE_EMPTY;
    }
    GetDataByType<std::vector<std::string>>(globalOsAccountConstraintsConfig, Constants::ALL_GLOBAL_CONSTRAINTS,
                                            constraints);
    return ERR_OK;
}

ErrCode OsAccountFileOperator::GetSpecificOAConstraintsList(const int id, std::vector<std::string> &constraints)
{
    auto specificOsAccountConstraintsConfig = CreateJson();
    if (accountFileOperator_->IsExistFile(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        std::string specificOsAccountConstraintsConfigStr;
        accountFileOperator_->GetFileContentByPath(
            Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, specificOsAccountConstraintsConfigStr);
        specificOsAccountConstraintsConfig = CreateJsonFromString(specificOsAccountConstraintsConfigStr);
        if (specificOsAccountConstraintsConfig == nullptr) {
            ACCOUNT_LOGE("SpecificOsAccountConstraints config is empty");
            REPORT_OS_ACCOUNT_FAIL(0, Constants::OPERATION_CONSTRAINT,
                ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY,
                "Specific constraints config is empty");
            return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY;
        }
    }

    if (GetItemNum(specificOsAccountConstraintsConfig) == 0) {
        ACCOUNT_LOGE("SpecificOsAccountConstraints data is empty");
        REPORT_OS_ACCOUNT_FAIL(0, Constants::OPERATION_CONSTRAINT,
            ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY,
            "Specific constraints data is empty");
        return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY;
    }
    CJson *SpecificOAConstraintsData = nullptr;
    GetDataByType<CJson *>(specificOsAccountConstraintsConfig, std::to_string(id), SpecificOAConstraintsData);
    GetDataByType<std::vector<std::string>>(SpecificOAConstraintsData, Constants::ALL_SPECIFIC_CONSTRAINTS,
                                            constraints);
    return ERR_OK;
}

ErrCode OsAccountFileOperator::GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    isMultiOsAccountEnable = true;
    std::string str;
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::OS_ACCOUNT_CONSTRAINT_CONFIG_PATH, str);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get file content, errCode: %{public}d", errCode);
        return errCode;
    }
    auto configJson = CreateJsonFromString(str);
    bool ret = GetDataByType<bool>(configJson, Constants::IS_MULTI_OS_ACCOUNT_ENABLE, isMultiOsAccountEnable);
    if (!ret) {
        ACCOUNT_LOGE("Failed to parse IsMultiOsAccountEnabled");
    }
    return ERR_OK;
}

ErrCode OsAccountFileOperator::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    isAllowedCreateAdmin = false;
    std::string str;
    ErrCode errCode = accountFileOperator_->GetFileContentByPath(Constants::OS_ACCOUNT_CONSTRAINT_CONFIG_PATH, str);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get file content, errCode: %{public}d", errCode);
        return errCode;
    }
    auto configJson = CreateJsonFromString(str);
    bool ret = GetDataByType<bool>(configJson, IS_ALLOWED_CREATE_ADMIN, isAllowedCreateAdmin);
    if (!ret) {
        ACCOUNT_LOGE("Failed to parse IsAllowedCreateAdmin");
    }
    return ERR_OK;
}

bool OsAccountFileOperator::CheckConstraints(const std::vector<std::string> &constraints)
{
    std::string str;
    ErrCode errCode =
        accountFileOperator_->GetFileContentByPath(Constants::OS_ACCOUNT_CONSTRAINT_DEFINITION_PATH, str);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get the list of constraints, errCode: %{public}d", errCode);
        return false;
    }
    auto constraintSetJson = CreateJsonFromString(str);
    std::set<std::string> constraintSet;
    bool ret = GetDataByType<std::set<std::string>>(constraintSetJson, KEY_CONSTRAINTS_LIST, constraintSet);
    if (!ret) {
        ACCOUNT_LOGE("Failed to parse constraint definition");
        return false;
    }
    for (auto it = constraints.begin(); it != constraints.end(); it++) {
        if (std::find(constraintSet.begin(), constraintSet.end(), *it) == constraintSet.end()) {
            ACCOUNT_LOGE("Invalid constraint: %{public}s", (*it).c_str());
            return false;
        }
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS