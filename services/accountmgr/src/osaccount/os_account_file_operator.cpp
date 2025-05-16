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
    Json configJson = Json::parse(str, nullptr, false);
    Json typeJson;
    bool ret = OHOS::AccountSA::GetDataByType<Json>(configJson, configJson.end(), KEY_TYPE_TO_CONSTRAINTS, typeJson,
        OHOS::AccountSA::JsonType::OBJECT);
    if (!ret) {
        ACCOUNT_LOGE("Failed to parse %{public}s", KEY_TYPE_TO_CONSTRAINTS);
        return ERR_ACCOUNT_COMMON_BAD_JSON_FORMAT_ERROR;
    }
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        typeJson, typeJson.end(), std::to_string(type), constraints, OHOS::AccountSA::JsonType::ARRAY);
    ACCOUNT_LOGD("End");
    return ERR_OK;
}

ErrCode OsAccountFileOperator::GetBaseOAConstraintsList(const int id, std::vector<std::string> &constraints)
{
    Json baseOsAccountConstraintsConfig;
    if (accountFileOperator_->IsExistFile(Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        std::string baseUserConstraintsConfigStr;
        accountFileOperator_->GetFileContentByPath(
            Constants::BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH, baseUserConstraintsConfigStr);
        baseOsAccountConstraintsConfig = Json::parse(baseUserConstraintsConfigStr, nullptr, false);
        if (baseOsAccountConstraintsConfig.is_discarded()) {
            return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY;
        }
    }
    if (baseOsAccountConstraintsConfig.size() == 0) {
        ACCOUNT_LOGE("BaseOsAccountConstraints data is empty");
        return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY;
    }
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(baseOsAccountConstraintsConfig,
        baseOsAccountConstraintsConfig.end(),
        std::to_string(id),
        constraints,
        OHOS::AccountSA::JsonType::ARRAY);
    return ERR_OK;
}

ErrCode OsAccountFileOperator::GetGlobalOAConstraintsList(std::vector<std::string> &constraints)
{
    Json globalOsAccountConstraintsConfig;
    if (accountFileOperator_->IsExistFile(Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        std::string globalOsAccountConstraintsConfigStr;
        accountFileOperator_->GetFileContentByPath(
            Constants::GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH, globalOsAccountConstraintsConfigStr);
        globalOsAccountConstraintsConfig = Json::parse(globalOsAccountConstraintsConfigStr, nullptr, false);
        if (globalOsAccountConstraintsConfig.is_discarded()) {
            return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_GLOBAL_CONSTRAINTS_FILE_EMPTY;
        }
    }

    if (globalOsAccountConstraintsConfig.size() == 0) {
        ACCOUNT_LOGE("GlobalOsAccountConstraints data is empty");
        return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_GLOBAL_CONSTRAINTS_FILE_EMPTY;
    }
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(globalOsAccountConstraintsConfig,
        globalOsAccountConstraintsConfig.end(),
        Constants::ALL_GLOBAL_CONSTRAINTS,
        constraints,
        OHOS::AccountSA::JsonType::ARRAY);
    return ERR_OK;
}

ErrCode OsAccountFileOperator::GetSpecificOAConstraintsList(const int id, std::vector<std::string> &constraints)
{
    Json specificOsAccountConstraintsConfig;
    if (accountFileOperator_->IsExistFile(Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        std::string specificOsAccountConstraintsConfigStr;
        accountFileOperator_->GetFileContentByPath(
            Constants::SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH, specificOsAccountConstraintsConfigStr);
        specificOsAccountConstraintsConfig = Json::parse(specificOsAccountConstraintsConfigStr, nullptr, false);
        if (specificOsAccountConstraintsConfig.is_discarded()) {
            return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY;
        }
    }

    if (specificOsAccountConstraintsConfig.size() == 0) {
        ACCOUNT_LOGE("GlobalOsAccountConstraints data is empty");
        return ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY;
    }
    Json SpecificOAConstraintsData;
    OHOS::AccountSA::GetDataByType<Json>(specificOsAccountConstraintsConfig,
        specificOsAccountConstraintsConfig.end(),
        std::to_string(id),
        SpecificOAConstraintsData,
        OHOS::AccountSA::JsonType::OBJECT);
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(SpecificOAConstraintsData,
        SpecificOAConstraintsData.end(),
        Constants::ALL_SPECIFIC_CONSTRAINTS,
        constraints,
        OHOS::AccountSA::JsonType::ARRAY);
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
    Json configJson = Json::parse(str, nullptr, false);
    bool ret = OHOS::AccountSA::GetDataByType<Json>(configJson, configJson.end(),
        Constants::IS_MULTI_OS_ACCOUNT_ENABLE, isMultiOsAccountEnable, OHOS::AccountSA::JsonType::BOOLEAN);
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
    Json configJson = Json::parse(str, nullptr, false);
    bool ret = OHOS::AccountSA::GetDataByType<Json>(configJson, configJson.end(), IS_ALLOWED_CREATE_ADMIN,
        isAllowedCreateAdmin, OHOS::AccountSA::JsonType::BOOLEAN);
    if (!ret) {
        ACCOUNT_LOGE("Failed to parse IsMultiOsAccountEnabled");
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
    Json constraintSetJson = Json::parse(str, nullptr, false);
    std::set<std::string> constraintSet;
    bool ret = OHOS::AccountSA::GetDataByType<std::set<std::string>>(constraintSetJson,
        constraintSetJson.end(), KEY_CONSTRAINTS_LIST, constraintSet, OHOS::AccountSA::JsonType::ARRAY);
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