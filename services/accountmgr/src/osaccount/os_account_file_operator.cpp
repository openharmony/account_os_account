/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "os_account_constants.h"

#include "os_account_file_operator.h"
namespace OHOS {
namespace AccountSA {
OsAccountFileOperator::OsAccountFileOperator()
{
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
    isAlreadyInit_ = false;
    constratinsList_.clear();
}
OsAccountFileOperator::~OsAccountFileOperator()
{}
void OsAccountFileOperator::Init()
{
    std::string constraintsConfigStr;
    if (accountFileOperator_->IsExistFile(Constants::OSACCOUNT_CONSTRAINTS_JSON_PATH)) {
        accountFileOperator_->GetFileContentByPath(Constants::OSACCOUNT_CONSTRAINTS_JSON_PATH, constraintsConfigStr);
        constraintsConfig_ = Json::parse(constraintsConfigStr, nullptr, false);
        isAlreadyInit_ = true;
    } else {
        isAlreadyInit_ = false;
    }
    std::string constratinsListColloctingStr;
    if (accountFileOperator_->IsExistFile(Constants::CONSTRAINTS_LIST_JSON_PATH)) {
        accountFileOperator_->GetFileContentByPath(Constants::CONSTRAINTS_LIST_JSON_PATH, constratinsListColloctingStr);
        Json constratinsListCollocting = Json::parse(constratinsListColloctingStr, nullptr, false);
        OHOS::AccountSA::GetDataByType<std::vector<std::string>>(constratinsListCollocting,
            constratinsListCollocting.end(),
            Constants::CONSTANS_LITE,
            constratinsList_,
            OHOS::AccountSA::JsonType::ARRAY);
    }
}

ErrCode OsAccountFileOperator::GetConstraintsByType(const int type, std::vector<std::string> &constratins)
{
    ACCOUNT_LOGI("OsAccountFileOperator GetConstraintsByType Start");
    if (!isAlreadyInit_) {
        return ERR_OS_ACCOUNT_SERVICE_OS_FILE_GET_CONFIG_ERROR;
    }
    std::vector<std::string> typeList;
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        constraintsConfig_, constraintsConfig_.end(), Constants::TYPE_LIST, typeList, OHOS::AccountSA::JsonType::ARRAY);
    if (std::find(typeList.begin(), typeList.end(), std::to_string(type)) == typeList.end()) {
        return ERR_OS_ACCOUNT_SERVICE_CONTROL_GET_TYPE_ERROR;
    }
    Json typeJson;
    OHOS::AccountSA::GetDataByType<Json>(constraintsConfig_,
        constraintsConfig_.end(),
        Constants::USER_CONSTRATINTS_TEMPLATE,
        typeJson,
        OHOS::AccountSA::JsonType::OBJECT);
    constratins.clear();
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        typeJson, typeJson.end(), std::to_string(type), constratins, OHOS::AccountSA::JsonType::ARRAY);
    ACCOUNT_LOGI("OsAccountFileOperator GetConstraintsByType End");
    return ERR_OK;
}

ErrCode OsAccountFileOperator::GetIsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    if (!isAlreadyInit_) {
        return ERR_OS_ACCOUNT_SERVICE_OS_FILE_GET_CONFIG_ERROR;
    }
    OHOS::AccountSA::GetDataByType<Json>(constraintsConfig_,
        constraintsConfig_.end(),
        Constants::IS_MULTI_OS_ACCOUNT_ENABLE,
        isMultiOsAccountEnable,
        OHOS::AccountSA::JsonType::BOOLEAN);
    return ERR_OK;
}

ErrCode OsAccountFileOperator::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    if (!isAlreadyInit_) {
        return ERR_OS_ACCOUNT_SERVICE_OS_FILE_GET_CONFIG_ERROR;
    }
    OHOS::AccountSA::GetDataByType<Json>(constraintsConfig_,
        constraintsConfig_.end(),
        Constants::IS_ALLOWED_CREATE_ADMIN,
        isAllowedCreateAdmin,
        OHOS::AccountSA::JsonType::BOOLEAN);
    return ERR_OK;
}

ErrCode OsAccountFileOperator::IsConstrarionsInTypeList(const std::vector<std::string> &constrains, bool &isExists)
{
    if (constratinsList_.size() == 0) {
        return ERR_OS_ACCOUNT_SERVICE_OS_FILE_GET_CONSTRATIONS_LITS_ERROR;
    }
    isExists = true;
    for (auto it = constrains.begin(); it != constrains.end(); it++) {
        if (std::find(constratinsList_.begin(), constratinsList_.end(), *it) == constratinsList_.end()) {
            isExists = false;
        }
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS