/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "taihe_common.h"
#include "account_log_wrapper.h"
#include "ani.h"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace AccountSA {

bool IsAccountIdValid(int32_t accountId)
{
    if (accountId < 0) {
        ACCOUNT_LOGI("The account id is invalid");
        return false;
    }
    return true;
}

bool IsSystemApp()
{
    uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
}

bool CheckPermission(const std::string &permissionName)
{
    OHOS::Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetSelfTokenID();
    ErrCode result = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    return result == OHOS::Security::AccessToken::TypePermissionState::PERMISSION_GRANTED;
}

void GenerateEmptyAdditionRecord(taihe::optional<uintptr_t> &additional)
{
    ani_env *env = get_env();
    if (env == nullptr) {
        ACCOUNT_LOGE("Env is nullptr.");
        return;
    }
    ani_class cls;
    ani_status status = env->FindClass("std.core.Record", &cls);
    if (status != ANI_OK) {
        ACCOUNT_LOGE("Record not found, ret:%{public}d.", status);
        return;
    }
    ani_method ctorMethod = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":", &ctorMethod);
    if (status != ANI_OK) {
        ACCOUNT_LOGE("Ctor not found, ret: %{public}d.", status);
        return;
    }
    ani_object obj = nullptr;
    status = env->Object_New(cls, ctorMethod, &obj);
    if (status != ANI_OK) {
        ACCOUNT_LOGE("Create object failed, ret: %{public}d.", status);
        return;
    }
    additional = taihe::optional<uintptr_t>(std::in_place_t{}, reinterpret_cast<uintptr_t>(obj));
    return;
}

void GetAdditionalInfo(const std::string &additionInfo, taihe::optional<uintptr_t> &additional)
{
    if (!additionInfo.empty()) {
        auto additionInfoJson = nlohmann::json::parse(additionInfo, nullptr, false);
        if (!additionInfoJson.is_discarded()) {
            ani_env *env = get_env();
            AAFwk::WantParams additionInfoWantParams;
            from_json(additionInfoJson, additionInfoWantParams);
            ani_ref additionInfoRef = AppExecFwk::WrapWantParams(env, additionInfoWantParams);
            if (additionInfoRef != nullptr) {
                additional = taihe::optional<uintptr_t>(std::in_place_t{},
                    reinterpret_cast<uintptr_t>(additionInfoRef));
                return;
            } else {
                ACCOUNT_LOGE("AdditionInfoRef is null.");
            }
        } else {
            ACCOUNT_LOGE("AdditionInfoJson parse error.");
        }
    }
    GenerateEmptyAdditionRecord(additional);
}

ohos::account::osAccount::DomainAccountInfo ConvertDomainInfo(const AccountSA::DomainAccountInfo &sourceInfo)
{
    taihe::optional<uintptr_t> additional = taihe::optional<uintptr_t>();
    GetAdditionalInfo(sourceInfo.additionInfo_, additional);

    return ohos::account::osAccount::DomainAccountInfo{
        .domain = taihe::string(sourceInfo.domain_.c_str()),
        .accountName = taihe::string(sourceInfo.accountName_.c_str()),
        .accountId = taihe::optional<taihe::string>(std::in_place_t{}, sourceInfo.accountId_.c_str()),
        .isAuthenticated = taihe::optional<bool>(std::in_place_t{},
            (sourceInfo.status_ != AccountSA::DomainAccountStatus::LOGOUT) &&
            (sourceInfo.status_ < AccountSA::DomainAccountStatus::LOG_END)),
        .serverConfigId = taihe::optional<taihe::string>(std::in_place_t{}, sourceInfo.serverConfigId_.c_str()),
        .additionalInfo = additional};
}
}
}