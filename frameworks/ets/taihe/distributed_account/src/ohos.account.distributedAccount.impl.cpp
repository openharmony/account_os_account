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

#include "account_log_wrapper.h"
#include "ani_common_want.h"
#include "napi_account_error.h"
#include "ohos.account.distributedAccount.impl.hpp"
#include "ohos.account.distributedAccount.proj.hpp"
#include "ohos_account_kits.h"
#include "stdexcept"
#include "taihe/runtime.hpp"

using namespace taihe;
using namespace ohos::account::distributedAccount;
using namespace OHOS;

namespace {
using OHOS::AccountSA::ACCOUNT_LABEL;

static DistributedAccountStatus GetDistributedAccountStatus(int32_t status)
{
    DistributedAccountStatus loginStatus(DistributedAccountStatus::key_t::LOGGED_IN);
    int32_t loginStatusId = loginStatus.get_value();
    if (status == loginStatusId) {
        return DistributedAccountStatus(DistributedAccountStatus::key_t::LOGGED_IN);
    }
    return DistributedAccountStatus(DistributedAccountStatus::key_t::NOT_LOGGED_IN);
}

DistributedInfo ConvertToDistributedInfoTH(const AccountSA::OhosAccountInfo &info)
{
ACCOUNT_LOGI("ohosAccountInfo.name_: %{public}s, uid_: %{public}s, nickname_: %{public}s, avatar_: %{public}s",
    info.name_.c_str(), info.uid_.c_str(), info.nickname_.c_str(), info.avatar_.c_str());
ACCOUNT_LOGI("ohosAccountInfo.scalableData_ is empty: %{public}d, status_: %{public}d",
    info.scalableData_.GetParams().IsEmpty(), info.status_);
DistributedInfo ret = DistributedInfo{
    .name = taihe::string(info.name_.c_str()),
    .id = taihe::string(info.uid_.c_str()),
    .nickname = optional<string>(std::in_place_t{}, info.nickname_.c_str()),
    .avatar = optional<string>(std::in_place_t{}, info.avatar_.c_str()),
    .status = optional<DistributedAccountStatus>(std::in_place_t{}, GetDistributedAccountStatus(info.status_)),
    .scalableData = optional<uintptr_t>(std::nullopt),
};
if (info.scalableData_.GetParams().IsEmpty()) {
    return ret;
}
ani_env *env = get_env();
auto scalableData = AppExecFwk::WrapWantParams(env, info.scalableData_.GetParams());
if (scalableData == nullptr) {
    ACCOUNT_LOGE("WrapWantParams get nullptr");
}
return ret;
}

class DistributedAccountAbilityImpl {
public:
    DistributedAccountAbilityImpl() {}

    DistributedInfo GetOsAccountDistributedInfoSync()
    {
        AccountSA::OhosAccountInfo info;
        ErrCode err = AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(info);
        if (err != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(err);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return ConvertToDistributedInfoTH(info);
        }
        return ConvertToDistributedInfoTH(info);
    }
};

DistributedAccountAbility getDistributedAccountAbility()
{
    return make_holder<DistributedAccountAbilityImpl, DistributedAccountAbility>();
}
} // namespace

namespace OHOS {
namespace AccountSA {

DistributedInfo CreateDistributedInfoFromAccountInfo(const OhosAccountInfo& info)
{
    return ConvertToDistributedInfoTH(info);
}

} // namespace AccountSA
} // namespace OHOS

TH_EXPORT_CPP_API_getDistributedAccountAbility(getDistributedAccountAbility);
 