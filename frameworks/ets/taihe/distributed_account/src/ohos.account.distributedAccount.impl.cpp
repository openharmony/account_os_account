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
    ani_env *env = get_env();

    DistributedInfo ret = DistributedInfo{
        .name = info.name_,
        .id = info.uid_,
        .nickname = optional<string>(std::in_place_t{}, info.nickname_),
        .avatar = optional<string>(std::in_place_t{}, info.avatar_),
        .status = optional<DistributedAccountStatus>(std::in_place_t{}, GetDistributedAccountStatus(info.status_)),
        .scalableData = optional<uintptr_t>(std::nullopt),
    };

    auto scalableData = AppExecFwk::WrapWantParams(env, info.scalableData_.GetParams());
    if (scalableData == nullptr) {
        ACCOUNT_LOGE("WrapWantParams get nullptr");
        return ret;
    }
    ret.scalableData = optional<uintptr_t>(std::in_place_t{}, reinterpret_cast<uintptr_t>(scalableData));
    return ret;
}

AccountSA::OhosAccountInfo ConvertToOhosAccountInfoTH(const DistributedInfo &info)
{
    std::string name(info.name.data(), info.name.size());
    std::string id(info.id.data(), info.id.size());
    std::int32_t status = info.status->get_value();
    std::string event(info.event.data(), info.event.size());

    AccountSA::OhosAccountInfo ret;
    ret.name_ = name;
    ret.uid_ = id;
    ret.status_ = status;
    ret.name_ = name;

    if (info.nickname.has_value()) {
        ret.nickname_ = std::string(info.nickname.value().data(), info.nickname.value().size());
    }
    if (info.avatar.has_value()) {
        ret.avatar_ = std::string(info.avatar.value().data(), info.avatar.value().size());
    }
    if (info.scalableData.has_value()) {
        AAFwk::Want* wantPtr = reinterpret_cast<AAFwk::Want*>(info.scalableData.value());
        auto params = wantPtr->GetParams();
        ret.scalableData_.SetParams(params);
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
        }
        return ConvertToDistributedInfoTH(info);
    }

    DistributedInfo GetOsAccountDistributedInfoByLocalIdSync(int32_t localId)
    {
        AccountSA::OhosAccountInfo info;
        ErrCode err = AccountSA::OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, info);
        if (err != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(err);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return ConvertToDistributedInfoTH(info);
    }

    void SetOsAccountDistributedInfoSync(DistributedInfo const& accountInfo)
    {
        std::string event(accountInfo.event.data(), accountInfo.event.size());
        AccountSA::OhosAccountInfo info = ConvertToOhosAccountInfoTH(accountInfo);
        ErrCode err = AccountSA::OhosAccountKits::GetInstance().SetOhosAccountInfo(info, event);
        if (err != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(err);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void SetOsAccountDistributedInfoByLocalIdSync(int32_t localId, DistributedInfo const& distributedInfo)
    {
        std::string event(distributedInfo.event.data(), distributedInfo.event.size());
        AccountSA::OhosAccountInfo info = ConvertToOhosAccountInfoTH(distributedInfo);
        ErrCode err = AccountSA::OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(localId, info, event);
        if (err != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(err);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }
};
DistributedAccountAbility getDistributedAccountAbility()
{
    return make_holder<DistributedAccountAbilityImpl, DistributedAccountAbility>();
}
} // namespace

namespace OHOS {
namespace AccountSA {

DistributedInfo CreateDistributedInfoFromAccountInfo(const OhosAccountInfo &info)
{
    return ConvertToDistributedInfoTH(info);
}

} // namespace AccountSA
} // namespace OHOS

TH_EXPORT_CPP_API_getDistributedAccountAbility(getDistributedAccountAbility);
