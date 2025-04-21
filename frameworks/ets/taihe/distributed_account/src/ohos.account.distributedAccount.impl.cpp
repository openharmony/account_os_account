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

#include "ani_common_want.h"
#include "napi_account_error.h"
#include "account_error_no.h"
#include "ohos.account.distributedAccount.impl.hpp"
#include "ohos.account.distributedAccount.proj.hpp"
#include "ohos_account_kits.h"
#include "stdexcept"
#include "taihe/runtime.hpp"

using namespace taihe;
using namespace ohos::account::distributedAccount;
using namespace OHOS;

namespace {
static DistributedAccountStatus GetDistributedAccountStatus(int32_t status)
{
    DistributedAccountStatus loginStatus(DistributedAccountStatus::key_t::LOGGED_IN);
    int32_t loginStatusId = loginStatus.get_value();
    if (status == loginStatusId) {
        return DistributedAccountStatus(DistributedAccountStatus::key_t::LOGGED_IN);
    }
    return DistributedAccountStatus(DistributedAccountStatus::key_t::NOT_LOGGED_IN);
}

class DistributedInfoImpl {
public:
    DistributedInfoImpl() {}

    explicit DistributedInfoImpl(const AccountSA::OhosAccountInfo &info)
    {
        this->name_ = info.name_;
        this->id_ = info.uid_;
        this->nickName_ = optional<string>(std::in_place_t{}, info.nickname_);
        this->avatar_ = optional<string>(std::in_place_t{}, info.avatar_);
        this->status_ =
            optional<DistributedAccountStatus>(std::in_place_t{}, GetDistributedAccountStatus(info.status_));
        ani_env *env = get_env();
        ani_ref wantParams = AppExecFwk::WrapWantParams(env, info.scalableData_.GetParams());
        this->scalableData_ = optional<uintptr_t>(std::in_place_t{}, reinterpret_cast<uintptr_t>(wantParams));
    }

    string GetName()
    {
        return this->name_;
    }

    void SetName(string_view name)
    {
        this->name_ = name;
    }

    string GetId()
    {
        return this->id_;
    }

    void SetId(string_view id)
    {
        this->id_ = id;
    }

    string GetEvent()
    {
        return this->event_;
    }

    void SetEvent(string_view event)
    {
        this->event_ = event;
    }

    optional<string> GetNickname()
    {
        return this->nickName_;
    }

    void SetNickname(string_view nickName)
    {
        this->nickName_ = optional<string>(std::in_place_t{}, nickName);
    }

    optional<string> GetAvatar()
    {
        return this->avatar_;
    }

    void SetAvatar(string_view avatar)
    {
        this->avatar_ = optional<string>(std::in_place_t{}, avatar);
    }

    optional<DistributedAccountStatus> GetStatus()
    {
        return this->status_;
    }

    optional<uintptr_t> GetScalableData()
    {
        return this->scalableData_;
    }

    void SetScalableData(uintptr_t scalableData)
    {
        this->scalableData_ = optional<uintptr_t>(std::in_place_t{}, scalableData);
    }

private:
    string name_ = "";
    string id_ = "";
    string event_ = "";
    optional<string> nickName_ = optional<string>(std::nullopt);
    optional<string> avatar_ = optional<string>(std::nullopt);
    optional<DistributedAccountStatus> status_ = optional<DistributedAccountStatus>(std::nullopt);
    optional<uintptr_t> scalableData_ = optional<uintptr_t>(std::nullopt);
};

class DistributedAccountAbilityImpl {
public:
    DistributedAccountAbilityImpl() {}

    DistributedInfo getOsAccountDistributedInfoSync()
    {
        AccountSA::OhosAccountInfo info;
        ErrCode err = AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(info);
        if (err != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(err);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return make_holder<DistributedInfoImpl, DistributedInfo>();
        }
        return make_holder<DistributedInfoImpl, DistributedInfo>(info);
    }
};

DistributedAccountAbility getDistributedAccountAbility()
{
    return make_holder<DistributedAccountAbilityImpl, DistributedAccountAbility>();
}
} // namespace

namespace OHOS {
namespace AccountSA {

DistributedInfo CreateDistributedInfo()
{
    return make_holder<DistributedInfoImpl, DistributedInfo>();
}

DistributedInfo CreateDistributedInfoFromAccountInfo(const OhosAccountInfo& info)
{
    return make_holder<DistributedInfoImpl, DistributedInfo>(info);
}

} // namespace AccountSA
} // namespace OHOS

TH_EXPORT_CPP_API_getDistributedAccountAbility(getDistributedAccountAbility);
