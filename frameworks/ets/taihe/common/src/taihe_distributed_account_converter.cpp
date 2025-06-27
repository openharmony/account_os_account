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

#include "taihe_distributed_account_converter.h"
#include "account_log_wrapper.h"
#include "ani_common_want.h"
#include "ohos.account.distributedAccount.proj.hpp"
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

} // namespace

namespace OHOS {
namespace AccountSA {

DistributedInfo ConvertToDistributedInfoTH(const OhosAccountInfo& info)
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

} // namespace AccountSA
} // namespace OHOS
