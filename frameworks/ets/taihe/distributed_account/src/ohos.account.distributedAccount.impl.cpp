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
#include "taihe_distributed_account_converter.h"

using namespace taihe;
using namespace ohos::account::distributedAccount;
using namespace OHOS;

namespace {
using OHOS::AccountSA::ACCOUNT_LABEL;

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
        return OHOS::AccountSA::ConvertToDistributedInfoTH(info);
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
