/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "domain_account_callback_adapters.h"

#include "account_log_wrapper.h"
#include "domain_account_common.h"
#include "get_access_token_callback.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
GetAccessTokenCallbackAdapter::GetAccessTokenCallbackAdapter(const std::shared_ptr<GetAccessTokenCallback> &callback)
    : innerCallback_(callback)
{}

void GetAccessTokenCallbackAdapter::OnResult(const int32_t errCode, Parcel &parcel)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    std::vector<uint8_t> accessToken;
    if (errCode == ERR_OK) {
        parcel.ReadUInt8Vector(&accessToken);
    }
    return innerCallback_->OnResult(errCode, accessToken);
}
}  // namespace AccountSA
}  // namespace OHOS