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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOAMIN_ACCOUNT_CALLBACK_ADAPTERS_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOAMIN_ACCOUNT_CALLBACK_ADAPTERS_H

#include "domain_account_callback.h"
#include "domain_account_common.h"
#include "get_access_token_callback.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
class GetAccessTokenCallbackAdapter final : public DomainAccountCallback {
public:
    GetAccessTokenCallbackAdapter(const std::shared_ptr<GetAccessTokenCallback> &callback);
    void OnResult(const int32_t errCode, Parcel &parcel) override;

private:
    std::shared_ptr<GetAccessTokenCallback> innerCallback_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOAMIN_ACCOUNT_CALLBACK_ADAPTERS_H
