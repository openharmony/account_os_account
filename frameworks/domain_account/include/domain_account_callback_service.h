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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CALLBACK_SERVICE_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CALLBACK_SERVICE_H

#include "domain_account_callback.h"
#include "domain_account_callback_stub.h"

namespace OHOS {
namespace AccountSA {
using DomainAccountCallbackFunc = std::function<void(const int32_t, Parcel &)>;
class DomainAccountCallbackService : public DomainAccountCallbackStub {
public:
    DomainAccountCallbackService(const std::shared_ptr<DomainAccountCallback> &callback);
    DomainAccountCallbackService(const DomainAccountCallbackFunc &callback);
    ~DomainAccountCallbackService() override;
    void OnResult(const int32_t errCode, Parcel &parcel) override;

private:
    std::shared_ptr<DomainAccountCallback> innerCallback_;
    DomainAccountCallbackFunc callback_;
    DISALLOW_COPY_AND_MOVE(DomainAccountCallbackService);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CALLBACK_SERVICE_H