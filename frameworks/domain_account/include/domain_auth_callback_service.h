/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_AUTH_CALLBACK_SERVICE_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_AUTH_CALLBACK_SERVICE_H

#include "domain_auth_callback.h"
#include "domain_auth_callback_stub.h"

namespace OHOS {
namespace AccountSA {
class DomainAuthCallbackService : public DomainAuthCallbackStub {
public:
    explicit DomainAuthCallbackService(const std::shared_ptr<DomainAuthCallback> &callback);
    ~DomainAuthCallbackService() override;
    void OnResult(int32_t resultCode, const DomainAuthResult &result) override;

private:
    std::shared_ptr<DomainAuthCallback> innerCallback_;
    DISALLOW_COPY_AND_MOVE(DomainAuthCallbackService);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_AUTH_CALLBACK_SERVICE_H
