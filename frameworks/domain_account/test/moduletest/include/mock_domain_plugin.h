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

#ifndef OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_PLUGIN_H
#define OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_PLUGIN_H

#include "domain_account_plugin.h"

namespace OHOS {
namespace AccountSA {
class MockDomainPlugin : public DomainAccountPlugin {
public:
    MockDomainPlugin();
    virtual ~MockDomainPlugin();
    void Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const std::shared_ptr<DomainAuthCallback> &callback) override;
    int32_t GetAuthProperty(const DomainAccountInfo &info, DomainAuthProperty &property) override;

private:
    int32_t remainingTimes_;
    int32_t freezingTime_;
};
}  // AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_PLUGIN_H