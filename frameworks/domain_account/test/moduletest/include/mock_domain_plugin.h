/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
        const std::shared_ptr<DomainAccountCallback> &callback) override;
    void AuthWithPopup(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback) override;
    void AuthWithToken(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback) override;
    void GetAuthStatusInfo(const DomainAccountInfo &info,
        const std::shared_ptr<DomainAccountCallback> &callback) override;
    virtual void GetDomainAccountInfo(const GetDomainAccountInfoOptions &options,
        const std::shared_ptr<DomainAccountCallback> &callback) override;
    void OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
        const std::shared_ptr<DomainAccountCallback> &callback) override;
    void OnAccountUnBound(const DomainAccountInfo &info,
        const std::shared_ptr<DomainAccountCallback> &callback) override;
    void IsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<DomainAccountCallback> &callback) override;
    void GetAccessToken(const DomainAccountInfo &domainInfo, const std::vector<uint8_t> &accountToken,
        const GetAccessTokenOptions &option, const std::shared_ptr<DomainAccountCallback> &callback) override;

private:
    void AuthCommonInterface(const DomainAccountInfo &info, const std::vector<uint8_t> &authData,
        const std::shared_ptr<DomainAccountCallback> &callback, AuthMode authMode);

private:
    int32_t remainingTimes_;
    int32_t freezingTime_;
};
}  // AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_PLUGIN_H