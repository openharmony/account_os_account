/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MOCK_IACCOUNT_IAM_H
#define MOCK_IACCOUNT_IAM_H

#include <gmock/gmock.h>
#include "iaccount_i_a_m.h"

namespace OHOS {
namespace AccountTest {
class MockIAccountIAM : public AccountSA::IAccountIAM {
public:
    MOCK_METHOD2(OpenSession, ErrCode(int32_t userId, std::vector<uint8_t>& challenge));
    MOCK_METHOD1(CloseSession, ErrCode(int32_t userId));
    MOCK_METHOD3(AddCredential, ErrCode(int32_t userId,
        const AccountSA::CredentialParametersIam& credInfoIam, const sptr<AccountSA::IIDMCallback>& idmCallback));
    MOCK_METHOD3(UpdateCredential, ErrCode(int32_t userId,
        const AccountSA::CredentialParametersIam& credInfoIam, const sptr<AccountSA::IIDMCallback>& idmCallback));
    MOCK_METHOD1(Cancel, ErrCode(int32_t userId));
    MOCK_METHOD4(DelCred, ErrCode(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t>& authToken, const sptr<AccountSA::IIDMCallback>& idmCallback));
    MOCK_METHOD3(DelUser, ErrCode(int32_t userId,
        const std::vector<uint8_t>& authToken, const sptr<AccountSA::IIDMCallback>& idmCallback));
    MOCK_METHOD3(GetCredentialInfo, ErrCode(int32_t userId, int32_t authTypeInt,
        const sptr<AccountSA::IGetCredInfoCallback>& getCredInfoCallback));
    MOCK_METHOD2(PrepareRemoteAuth, ErrCode(const std::string& remoteNetworkId,
        const sptr<AccountSA::IPreRemoteAuthCallback>& preRemoteAuthCallback));
    MOCK_METHOD3(AuthUser, ErrCode(const AccountSA::AuthParam& authParam,
        const sptr<AccountSA::IIDMCallback>& idmCallback, uint64_t& contextId));
    MOCK_METHOD1(CancelAuth, ErrCode(uint64_t contextId));
    MOCK_METHOD3(GetAvailableStatus, ErrCode(
        int32_t authTypeInt, uint32_t authTrustLevelInt, int32_t& status));
    MOCK_METHOD3(GetProperty, ErrCode(int32_t userId, const AccountSA::GetPropertyRequestIam& request,
        const sptr<AccountSA::IGetSetPropCallback>& getSetPropCallback));
    MOCK_METHOD3(GetPropertyByCredentialId, ErrCode(uint64_t credentialId,
        const std::vector<int32_t>& keysInt, const sptr<AccountSA::IGetSetPropCallback>& getSetPropCallback));
    MOCK_METHOD3(SetProperty, ErrCode(int32_t userId, const AccountSA::SetPropertyRequestIam& request,
        const sptr<AccountSA::IGetSetPropCallback>& getSetPropCallback));
    MOCK_METHOD3(GetEnrolledId, ErrCode(int32_t accountId, int32_t authTypeInt,
        const sptr<AccountSA::IGetEnrolledIdCallback>& getEnrolledIdCallback));
    MOCK_METHOD2(GetAccountState, ErrCode(int32_t userId, int32_t& funcResult));
    MOCK_METHOD4(SetDomainAuthUnlockEnabled, ErrCode(int32_t localId,
        const std::vector<uint8_t>& token, const std::vector<uint8_t>& secret, int32_t enabled));

    sptr<IRemoteObject> AsObject() override { return nullptr; }
};
}  // namespace AccountTest
}  // namespace OHOS
#endif  // MOCK_IACCOUNT_IAM_H
