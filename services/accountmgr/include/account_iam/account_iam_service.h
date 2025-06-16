/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_SERVICE_H

#include <vector>

#include "account_error_no.h"
#include "account_i_a_m_stub.h"

namespace OHOS {
namespace AccountSA {
class AccountIAMService : public AccountIAMStub {
public:
    AccountIAMService();
    ~AccountIAMService() override;

    int32_t OpenSession(int32_t userId, std::vector<uint8_t>& challenge) override;
    int32_t CloseSession(int32_t userId) override;
    int32_t AddCredential(
        int32_t userId, const CredentialParametersIam& credInfoIam, const sptr<IIDMCallback>& idmCallback) override;
    int32_t UpdateCredential(
        int32_t userId, const CredentialParametersIam& credInfoIam, const sptr<IIDMCallback>& idmCallback) override;
    int32_t Cancel(int32_t userId) override;
    int32_t DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t>& authToken,
        const sptr<IIDMCallback>& idmCallback) override;
    int32_t DelUser(
        int32_t userId, const std::vector<uint8_t>& authToken, const sptr<IIDMCallback>& idmCallback) override;
    int32_t GetCredentialInfo(
        int32_t userId, int32_t authTypeInt, const sptr<IGetCredInfoCallback>& getCredInfoCallback) override;
    int32_t PrepareRemoteAuth(
        const std::string& remoteNetworkId, const sptr<IPreRemoteAuthCallback>& preRemoteAuthCallback) override;
    int32_t AuthUser(const AuthParam& authParam, const sptr<IIDMCallback>& idmCallback, uint64_t& contextId) override;
    int32_t CancelAuth(uint64_t contextId) override;
    int32_t GetAvailableStatus(int32_t authTypeInt, uint32_t authTrustLevelInt, int32_t& status) override;
    int32_t GetProperty(int32_t userId, const GetPropertyRequestIam& request,
        const sptr<IGetSetPropCallback>& getSetPropCallback) override;
    int32_t GetPropertyByCredentialId(uint64_t credentialId, const std::vector<int32_t>& keysInt,
        const sptr<IGetSetPropCallback>& getSetPropCallback) override;
    int32_t SetProperty(
        int32_t userId, const SetPropertyRequestIam& request, const sptr<IGetSetPropCallback>& callback) override;
    int32_t GetEnrolledId(
        int32_t accountId, int32_t authTypeInt, const sptr<IGetEnrolledIdCallback>& getEnrolledIdCallback) override;
    int32_t GetAccountState(int32_t userId, int32_t& funcResult) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override
    {
        return ERR_OK;
    }

private:
    bool CheckPermission(const std::string &permission);
    DISALLOW_COPY_AND_MOVE(AccountIAMService);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_SERVICE_H
