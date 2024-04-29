/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

/**
 * @addtogroup AccountIAM
 * @{
 *
 * @brief Provides account identity and access management.
 *
 * Provides the capability to manage the identity and access of the local account.
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file account_iam_client.h
 *
 * @brief Declares account iam client interfaces.
 *
 * @since 8.0
 * @version 8.0
 */
#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CLIENT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CLIENT_H

#include <map>
#include <mutex>
#include <vector>
#include <set>
#include "account_iam_client_callback.h"
#include "account_iam_info.h"
#include "account_error_no.h"
#include "account_permission_manager.h"
#include "iaccount_iam.h"

namespace OHOS {
namespace AccountSA {
class AccountIAMClient {
public:
    /**
     * Gets the instance of AccountIAMClient.
     * @return the instance of AccountIAMClient.
     */
    static AccountIAMClient &GetInstance();

    /**
     * @brief Opens session.
     * @permission ohos.permission.MANAGE_USER_IDM
     * @param userId - Indicates the user identification.
     * @param challenge - Indicates the challenge value.
     * @return error code, see account_error_no.h
     */
    int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge);

    /**
     * @brief Closes session.
     * @permission ohos.permission.MANAGE_USER_IDM
     * @param userId - Indicates the user identification.
     * @return error code, see account_error_no.h
     */
    int32_t CloseSession(int32_t userId);

    /**
     * @brief Adds credential information.
     * @permission ohos.permission.MANAGE_USER_IDM
     * @param userId - Indicates the user identification.
     * @param credentialInfo - Indicates the credential information.
     * @param callback - Indicates the callback to get results and acquireInfo.
     */
    void AddCredential(
        int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback);

    /**
     * @brief Updates credential.
     * @permission ohos.permission.MANAGE_USER_IDM
     * @param userId - Indicates the user identification.
     * @param credentialInfo - Indicates the credential information.
     * @param callback - Indicates the callback to get results and acquireInfo.
     */
    void UpdateCredential(
        int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback);

    /**
     * @brief Cancels entry with a challenge value.
     * @permission ohos.permission.MANAGE_USER_IDM
     * @param userId - Indicates the user identification.
     * @return error code, see account_error_no.h
     */
    int32_t Cancel(int32_t userId);

    /**
     * @brief Deletes the user credential information.
     * @permission ohos.permission.MANAGE_USER_IDM
     * @param userId - Indicates the user identification.
     * @param credentialId - Indicates the credential index.
     * @param authToken - Indicates the authentication token.
     * @param callback - Indicates the callback to get the deletion result.
     */
    void DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const std::shared_ptr<IDMCallback>& callback);

    /**
     * @brief Deletes the user with the authentication token.
     * @permission ohos.permission.MANAGE_USER_IDM
     * @param userId - Indicates the user identification.
     * @param authToken - Indicates the authentication token.
     * @param callback - Indicates the callback to get the deletion result.
     */
    void DelUser(int32_t userId, const std::vector<uint8_t> &authToken, const std::shared_ptr<IDMCallback> &callback);

    /**
     * @brief Gets authentication information.
     * @permission ohos.permission.USE_USER_IDM
     * @param userId - Indicates the user identification.
     * @param authType - Indicates the authentication type.
     * @param callback - Indicates the callback to get all registered credential information of
     * the specified type for the current user.
     * @return error code, see account_error_no.h
     */
    int32_t GetCredentialInfo(int32_t userId, AuthType authType, const std::shared_ptr<GetCredInfoCallback> &callback);

    /**
     * @brief Prepare remote auth.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param remoteNetworkId - Indicates the remote network id.
     * @param callback - Indicates the callback for getting result.
     * @return error code, see account_error_no.h
     */
    int32_t PrepareRemoteAuth(
        const std::string &remoteNetworkId, const std::shared_ptr<PreRemoteAuthCallback> &callback);

    /**
     * @brief Executes user authentication.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param authOptions - Indicates the AuthOptions.
     * @param challenge - Indicates the challenge value.
     * @param authType - Indicates the authentication type.
     * @param authTrustLevel - Indicates the trust level of authentication result.
     * @param callback - Indicates the callback to get result and acquireInfo.
     * @return a context ID for cancellation.
     */
    uint64_t Auth(AuthOptions& authOptions, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback);

    /**
     * @brief Executes user authentication.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param authOptions - Indicates the AuthOptions.
     * @param challenge - Indicates the challenge value.
     * @param authType - Indicates the authentication type.
     * @param authTrustLevel - Indicates the trust level of authentication result.
     * @param callback - Indicates the callback to get result and acquireInfo.
     * @return a context ID for cancellation.
     */
    uint64_t AuthUser(AuthOptions &authOptions, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback);

    /**
     * @brief Cancels authentication with context ID.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param contextID - Indicates the authentication context ID.
     * @return error code, see account_error_no.h
     */
    int32_t CancelAuth(uint64_t contextId);

    /**
     * @brief Checks whether the authentication capability is available.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param authType - Indicates the credential type for authentication.
     * @param authTrustLevel - Indicates the trust level of authentication result.
     * @param status - Indicates a status result.
     * @return error code, see account_error_no.h
     */
    int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status);

    /**
     * @brief Gets the property based on the specified request information.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param userId - Indicates the user identification.
     * @param request - Indicates the request information, including authentication type, and property type list.
     * @param callback - Indicates the callback for getting an executor property.
     * @return error code, see account_error_no.h
     */
    void GetProperty(
        int32_t userId, const GetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback);

    /**
     * @brief Sets property that can be used to initialize algorithms.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param userId - Indicates the user identification.
     * @param request - Indicates the request information, including authentication type and the key-value to be set.
     * @param callback - Indicates the callback for getting result.
     * @return error code, see account_error_no.h
     */
    void SetProperty(
        int32_t userId, const SetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback);

    /**
     * @brief Get the enrolled id based on the specified information.
     * @permission ohos.permission.USE_USER_IDM
     * @param accountId - Indicates the user identification.
     * @param authType - Indicates the credential type.
     * @param callback - Indicates the callback for getting result.
     * @return error code, see account_error_no.h
     */
    void GetEnrolledId(int32_t accountId, AuthType authType, const std::shared_ptr<GetEnrolledIdCallback> &callback);

#ifdef HAS_PIN_AUTH_PART
    /**
     * @brief Registers inputer.
     * @permission ohos.permission.ACCESS_PIN_AUTH
     * @param inputer - Indicates the password input box callback
     * @return error code, see account_error_no.h
     */
    ErrCode RegisterPINInputer(const std::shared_ptr<IInputer> &inputer);

    /**
     * @brief Unregisters inputer.
     * @permission ohos.permission.ACCESS_PIN_AUTH
     * @return error code, see account_error_no.h
     */
    ErrCode UnregisterPINInputer();

    /**
     * @brief Registers credential inputer by authentication type.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL or ohos.permission.MANAGE_USER_IDM
     * @param authType - Indicates the authentication type.
     * @param inputer - Indicates the credential input box callback.
     * @return error code, see account_error_no.h
     */
    ErrCode RegisterInputer(int32_t authType, const std::shared_ptr<IInputer> &inputer);

    /**
     * @brief Unregisters credential inputer by authentication type.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL or ohos.permission.MANAGE_USER_IDM
     * @param authType - Indicates the authentication type.
     * @return error code, see account_error_no.h
     */
    ErrCode UnregisterInputer(int32_t authType);
#endif

    /**
     * @brief Gets the state of the specified account.
     * @param userId - Indicates the user identification.
     * @return the state of the specified account
     */
    IAMState GetAccountState(int32_t userId);

    /**
     * @brief Sets the authentication subtype of the specified account.
     * @param userId - Indicates the user identification.
     * @param authSubType - Indicates the authentication subtype.
     */
    void SetAuthSubType(int32_t userId, int32_t authSubType);

    /**
     * @brief Gets the authentication subtype of the specified account.
     * @param userId - Indicates the user identification.
     * @return the authentication subtype.
     */
    int32_t GetAuthSubType(int32_t userId);

    /**
     * @brief Sets the credential of the specified account.
     * @param userId - Indicates the user identification.
     * @param credential - Indicates the credential.
     */
    void SetCredential(int32_t userId, const std::vector<uint8_t> &credential);

    /**
     * @brief Gets the credential information of the specified account.
     * @param userId - Indicates the user identification.
     * @param credItem - Indicates the credential information.
     */
    void GetCredential(int32_t userId, CredentialItem &credItem);

    /**
     * @brief Clears the credential of the specified account.
     * @param userId - Indicates the user identification.
     */
    void ClearCredential(int32_t userId);

private:
    AccountIAMClient() = default;
    ~AccountIAMClient() = default;
    DISALLOW_COPY_AND_MOVE(AccountIAMClient);
    class AccountIAMDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AccountIAMDeathRecipient() = default;
        ~AccountIAMDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(AccountIAMDeathRecipient);
    };
    sptr<IAccountIAM> GetAccountIAMProxy();
    void ResetAccountIAMProxy(const wptr<IRemoteObject>& remote);
    bool GetCurrentUserId(int32_t &userId);
    uint64_t StartDomainAuth(int32_t userId, const std::shared_ptr<IDMCallback> &callback);
#ifdef HAS_PIN_AUTH_PART
    ErrCode RegisterDomainInputer(const std::shared_ptr<IInputer> &inputer);
    ErrCode UnregisterDomainInputer();
#endif
    bool CheckSelfPermission(const std::string &permissionName);

private:
    std::mutex mutex_;
    std::mutex pinMutex_;
    std::mutex domainMutex_;
    std::map<int32_t, CredentialItem> credentialMap_;
    sptr<IAccountIAM> proxy_ = nullptr;
    sptr<AccountIAMDeathRecipient> deathRecipient_ = nullptr;
#ifdef HAS_PIN_AUTH_PART
    std::shared_ptr<IInputer> pinInputer_ = nullptr;
    std::shared_ptr<IInputer> domainInputer_ = nullptr;
#endif
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CLIENT_H