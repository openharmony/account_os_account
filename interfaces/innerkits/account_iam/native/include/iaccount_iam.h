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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_IACCOUNT_IAM_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_IACCOUNT_IAM_H

#include "iaccount_iam_callback.h"
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
class IAccountIAM : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAccountIAM");

    virtual void OpenSession(int32_t userId, std::vector<uint8_t> &challenge) = 0;
    virtual void CloseSession(int32_t userId) = 0;
    virtual void AddCredential(
        int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback) = 0;
    virtual void UpdateCredential(int32_t userId, const CredentialParameters &credInfo,
        const sptr<IIDMCallback> &callback) = 0;
    virtual int32_t Cancel(int32_t userId, uint64_t challenge) = 0;
    virtual void DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const sptr<IIDMCallback> &callback) = 0;
    virtual void DelUser(
        int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback) = 0;
    virtual void GetCredentialInfo(
        int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback) = 0;
    virtual uint64_t AuthUser(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, const sptr<IIDMCallback> &callback) = 0;
    virtual int32_t CancelAuth(uint64_t contextId) = 0;
    virtual int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel) = 0;
    virtual void GetProperty(
        int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback) = 0;
    virtual void SetProperty(
        int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback) = 0;
    virtual bool RegisterInputer(const sptr<IGetDataCallback> &inputer) = 0;
    virtual void UnRegisterInputer() = 0;

    enum class Message {
        OPEN_SESSION,
        CLOSE_SESSION,
        ADD_CREDENTIAL,
        UPDATE_CREDENTIAL,
        CANCEL,
        DEL_CRED,
        DEL_USER,
        GET_CREDENTIAL_INFO,
        AUTH_USER,
        CANCEL_AUTH,
        GET_AVAILABLE_STATUS,
        GET_PROPERTY,
        SET_PROPERTY,
        REGISTER_INPUTER,
        UNREGISTER_INPUTER
    };
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_IACCOUNT_IAM_H
