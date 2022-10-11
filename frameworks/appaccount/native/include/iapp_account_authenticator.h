/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_AUTHENTICATOR_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_AUTHENTICATOR_H

#include "app_account_common.h"
#include "iremote_broker.h"
#include "want_params.h"

namespace OHOS {
namespace AccountSA {
class IAppAccountAuthenticator : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAppAccountAuthenticator");

    virtual ErrCode AddAccountImplicitly(const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode Authenticate(
        const std::string &name, const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode VerifyCredential(
        const std::string &name, const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode CheckAccountLabels(
        const std::string &name, const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode SetProperties(const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode IsAccountRemovable(const std::string &name, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode CreateAccountImplicitly(
        const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback) = 0;
    virtual ErrCode Auth(const std::string &name, const std::string &authType,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) = 0;

    enum class Message {
        ADD_ACCOUNT_IMPLICITLY = 0,
        AUTHENTICATE,
        VERIFY_CREDENTIAL,
        CHECK_ACCOUNT_LABELS,
        SET_PROPERTIES,
        IS_ACCOUNT_REMOVABLE,
        CREATE_ACCOUNT_IMPLICITLY,
        AUTH
    };
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_AUTHENTICATOR_H
