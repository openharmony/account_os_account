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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_AUTHENTICATOR_STUB_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_AUTHENTICATOR_STUB_H

#include "app_account_authenticator_stub.h"

namespace OHOS {
namespace AccountSA {
class MockAppAccountAuthenticator : public AppAccountAuthenticatorStub {
public:
    ErrCode AddAccountImplicitly(const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback);
    ErrCode Authenticate(const std::string &name, const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback);
    ErrCode VerifyCredential(
        const std::string &name, const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback);
    ErrCode CheckAccountLabels(
        const std::string &name, const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback);
    ErrCode SetProperties(const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback);
    ErrCode IsAccountRemovable(const std::string &name, const sptr<IRemoteObject> &callback);
    ErrCode CreateAccountImplicitly(const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback);
    ErrCode Auth(const std::string &name, const std::string &authType, const AAFwk::WantParams &options,
        const sptr<IRemoteObject> &callback);

public:
    bool status = true;
};
} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_AUTHENTICATOR_STUB_H