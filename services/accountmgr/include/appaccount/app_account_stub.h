/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_STUB_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_STUB_H

#include "iapp_account.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class AppAccountStub : public IRemoteStub<IAppAccount> {
public:
    using MessageProcFunction = ErrCode (AppAccountStub::*)(MessageParcel &data, MessageParcel &reply);

    AppAccountStub();
    ~AppAccountStub() override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    template<typename T>
    bool WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data);
    template<typename T>
    bool ReadParcelableVector(std::vector<T> &parcelableInfos, MessageParcel &data);

    ErrCode ProcAddAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAddAccountImplicitly(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeleteAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountExtraInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAccountExtraInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcEnableAppAccess(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDisableAppAccess(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAppAccess(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAppAccountSyncEnable(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAppAccountSyncEnable(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAssociatedData(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAssociatedData(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAccountCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeleteAccountCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAuthenticate(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOAuthToken(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOAuthToken(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeleteOAuthToken(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOAuthTokenVisibility(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckOAuthTokenVisibility(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAuthenticatorInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAllOAuthTokens(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOAuthList(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAuthenticatorCallback(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAllAccounts(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAllAccessibleAccounts(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSubscribeAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUnsubscribeAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSelectAccountsByOptions(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcVerifyCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAccountLabels(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAuthenticatorProperties(MessageParcel &data, MessageParcel &reply);

private:
    static const std::map<uint32_t, MessageProcFunction> messageProcMap_;

    DISALLOW_COPY_AND_MOVE(AppAccountStub);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_STUB_H
