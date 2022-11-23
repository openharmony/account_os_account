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
    using MessageProcFunction = ErrCode (AppAccountStub::*)(uint32_t code, MessageParcel &data, MessageParcel &reply);

    AppAccountStub();
    ~AppAccountStub() override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    template<typename T>
    bool WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data);
    template<typename T>
    bool ReadParcelableVector(std::vector<T> &parcelableInfos, MessageParcel &data);

    ErrCode ProcAddAccount(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAddAccountImplicitly(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCreateAccount(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCreateAccountImplicitly(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeleteAccount(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountExtraInfo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAccountExtraInfo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAppAccess(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAppAccess(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAppAccountSyncEnable(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAppAccountSyncEnable(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAssociatedData(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAssociatedData(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountCredential(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAccountCredential(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeleteAccountCredential(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAuthenticate(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAuthToken(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOAuthToken(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeleteAuthToken(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAuthTokenVisibility(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAuthTokenVisibility(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAuthenticatorInfo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAllOAuthTokens(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAuthList(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAuthenticatorCallback(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAllAccounts(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAllAccessibleAccounts(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSubscribeAccount(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUnsubscribeAccount(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSelectAccountsByOptions(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcVerifyCredential(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAccountLabels(uint32_t code, MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAuthenticatorProperties(uint32_t code, MessageParcel &data, MessageParcel &reply);

private:
    static const std::map<uint32_t, MessageProcFunction> messageProcMap_;

    DISALLOW_COPY_AND_MOVE(AppAccountStub);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_STUB_H
