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

#ifndef APP_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_STUB_H
#define APP_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_STUB_H

#include "iapp_account.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class AppAccountStub : public IRemoteStub<IAppAccount> {
public:
    AppAccountStub();
    virtual ~AppAccountStub() override;

    DECLARE_INTERFACE_DESCRIPTOR(u"IAppAccount");

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    template <typename T>
    bool WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data);
    template <typename T>
    bool ReadParcelableVector(std::vector<T> &parcelableInfos, MessageParcel &data);

    void CreateMessageProcMap();

    ErrCode ProcAddAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDeleteAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountExtraInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAccountExtraInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcEnableAppAccess(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDisableAppAccess(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAppAccountSyncEnable(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAppAccountSyncEnable(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAssociatedData(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAssociatedData(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAccountCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetOAuthToken(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetOAuthToken(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcClearOAuthToken(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAllAccounts(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAllAccessibleAccounts(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSubscribeAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUnsubscribeAccount(MessageParcel &data, MessageParcel &reply);

private:
    using messageProcFunction = ErrCode (AppAccountStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, messageProcFunction> messageProcMap_;

    DISALLOW_COPY_AND_MOVE(AppAccountStub);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // APP_ACCOUNT_FRAMEWORKS_APPACCOUNT_CORE_INCLUDE_APP_ACCOUNT_STUB_H
