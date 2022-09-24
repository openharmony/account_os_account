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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAM_STUB_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAM_STUB_H

#include "iaccount_iam.h"

#include <map>
#include "account_error_no.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class AccountIAMMgrStub : public IRemoteStub<IAccountIAM> {
public:
    using MessageProcFunction = ErrCode (AccountIAMMgrStub::*)(MessageParcel &data, MessageParcel &reply);
    AccountIAMMgrStub();
    ~AccountIAMMgrStub() override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode ProcOpenSession(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCloseSession(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAddCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUpdateCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDelCred(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcDelUser(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCancel(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetCredentialInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAuthUser(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCancelAuth(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAvailableStatus(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetProperty(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetProperty(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountState(MessageParcel &data, MessageParcel &reply);
    ErrCode ReadUserIdAndAuthType(MessageParcel &data, int32_t &userId, int32_t &authType);
    ErrCode AddOrUpdateCredential(MessageParcel &data, MessageParcel &reply, bool isAdd = true);
    bool CheckPermission(const std::string &permission);

private:
    static const std::map<uint32_t, MessageProcFunction> messageProcMap_;
    DISALLOW_COPY_AND_MOVE(AccountIAMMgrStub);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAM_STUB_H