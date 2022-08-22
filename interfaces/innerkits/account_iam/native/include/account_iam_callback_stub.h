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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_STUB_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_STUB_H

#include <map>
#include "iaccount_iam_callback.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class IDMCallbackStub : public IRemoteStub<IIDMCallback> {
public:
    using MessageProcFunction = ErrCode (IDMCallbackStub::*)(MessageParcel &data, MessageParcel &reply);
    IDMCallbackStub() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode ProcOnAcquireInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcOnResult(MessageParcel &data, MessageParcel &reply);

private:
    static const std::map<uint32_t, MessageProcFunction> messageProcMap_;
    DISALLOW_COPY_AND_MOVE(IDMCallbackStub);
};

class GetCredInfoCallbackStub : public IRemoteStub<IGetCredInfoCallback> {
public:
    using MessageProcFunction = ErrCode (GetCredInfoCallbackStub::*)(MessageParcel &data, MessageParcel &reply);
    GetCredInfoCallbackStub() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode ProcOnCredentialInfo(MessageParcel &data, MessageParcel &reply);

private:
    static const std::map<uint32_t, MessageProcFunction> messageProcMap_;
    DISALLOW_COPY_AND_MOVE(GetCredInfoCallbackStub);
};

class GetSetPropCallbackStub : public IRemoteStub<IGetSetPropCallback> {
public:
    using MessageProcFunction = ErrCode (GetSetPropCallbackStub::*)(MessageParcel &data, MessageParcel &reply);
    GetSetPropCallbackStub() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode ProcOnResult(MessageParcel &data, MessageParcel &reply);

private:
    static const std::map<uint32_t, MessageProcFunction> messageProcMap_;
    DISALLOW_COPY_AND_MOVE(GetSetPropCallbackStub);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_STUB_H