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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_H

#include "accountmgr_service_ipc_interface_code.h"
#include "account_iam_info.h"
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
class IIDMCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IIDMCallback");
    virtual void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) = 0;
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class IGetCredInfoCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IGetCredInfoCallback");
    virtual void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList) = 0;
};

class IGetSetPropCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IGetSetPropCallback");
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};

class IGetEnrolledIdCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IGetEnrolledIdCallback");
    virtual void OnEnrolledId(int32_t result, uint64_t enrolledId) = 0;
};

class IPreRemoteAuthCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IPreRemoteAuthCallback");
    virtual void OnResult(int32_t result) = 0;
};
}  // namespace AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_H
