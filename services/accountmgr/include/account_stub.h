/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STUB_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STUB_H

#include "iaccount.h"
#include "iaccount_context.h"
#include <iremote_broker.h>
#include <iremote_object.h>
#include <iremote_stub.h>
#include <map>

namespace OHOS {
namespace AccountSA {
class AccountStub;
using AccountStubFunc = std::function<std::int32_t(MessageParcel &data, MessageParcel &reply)>;
class AccountStub : public IRemoteStub<IAccount>, public IAccountContext {
public:
    AccountStub();
    virtual std::int32_t OnRemoteRequest(
        std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

public:
    ErrCode InnerUpdateOhosAccountInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdUpdateOhosAccountInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode InnerSetOhosAccountInfo(int32_t userId, MessageParcel &data, MessageParcel &reply);
    ErrCode CmdSetOhosAccountInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdSetOhosAccountInfoByUserId(MessageParcel &data, MessageParcel &reply);

    ErrCode InnerGetOhosAccountInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdGetOhosAccountInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdGetOhosAccountInfoByUserId(MessageParcel &data, MessageParcel &reply);
    ErrCode InnerQueryOhosAccountInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode InnerQueryDistributedVirtualDeviceId(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdQueryDistributedVirtualDeviceId(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdQueryDVIDByBundleName(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdQueryOhosAccountInfo(MessageParcel &data, MessageParcel &reply);

    ErrCode CmdQueryOhosAccountInfoByUserId(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdQueryDeviceAccountId(MessageParcel &data, MessageParcel &reply);

    ErrCode CmdSubscribeDistributedAccountEvent(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdUnsubscribeDistributedAccountEvent(MessageParcel &data, MessageParcel &reply);

    ErrCode CmdGetAppAccountService(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdGetOsAccountService(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdGetAccountIAMService(MessageParcel &data, MessageParcel &reply);
    ErrCode CmdGetDomainAccountService(MessageParcel &data, MessageParcel &reply);
    bool HasAccountRequestPermission(const std::string &permissionName);

private:
    std::map<AccountMgrInterfaceCode, AccountStubFunc> stubFuncMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STUB_H
