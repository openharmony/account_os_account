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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STOP_USER_CALLBACK_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STOP_USER_CALLBACK_H

#include "iremote_stub.h"
#include "nocopyable.h"
#include "user_callback.h"

namespace OHOS {
namespace AccountSA {
class OsAccountUserCallback : public IRemoteStub<AAFwk::IUserCallback> {
public:
    OsAccountUserCallback();
    virtual ~OsAccountUserCallback() = default;

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnStopUserDone(int userId, int errcode) override;
    void OnStartUserDone(int userId, int errcode) override;

public:
    bool isReturnOk_ = false;
    std::mutex mutex_;
    std::condition_variable onStartCondition_;
    std::condition_variable onStopCondition_;
private:
    DISALLOW_COPY_AND_MOVE(OsAccountUserCallback);

    int OnStopUserDoneInner(MessageParcel &data, MessageParcel &reply);
    int OnStartUserDoneInner(MessageParcel &data, MessageParcel &reply);

private:
    using UserCallbackFunc = int (OsAccountUserCallback::*)(MessageParcel &data, MessageParcel &reply);
    std::vector<UserCallbackFunc> vecMemberFunc_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STOP_USER_CALLBACK_H
