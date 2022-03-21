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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_EVENT_STUB_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_EVENT_STUB_H

#include "ios_account_event.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class OsAccountEventStub : public IRemoteStub<IOsAccountEvent> {
public:
    OsAccountEventStub();
    ~OsAccountEventStub() override;

    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    template<typename T>
    bool ReadParcelableVector(std::vector<T> &parcelableVector, MessageParcel &data);

private:
    DISALLOW_COPY_AND_MOVE(OsAccountEventStub);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_EVENT_STUB_H
