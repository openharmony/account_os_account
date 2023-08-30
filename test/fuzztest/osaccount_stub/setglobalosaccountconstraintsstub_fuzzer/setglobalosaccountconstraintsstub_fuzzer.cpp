/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "setglobalosaccountconstraintsstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "ios_account.h"
#include "os_account_manager_service.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const int32_t ENFORCER_ID = 100;
const int CONSTANTS_NUMBER_TWO = 2;
const int CONSTANTS_NUMBER_THREE = 3;
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool SetGlobalOsAccountConstraintsStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);

    if (!datas.WriteInt32(ENFORCER_ID)) {
        return false;
    }
    std::vector<std::string> constraints {
        "constraint.print",
        "constraint.screen.timeout.set",
        "constraint.share.into.profile"
    };
    if (!datas.WriteStringVector(constraints)) {
        return false;
    }
    bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
    bool isDeviceOwner = ((size % CONSTANTS_NUMBER_THREE) == 0);

    if (!datas.WriteBool(enable)) {
        return false;
    }
    if (!datas.WriteBool(isDeviceOwner)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;

    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::SET_GLOBAL_OS_ACCOUNT_CONSTRAINTS), datas, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SetGlobalOsAccountConstraintsStubFuzzTest(data, size);
    return 0;
}
