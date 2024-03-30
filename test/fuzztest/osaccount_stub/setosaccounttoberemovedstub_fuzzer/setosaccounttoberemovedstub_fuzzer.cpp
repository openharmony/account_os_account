/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "setosaccounttoberemovedstub_fuzzer.h"

#include "ios_account.h"
#include "os_account_manager_service.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
bool SetOsAccountToBeRemovedStubFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel dataParcel;
    dataParcel.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    int32_t testId = static_cast<int32_t>(size) - 1;
    if (!dataParcel.WriteInt32(testId)) {
        return false;
    }
    if (!dataParcel.WriteBool(size < 1)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountManagerService_ ->OnRemoteRequest(
        static_cast<int32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_TO_BE_REMOVED), dataParcel, reply, option);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetOsAccountToBeRemovedStubFuzzTest(data, size);
    return 0;
}

