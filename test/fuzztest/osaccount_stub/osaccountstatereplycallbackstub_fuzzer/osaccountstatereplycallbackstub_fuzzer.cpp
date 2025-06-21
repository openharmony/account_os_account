/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "osaccountstatereplycallbackstub_fuzzer.h"
#include "fuzz_data.h"
#include "os_account_state_reply_callback_service.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
const std::u16string DESCRIPTOR = u"ohos.accountfwk.IOsAccountStateReplyCallback";

bool OsAccountStateReplyCallbackStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    MessageParcel message;
    message.WriteInterfaceToken(DESCRIPTOR);
    MessageParcel reply;
    MessageOption option;
    auto cvPtr = std::make_shared<std::condition_variable>();
    auto safeQueue = std::make_shared<SafeQueue<uint8_t>>();
    auto replyCallbackService = std::make_shared<OsAccountStateReplyCallbackService>(fuzzData.GetData<int32_t>(),
        static_cast<OsAccountState>(fuzzData.GetData<int32_t>()), cvPtr, safeQueue, fuzzData.GetData<int32_t>());
    replyCallbackService->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountStateReplyCallbackIpcCode::COMMAND_ON_COMPLETE), message, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::OsAccountStateReplyCallbackStubFuzzTest(data, size);
    return 0;
}
