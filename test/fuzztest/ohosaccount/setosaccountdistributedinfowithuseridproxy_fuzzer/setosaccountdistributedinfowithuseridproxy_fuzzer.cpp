/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "setosaccountdistributedinfowithuseridproxy_fuzzer.h"

#include "account_proxy.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "distributed_account_subscribe_callback.h"
#include "fuzz_data.h"
#include "ohos_account_kits.h"
#include "ohos_account_kits_impl.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
static constexpr uint32_t OHOS_ACCOUNT_STATE_NUM = 5;
}
bool SetOsAccountDistributedInfoWithUserIdProxyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    std::shared_ptr<AccountProxy> accountProxy = std::make_shared<AccountProxy>(nullptr);
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    OhosAccountInfo testOhosAccountInfo(
        fuzzData.GenerateString(),
        fuzzData.GenerateString(),
        fuzzData.GetData<int32_t>() % OHOS_ACCOUNT_STATE_NUM - 1
    );
    std::string testEventStr(fuzzData.GenerateString());
    int32_t result = accountProxy->SetOsAccountDistributedInfo(userId, testOhosAccountInfo, testEventStr);
    std::string deviceId;
    result = accountProxy->QueryDistributedVirtualDeviceId(deviceId);
    return result == ERR_OK;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetOsAccountDistributedInfoWithUserIdProxyFuzzTest(data, size);
    return 0;
}

