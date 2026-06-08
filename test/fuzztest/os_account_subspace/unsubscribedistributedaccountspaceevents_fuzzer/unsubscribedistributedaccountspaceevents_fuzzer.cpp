/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "unsubscribedistributedaccountspaceevents_fuzzer.h"

#include <set>
#include "account_log_wrapper.h"
#include "distributed_account_subscribe_callback.h"
#include "fuzz_data.h"
#include "os_account_subprofile_client.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
class TestDistributedAccountSpaceSubscribeCallback final : public DistributedAccountSubscribeCallback {
public:
    explicit TestDistributedAccountSpaceSubscribeCallback() {}
    void OnAccountsChanged(const DistributedAccountEventData &eventData) {}
    void OnSpaceAccountsChanged(const DistributedAccountSubProfileEventData &eventData) {}
};

bool UnsubscribeDistributedAccountSpaceEventsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    std::shared_ptr<DistributedAccountSubscribeCallback> callback = nullptr;
    bool isInitCallback = fuzzData.GetData<bool>();
    if (isInitCallback) {
        callback = std::make_shared<TestDistributedAccountSpaceSubscribeCallback>();
    }
    ErrCode result = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(callback);
    return result == ERR_OK;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::UnsubscribeDistributedAccountSpaceEventsFuzzTest(data, size);
    return 0;
}