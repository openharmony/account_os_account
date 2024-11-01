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

#include "subscribeosaccount_fuzzer.h"

#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include "os_account_subscriber.h"
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

class TestOsAccountSubscriber : public OsAccountSubscriber {
public:
    void OnAccountsChanged(const int& id) {}
};

namespace OHOS {
bool SubscribeOsAccountFuzzTest(const uint8_t* data, size_t size)
{
    std::shared_ptr<OsAccountSubscriber> subscriber = make_shared<TestOsAccountSubscriber>();
    int32_t result = OsAccountManager::SubscribeOsAccount(subscriber);
    return result == OHOS::ERR_OK;
}

bool UnsubscribeOsAccountFuzzTest(const uint8_t* data, size_t size)
{
    std::shared_ptr<OsAccountSubscriber> subscriber = make_shared<TestOsAccountSubscriber>();
    int32_t result = OsAccountManager::UnsubscribeOsAccount(subscriber);
    return result == OHOS::ERR_OK;
}
} // namespace

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SubscribeOsAccountFuzzTest(data, size);
    OHOS::UnsubscribeOsAccountFuzzTest(data, size);
    return 0;
}

