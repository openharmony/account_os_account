/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <thread>
#include <memory>
#include <unistd.h>

#include "account_log_wrapper.h"
#include "account_kvstore_death_recipient_callback.h"

using namespace OHOS::DistributedKv;

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t CHECK_TIMES = 300;
const int32_t CHECK_INTERVAL = 100000;  // 100ms
}  // namespace

AccountKvStoreDeathRecipientCallback::~AccountKvStoreDeathRecipientCallback()
{
    ACCOUNT_LOGE("AccountDataStorage ~AccountKvStoreDeathRecipientCallback start ");
    ACCOUNT_LOGD("destroy kvstore death recipient callback instance %{public}p", this);
}

AccountKvStoreDeathRecipientCallback::AccountKvStoreDeathRecipientCallback(
    std::shared_ptr<AccountDataStorage> accountDataStorage)
{
    ACCOUNT_LOGE("AccountDataStorage AccountKvStoreDeathRecipientCallback start ");
    accountDataStorage_ = accountDataStorage;
    ACCOUNT_LOGE("AccountDataStorage AccountKvStoreDeathRecipientCallback end ");
}

void AccountKvStoreDeathRecipientCallback::OnRemoteDied()
{
    ACCOUNT_LOGD("OnRemoteDied, register data change listener begin");

    if (!accountDataStorage_) {
        ACCOUNT_LOGD("dataStorage is nullptr");
        return;
    }
    auto accountDataStorage = accountDataStorage_;

    std::thread([accountDataStorage] {
        int32_t times = 0;
        while (times < CHECK_TIMES) {
            times++;
            // init kvStore.
            if (accountDataStorage && accountDataStorage->ResetKvStore()) {
                // register data change listener again.
                ACCOUNT_LOGD("current times is %{public}d", times);
                break;
            }
            usleep(CHECK_INTERVAL);
        }
    })
        .detach();

    ACCOUNT_LOGD("OnRemoteDied, register data change listener end");
}
}  // namespace AccountSA
}  // namespace OHOS
