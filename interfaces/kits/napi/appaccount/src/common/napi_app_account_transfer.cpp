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

#include "napi_app_account_transfer.h"

namespace OHOS {
namespace AccountJsKit {
void InsertAppAccountSubscriberInfoToMap(uint64_t key, AsyncContextForSubscribeBase *value)
{
    AppAccountSubscriberInfo::GetInstance().appAccountSubscribersMap[key].emplace_back(value);
}

SubscribersMapIterator GetAppAccountSubscribersMapIterator(uint64_t key)
{
    return AppAccountSubscriberInfo::GetInstance().appAccountSubscribersMap.find(key);
}

void EraseAccountSubscribersMap(uint64_t key)
{
    AppAccountSubscriberInfo::GetInstance().appAccountSubscribersMap.erase(key);
}

SubscribersMapIterator GetBeginAppAccountSubscribersMapIterator()
{
    return AppAccountSubscriberInfo::GetInstance().appAccountSubscribersMap.begin();
}

SubscribersMapIterator GetEndAppAccountSubscribersMapIterator()
{
    return AppAccountSubscriberInfo::GetInstance().appAccountSubscribersMap.end();
}
} // AccountJsKit
} // OHOS
