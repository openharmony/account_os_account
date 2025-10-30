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
#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_TRANSFER_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_TRANSFER_H

#include <mutex>
#include <thread>
#include "napi_account_common.h"

namespace OHOS {
namespace AccountJsKit {
typedef std::map<uint64_t, std::vector<AsyncContextForSubscribeBase *>>::iterator SubscribersMapIterator;
void InsertAppAccountSubscriberInfoToMap(uint64_t key, AsyncContextForSubscribeBase *value);
SubscribersMapIterator GetAppAccountSubscribersMapIterator(uint64_t key);
void EraseAccountSubscribersMap(uint64_t key);
SubscribersMapIterator GetBeginAppAccountSubscribersMapIterator();
SubscribersMapIterator GetEndAppAccountSubscribersMapIterator();
} // AccountJsKit
} // OHOS

#endif // OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_TRANSFER_H