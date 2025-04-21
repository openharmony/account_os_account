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

#ifndef OHOS_ACCOUNT_DISTRIBUTED_ACCOUNT_H
#define OHOS_ACCOUNT_DISTRIBUTED_ACCOUNT_H

#include "ohos.account.distributedAccount.impl.hpp"
#include "ohos.account.distributedAccount.proj.hpp"
#include "account_info.h"

namespace OHOS {
namespace AccountSA {

ohos::account::distributedAccount::DistributedInfo CreateDistributedInfo();
ohos::account::distributedAccount::DistributedInfo CreateDistributedInfoFromAccountInfo(const OhosAccountInfo& info);
    
} // namespace AccountSA
} // namespace OHOS

#endif // OHOS_ACCOUNT_DISTRIBUTED_ACCOUNT_H