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

#ifndef OS_ACCOUNT_FRAMEWORKS_ACCOUNT_TIMER_H
#define OS_ACCOUNT_FRAMEWORKS_ACCOUNT_TIMER_H

#include <stdint.h>
#include "account_constants.h"

namespace OHOS {
namespace AccountSA {
class AccountTimer {
public:
    AccountTimer(bool needInit = true);
    ~AccountTimer();
    void Init(int32_t timeout = TIMEOUT);

private:
    int64_t timerId_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_FRAMEWORKS_ACCOUNT_TIMER_H