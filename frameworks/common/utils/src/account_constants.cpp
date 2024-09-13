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
#include "account_constants.h"

#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace AccountSA {
AccountTimer::AccountTimer(bool needInit)
{
    if (needInit) {
        Init();
    }
}

AccountTimer::~AccountTimer()
{
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId_);
#endif // HICOLLIE_ENABLE
}

void AccountTimer::Init()
{
#ifdef HICOLLIE_ENABLE
    timerId_ = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, TIMEOUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
}
} // namespace AccountSA
} // namespace OHOS
