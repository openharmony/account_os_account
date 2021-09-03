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

#include <common_event_data.h>
#include <common_event_support.h>
#include "account_event_provider.h"
#include "account_log_wrapper.h"
#include "common_event_manager.h"
#include "ohos/aafwk/content/want.h"

using namespace OHOS::EventFwk;

namespace OHOS {
namespace AccountSA {
bool AccountEventProvider::EventPublish(const std::string& event)
{
    Want want;
    want.SetAction(event);
    CommonEventData data;
    data.SetWant(want);

    /* publish */
    bool ret = CommonEventManager::PublishCommonEvent(data);
    if (ret != true) {
        ACCOUNT_LOGE("publish event failed: %{public}d", ret);
    }
    return ret;
}
} // namespace AccountSA
} // namespace OHOS