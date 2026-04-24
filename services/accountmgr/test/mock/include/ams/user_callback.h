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

#ifndef OHOS_ACCOUNT_TEST_MOCK_ABILITY_RUNTIME_USER_CALLBACK_H
#define OHOS_ACCOUNT_TEST_MOCK_ABILITY_RUNTIME_USER_CALLBACK_H

#include "iremote_broker.h"

namespace OHOS {
namespace AAFwk {
class IUserCallback : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.UserCallback");

    virtual void OnUserCmdDone(int userId, int errcode) {}

    enum UserCallbackCmd {
        ON_USER_CMD_DONE = 0,
        CMD_MAX
    };
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ACCOUNT_TEST_MOCK_ABILITY_RUNTIME_USER_CALLBACK_H