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

#ifndef OS_ACCOUNT_CONSTRAINT_MANAGER_H
#define OS_ACCOUNT_CONSTRAINT_MANAGER_H

#include "os_account_constraint_subscribe_info.h"
#include "iinner_os_account.h"
#include "ios_account_control.h"
#include "ios_account_subscribe.h"
#include "os_account_constraint_subscribe_manager.h"
#include "os_account_control_file_manager.h"

namespace OHOS {
namespace AccountSA {
class OsAccountConstraintManager {
public:
    static OsAccountConstraintManager &GetInstance();
    ErrCode SubscribeOsAccountConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &eventListener);
    ErrCode UnsubscribeOsAccountConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &eventListener);
    void Publish(int32_t localId, const std::set<std::string> &constraints, const bool isEnabled);

private:
    OsAccountConstraintManager();
    ~OsAccountConstraintManager() = default;
    DISALLOW_COPY_AND_MOVE(OsAccountConstraintManager);

private:
    std::shared_ptr<IOsAccountControl> osAccountControl_;
    OsAccountConstraintSubscribeManager &subscribeManager_;
};
} // AccountSA
} // OHOS
#endif //OS_ACCOUNT_CONSTRAINT_MANAGER_H