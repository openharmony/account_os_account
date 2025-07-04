/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_SUBSCRIBE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_SUBSCRIBE_MANAGER_H

#include "app_account_subscribe_manager.h"
#include "mock_app_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
class MockAppAccountSubscribeManager : public AppAccountSubscribeManager {
public:
    ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr,
        const sptr<IRemoteObject> &eventListener, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener, std::vector<std::string> &owners);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_APP_ACCOUNT_SUBSCRIBE_MANAGER_H
