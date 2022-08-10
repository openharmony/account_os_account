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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_INNER_APP_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_INNER_APP_ACCOUNT_MANAGER_H

#include "inner_app_account_manager.h"
#include "mock_inner_app_account_manager.h"

namespace OHOS {
namespace AccountSA {
class MockInnerAppAccountManager : public InnerAppAccountManager {
public:
    MockInnerAppAccountManager();
    virtual ~MockInnerAppAccountManager();

    ErrCode AddAccount(
        const std::string &name, const std::string &extraInfo, const std::string &bundleName, const uint32_t &appIndex);
    ErrCode DeleteAccount(const std::string &name, const std::string &bundleName, const uint32_t &appIndex);

    ErrCode SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener,
        const std::string &bundleName, const uint32_t &appIndex);
    ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_MOCK_INNER_APP_ACCOUNT_MANAGER_H
