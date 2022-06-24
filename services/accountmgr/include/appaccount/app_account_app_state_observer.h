/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_APP_STATE_OBSERVER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_APP_STATE_OBSERVER_H

#include "application_state_observer_stub.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAppStateObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    AppAccountAppStateObserver();
    virtual ~AppAccountAppStateObserver() = default;

    void OnAbilityStateChanged(const AppExecFwk::AbilityStateData &abilityStateData) override;
};
}  // AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_APP_STATE_OBSERVER_H
