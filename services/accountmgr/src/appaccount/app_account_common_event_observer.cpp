/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "app_account_common_event_observer.h"
#include <pthread.h>
#include <thread>
#include <unistd.h>
#include "account_log_wrapper.h"
#include "app_account_control_manager.h"
#include "bundle_constants.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "os_account_state_subscriber.h"
#include "os_account_subscribe_manager.h"

#ifdef HAS_CES_PART
using namespace OHOS::EventFwk;
#endif // HAS_CES_PART

namespace OHOS {
namespace AccountSA {
#ifdef HAS_CES_PART
namespace {
const char THREAD_COMMON_EVENT[] = "commonEvent";
constexpr int32_t DELAY_FOR_TIME_INTERVAL = 1 * 1000;
constexpr int32_t MAX_TRY_TIMES = 10;
}

AppAccountCommonEventObserver &AppAccountCommonEventObserver::GetInstance()
{
    static AppAccountCommonEventObserver *instance = new (std::nothrow) AppAccountCommonEventObserver();
    return *instance;
}

AppAccountCommonEventObserver::AppAccountCommonEventObserver()
{
    ACCOUNT_LOGI("Constructed");
    counter_ = 0;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);

    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscriber_ = std::make_shared<AppAccountCommonEventSubscriber>(
        subscribeInfo, [this] (const CommonEventData &data) { this->OnReceiveEvent(data); });

    auto task = [this] {
        this->SubscribeCommonEvent();
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
        this->SubscribeOsAccountEvent();
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_COMMON_EVENT);
    taskThread.detach();
}

AppAccountCommonEventObserver::~AppAccountCommonEventObserver()
{
    ACCOUNT_LOGI("Destroyed");
    CommonEventManager::UnSubscribeCommonEvent(subscriber_);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    OsAccountSubscribeManager::GetInstance().UnsubscribeOsAccount(subscriberOsAccountPtr_);
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
}

void AppAccountCommonEventObserver::SubscribeOsAccountEvent(void)
{
    std::set<OsAccountState> states = { OsAccountState::STOPPING };
    OsAccountSubscribeInfo subscribeInfo(states, true);
    subscriberOsAccountPtr_ = (new (std::nothrow) OsAccountStateSubscriber());
    auto subscribeInfoPtr = std::make_shared<OsAccountSubscribeInfo>(subscribeInfo);
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("SubscribeInfoPtr is nullptr");
    }
    OsAccountSubscribeManager::GetInstance().SubscribeOsAccount(subscribeInfoPtr, subscriberOsAccountPtr_);
}

void AppAccountCommonEventObserver::SubscribeCommonEvent(void)
{
    while (counter_ != MAX_TRY_TIMES) {
        if (CommonEventManager::SubscribeCommonEvent(subscriber_)) {
            ACCOUNT_LOGI("Successfully");
            counter_ = 0;
            break;
        }
        if (++counter_ == MAX_TRY_TIMES) {
            ACCOUNT_LOGE("failed to subscribe common event and tried %{public}d times", counter_);
        }
        sleep(DELAY_FOR_TIME_INTERVAL / 1000); // 1000: 1s
    }
}

void AppAccountCommonEventObserver::OnReceiveEvent(const CommonEventData &data)
{
    auto want = data.GetWant();
    std::string action = want.GetAction();
    if (action == CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED) {
        DealWithRemoveEvent(want, action);
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        AppAccountControlManager::GetInstance().OnUserRemoved(data.GetCode());
        return;
    }
    if (action == CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        AppAccountControlManager::GetInstance().AddMigratedAccount(data.GetCode());
    }
}

void AppAccountCommonEventObserver::DealWithRemoveEvent(const AAFwk::Want &want, const std::string action)
{
    auto element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    auto uid = want.GetIntParam(AppExecFwk::Constants::UID, -1);
    int32_t appIndex = 0;
    if (action == CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED) {
        appIndex = want.GetIntParam(AppExecFwk::Constants::SANDBOX_APP_INDEX, -1);
    } else {
        appIndex = want.GetIntParam(AppExecFwk::Constants::APP_INDEX, -1);
    }
    if (appIndex < 0) {
        ACCOUNT_LOGW("appIndex = %{public}d is invalid.", appIndex);
        return;
    }
    ACCOUNT_LOGI("uid = %{public}d, bundleName = %{public}s. appIndex = %{public}d",
        uid, bundleName.c_str(), appIndex);
    AppAccountControlManager::GetInstance().OnPackageRemoved(uid, bundleName, appIndex);
}
#endif // HAS_CES_PART
}  // namespace AccountSA
}  // namespace OHOS