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

#include "account_log_wrapper.h"
#include "bundle_constants.h"
#include "common_event_manager.h"
#include "common_event_support.h"

#include "app_account_common_event_oberserver.h"

using namespace OHOS::EventFwk;

namespace OHOS {
namespace AccountSA {
AppAccountCommonEventOberserver::AppAccountCommonEventOberserver(const CommonEventCallback &callback)
    : callback_(callback)
{
    ACCOUNT_LOGI("enter");

    counter_ = 0;

    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);

    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscriber_ = std::make_shared<AppAccountCommonEventSubscriber>(
        subscribeInfo, std::bind(&AppAccountCommonEventOberserver::OnReceiveEvent, this, std::placeholders::_1));

    if (GetEventHandler() != ERR_OK) {
        ACCOUNT_LOGE("failed to get event handler");
    } else {
        Callback callback = std::bind(&AppAccountCommonEventOberserver::SubscribeCommonEvent, this);
        handler_->PostTask(callback, DELAY_FOR_COMMON_EVENT_SERVICE);
    }

    ACCOUNT_LOGI("end");
}

AppAccountCommonEventOberserver::~AppAccountCommonEventOberserver()
{
    ACCOUNT_LOGI("enter");

    if (handler_) {
        handler_.reset();
    }

    CommonEventManager::UnSubscribeCommonEvent(subscriber_);
}

ErrCode AppAccountCommonEventOberserver::GetEventHandler(void)
{
    ACCOUNT_LOGI("enter");

    if (!handler_) {
        handler_ = std::make_shared<EventHandler>(EventRunner::Create());
        if (handler_ == nullptr) {
            ACCOUNT_LOGE("failed to create event handler");
            return ERR_APPACCOUNT_SERVICE_CREATE_EVENT_HANDLER;
        }
    }

    return ERR_OK;
}

void AppAccountCommonEventOberserver::SubscribeCommonEvent(void)
{
    ACCOUNT_LOGI("enter");

    bool result = CommonEventManager::SubscribeCommonEvent(subscriber_);
    ACCOUNT_LOGI("result = %{public}d", result);
    if (result) {
        counter_ = 0;
    } else {
        counter_++;
        if (counter_ == MAX_TRY_TIMES) {
            ACCOUNT_LOGE("failed to subscribe common event and tried %{public}d times", counter_);
        } else {
            Callback callback = std::bind(&AppAccountCommonEventOberserver::SubscribeCommonEvent, this);
            handler_->PostTask(callback, DELAY_FOR_TIME_INTERVAL);
        }
    }

    ACCOUNT_LOGI("end, counter_ = %{public}d", counter_);
}

void AppAccountCommonEventOberserver::OnReceiveEvent(const CommonEventData &data)
{
    ACCOUNT_LOGI("enter");

    auto want = data.GetWant();
    std::string action = want.GetAction();
    if (action == CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        if (callback_.OnPackageRemoved != nullptr) {
            auto want = data.GetWant();
            std::string action = want.GetAction();
            auto element = want.GetElement();
            std::string bundleName = element.GetBundleName();
            auto uid = want.GetIntParam(AppExecFwk::Constants::UID, -1);

            ACCOUNT_LOGI("uid = %{public}d", uid);
            ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

            callback_.OnPackageRemoved(uid, bundleName);
        }
    }
}
}  // namespace AccountSA
}  // namespace OHOS