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

#include "os_account_constraint_manager.h"

#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"

namespace OHOS {
namespace AccountSA {
OsAccountConstraintManager::OsAccountConstraintManager()
    : subscribeManager_(OsAccountConstraintSubscribeManager::GetInstance())
{
    osAccountControl_ = std::make_shared<OsAccountControlFileManager>();
}

OsAccountConstraintManager &OsAccountConstraintManager::GetInstance()
{
    static OsAccountConstraintManager instance;
    return instance;
}

ErrCode OsAccountConstraintManager::SubscribeConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener)
{
    std::set<std::string> constraints;
    subscribeInfo.GetConstraints(constraints);
    if (constraints.empty()) {
        ACCOUNT_LOGE("Empty constraints");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::vector<std::string> constraintVec(constraints.begin(), constraints.end());
    if (!osAccountControl_->CheckConstraints(constraintVec)) {
        ACCOUNT_LOGE("Invalid constraints");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return subscribeManager_.SubscribeConstraints(constraints, eventListener);
}

ErrCode OsAccountConstraintManager::UnsubscribeConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener)
{
    std::set<std::string> constraints;
    subscribeInfo.GetConstraints(constraints);
    if (constraints.empty()) {
        ACCOUNT_LOGE("Empty constraints");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::vector<std::string> constraintVec(constraints.begin(), constraints.end());
    if (!osAccountControl_->CheckConstraints(constraintVec)) {
        ACCOUNT_LOGE("Invalid constraints");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return subscribeManager_.UnsubscribeConstraints(constraints, eventListener);
}

void OsAccountConstraintManager::Publish(int32_t localId, const std::set<std::string> &oldConstraints,
    const std::set<std::string> &newConstraints, const bool enable)
{
    return subscribeManager_.Publish(localId, oldConstraints, newConstraints, enable);
}
} // AccountSA
} // OHOS