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

ErrCode OsAccountConstraintManager::SubscribeOsAccountConstraints(const OsAccountConstraintSubscribeInfo &subscribeInfo,
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
    if (!subscribeInfo.enableAcross) {
        return subscribeManager_.SubscribeOsAccountConstraints(subscribeInfo.localId, constraints, eventListener);
    }
    return subscribeManager_.SubscribeOsAccountConstraints(constraints, eventListener);
}

ErrCode OsAccountConstraintManager::UnsubscribeOsAccountConstraints(
    const OsAccountConstraintSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
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
    if (!subscribeInfo.enableAcross) {
        return subscribeManager_.UnsubscribeOsAccountConstraints(subscribeInfo.localId, constraints, eventListener);
    }
    return subscribeManager_.UnsubscribeOsAccountConstraints(constraints, eventListener);
}

void OsAccountConstraintManager::Publish(int32_t localId, const std::set<std::string> &constraints, const bool enable)
{
    return subscribeManager_.Publish(localId, constraints, enable);
}
} // AccountSA
} // OHOS