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

#include "os_account_constraint_subscribe_info.h"

#include "account_log_wrapper.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
OsAccountConstraintSubscribeInfo::OsAccountConstraintSubscribeInfo()
{}

OsAccountConstraintSubscribeInfo::OsAccountConstraintSubscribeInfo(const std::set<std::string> &constraints)
    : constraintSet_(constraints)
{}

void OsAccountConstraintSubscribeInfo::SetConstraints(const std::set<std::string> &constraints)
{
    constraintSet_ = constraints;
}

void OsAccountConstraintSubscribeInfo::GetConstraints(std::set<std::string> &constraints) const
{
    constraints = constraintSet_;
}

bool OsAccountConstraintSubscribeInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(constraintSet_.size())) {
        ACCOUNT_LOGE("Write constraintSet size failed.");
        return false;
    }
    for (const auto &item : constraintSet_) {
        if ((!parcel.WriteString(item))) {
            ACCOUNT_LOGE("Write constraintSet item failed.");
            return false;
        }
    }
    return true;
}

OsAccountConstraintSubscribeInfo *OsAccountConstraintSubscribeInfo::Unmarshalling(Parcel &parcel)
{
    OsAccountConstraintSubscribeInfo *info = new (std::nothrow) OsAccountConstraintSubscribeInfo();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read OsAccountConstraintSubscribeInfo from parcel failed.");
        delete info;
        info = nullptr;
    }
    return info;
}

bool OsAccountConstraintSubscribeInfo::ReadFromParcel(Parcel &parcel)
{
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        ACCOUNT_LOGE("Read size failed.");
        return false;
    }
    if (size > Constants::CONSTRAINT_MAX_SIZE) {
        ACCOUNT_LOGE("Constraint is oversize, the size is %{public}u", size);
        return false;
    }
    std::string constraint;
    for (uint32_t i = 0; i < size; i++) {
        if ((!parcel.ReadString(constraint))) {
            ACCOUNT_LOGE("Read constraint item failed.");
            return false;
        }
        constraintSet_.emplace(constraint);
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS