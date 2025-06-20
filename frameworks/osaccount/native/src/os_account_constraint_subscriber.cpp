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

#include "os_account_constraint_subscriber.h"

namespace OHOS {
namespace AccountSA {
OsAccountConstraintSubscriber::OsAccountConstraintSubscriber(const std::set<std::string> &constraintSet)
    : constraintSet_(constraintSet)
{}

OsAccountConstraintSubscriber::~OsAccountConstraintSubscriber()
{}

void OsAccountConstraintSubscriber::GetConstraintSet(std::set<std::string> &constraintSet) const
{
    constraintSet = constraintSet_;
}
}  // namespace AccountSA
}  // namespace OHOS