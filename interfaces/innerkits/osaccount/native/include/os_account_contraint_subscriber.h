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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_CONSTRAINT_SUBSCRIBER_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_CONSTRAINT_SUBSCRIBER_H

#include "os_account_constraint_subscribe_info.h"

namespace OHOS {
namespace AccountSA {
class OsAccountConstraintSubscriber {
public:
    explicit OsAccountConstraintSubscriber(const std::set<std::string> &constraintSet);
    virtual ~OsAccountConstraintSubscriber();
    /**
     * Notify the std::string> &constraint change.
     *
     * @param localId - the os acount id's constraint has changed
     * @param constraint - this constraint has changed
     * @param value - this constraint's new value, true means enable
     * @since 20
     */
    virtual void OnConstraintChanged(int localId, const std::string &constraint, bool enable) {};
    void GetConstraintSet(std::set<std::string> &constraintSet) const;
private:
    std::set<std::string> constraintSet_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif // OS_ACCOUNT_INTERFACES_INNERKITS_OSACCOUNT_NATIVE_INCLUDE_OS_ACCOUNT_CONSTRAINT_SUBSCRIBER_H