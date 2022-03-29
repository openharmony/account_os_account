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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STATE_ACTION_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STATE_ACTION_H

namespace OHOS {
namespace AccountSA {
/**
 * Base class of state change process.
 */
class AccountStateAction {
public:
    /**
     * Constructor.
     *
     * @param nextStateId the unique State ID. It should be a non-negative number.
     */
    explicit AccountStateAction(const int nextStateId) : nextState_(nextStateId) {}

    /**
     * Destructor.
     *
     */
    virtual ~AccountStateAction() {}

    /**
     * Get the next State ID.
     *
     * @return the next State ID
     */
    int GetNextState() const
    {
        return nextState_;
    }

private:
    /**
     * the next State ID
     */
    int nextState_;
};
} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STATE_ACTION_H
