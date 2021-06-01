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

#ifndef BASE_MOCK_ACCOUNT_MGR_SERVICE_H
#define BASE_MOCK_ACCOUNT_MGR_SERVICE_H

#include <gtest/gtest.h>
#include <cstdint>
#include "iaccount_context.h"
#include "account_stub.h"

namespace OHOS {
namespace AccountSA {
constexpr std::int32_t MAX_SUPPORTED_ACCOUNT_NUMBER = 4;
class MockAccountMgrService final: public AccountStub {
public:
    MockAccountMgrService();
    MockAccountMgrService(const MockAccountMgrService&) = delete;
    ~MockAccountMgrService() override;

    void HandleNotificationEvents(const std::string& eventStr) override;
    std::int32_t QueryDeviceAccountId(std::int32_t& accountId) override;
    bool UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
                               const std::string& eventStr) override;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo(void) override;
    std::int32_t QueryDeviceAccountIdFromUid(std::int32_t uid) override;
    bool IsServiceStarted() const override
    {
        return true;
    }
private:
    std::int32_t devAccountId_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // BASE_MOCK_ACCOUNT_MGR_SERVICE_H
