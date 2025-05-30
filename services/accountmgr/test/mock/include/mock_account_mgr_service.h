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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_INCLUDE_MOCK_ACCOUNT_MGR_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_INCLUDE_MOCK_ACCOUNT_MGR_SERVICE_H

#include <gtest/gtest.h>
#include <cstdint>
#include "iaccount_context.h"
#include "account_stub.h"

namespace OHOS {
namespace AccountSA {
constexpr std::int32_t MAX_SUPPORTED_ACCOUNT_NUMBER = 4;
class MockAccountMgrService final : public AccountStub {
public:
    MockAccountMgrService();
    MockAccountMgrService(const MockAccountMgrService &) = delete;
    ~MockAccountMgrService() override;

    void HandleNotificationEvents(const std::string &eventStr) override;
    std::int32_t QueryDeviceAccountId(std::int32_t &accountId) override;
    ErrCode UpdateOhosAccountInfo(
        const std::string &accountName, const std::string &uid, const std::string &eventStr) override;
    ErrCode QueryOhosAccountInfo(OhosAccountInfo &accountInfo) override;
    ErrCode QueryOsAccountDistributedInfo(std::int32_t localId, OhosAccountInfo &accountInfo) override;
    ErrCode SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) override;
    sptr<IRemoteObject> GetAppAccountService() override;
    sptr<IRemoteObject> GetOsAccountService() override;
    sptr<IRemoteObject> GetDomainAccountService() override;
    std::int32_t SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr) override
    {
        return 0;
    }

    std::int32_t SetOsAccountDistributedInfo(
        const int32_t localId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr) override
    {
        return 0;
    }

    ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) override
    {
        return 0;
    }

    ErrCode GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo &info) override
    {
        return 0;
    }

    ErrCode QueryDistributedVirtualDeviceId(std::string &dvid) override
    {
        return 0;
    }

    ErrCode QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId, std::string &dvid) override
    {
        return 0;
    }

    sptr<IRemoteObject> GetAccountIAMService() override
    {
        return nullptr;
    }

    bool IsServiceStarted() const override
    {
        return true;
    }

private:
    std::int32_t devAccountId_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_INCLUDE_MOCK_ACCOUNT_MGR_SERVICE_H
