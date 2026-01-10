/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
class MockAccountMgrService final : public AccountStub, public IAccountContext {
public:
    MockAccountMgrService();
    MockAccountMgrService(const MockAccountMgrService &) = delete;
    ~MockAccountMgrService() override;

    void HandleNotificationEvents(const std::string &eventStr) override;
    std::int32_t QueryDeviceAccountId(std::int32_t& accountId) override;
    ErrCode UpdateOhosAccountInfo(
        const std::string& accountName, const std::string& uid, const std::string& eventStr) override;
    ErrCode QueryOhosAccountInfo(std::string& accountName, std::string& uid, int32_t& status) override;
    ErrCode QueryOsAccountDistributedInfo(
        std::int32_t localId, std::string& accountName, std::string& uid, int32_t& status) override;
    ErrCode SubscribeDistributedAccountEvent(const int32_t typeInt, const sptr<IRemoteObject>& eventListener) override;
    ErrCode UnsubscribeDistributedAccountEvent(
        const int32_t typeInt, const sptr<IRemoteObject>& eventListener) override;
    ErrCode GetAppAccountService(sptr<IRemoteObject>& funcResult) override;
    ErrCode GetOsAccountService(sptr<IRemoteObject>& funcResult) override;
    ErrCode GetDomainAccountService(sptr<IRemoteObject>& funcResult) override;
    std::int32_t SetOhosAccountInfo(const OhosAccountInfo& ohosAccountInfo, const std::string& eventStr) override
    {
        return 0;
    }

    std::int32_t SetOsAccountDistributedInfo(
        int32_t localId, const OhosAccountInfo& ohosAccountInfo, const std::string& eventStr) override
    {
        return 0;
    }

    ErrCode GetOhosAccountInfo(OhosAccountInfo& accountInfo) override
    {
        return 0;
    }

    ErrCode GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo& info) override
    {
        return 0;
    }

    ErrCode QueryDistributedVirtualDeviceId(std::string& dvid) override
    {
        return 0;
    }

    ErrCode QueryDistributedVirtualDeviceId(const std::string& bundleName, int32_t localId, std::string& dvid) override
    {
        return 0;
    }

    ErrCode GetAccountIAMService(sptr<IRemoteObject>& funcResult) override
    {
        funcResult = nullptr;
        return 0;
    }
    
    ErrCode GetAuthorizationService(sptr<IRemoteObject>& funcResult) override
    {
        funcResult = nullptr;
        return 0;
    }

    bool IsServiceStarted() const override
    {
        return true;
    }

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override
    {
        return ERR_OK;
    }

    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override
    {
        return ERR_OK;
    }

private:
    std::int32_t devAccountId_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_INCLUDE_MOCK_ACCOUNT_MGR_SERVICE_H
