/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "mock_domain_create_domain_account_callback.h"
#include "mock_domain_plugin.h"

#include "account_log_wrapper.h"
#include "condition_variable"
#include "os_account_manager.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
namespace {
}

TestCreateDomainAccountCallback::TestCreateDomainAccountCallback(
    const std::shared_ptr<MockDomainCreateDomainAccountCallback> &callback)
    : callback_(callback)
{}

TestCreateDomainAccountCallback::~TestCreateDomainAccountCallback()
{}

void TestCreateDomainAccountCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    if (callback_ == nullptr) {
        return;
    }
    OsAccountInfo *osAccountInfo = OsAccountInfo::Unmarshalling(parcel);
    DomainAccountInfo newDomainInfo;
    osAccountInfo->GetDomainInfo(newDomainInfo);
    callback_->OnResult(errCode, newDomainInfo.accountName_, newDomainInfo.domain_, newDomainInfo.accountId_);
    localId_ = osAccountInfo->GetLocalId();
    if ((newDomainInfo.accountName_ == "zhangsan") || (newDomainInfo.accountName_ == "zhangsan777") ||
        (newDomainInfo.accountName_ == "zhangsan666")) {
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    OsAccountManager::RemoveOsAccount(osAccountInfo->GetLocalId());
    std::unique_lock<std::mutex> lock(mutex);
    isReady = true;
    cv.notify_one();
    return;
}

int32_t TestCreateDomainAccountCallback::GetLocalId(void)
{
    return localId_;
}
}  // AccountSA
}  // OHOS