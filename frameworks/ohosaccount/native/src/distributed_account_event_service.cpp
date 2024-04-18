/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "distributed_account_event_service.h"

namespace OHOS {
namespace AccountSA {
DistributedAccountEventService::DistributedAccountEventService(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
    : distributedAccountSubscribeCallback_(callback)
{
    types_.insert(type);
}

DistributedAccountEventService::~DistributedAccountEventService()
{}

bool DistributedAccountEventService::IsTypeExist(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type)
{
    std::lock_guard<std::mutex> lock(typesLock_);
    return types_.find(type) != types_.end();
}

void DistributedAccountEventService::AddType(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type)
{
    std::lock_guard<std::mutex> lock(typesLock_);
    types_.insert(type);
}

void DistributedAccountEventService::DeleteType(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type)
{
    std::lock_guard<std::mutex> lock(typesLock_);
    types_.erase(type);
}

int32_t DistributedAccountEventService::GetTypeSize()
{
    return types_.size();
}

void DistributedAccountEventService::GetAllType(std::vector<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE> &typeList)
{
    for (auto it : types_) {
        typeList.push_back(it);
    }
}

void DistributedAccountEventService::OnAccountsChanged(const DistributedAccountEventData &eventData)
{
    if (distributedAccountSubscribeCallback_ == nullptr) {
        ACCOUNT_LOGE("Callback_ is nullptr");
        return;
    }
    distributedAccountSubscribeCallback_->OnAccountsChanged(eventData);
}
}  // namespace AccountSA
}  // namespace OHOS
