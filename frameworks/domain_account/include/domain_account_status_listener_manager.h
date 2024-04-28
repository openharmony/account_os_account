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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STATUS_LISTENER_SERVICE_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STATUS_LISTENER_SERVICE_H

#include <map>
#include <mutex>
#include <set>

#include "domain_account_callback.h"
#include "domain_account_status_listener.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountStatusListenerManager : public DomainAccountCallback {
public:
    DomainAccountStatusListenerManager();
    virtual ~DomainAccountStatusListenerManager();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    void InsertRecord(const std::shared_ptr<DomainAccountStatusListener> &listener);
    void RemoveRecord(const std::shared_ptr<DomainAccountStatusListener> &listener);
    bool IsRecordEmpty();
    std::set<std::string> GetDomainInfoRecords();

private:
    std::string GetDomainAccountStr(const std::string &domain, const std::string &accountName);

private:
    std::mutex mutex_;
    std::set<std::shared_ptr<DomainAccountStatusListener>> listenerAll_;
};
}  // AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STATUS_LISTENER_SERVICE_H