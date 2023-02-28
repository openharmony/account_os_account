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

#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "domain_account_common.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {

DomainAccountInfo::DomainAccountInfo() : domain_(""), accountName_(""), accountId_("")
{}

DomainAccountInfo::DomainAccountInfo(const std::string &domain, const std::string &domainAccountName)
    : domain_(domain), accountName_(domainAccountName)
{}

DomainAccountInfo::DomainAccountInfo(
    const std::string &domain, const std::string &domainAccountName, const std::string &accountId)
    : domain_(domain), accountName_(domainAccountName), accountId_(accountId)
{}

void DomainAccountInfo::Clear()
{
    domain_.clear();
    accountName_.clear();
    accountId_.clear();
}

bool DomainAccountInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(accountName_)) {
        ACCOUNT_LOGE("failed to read domain account name");
        return false;
    }
    if (!parcel.ReadString(domain_)) {
        ACCOUNT_LOGE("failed to read domain");
        return false;
    }
    if (!parcel.ReadString(accountId_)) {
        ACCOUNT_LOGE("failed to read domain accountId");
        return false;
    }
    return true;
}

bool DomainAccountInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(accountName_)) {
        ACCOUNT_LOGE("failed to read write account name");
        return false;
    }
    if (!parcel.WriteString(domain_)) {
        ACCOUNT_LOGE("failed to write domain");
        return false;
    }
    if (!parcel.WriteString(accountId_)) {
        ACCOUNT_LOGE("failed to read write accountId");
        return false;
    }
    return true;
}

DomainAccountInfo *DomainAccountInfo::Unmarshalling(Parcel &parcel)
{
    DomainAccountInfo *domainAccountInfo = new (std::nothrow) DomainAccountInfo();
    if (domainAccountInfo == nullptr) {
        return nullptr;
    }

    if (!domainAccountInfo->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete domainAccountInfo;
        domainAccountInfo = nullptr;
    }

    return domainAccountInfo;
}
}  // namespace AccountSA
}  // namespace OHOS