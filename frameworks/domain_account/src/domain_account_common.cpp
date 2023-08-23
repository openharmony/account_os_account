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

GetAccessTokenOptions::GetAccessTokenOptions(const int32_t &callingUid, const AAFwk::WantParams &getTokenParams)
    : callingUid_(callingUid), getTokenParams_(getTokenParams)
{}

GetAccessTokenOptions::GetAccessTokenOptions()
{}

bool GetAccessTokenOptions::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(callingUid_)) {
        ACCOUNT_LOGE("failed to read callingUid");
        return false;
    }
    auto param = parcel.ReadParcelable<AAFwk::WantParams>();
    if (param == nullptr) {
        ACCOUNT_LOGE("failed to read wantParams");
        return false;
    }
    getTokenParams_ = (*param);
    delete param;
    return true;
}

bool GetAccessTokenOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(callingUid_)) {
        ACCOUNT_LOGE("failed to read write callingUid");
        return false;
    }
    if (!parcel.WriteParcelable(&getTokenParams_)) {
        ACCOUNT_LOGE("failed to write getTokenParams");
        return false;
    }
    return true;
}

GetAccessTokenOptions *GetAccessTokenOptions::Unmarshalling(Parcel &parcel)
{
    GetAccessTokenOptions *getAccessTokenOptions = new (std::nothrow) GetAccessTokenOptions();
    if (getAccessTokenOptions == nullptr) {
        return nullptr;
    }

    if (!getAccessTokenOptions->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete getAccessTokenOptions;
        getAccessTokenOptions = nullptr;
    }

    return getAccessTokenOptions;
}

bool GetDomainAccountInfoOptions::ReadFromParcel(Parcel &parcel)
{
    std::shared_ptr<DomainAccountInfo> infoPtr(parcel.ReadParcelable<DomainAccountInfo>());
    if (infoPtr == nullptr) {
        ACCOUNT_LOGE("failed to read authStatusInfo");
        return false;
    }
    accountInfo = *infoPtr;
    if (!parcel.ReadInt32(callingUid)) {
        ACCOUNT_LOGE("failed to read callingUid");
        return false;
    }
    return true;
}

bool GetDomainAccountInfoOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteParcelable(&accountInfo)) {
        ACCOUNT_LOGE("failed to write authStatusInfo");
        return false;
    }
    if (!parcel.WriteInt32(callingUid)) {
        ACCOUNT_LOGE("failed to read write callingUid");
        return false;
    }
    return true;
}

GetDomainAccountInfoOptions *GetDomainAccountInfoOptions::Unmarshalling(Parcel &parcel)
{
    GetDomainAccountInfoOptions *getAccountInfoOptions = new (std::nothrow) GetDomainAccountInfoOptions();
    if (getAccountInfoOptions == nullptr) {
        return nullptr;
    }

    if (!getAccountInfoOptions->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete getAccountInfoOptions;
        getAccountInfoOptions = nullptr;
    }

    return getAccountInfoOptions;
}

bool AuthStatusInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(remainingTimes)) {
        ACCOUNT_LOGE("failed to read remainingTimes");
        return false;
    }
    if (!parcel.ReadInt32(freezingTime)) {
        ACCOUNT_LOGE("failed to read freezingTime");
        return false;
    }
    return true;
}

bool AuthStatusInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(remainingTimes)) {
        ACCOUNT_LOGE("failed to read write remainingTimes");
        return false;
    }
    if (!parcel.WriteInt32(freezingTime)) {
        ACCOUNT_LOGE("failed to write freezingTime");
        return false;
    }
    return true;
}

AuthStatusInfo *AuthStatusInfo::Unmarshalling(Parcel &parcel)
{
    AuthStatusInfo *info = new (std::nothrow) AuthStatusInfo();
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to create AuthStatusInfo");
        return nullptr;
    }
    if (!info->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete info;
        info = nullptr;
    }
    return info;
}

bool DomainAuthResult::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadUInt8Vector(&token)) {
        ACCOUNT_LOGE("failed to read remainingTimes");
        return false;
    }
    std::shared_ptr<AuthStatusInfo> infoPtr(parcel.ReadParcelable<AuthStatusInfo>());
    if (infoPtr == nullptr) {
        ACCOUNT_LOGE("failed to read authStatusInfo");
        return false;
    }
    authStatusInfo = *infoPtr;
    return true;
}

bool DomainAuthResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUInt8Vector(token)) {
        ACCOUNT_LOGE("failed to read write token");
        return false;
    }
    if (!parcel.WriteParcelable(&authStatusInfo)) {
        ACCOUNT_LOGE("failed to write authStatusInfo");
        return false;
    }
    return true;
}

DomainAuthResult *DomainAuthResult::Unmarshalling(Parcel &parcel)
{
    DomainAuthResult *result = new (std::nothrow) DomainAuthResult();
    if (result == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAuthResult");
        return nullptr;
    }
    if (!result->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete result;
        result = nullptr;
    }
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS