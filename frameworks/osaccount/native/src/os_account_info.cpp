/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "os_account_info.h"
#include "os_account_info_json_parser.h"
#include <ctime>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {

OsAccountInfo::OsAccountInfo()
{}

OsAccountInfo::OsAccountInfo(int localId, const std::string localName, OsAccountType type, int64_t serialNumber)
    : localId_(localId), localName_(localName), type_(type), serialNumber_(serialNumber)
{}

OsAccountInfo::OsAccountInfo(int localId, const std::string localName, OsAccountType type)
    : localId_(localId), localName_(localName), type_(type)
{}

OsAccountInfo::OsAccountInfo(int localId, const std::string localName, const std::string shortName, OsAccountType type,
    int64_t serialNumber)
    : localId_(localId), localName_(localName), shortName_(shortName), type_(type), serialNumber_(serialNumber)
{}

int OsAccountInfo::GetLocalId() const
{
    return localId_;
}

void OsAccountInfo::SetLocalId(int localId)
{
    localId_ = localId;
}

std::string OsAccountInfo::GetLocalName() const
{
    return localName_;
}

void OsAccountInfo::SetLocalName(const std::string localName)
{
    localName_ = localName;
}

std::string OsAccountInfo::GetShortName() const
{
    return shortName_;
}

void OsAccountInfo::SetShortName(const std::string &shortName)
{
    shortName_ = shortName;
}

OsAccountType OsAccountInfo::GetType() const
{
    return type_;
}

void OsAccountInfo::SetType(OsAccountType type)
{
    type_ = type;
}

std::vector<std::string> OsAccountInfo::GetConstraints() const
{
    return constraints_;
}

void OsAccountInfo::SetConstraints(const std::vector<std::string> constraints)
{
    constraints_ = constraints;
}

bool OsAccountInfo::GetIsVerified() const
{
    return isVerified_;
}

void OsAccountInfo::SetIsVerified(bool isVerified)
{
    isVerified_ = isVerified;
}

bool OsAccountInfo::GetIsCreateCompleted() const
{
    return isCreateCompleted_;
}

void OsAccountInfo::SetIsCreateCompleted(const bool isCreateCompleted)
{
    isCreateCompleted_ = isCreateCompleted;
}

uint64_t OsAccountInfo::GetCredentialId() const
{
    return credentialId_;
}

void OsAccountInfo::SetCredentialId(uint64_t credentialId)
{
    credentialId_ = credentialId;
}

uint64_t OsAccountInfo::GetDisplayId() const
{
    return displayId_;
}

void OsAccountInfo::SetDisplayId(const uint64_t displayId)
{
    displayId_ = displayId;
}

bool OsAccountInfo::GetIsForeground() const
{
    return isForeground_;
}

void OsAccountInfo::SetIsForeground(bool isForeground)
{
    isForeground_ = isForeground;
}

bool OsAccountInfo::GetIsLoggedIn() const
{
    return isLoggedIn_;
}

void OsAccountInfo::SetIsLoggedIn(bool isLoggedIn)
{
    isLoggedIn_ = isLoggedIn;
}

bool OsAccountInfo::GetIsDataRemovable() const
{
    return isDataRemovable_;
}

void OsAccountInfo::SetIsDataRemovable(bool isDataRemovable)
{
    isDataRemovable_ = isDataRemovable;
}

int32_t OsAccountInfo::GetCreatorType() const
{
    return creatorType_;
}

void OsAccountInfo::SetCreatorType(int32_t creatorType)
{
    creatorType_ = creatorType;
}

bool OsAccountInfo::SetDomainInfo(const DomainAccountInfo &domainInfo)
{
    if (domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("domain account name too long! %{public}zu.", domainInfo.accountName_.size());
        return false;
    }
    if (domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("domain name too long! %{public}zu.", domainInfo.domain_.size());
        return false;
    }
    domainInfo_ = domainInfo;
    return true;
}

void OsAccountInfo::GetDomainInfo(DomainAccountInfo &domainInfo) const
{
    domainInfo = domainInfo_;
}

bool OsAccountInfo::GetIsActived() const
{
    return isActivated_;
}

void OsAccountInfo::SetIsActived(const bool isActivated)
{
    isActivated_ = isActivated;
}

std::string OsAccountInfo::GetPhoto() const
{
    return photo_;
}

void OsAccountInfo::SetPhoto(const std::string photo)
{
    photo_ = photo;
}

int64_t OsAccountInfo::GetCreateTime() const
{
    return createTime_;
}

void OsAccountInfo::SetCreateTime(const int64_t createTime)
{
    createTime_ = createTime;
}

int64_t OsAccountInfo::GetLastLoginTime() const
{
    return lastLoginTime_;
}

void OsAccountInfo::SetLastLoginTime(const int64_t lastLoginTime)
{
    lastLoginTime_ = lastLoginTime;
}

OsAccountInfo *OsAccountInfo::Unmarshalling(Parcel &parcel)
{
    OsAccountInfo *osAccountInfo = new (std::nothrow) OsAccountInfo();

    if (osAccountInfo && !osAccountInfo->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete osAccountInfo;
        osAccountInfo = nullptr;
    }

    return osAccountInfo;
}

bool OsAccountInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(ToString());
}

bool OsAccountInfo::ReadFromParcel(Parcel &parcel)
{
    std::string jsonString = parcel.ReadString();
    auto jsonObject = CreateJsonFromString(jsonString);
    if (jsonObject == nullptr) {
        ACCOUNT_LOGE("jsonObject is_discarded");
    }
    FromJson(jsonObject.get(), *this);
    return true;
}

std::string OsAccountInfo::ToString() const
{
    auto jsonObject = ToJson(*this);
    std::string jsonString = PackJsonToString(jsonObject);
    if (jsonString.empty()) {
        ACCOUNT_LOGE("failed to dump json object");
    }
    return jsonString;
}

std::string OsAccountInfo::GetPrimeKey() const
{
    return std::to_string(localId_);
}

int64_t OsAccountInfo::GetSerialNumber() const
{
    return serialNumber_;
}

void OsAccountInfo::SetSerialNumber(const int64_t serialNumber)
{
    serialNumber_ = serialNumber;
}

bool OsAccountInfo::GetToBeRemoved() const
{
    return toBeRemoved_;
}

void OsAccountInfo::SetToBeRemoved(bool toBeRemoved)
{
    toBeRemoved_ = toBeRemoved;
}

bool OsAccountInfo::IsTypeOutOfRange() const
{
    return (type_ < OsAccountType::ADMIN) || ((type_ > OsAccountType::GUEST) && (type_ < OsAccountType::PRIVATE)) ||
        (type_ >= OsAccountType::END);
}

ErrCode OsAccountInfo::ParamCheck()
{
    if (localId_ < Constants::START_USER_ID) {
        ACCOUNT_LOGE("os localId is invalid");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (localName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("local name length %{public}zu is too long!", localName_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (localName_.empty() && localId_ != Constants::START_USER_ID) {
        ACCOUNT_LOGE("local name is empty!");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (IsTypeOutOfRange() || (localId_ == Constants::START_USER_ID && type_ != OsAccountType::ADMIN)) {
        ACCOUNT_LOGE("os account type is invalid");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if ((createTime_ <= 0) && (localId_ != Constants::START_USER_ID)) {
        ACCOUNT_LOGE("os create time is invalid");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    return ERR_OK;
}

bool CreateOsAccountOptions::Marshalling(Parcel &parcel) const
{
    if (allowedHapList.has_value()) {
        if (!parcel.WriteBool(true)) {
            ACCOUNT_LOGE("Write has value failed.");
            return false;
        }
        std::vector<std::string> list = allowedHapList.value();
        if (list.size() > ALLOWED_HAP_LIST_MAX_SIZE) {
            ACCOUNT_LOGE("Abnormal allowedHapList data size, size %{public}zu", list.size());
            return false;
        }
        if (!parcel.WriteStringVector(list)) {
            ACCOUNT_LOGE("Write allowedHapList failed.");
            return false;
        }
    } else {
        if (!parcel.WriteBool(false)) {
            ACCOUNT_LOGE("Write has not value failed.");
            return false;
        }
    }
    return parcel.WriteStringVector(disallowedHapList) && parcel.WriteBool(hasShortName);
}

CreateOsAccountOptions *CreateOsAccountOptions::Unmarshalling(Parcel &parcel)
{
    CreateOsAccountOptions *options = new (std::nothrow) CreateOsAccountOptions();
    if ((options != nullptr) && (!options->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("read from parcel failed");
        delete options;
        options = nullptr;
    }
    return options;
}

bool CreateOsAccountOptions::ReadFromParcel(Parcel &parcel)
{
    bool hasValue = false;
    if (!parcel.ReadBool(hasValue)) {
        ACCOUNT_LOGE("Read has value failed.");
        return false;
    }
    if (hasValue) {
        std::vector<std::string> list = {};
        if (!parcel.ReadStringVector(&list)) {
            ACCOUNT_LOGE("Read allowedHapList failed.");
            return false;
        }
        if (list.size() > ALLOWED_HAP_LIST_MAX_SIZE) {
            ACCOUNT_LOGE("Abnormal allowedHapList data size reading form parcel, size %{public}zu", list.size());
            return false;
        }
        allowedHapList = std::make_optional<std::vector<std::string>>(list);
    }
    return parcel.ReadStringVector(&disallowedHapList) && parcel.ReadBool(hasShortName);
}
}  // namespace AccountSA
}  // namespace OHOS