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

#include <ctime>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string LOCAL_ID = "localId";
const std::string LOCAL_NAME = "localName";
const std::string SHORT_NAME = "shortName";
const std::string TYPE = "type";
const std::string CONSTRAINTS = "constraints";
const std::string IS_OS_ACCOUNT_VERIFIED = "isVerified";
const std::string PHOTO = "photo";
const std::string CREATE_TIME = "createTime";
const std::string LAST_LOGGED_IN_TIME = "lastLoginTime";
const std::string SERIAL_NUMBER = "serialNumber";
const std::string IS_ACTIVATED = "isActived";
const std::string IS_ACCOUNT_COMPLETED = "isCreateCompleted";
const std::string DOMAIN_INFO = "domainInfo";
const std::string DOMAIN_NAME = "domain";
const std::string DOMAIN_ACCOUNT_NAME = "accountName";
const std::string DOMAIN_ACCOUNT_ID = "accountId";
const std::string TO_BE_REMOVED = "toBeRemoved";
const std::string CREDENTIAL_ID = "credentialId";
const std::string DISPLAY_ID = "displayId";
const std::string IS_FOREGROUND = "isForeground";
const std::string IS_LOGGED_IN = "isLoggedIn";
const std::string DOMAIN_ACCOUNT_STATUS = "domainAccountStatus";
const std::string DOMAIN_ACCOUNT_CONFIG = "domainServerConfigId";
}  // namespace

OsAccountInfo::OsAccountInfo()
{}

OsAccountInfo::OsAccountInfo(int localId, const std::string localName, OsAccountType type, int64_t serialNumber)
    : localId_(localId), localName_(localName), type_(type), serialNumber_(serialNumber)
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

Json OsAccountInfo::ToJson() const
{
    Json jsonObject = Json {
        {LOCAL_ID, localId_},
        {LOCAL_NAME, localName_},
        {SHORT_NAME, shortName_},
        {TYPE, type_},
        {CONSTRAINTS, constraints_},
        {IS_OS_ACCOUNT_VERIFIED, isVerified_},
        {PHOTO, photo_},
        {CREATE_TIME, createTime_},
        {LAST_LOGGED_IN_TIME, lastLoginTime_},
        {SERIAL_NUMBER, serialNumber_},
        {IS_ACTIVATED, isActivated_},
        {IS_ACCOUNT_COMPLETED, isCreateCompleted_},
        {TO_BE_REMOVED, toBeRemoved_},
        {CREDENTIAL_ID, credentialId_},
        {DISPLAY_ID, displayId_},
        {IS_FOREGROUND, isForeground_},
        {IS_LOGGED_IN, isLoggedIn_},
        {DOMAIN_INFO, {
            {DOMAIN_NAME, domainInfo_.domain_},
            {DOMAIN_ACCOUNT_NAME, domainInfo_.accountName_},
            {DOMAIN_ACCOUNT_ID, domainInfo_.accountId_},
            {DOMAIN_ACCOUNT_STATUS, domainInfo_.status_},
            {DOMAIN_ACCOUNT_CONFIG, domainInfo_.serverConfigId_},
        },
        }
    };
    return jsonObject;
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

void OsAccountInfo::GetDomainInfoFromJson(const Json &jsonObject)
{
    const auto &jsonObjectEnd = jsonObject.end();
    Json typeJson;
    OHOS::AccountSA::GetDataByType<Json>(
        jsonObject, jsonObjectEnd, DOMAIN_INFO, typeJson, OHOS::AccountSA::JsonType::OBJECT);
    OHOS::AccountSA::GetDataByType<std::string>(
        typeJson, typeJson.end(), DOMAIN_NAME, domainInfo_.domain_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<std::string>(
        typeJson, typeJson.end(), DOMAIN_ACCOUNT_NAME, domainInfo_.accountName_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<std::string>(
        typeJson, typeJson.end(), DOMAIN_ACCOUNT_ID, domainInfo_.accountId_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<DomainAccountStatus>(
        typeJson, typeJson.end(), DOMAIN_ACCOUNT_STATUS, domainInfo_.status_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<std::string>(
        typeJson, typeJson.end(), DOMAIN_ACCOUNT_CONFIG, domainInfo_.serverConfigId_,
        OHOS::AccountSA::JsonType::STRING);
}

void OsAccountInfo::FromJson(const Json &jsonObject)
{
    const auto &jsonObjectEnd = jsonObject.end();
    OHOS::AccountSA::GetDataByType<int>(
        jsonObject, jsonObjectEnd, LOCAL_ID, localId_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, LOCAL_NAME, localName_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, SHORT_NAME, shortName_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<OsAccountType>(
        jsonObject, jsonObjectEnd, TYPE, type_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        jsonObject, jsonObjectEnd, CONSTRAINTS, constraints_, OHOS::AccountSA::JsonType::ARRAY);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_OS_ACCOUNT_VERIFIED, isVerified_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, PHOTO, photo_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<int64_t>(
        jsonObject, jsonObjectEnd, CREATE_TIME, createTime_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<int64_t>(
        jsonObject, jsonObjectEnd, LAST_LOGGED_IN_TIME, lastLoginTime_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<int64_t>(
        jsonObject, jsonObjectEnd, SERIAL_NUMBER, serialNumber_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_ACTIVATED, isActivated_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_ACCOUNT_COMPLETED, isCreateCompleted_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, TO_BE_REMOVED, toBeRemoved_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<uint64_t>(
        jsonObject, jsonObjectEnd, CREDENTIAL_ID, credentialId_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<uint64_t>(
        jsonObject, jsonObjectEnd, DISPLAY_ID, displayId_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_FOREGROUND, isForeground_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_LOGGED_IN, isLoggedIn_, OHOS::AccountSA::JsonType::BOOLEAN);

    GetDomainInfoFromJson(jsonObject);
}

bool OsAccountInfo::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(ToString());
    return true;
}

bool OsAccountInfo::ReadFromParcel(Parcel &parcel)
{
    std::string jsonString = parcel.ReadString();
    nlohmann::json jsonObject = nlohmann::json::parse(jsonString, nullptr, false);
    if (jsonObject.is_discarded()) {
        ACCOUNT_LOGI("jsonObject is discarded");
    }
    FromJson(jsonObject);
    return true;
}

std::string OsAccountInfo::ToString() const
{
    auto jsonObject = ToJson();
    std::string jsonString;
    try {
        jsonString = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
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
    return parcel.WriteStringVector(disallowedHapList);
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
    return parcel.ReadStringVector(&disallowedHapList);
}
}  // namespace AccountSA
}  // namespace OHOS