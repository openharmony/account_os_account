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
#include "os_account_info.h"
namespace OHOS {
namespace AccountSA {
namespace {
const std::string LOCAL_ID = "localId";
const std::string LOCAL_NAME = "localName";
const std::string TYPE = "type";
const std::string CONSTRAINTS = "constraints";
const std::string IS_OS_ACCOUNT_VERIFIED = "isVerified";
const std::string PHOTO = "photo";
const std::string CREATE_TIME = "createTime";
const std::string LAST_LOGGED_IN_TIME = "lastLoginTime";
const std::string SERIAL_NUMBER = "serialNumber";
const std::string IS_ACTIVED = "isActived";
const std::string IS_ACCOUNT_COMPLETED = "isCreateCompleted";
}  // namespace

OsAccountInfo::OsAccountInfo()
{
    localId_ = -1;
    localName_.clear();
    type_ = OsAccountType::ADMIN;
    constraints_.clear();
    isVerified_ = false;
    photo_.clear();
    createTime_ = 0;
    lastLoginTime_ = 0;
    serialNumber_ = 0;
    isActived_ = false;
    isCreateCompleted_ = false;
}

OsAccountInfo::OsAccountInfo(int localId, const std::string localName, OsAccountType type, int64_t serialNumber)
    : localId_(localId), localName_(localName), type_(type), serialNumber_(serialNumber)
{
    constraints_.clear();
    isVerified_ = false;
    photo_.clear();
    createTime_ = 0;
    lastLoginTime_ = 0;
    isActived_ = false;
    isCreateCompleted_ = false;
}

OsAccountInfo::OsAccountInfo(int localId, std::string localName, OsAccountType type,
    std::vector<std::string> constraints, bool isVerified, std::string photo, int64_t createTime, int64_t lastLoginTime,
    int64_t serialNumber, bool isCreateCompleted)
    : localId_(localId),
      localName_(localName),
      type_(type),
      constraints_(constraints),
      isVerified_(isVerified),
      photo_(photo),
      createTime_(createTime),
      lastLoginTime_(lastLoginTime),
      serialNumber_(serialNumber),
      isCreateCompleted_(isCreateCompleted)
{
    isActived_ = false;
}

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

bool OsAccountInfo::GetIsActived() const
{
    return isActived_;
}

void OsAccountInfo::SetIsActived(const bool isActived)
{
    isActived_ = isActived;
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
        {TYPE, type_},
        {CONSTRAINTS, constraints_},
        {IS_OS_ACCOUNT_VERIFIED, isVerified_},
        {PHOTO, photo_},
        {CREATE_TIME, createTime_},
        {LAST_LOGGED_IN_TIME, lastLoginTime_},
        {SERIAL_NUMBER, serialNumber_},
        {IS_ACTIVED, isActived_},
        {IS_ACCOUNT_COMPLETED, isCreateCompleted_},
    };
    return jsonObject;
}
OsAccountInfo *OsAccountInfo::Unmarshalling(Parcel &parcel)
{
    ACCOUNT_LOGI("enter");

    OsAccountInfo *osAccountInfo = new (std::nothrow) OsAccountInfo();

    if (osAccountInfo && !osAccountInfo->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from pacel");
        delete osAccountInfo;
        osAccountInfo = nullptr;
    }

    return osAccountInfo;
}
void OsAccountInfo::FromJson(const Json &jsonObject)
{
    const auto &jsonObjectEnd = jsonObject.end();
    OHOS::AccountSA::GetDataByType<int>(
        jsonObject, jsonObjectEnd, LOCAL_ID, localId_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, LOCAL_NAME, localName_, OHOS::AccountSA::JsonType::STRING);
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
        jsonObject, jsonObjectEnd, IS_ACTIVED, isActived_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_ACCOUNT_COMPLETED, isCreateCompleted_, OHOS::AccountSA::JsonType::BOOLEAN);
}

bool OsAccountInfo::Marshalling(Parcel &parcel) const
{
    auto jsonObject = ToJson();
    parcel.WriteString(jsonObject.dump());
    return true;
}

bool OsAccountInfo::ReadFromParcel(Parcel &parcel)
{
    std::string jsonString = parcel.ReadString();
    nlohmann::json jsonObject = nlohmann::json::parse(jsonString, nullptr, false);
    FromJson(jsonObject);
    return true;
}

std::string OsAccountInfo::ToString() const
{
    auto jsonObject = ToJson();
    return jsonObject.dump();
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

void to_json(Json &jsonObject, const OsAccountInfo &osAccountInfo)
{
    jsonObject = Json {
        {LOCAL_ID, osAccountInfo.GetLocalId()},
        {LOCAL_NAME, osAccountInfo.GetLocalName()},
        {TYPE, osAccountInfo.GetType()},
        {CONSTRAINTS, osAccountInfo.GetConstraints()},
        {IS_OS_ACCOUNT_VERIFIED, osAccountInfo.GetIsVerified()},
        {PHOTO, osAccountInfo.GetPhoto()},
        {CREATE_TIME, osAccountInfo.GetCreateTime()},
        {LAST_LOGGED_IN_TIME, osAccountInfo.GetLastLoginTime()},
        {SERIAL_NUMBER, osAccountInfo.GetSerialNumber()},
        {IS_ACTIVED, osAccountInfo.GetIsActived()},
        {IS_ACCOUNT_COMPLETED, osAccountInfo.GetIsCreateCompleted()},
    };
}
}  // namespace AccountSA
}  // namespace OHOS