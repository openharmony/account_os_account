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
const std::string ID = "id";
const std::string NAME = "name";
const std::string TYPE = "type";
const std::string CONSTRAINTS = "constraints";
const std::string IS_OS_ACCOUNT_VERIFIED = "isOsAccountVerified";
const std::string PHOTO = "photo";
const std::string CREATE_TIME = "createTime";
const std::string LAST_LOGGED_IN_TIME = "lastLoggedInTime";
const std::string SERIAL_NUMBER = "serialNumber";
const std::string IS_ACTIVED = "isActived";
const std::string IS_ACCOUNT_COMPLETED = "isAccountCompleted";
}  // namespace

OsAccountInfo::OsAccountInfo()
{
    id_ = -1;
    name_.clear();
    type_ = -1;
    constraints_.clear();
    isAccountVerified_ = false;
    photo_.clear();
    createTime_ = 0;
    lastLoggedInTime_ = 0;
    serialNumber_ = 0;
    isActived_ = false;
    isAccountCompleted_ = false;
}

OsAccountInfo::OsAccountInfo(int id, const std::string name, int type, int64_t serialNumber)
    : id_(id), name_(name), type_(type), serialNumber_(serialNumber)
{
    constraints_.clear();
    isAccountVerified_ = false;
    photo_.clear();
    createTime_ = 0;
    lastLoggedInTime_ = 0;
    isActived_ = false;
    isAccountCompleted_ = false;
}

OsAccountInfo::OsAccountInfo(int id, std::string name, int type, std::vector<std::string> constraints,
    bool isOsAccountVerified, std::string photo, int64_t createTime, int64_t lastLoggedInTime, int64_t serialNumber,
    bool isAccountCompleted)
    : id_(id),
      name_(name),
      type_(type),
      constraints_(constraints),
      isAccountVerified_(isOsAccountVerified),
      photo_(photo),
      createTime_(createTime),
      lastLoggedInTime_(lastLoggedInTime),
      serialNumber_(serialNumber),
      isAccountCompleted_(isAccountCompleted)
{
    isActived_ = false;
}

int OsAccountInfo::GetId() const
{
    return id_;
}

void OsAccountInfo::SetId(int id)
{
    id_ = id;
}

std::string OsAccountInfo::GetName() const
{
    return name_;
}

void OsAccountInfo::SetName(const std::string name)
{
    name_ = name;
}

int OsAccountInfo::GetType() const
{
    return type_;
}

void OsAccountInfo::SetType(int type)
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

bool OsAccountInfo::GetIsAccountVerified() const
{
    return isAccountVerified_;
}

void OsAccountInfo::SetIsAccountVerified(bool isAccountVerified)
{
    isAccountVerified_ = isAccountVerified;
}

bool OsAccountInfo::GetIsAccountCompleted() const
{
    return isAccountCompleted_;
}

void OsAccountInfo::SetIsAccountCompleted(const bool isAccountCompleted)
{
    isAccountCompleted_ = isAccountCompleted;
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

int64_t OsAccountInfo::GetLastLoggedInTime() const
{
    return lastLoggedInTime_;
}

void OsAccountInfo::SetLastLoggedInTime(const int64_t lastLoggedInTime)
{
    lastLoggedInTime_ = lastLoggedInTime;
}

Json OsAccountInfo::ToJson() const
{
    Json jsonObject = Json {
        {ID, id_},
        {NAME, name_},
        {TYPE, type_},
        {CONSTRAINTS, constraints_},
        {IS_OS_ACCOUNT_VERIFIED, isAccountVerified_},
        {PHOTO, photo_},
        {CREATE_TIME, createTime_},
        {LAST_LOGGED_IN_TIME, lastLoggedInTime_},
        {SERIAL_NUMBER, serialNumber_},
        {IS_ACTIVED, isActived_},
        {IS_ACCOUNT_COMPLETED, isAccountCompleted_},
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
    OHOS::AccountSA::GetDataByType<int>(jsonObject, jsonObjectEnd, ID, id_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, NAME, name_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<int>(jsonObject, jsonObjectEnd, TYPE, type_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<std::vector<std::string>>(
        jsonObject, jsonObjectEnd, CONSTRAINTS, constraints_, OHOS::AccountSA::JsonType::ARRAY);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_OS_ACCOUNT_VERIFIED, isAccountVerified_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, PHOTO, photo_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<int64_t>(
        jsonObject, jsonObjectEnd, CREATE_TIME, createTime_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<int64_t>(
        jsonObject, jsonObjectEnd, LAST_LOGGED_IN_TIME, lastLoggedInTime_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<int64_t>(
        jsonObject, jsonObjectEnd, SERIAL_NUMBER, serialNumber_, OHOS::AccountSA::JsonType::NUMBER);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_ACTIVED, isActived_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, IS_ACCOUNT_COMPLETED, isAccountCompleted_, OHOS::AccountSA::JsonType::BOOLEAN);
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
    return std::to_string(id_);
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
        {ID, osAccountInfo.GetId()},
        {NAME, osAccountInfo.GetName()},
        {TYPE, osAccountInfo.GetType()},
        {CONSTRAINTS, osAccountInfo.GetConstraints()},
        {IS_OS_ACCOUNT_VERIFIED, osAccountInfo.GetIsAccountVerified()},
        {PHOTO, osAccountInfo.GetPhoto()},
        {CREATE_TIME, osAccountInfo.GetCreateTime()},
        {LAST_LOGGED_IN_TIME, osAccountInfo.GetLastLoggedInTime()},
        {SERIAL_NUMBER, osAccountInfo.GetSerialNumber()},
        {IS_ACTIVED, osAccountInfo.GetIsActived()},
        {IS_ACCOUNT_COMPLETED, osAccountInfo.GetIsAccountCompleted()},
    };
}
}  // namespace AccountSA
}  // namespace OHOS