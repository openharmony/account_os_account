/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "account_iam_info.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {

bool AuthParam::WriteRemoteAuthParam(Parcel& parcel) const
{
    bool hasValue = (remoteAuthParam != std::nullopt);
    if (!parcel.WriteBool(hasValue)) {
        ACCOUNT_LOGE("Write RemoteAuthParam exist failed.");
        return false;
    }
    if (!hasValue) {
        return true;
    }
    hasValue = (remoteAuthParam.value().verifierNetworkId != std::nullopt);
    if (!parcel.WriteBool(hasValue)) {
        ACCOUNT_LOGE("Write verifierNetworkId exist failed.");
        return false;
    }
    if (hasValue) {
        if (!parcel.WriteString(remoteAuthParam.value().verifierNetworkId.value())) {
            ACCOUNT_LOGE("Write verifierNetworkId failed.");
            return false;
        }
    }
    hasValue = (remoteAuthParam.value().collectorNetworkId != std::nullopt);
    if (!parcel.WriteBool(hasValue)) {
        ACCOUNT_LOGE("Write collectorNetworkId exist failed.");
        return false;
    }
    if (hasValue) {
        if (!parcel.WriteString(remoteAuthParam.value().collectorNetworkId.value())) {
            ACCOUNT_LOGE("Write collectorNetworkId failed.");
            return false;
        }
    }
    hasValue = (remoteAuthParam.value().collectorTokenId != std::nullopt);
    if (!parcel.WriteBool(hasValue)) {
        ACCOUNT_LOGE("Write collectorTokenId exist failed.");
        return false;
    }
    if (hasValue) {
        if (!parcel.WriteUint32(remoteAuthParam.value().collectorTokenId.value())) {
            ACCOUNT_LOGE("Write collectorTokenId failed.");
            return false;
        }
    }
    return true;
}

bool AuthParam::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt32(userId)) {
        ACCOUNT_LOGE("Failed to write userId!");
        return false;
    }
    if (!parcel.WriteUInt8Vector(challenge)) {
        ACCOUNT_LOGE("Failed to write challenge");
        return false;
    }
    if (!parcel.WriteInt32(authType)) {
        ACCOUNT_LOGE("Failed to write authType");
        return false;
    }
    if (!parcel.WriteUint32(authTrustLevel)) {
        ACCOUNT_LOGE("Failed to write authTrustLevel");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(authIntent))) {
        ACCOUNT_LOGE("Failed to write authTrustLevel");
        return false;
    }
    if (!WriteRemoteAuthParam(parcel)) {
        ACCOUNT_LOGE("Failed to write remoteAuthParam");
        return false;
    }
    return true;
}

AuthParam* AuthParam::Unmarshalling(Parcel& parcel)
{
    AuthParam* info = new (std::nothrow) AuthParam();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool AuthParam::ReadFromParcel(Parcel& parcel)
{
    if (!parcel.ReadInt32(userId)) {
        ACCOUNT_LOGE("Failed to read userId");
        return false;
    }
    if (!parcel.ReadUInt8Vector(&challenge)) {
        ACCOUNT_LOGE("Failed to read challenge");
        return false;
    }
    int32_t authTypeNum;
    if (!parcel.ReadInt32(authTypeNum)) {
        ACCOUNT_LOGE("Failed to read authType for AuthUser");
        return false;
    }
    authType = static_cast<AuthType>(authTypeNum);
    uint32_t authTrustLevelNum;
    if (!parcel.ReadUint32(authTrustLevelNum)) {
        ACCOUNT_LOGE("Failed to read authTrustLevel for AuthUser");
        return false;
    }
    authTrustLevel = static_cast<AuthTrustLevel>(authTrustLevelNum);
    int32_t authIntentNum = 0;
    if (!parcel.ReadInt32(authIntentNum)) {
        ACCOUNT_LOGE("Failed to read authIntent for AuthUser");
        return false;
    }
    authIntent = static_cast<AuthIntent>(authIntentNum);
    if (!ReadRemoteAuthParam(parcel)) {
        ACCOUNT_LOGE("Failed to read remoteAuthParam for AuthUser");
        return false;
    }
    return true;
}

bool AuthParam::ReadRemoteAuthParam(Parcel& parcel)
{
    bool hasValue = false;
    if (!parcel.ReadBool(hasValue)) {
        ACCOUNT_LOGE("Read RemoteAuthParam exist failed.");
        return false;
    }
    if (!hasValue) {
        return true;
    }
    remoteAuthParam = RemoteAuthParam();
    if (!parcel.ReadBool(hasValue)) {
        ACCOUNT_LOGE("Read verifierNetworkId exist failed.");
        return false;
    }
    if (hasValue) {
        std::string networkId;
        if (!parcel.ReadString(networkId)) {
            ACCOUNT_LOGE("Read verifierNetworkId failed.");
            return false;
        }
        remoteAuthParam.value().verifierNetworkId = networkId;
    }
    if (!parcel.ReadBool(hasValue)) {
        ACCOUNT_LOGE("Read collectorNetworkId exist failed.");
        return false;
    }
    if (hasValue) {
        std::string collectorNetworkId;
        if (!parcel.ReadString(collectorNetworkId)) {
            ACCOUNT_LOGE("Read collectorNetworkId failed.");
            return false;
        }
        remoteAuthParam.value().collectorNetworkId = collectorNetworkId;
    }
    if (!parcel.ReadBool(hasValue)) {
        ACCOUNT_LOGE("Read collectorTokenId exist failed.");
        return false;
    }
    if (hasValue) {
        uint32_t tokenId;
        if (!parcel.ReadUint32(tokenId)) {
            ACCOUNT_LOGE("Read collectorTokenId failed.");
            return false;
        }
        remoteAuthParam.value().collectorTokenId = tokenId;
    }
    return true;
}

bool CredentialInfoIam::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteUint64(credentialInfo.credentialId)) {
        ACCOUNT_LOGE("Write credentialId fail");
        return false;
    }
    if (!parcel.WriteInt32(credentialInfo.authType)) {
        ACCOUNT_LOGE("Write authType fail");
        return false;
    }
    PinSubType pinType = credentialInfo.pinType.value_or(PinSubType::PIN_MAX);
    if (!parcel.WriteInt32(pinType)) {
        ACCOUNT_LOGE("Write authSubType fail");
        return false;
    }
    if (!parcel.WriteUint64(credentialInfo.templateId)) {
        ACCOUNT_LOGE("Write templateId fail");
        return false;
    }
    if (!parcel.WriteBool(credentialInfo.isAbandoned)) {
        ACCOUNT_LOGE("Write isAbandoned fail");
        return false;
    }
    if (!parcel.WriteInt64(credentialInfo.validityPeriod)) {
        ACCOUNT_LOGE("Write validityPeriod fail");
        return false;
    }
    return true;
}

CredentialInfoIam* CredentialInfoIam::Unmarshalling(Parcel& parcel)
{
    CredentialInfoIam* info = new (std::nothrow) CredentialInfoIam();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool CredentialInfoIam::ReadFromParcel(Parcel& parcel)
{
    int32_t authType = 0;
    int32_t pinType = 0;
    if (!parcel.ReadUint64(credentialInfo.credentialId)) {
        ACCOUNT_LOGE("Failed to read credentialId");
        return false;
    }
    if (!parcel.ReadInt32(authType)) {
        ACCOUNT_LOGE("Failed to read authType");
        return false;
    }
    if (!parcel.ReadInt32(pinType)) {
        ACCOUNT_LOGE("Failed to read pinSubType");
        return false;
    }
    if (!parcel.ReadUint64(credentialInfo.templateId)) {
        ACCOUNT_LOGE("Failed to read templateId");
        return false;
    }
    if (!parcel.ReadBool(credentialInfo.isAbandoned)) {
        ACCOUNT_LOGE("Failed to read isAbandoned");
        return false;
    }
    if (!parcel.ReadInt64(credentialInfo.validityPeriod)) {
        ACCOUNT_LOGE("Failed to read templateId");
        return false;
    }
    credentialInfo.authType = static_cast<AuthType>(authType);
    credentialInfo.pinType = static_cast<PinSubType>(pinType);
    return true;
}

std::vector<CredentialInfoIam> ConvertToCredentialInfoIamList(const std::vector<CredentialInfo>& infoList)
{
    std::vector<CredentialInfoIam> infoIamList;
    for (const auto& item : infoList) {
        CredentialInfoIam credentialInfoIam;
        credentialInfoIam.credentialInfo = item;
        infoIamList.emplace_back(credentialInfoIam);
    }
    return infoIamList;
}

std::vector<CredentialInfo> ConvertToCredentialInfoList(const std::vector<CredentialInfoIam>& infoIamList)
{
    std::vector<CredentialInfo> infoList;
    for (const auto& item : infoIamList) {
        infoList.emplace_back(item.credentialInfo);
    }
    return infoList;
}

bool CredentialParametersIam::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt32(credentialParameters.authType)) {
        ACCOUNT_LOGE("Failed to write authType");
        return false;
    }
    PinSubType pinType = credentialParameters.pinType.value_or(PinSubType::PIN_MAX);
    if (!parcel.WriteInt32(pinType)) {
        ACCOUNT_LOGE("Failed to write pinType");
        return false;
    }
    if (!parcel.WriteUInt8Vector(credentialParameters.token)) {
        ACCOUNT_LOGE("Failed to write token");
        return false;
    }
    return true;
}

CredentialParametersIam* CredentialParametersIam::Unmarshalling(Parcel& parcel)
{
    CredentialParametersIam* info = new (std::nothrow) CredentialParametersIam();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool CredentialParametersIam::ReadFromParcel(Parcel& parcel)
{
    int32_t authType;
    if (!parcel.ReadInt32(authType)) {
        ACCOUNT_LOGE("Failed to read authType");
        return false;
    }
    int32_t authSubType;
    if (!parcel.ReadInt32(authSubType)) {
        ACCOUNT_LOGE("Failed to read authSubType");
        return false;
    }
    if (!parcel.ReadUInt8Vector(&credentialParameters.token)) {
        ACCOUNT_LOGE("Failed to read token");
        return false;
    }
    credentialParameters.authType = static_cast<AuthType>(authType);
    credentialParameters.pinType = static_cast<PinSubType>(authSubType);
    return true;
}

bool GetPropertyRequestIam::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt32(getPropertyRequest.authType)) {
        ACCOUNT_LOGE("Failed to write authType for GetProperty");
        return false;
    }
    std::vector<uint32_t> attrKeys;
    std::transform(getPropertyRequest.keys.begin(), getPropertyRequest.keys.end(), std::back_inserter(attrKeys),
        [](const auto& key) { return static_cast<uint32_t>(key); });

    if (!parcel.WriteUInt32Vector(attrKeys)) {
        ACCOUNT_LOGE("Failed to write keys");
        return false;
    }
    return true;
}

GetPropertyRequestIam* GetPropertyRequestIam::Unmarshalling(Parcel& parcel)
{
    GetPropertyRequestIam* info = new (std::nothrow) GetPropertyRequestIam();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool GetPropertyRequestIam::ReadFromParcel(Parcel& parcel)
{
    int32_t authType;
    if (!parcel.ReadInt32(authType)) {
        ACCOUNT_LOGE("Failed to read authType");
        return false;
    }
    std::vector<uint32_t> keys;
    if (!parcel.ReadUInt32Vector(&keys)) {
        ACCOUNT_LOGE("Failed to read attribute keys");
        return false;
    }

    getPropertyRequest.authType = static_cast<AuthType>(authType);
    for (auto& key : keys) {
        getPropertyRequest.keys.push_back(static_cast<Attributes::AttributeKey>(key));
    }

    return true;
}

bool SetPropertyRequestIam::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt32(setPropertyRequest.authType)) {
        ACCOUNT_LOGE("Failed to write authType for SetProperty");
        return false;
    }
    auto buffer = setPropertyRequest.attrs.Serialize();
    if (!parcel.WriteUInt8Vector(buffer)) {
        ACCOUNT_LOGE("Failed to write attributes");
        return false;
    }
    return true;
}

SetPropertyRequestIam* SetPropertyRequestIam::Unmarshalling(Parcel& parcel)
{
    SetPropertyRequestIam* info = new (std::nothrow) SetPropertyRequestIam();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool SetPropertyRequestIam::ReadFromParcel(Parcel& parcel)
{
    int32_t authType;
    if (!parcel.ReadInt32(authType)) {
        ACCOUNT_LOGE("Failed to read authType");
        return false;
    }

    std::vector<uint8_t> attr;
    if (!parcel.ReadUInt8Vector(&attr)) {
        ACCOUNT_LOGE("Failed to read attributes");
        return false;
    }

    setPropertyRequest.authType = static_cast<AuthType>(authType);
    setPropertyRequest.attrs = Attributes(attr);

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS

