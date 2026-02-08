/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_COMMON_H
#define AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_COMMON_H

#include <string>
#include <vector>
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
struct CheckAuthorizationResult : public Parcelable {
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static CheckAuthorizationResult *Unmarshalling(Parcel &parcel);
    bool isAuthorized = false;
    std::vector<uint8_t> challenge = {};
};

/**
 * @brief Information for connecting to UI extension ability.
 *
 * This class contains all the information needed to establish
 * a connection to a UI extension for user interaction.
 */
class ConnectAbilityInfo : public Parcelable {
public:
    ConnectAbilityInfo() = default;
    ConnectAbilityInfo(const ConnectAbilityInfo& other)
    {
        privilege = other.privilege;
        description = other.description;
        bundleName = other.bundleName;
        abilityName = other.abilityName;
        callingUid = other.callingUid;
        callingPid = other.callingPid;
        challenge = other.challenge;
        timeout = other.timeout;
        callingBundleName = other.callingBundleName;
    }

    ConnectAbilityInfo& operator=(const ConnectAbilityInfo& other)
    {
        if (this != &other) {
            privilege = other.privilege;
            description = other.description;
            bundleName = other.bundleName;
            abilityName = other.abilityName;
            callingUid = other.callingUid;
            callingPid = other.callingPid;
            challenge = other.challenge;
            timeout = other.timeout;
            callingBundleName = other.callingBundleName;
        }
        return *this;
    }

    /// The privilege to authorize
    std::string privilege = "";
    /// Description of the authorization request
    std::string description = "";
    /// Name of the calling bundle
    std::string callingBundleName = "";
    /// Bundle name of the UI extension ability
    std::string bundleName = "";
    /// Ability name of the UI extension
    std::string abilityName = "";
    /// UID of the calling process
    int32_t callingUid = -1;
    /// PID of the calling process
    int32_t callingPid = -1;
    /// Timeout for the UI extension (in seconds)
    int32_t timeout = -1;
    /// Challenge data for the authorization request
    std::vector<uint8_t> challenge;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static ConnectAbilityInfo *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Authorization result codes.
 *
 * Enumerates all possible results of an authorization request.
 */
enum AuthorizationResultCode : int32_t {
    /// Authorization succeeded
    AUTHORIZATION_SUCCESS = 0,
    /// Authorization was canceled by user
    AUTHORIZATION_CANCELED = 12300301,
    /// Interaction is not allowed for this authorization
    AUTHORIZATION_INTERACTION_NOT_ALLOWED = 12300302,
    /// Authorization was denied
    AUTHORIZATION_DENIED = 12300303,
    /// System is busy, cannot process authorization
    AUTHORIZATION_SYSTEM_BUSY = 12300304,
};

/**
 * @brief Result of an authorization request.
 *
 * This class contains the result of an authorization attempt,
 * including the token, result code, and other relevant information.
 */
class AuthorizationResult : public Parcelable {
public:
    AuthorizationResult() = default;
    AuthorizationResult(const AuthorizationResult& other)
    {
        token = other.token;
        privilege = other.privilege;
        isReused = other.isReused;
        validityPeriod = other.validityPeriod;
        resultCode = other.resultCode;
    }

    AuthorizationResult& operator=(const AuthorizationResult& other)
    {
        if (this != &other) {
            token = other.token;
            privilege = other.privilege;
            isReused = other.isReused;
            validityPeriod = other.validityPeriod;
            resultCode = other.resultCode;
        }
        return *this;
    }

    /// The privilege that was authorized
    std::string privilege = "";
    /// The result code of the authorization
    AuthorizationResultCode resultCode = AuthorizationResultCode::AUTHORIZATION_SUCCESS;
    /// Whether the authorization result was reused from a previous successful authorization
    bool isReused = true;
    /// Validity period of the authorization token (in seconds)
    int32_t validityPeriod;
    /// The authorization token
    std::vector<uint8_t> token;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static AuthorizationResult *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Options for acquiring authorization.
 *
 * This class contains various options that control the authorization
 * process, including challenge data and interaction settings.
 */
class AcquireAuthorizationOptions : public Parcelable {
public:
    AcquireAuthorizationOptions() = default;
    AcquireAuthorizationOptions(const AcquireAuthorizationOptions&) = delete;
    AcquireAuthorizationOptions& operator=(const AcquireAuthorizationOptions&) = delete;

    /// Whether interaction context is provided
    bool hasContext = false;
    /// Challenge data for the authorization request
    std::vector<uint8_t> challenge;
    /// Whether token reuse is needed
    bool isReuseNeeded = true;
    /// Whether user interaction is allowed
    bool isInteractionAllowed = true;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static AcquireAuthorizationOptions *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Converts a uint8 vector to a hex string.
 *
 * @param vec The input uint8 vector
 * @param str Output string containing hex representation
 */
void TransVectorU8ToString(const std::vector<uint8_t> &vec, std::string &str);

/**
 * @brief Converts a hex string to a uint8 vector.
 *
 * @param vec Output uint8 vector
 * @param str Input hex string
 */
void TransStringToVectorU8(std::vector<uint8_t> &vec, const std::string &str);
}
}
#endif // AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_COMMON_H