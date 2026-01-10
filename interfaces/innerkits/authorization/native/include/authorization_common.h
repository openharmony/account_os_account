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

#ifndef AUTHORIZATION_INNERKITS_AUTHORIZATIONT_INCLUDE_AUTHORIZATION_COMMON_H
#define AUTHORIZATION_INNERKITS_AUTHORIZATIONT_INCLUDE_AUTHORIZATION_COMMON_H

#include <string>
#include <vector>
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
class ConnectAbilityInfo : public Parcelable {
public:
    ConnectAbilityInfo() = default;
    ConnectAbilityInfo(const ConnectAbilityInfo&) = delete;
    ConnectAbilityInfo& operator=(const ConnectAbilityInfo&) = delete;
public:
    std::string bundleName = "";
    std::string abilityName = "";
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static ConnectAbilityInfo *Unmarshalling(Parcel &parcel);
};

enum AuthorizationResultCode : int32_t {
    AUTHORIZATION_SUCCESS = 0,
    AUTHORIZATION_CANCELED = 12300301,
    AUTHORIZATION_INTERACTION_NOT_ALLOWED = 12300302,
    AUTHORIZATION_DENIED = 12300303,
    AUTHORIZATION_SYSTEM_BUSY = 12300304,
};

class AuthorizationResult : public Parcelable {
public:
    AuthorizationResult() = default;
    AuthorizationResult(const AuthorizationResult&) = delete;
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

public:
    std::string privilege = "";
    AuthorizationResultCode resultCode = AuthorizationResultCode::AUTHORIZATION_SUCCESS;
    bool isReused = true;
    int32_t validityPeriod;
    std::vector<uint8_t> token;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static AuthorizationResult *Unmarshalling(Parcel &parcel);
};

class AcquireAuthorizationOptions : public Parcelable {
public:
    AcquireAuthorizationOptions() = default;
    AcquireAuthorizationOptions(const AcquireAuthorizationOptions&) = delete;
    AcquireAuthorizationOptions& operator=(const AcquireAuthorizationOptions&) = delete;

public:
    bool hasContext = false;
    std::vector<uint8_t> challenge;
    bool isReuseNeeded = true;
    bool isInteractionAllowed = true;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static AcquireAuthorizationOptions *Unmarshalling(Parcel &parcel);
};
}
}
#endif // AUTHORIZATION_INNERKITS_AUTHORIZATIONT_INCLUDE_AUTHORIZATION_COMMON_H