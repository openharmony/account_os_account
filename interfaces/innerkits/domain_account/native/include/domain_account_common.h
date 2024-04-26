/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_COMMON_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_COMMON_H

#include <string>
#include <vector>
#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
typedef enum {
    AUTH_INVALID_MODE = -1,
    AUTH_WITH_CREDENTIAL_MODE = 0,
    AUTH_WITH_POPUP_MODE,
    AUTH_WITH_TOKEN_MODE,
    AUTH_MODE_END, // the upper bound of AuthMode.
} AuthMode;

typedef enum {
    LOGOUT = 0,
    LOGIN_BACKGROUND,
    LOGIN,
    LOG_END,
} DomainAccountStatus;

typedef enum {
    LOG_IN,
    TOKEN_UPDATED,
    TOKEN_INVALID,
    LOG_OUT,
} DomainAccountEvent;

struct CreateOsAccountForDomainOptions: public Parcelable {
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static CreateOsAccountForDomainOptions *Unmarshalling(Parcel &parcel);
    std::string shortName;
    bool hasShortName = false;
};

class DomainAccountInfo : public Parcelable {
public:
    DomainAccountInfo();

    DomainAccountInfo(const std::string &domain, const std::string &domainAccountName);

    DomainAccountInfo(const std::string &domain, const std::string &domainAccountName, const std::string &accountId);
    DomainAccountInfo(const std::string &domain, const std::string &domainAccountName, const std::string &accountId,
        const bool &isAuthed, const std::string &serverConfigId);
    void Clear();

public:
    std::string domain_;
    std::string accountName_;
    std::string accountId_;
    DomainAccountStatus status_ = DomainAccountStatus::LOG_END;
    bool isAuthenticated = false;
    std::string serverConfigId_ = "";
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static DomainAccountInfo *Unmarshalling(Parcel &parcel);
};

class GetAccessTokenOptions : public Parcelable {
public:
    GetAccessTokenOptions();
    GetAccessTokenOptions(const int32_t &callingUid, const AAFwk::WantParams &getTokenParams);

public:
    int32_t callingUid_ = -1;
    AAFwk::WantParams getTokenParams_;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static GetAccessTokenOptions *Unmarshalling(Parcel &parcel);
};

class DomainServerConfig : public Parcelable {
public:
    DomainServerConfig();
    DomainServerConfig(const std::string &parameters, const std::string &id);
    DomainServerConfig(const std::string &parameters, const std::string &id, const std::string &domain);
public:
    std::string parameters_ = "";
    std::string id_ = "";
    std::string domain_ = "";
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static DomainServerConfig *Unmarshalling(Parcel &parcel);
};

struct GetDomainAccountInfoOptions : public Parcelable {
    DomainAccountInfo accountInfo;
    int32_t callingUid = -1;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static GetDomainAccountInfoOptions *Unmarshalling(Parcel &parcel);
};

struct AuthStatusInfo : public Parcelable {
    int32_t remainingTimes = -1;  // -1 indicates the invalid value
    int32_t freezingTime = -1;  // -1 indicates the invalid value

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static AuthStatusInfo *Unmarshalling(Parcel &parcel);
};

struct DomainAuthResult : public Parcelable {
    std::vector<uint8_t> token;
    AuthStatusInfo authStatusInfo;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static DomainAuthResult *Unmarshalling(Parcel &parcel);
};

struct DomainAccountEventData {
    int32_t userId = -1;
    DomainAccountInfo domainAccountInfo;
    DomainAccountEvent event;
    DomainAccountStatus status;
};

struct DomainAccountPolicy {
    int32_t authenicationValidityPeriod = -1;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_COMMON_H