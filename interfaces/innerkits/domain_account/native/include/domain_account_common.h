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

class DomainAccountInfo : public Parcelable {
public:
    DomainAccountInfo();

    DomainAccountInfo(const std::string &domain, const std::string &domainAccountName);

    DomainAccountInfo(const std::string &domain, const std::string &domainAccountName, const std::string &accountId);

    void Clear();

public:
    std::string domain_;
    std::string accountName_;
    std::string accountId_;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static DomainAccountInfo *Unmarshalling(Parcel &parcel);
};

class GetAccessTokenOptions : public Parcelable {
public:
    GetAccessTokenOptions();
    GetAccessTokenOptions(const int32_t &callingUid, const AAFwk::WantParams &getTokenParams);

public:
    int32_t callingUid_;
    AAFwk::WantParams getTokenParams_;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static GetAccessTokenOptions *Unmarshalling(Parcel &parcel);
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
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_COMMON_H