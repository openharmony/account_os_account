/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_INFO_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_INFO_H
#include <ctime>
#include <vector>
#include "iaccount_info.h"
#include "parcel.h"
namespace OHOS {
namespace AccountSA {
typedef enum {
    ADMIN = 0,
    NORMAL,
    GUEST,
    END, // the upper bound of OsAccountType.
} OsAccountType;

typedef enum {
    CONSTRAINT_NOT_EXIST = 0,
    CONSTRAINT_TYPE_BASE,
    CONSTRAINT_TYPE_DEVICE_OWNER,
    CONSTRAINT_TYPE_PROFILE_OWNER,
} ConstraintSourceType;

struct ConstraintSourceTypeInfo {
    int32_t localId;
    ConstraintSourceType typeInfo;
};

class DomainAccountInfo {
public:
    DomainAccountInfo()
        : domain_(""), accountName_("")
    {}

    DomainAccountInfo(const std::string &domain, const std::string &domainAccountName)
        : domain_(domain), accountName_(domainAccountName)
    {}

    void Clear()
    {
        domain_.clear();
        accountName_.clear();
    }
    std::string domain_;
    std::string accountName_;
};

class OsAccountInfo : public IAccountInfo, public Parcelable {
public:
    OsAccountInfo();

    OsAccountInfo(int localId, const std::string localName, OsAccountType type, int64_t serialNumber);

    OsAccountInfo(int localId, std::string localName, OsAccountType type, std::vector<std::string> constraints,
        bool isVerified, std::string photo, int64_t createTime, int64_t lastLoginTime, int64_t serialNumber,
        bool isCreateCompleted);

    int GetLocalId() const;

    void SetLocalId(int localId);

    std::string GetLocalName() const;

    void SetLocalName(const std::string localName);

    OsAccountType GetType() const;

    void SetType(OsAccountType type);

    std::vector<std::string> GetConstraints() const;

    void SetConstraints(const std::vector<std::string> constraints);

    bool GetIsVerified() const;

    void SetIsVerified(bool isVerified);

    std::string GetPhoto() const;

    void SetPhoto(const std::string photo);

    int64_t GetCreateTime() const;

    void SetCreateTime(const int64_t createTime);

    int64_t GetLastLoginTime() const;

    void SetLastLoginTime(const int64_t lastLoginTime);

    Json ToJson() const override;

    void FromJson(const Json &jsonObject) override;

    bool Marshalling(Parcel &parcel) const override;

    bool ReadFromParcel(Parcel &parcel);

    std::string ToString() const override;

    std::string GetPrimeKey() const override;

    static OsAccountInfo *Unmarshalling(Parcel &parcel);

    int64_t GetSerialNumber() const;

    void SetSerialNumber(const int64_t serialNumber);

    bool GetIsActived() const;

    void SetIsActived(const bool isActived);

    bool GetIsCreateCompleted() const;

    void SetIsCreateCompleted(const bool isCreateCompleted);

    bool SetDomainInfo(const DomainAccountInfo &domainInfo);

    void GetDomainInfo(DomainAccountInfo &domainInfo) const;

    bool GetToBeRemoved() const;

    void SetToBeRemoved(bool toBeRemoved);

private:
    int localId_;
    std::string localName_;
    OsAccountType type_;
    std::vector<std::string> constraints_;
    bool isVerified_;
    std::string photo_;
    int64_t createTime_;
    int64_t lastLoginTime_;
    int64_t serialNumber_;
    bool isActived_;
    bool isCreateCompleted_;
    DomainAccountInfo domainInfo_;
    bool toBeRemoved_;
};
typedef enum {
    ERROR_MOD = 0,
    HOT_SWITCH,
    COLD_SWITCH,
} OS_ACCOUNT_SWITCH_MOD;
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_INFO_H
