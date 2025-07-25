/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <vector>
#include "domain_account_common.h"
#include "iaccount_info.h"
#include "parcel.h"
namespace OHOS {
namespace AccountSA {
typedef enum {
    ADMIN = 0,
    NORMAL,
    GUEST,
    MAINTENANCE = 512,
    PRIVATE = 1024,
    END, // the upper bound of OsAccountType.
} OsAccountType;

typedef enum {
    CONSTRAINT_NOT_EXIST = 0,
    CONSTRAINT_TYPE_BASE,
    CONSTRAINT_TYPE_DEVICE_OWNER,
    CONSTRAINT_TYPE_PROFILE_OWNER,
} ConstraintSourceType;

struct ConstraintSourceTypeInfo : public Parcelable {
    int32_t localId;
    ConstraintSourceType typeInfo;
    ConstraintSourceTypeInfo() = default;
    ConstraintSourceTypeInfo(int32_t id, ConstraintSourceType type) : localId(id), typeInfo(type) {}
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static ConstraintSourceTypeInfo *Unmarshalling(Parcel &parcel);
};

struct ForegroundOsAccount : public Parcelable {
    int32_t localId;
    uint64_t displayId;
    ForegroundOsAccount() = default;
    ForegroundOsAccount(int32_t id, uint64_t display) : localId(id), displayId(display) {}
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static ForegroundOsAccount *Unmarshalling(Parcel &parcel);
};

struct CreateOsAccountOptions: public Parcelable {
    std::vector<std::string> disallowedHapList = {};
    std::optional<std::vector<std::string>> allowedHapList = std::nullopt;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static CreateOsAccountOptions *Unmarshalling(Parcel &parcel);
    std::string shortName;
    bool hasShortName = true;
};

class OsAccountInfo : public IAccountInfo, public Parcelable {
public:
    OsAccountInfo();

    OsAccountInfo(int localId, const std::string localName, OsAccountType type);

    OsAccountInfo(int localId, const std::string localName, OsAccountType type, int64_t serialNumber);

    OsAccountInfo(int localId, const std::string localName, const std::string shortName, OsAccountType type,
        int64_t serialNumber);

    int GetLocalId() const;

    void SetLocalId(int localId);

    std::string GetLocalName() const;

    void SetLocalName(const std::string localName);

    std::string GetShortName() const;

    void SetShortName(const std::string &shortName);

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

    bool Marshalling(Parcel &parcel) const override;

    bool ReadFromParcel(Parcel &parcel);

    std::string ToString() const override;

    std::string GetPrimeKey() const override;

    static OsAccountInfo *Unmarshalling(Parcel &parcel);

    int64_t GetSerialNumber() const;

    void SetSerialNumber(const int64_t serialNumber);

    bool GetIsActived() const;

    void SetIsActived(const bool isActivated);

    bool GetIsCreateCompleted() const;

    void SetIsCreateCompleted(const bool isCreateCompleted);

    bool SetDomainInfo(const DomainAccountInfo &domainInfo);

    void GetDomainInfo(DomainAccountInfo &domainInfo) const;

    bool GetToBeRemoved() const;

    void SetToBeRemoved(bool toBeRemoved);

    uint64_t GetCredentialId() const;

    void SetCredentialId(uint64_t credentialId);

    uint64_t GetDisplayId() const;

    void SetDisplayId(const uint64_t credentialId);

    bool GetIsForeground() const;

    void SetIsForeground(const bool isForeground);

    bool GetIsLoggedIn() const;

    void SetIsLoggedIn(const bool isLoggedIn);

    bool GetIsDataRemovable() const;

    void SetIsDataRemovable(const bool isLoggedIn);

    int32_t GetCreatorType() const;

    void SetCreatorType(const int32_t creatorType);

    ErrCode ParamCheck();

    bool IsTypeOutOfRange() const;

public:
    int localId_ = -1;
    std::string localName_;
    std::string shortName_;
    OsAccountType type_ = OsAccountType::ADMIN;
    std::vector<std::string> constraints_;
    std::string photo_;
    int64_t createTime_ = 0;
    int64_t lastLoginTime_ = 0;
    int64_t serialNumber_ = 0;
    uint64_t credentialId_ = 0;
    bool isVerified_ = false;
    bool isActivated_ = false;
    bool isCreateCompleted_ = false;
    bool toBeRemoved_ = false;
    DomainAccountInfo domainInfo_;
    uint64_t displayId_ = -1;
    bool isForeground_ = false;
    bool isLoggedIn_ = false;
    bool isDataRemovable_ = true;
    int32_t creatorType_ = 0;
};

typedef enum {
    ERROR_MOD = 0,
    HOT_SWITCH,
    COLD_SWITCH,
} OS_ACCOUNT_SWITCH_MOD;
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_INFO_H
