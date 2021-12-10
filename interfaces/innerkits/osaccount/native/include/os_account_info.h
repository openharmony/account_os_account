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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_INFO_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_INFO_H
#include <ctime>
#include <vector>
#include "iaccount_info.h"
#include "parcel.h"
namespace OHOS {
namespace AccountSA {
class OsAccountInfo : public IAccountInfo, public Parcelable {
public:
    OsAccountInfo();

    OsAccountInfo(int id, const std::string name, int type, int64_t serialNumber);

    OsAccountInfo(int id, std::string name, int type, std::vector<std::string> constraints,
        bool isOsAccountVerified, std::string photo, int64_t createTime, int64_t lastLoggedInTime,
        int64_t serialNumber, bool isAccountCompleted);

    int GetId() const;

    void SetId(int id);

    std::string GetName() const;

    void SetName(const std::string name);

    int GetType() const;

    void SetType(int type);

    std::vector<std::string> GetConstraints() const;

    void SetConstraints(const std::vector<std::string> constraints);

    bool GetIsAccountVerified() const;

    void SetIsAccountVerified(bool isOsAccountVerified);

    std::string GetPhoto() const;

    void SetPhoto(const std::string photo);

    int64_t GetCreateTime() const;

    void SetCreateTime(const int64_t createTime);

    int64_t GetLastLoggedInTime() const;

    void SetLastLoggedInTime(const int64_t lastLoggedInTime);

    virtual Json ToJson() const override;

    virtual void FromJson(const Json &jsonObject) override;

    virtual bool Marshalling(Parcel &parcel) const override;

    bool ReadFromParcel(Parcel &parcel);

    virtual std::string ToString() const override;

    virtual std::string GetPrimeKey() const override;

    static OsAccountInfo *Unmarshalling(Parcel &parcel);

    int64_t GetSerialNumber() const;

    void SetSerialNumber(const int64_t serialNumber);

    bool GetIsActived() const;

    void SetIsActived(const bool isActived);

    bool GetIsAccountCompleted() const;

    void SetIsAccountCompleted(const bool isAccountCompleted);

private:
    int id_;
    std::string name_;
    int type_;
    std::vector<std::string> constraints_;
    bool isAccountVerified_;
    std::string photo_;
    int64_t createTime_;
    int64_t lastLoggedInTime_;
    int64_t serialNumber_;
    bool isActived_;
    bool isAccountCompleted_;
};
typedef enum {
    HOT_SWITCH = 0,
    COLD_SWITCH,
} OS_ACCOUNT_SWITCH_MOD;
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_INFO_H
