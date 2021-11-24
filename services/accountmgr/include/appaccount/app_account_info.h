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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_INFO_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_INFO_H

#include <set>

#include "account_error_no.h"
#include "iaccount_info.h"
#include "app_account_constants.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
class AppAccountInfo : public IAccountInfo, public Parcelable {
public:
    AppAccountInfo();
    explicit AppAccountInfo(const std::string &name, const std::string &owner);
    virtual ~AppAccountInfo();

    ErrCode GetOwner(std::string &owner);
    ErrCode SetOwner(const std::string &owner);

    ErrCode GetName(std::string &name) const;
    ErrCode SetName(const std::string &name);

    ErrCode GetExtraInfo(std::string &extraInfo) const;
    ErrCode SetExtraInfo(const std::string &extraInfo);

    ErrCode EnableAppAccess(const std::string &authorizedApp);
    ErrCode DisableAppAccess(const std::string &authorizedApp);

    ErrCode GetAuthorizedApps(std::set<std::string> &apps) const;
    ErrCode SetAuthorizedApps(const std::set<std::string> &apps);

    ErrCode GetSyncEnable(bool &syncEnable) const;
    ErrCode SetSyncEnable(const bool &syncEnable);

    ErrCode GetAssociatedData(const std::string &key, std::string &value) const;
    ErrCode SetAssociatedData(const std::string &key, const std::string &value);

    ErrCode GetAccountCredential(const std::string &credentialType, std::string &credential) const;
    ErrCode SetAccountCredential(const std::string &credentialType, const std::string &credential);

    ErrCode GetOAuthToken(std::string &token) const;
    ErrCode SetOAuthToken(const std::string &token);
    ErrCode ClearOAuthToken(void);

    virtual bool Marshalling(Parcel &parcel) const override;
    static AppAccountInfo *Unmarshalling(Parcel &parcel);

    virtual Json ToJson() const override;
    virtual void FromJson(const Json &jsonObject) override;
    virtual std::string ToString() const override;
    virtual std::string GetPrimeKey() const override;

private:
    bool ReadFromParcel(Parcel &parcel);

    bool WriteStringSet(const std::set<std::string> &stringSet, Parcel &data) const;
    bool ReadStringSet(std::set<std::string> &stringSet, Parcel &data);

private:
    std::string owner_;
    std::string name_;
    std::string extraInfo_;
    std::set<std::string> authorizedApps_;
    bool syncEnable_ = false;
    std::string associatedData_;
    std::string accountCredential_;
    std::string oauthToken_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_INFO_H
