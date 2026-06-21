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

#ifndef BASE_ACCOUNT_ACCOUNT_INFO_H
#define BASE_ACCOUNT_ACCOUNT_INFO_H

#include <ctime>
#include <string>

#include "account_error_no.h"
#include "ohos_account_constants.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AccountSA {

/**
 * Account state type .
 */
typedef enum : std::int32_t {
    // invalid state
    ACCOUNT_STATE_INVALID = -1,
    // no account bound
    ACCOUNT_STATE_UNBOUND = 0,
    // account login
    ACCOUNT_STATE_LOGIN,
    // account logout but not unbound
    ACCOUNT_STATE_NOTLOGIN,
    // account logoff, all the data of this account will be deleted in the network
    ACCOUNT_STATE_LOGOFF,
    // local token of account expired, need to re-authenticate
    ACCOUNT_STATE_TOKEN_EXPIRED,
} OHOS_ACCOUNT_STATE;

// event string
const char EVENT_PUBLISH[]                    = "event publish";
const char OHOS_ACCOUNT_EVENT_LOGIN[]         = "Ohos.account.event.LOGIN";
const char OHOS_ACCOUNT_EVENT_LOGOUT[]        = "Ohos.account.event.LOGOUT";
const char OHOS_ACCOUNT_EVENT_TOKEN_INVALID[] = "Ohos.account.event.TOKEN_INVALID";
const char OHOS_ACCOUNT_EVENT_LOGOFF[]           = "Ohos.account.event.LOGOFF";
const char OHOS_ACCOUNT_EVENT_DISTRIBUTED_SPACE_CREATE[]    = "Ohos.account.event.DISTRIBUTED_SPACE_CREATE";
const char OHOS_ACCOUNT_EVENT_DISTRIBUTED_SPACE_DELETED[]   = "Ohos.account.event.DISTRIBUTED_SPACE_DELETE";
const char OHOS_ACCOUNT_EVENT_DISTRIBUTED_SPACE_SWITCHED[]  = "Ohos.account.event.DISTRIBUTED_SPACE_SWITCH";
const char OPERATION_INIT_OPEN_FILE_TO_READ[] = "InitOpenFileToRead";
const char OPERATION_REMOVE_FILE[] = "RemoveFile";
const char OPERATION_OPEN_FILE_TO_READ[] = "OpenFileToRead";
const char OPERATION_OPEN_FILE_TO_WRITE[] = "OpenFileToWrite";
const char OPERATION_CHANGE_MODE_FILE[] = "ChangeModeFile";
const char OPERATION_FORCE_CREATE_DIRECTORY[] = "ForceCreateDirectory";
const char OPERATION_CHANGE_MODE_DIRECTORY[] = "ChangeModeDirectory";
/**
 * Account operation events
 */
typedef enum : std::int32_t {
    ACCOUNT_INVALID_EVT = -1, // invalid account event
    ACCOUNT_BIND_SUCCESS_EVT = 0, // bind account successfully
    ACCOUNT_BIND_FAILED_EVT, // bind account failed
    ACCOUNT_AUTHENTICATE_SUCCESS_EVT, // authenticate account successfully
    ACCOUNT_AUTHENTICATE_FAILED_EVT, // authenticate account failed
    ACCOUNT_TOKEN_EXPIRED_EVT, // local token of account expired
    ACCOUNT_PASSWORD_CHANGED_EVT, // account password changed in remount server
    ACCOUNT_MANUAL_LOGOUT_EVT, // account logout manually
    ACCOUNT_MANUAL_UNBOUND_EVT, // account unbound manually
    ACCOUNT_MANUAL_LOGOFF_EVT, // account logoff manually
    ACCOUNT_DISTRIBUTED_SPACE_CREATE_EVT, // distributed account space created
    ACCOUNT_DISTRIBUTED_SPACE_DELETED_EVT, // distributed account space deleted
    ACCOUNT_DISTRIBUTED_SPACE_SWITCHED_EVT, // distributed account space switched
} ACCOUNT_INNER_EVENT_TYPE;

const char DEFAULT_OHOS_ACCOUNT_NAME[] = "ohosAnonymousName"; // default name
const char DEFAULT_OHOS_ACCOUNT_UID[] = "ohosAnonymousUid"; // default UID
constexpr std::int32_t UID_TRANSFORM_DIVISOR = 200000; // local account id = uid / UID_TRANSFORM_DIVISOR
constexpr std::int32_t MAIN_OS_ACCOUNT_LOCAL_ID = 100; // main os account local id = 100
constexpr std::int32_t DEFAULT_CALLING_UID = -1; // main os account local id = 100
constexpr std::int32_t ACCOUNT_VERSION_DEFAULT = 0;
constexpr std::int32_t ACCOUNT_VERSION_ANON = 1;
class OhosAccountInfo : public Parcelable {
public:
    std::string name_;
    std::string uid_;
    std::int32_t status_;
    std::int32_t callingUid_ = DEFAULT_CALLING_UID;
    std::string nickname_;
    std::string avatar_;
    std::string scalableData_;

    OhosAccountInfo(const std::string &name, const std::string &id, std::int32_t status)
        : name_(name), uid_(id), status_(status), rawUid_(id)
    {
        nickname_ = "";
        avatar_ = "";
        scalableData_ = "";
    }

    OhosAccountInfo()
    {
        name_ = "";
        uid_ = "";
        nickname_ = "";
        avatar_ = "";
        scalableData_ = "";
        status_ = ACCOUNT_STATE_UNBOUND;
    }

    ~OhosAccountInfo() {};

    bool IsValid() const
    {
        return (nickname_.size() <= Constants::NICKNAME_MAX_SIZE) && (avatar_.size() <= Constants::AVATAR_MAX_SIZE) &&
            (scalableData_.size() <= Constants::SCALABLEDATA_MAX_SIZE);
    }

    std::string GetRawUid() const
    {
        return rawUid_;
    }

    void SetRawUid(std::string rawUid)
    {
        rawUid_ = rawUid;
    }

    bool Marshalling(Parcel& parcel) const override;
    static OhosAccountInfo* Unmarshalling(Parcel& parcel);

private:
    bool ReadFromParcel(Parcel& parcel);
    bool ReadAvatarData(Parcel& parcel);

private:
    std::string rawUid_;
};

struct OsAccountSubspaceResult : public Parcelable {
    int32_t id = 0;
    int32_t osAccountId = 0;
    int32_t index = 0;
    int64_t createTime = 0;

    bool Marshalling(Parcel &parcel) const override
    {
        return parcel.WriteInt32(id) && parcel.WriteInt32(osAccountId) && parcel.WriteInt32(index) &&
            parcel.WriteInt64(createTime);
    }
    static OsAccountSubspaceResult* Unmarshalling(Parcel &parcel);
};

class AccountInfo {
public:
    OhosAccountInfo ohosAccountInfo_;
    std::time_t bindTime_;
    std::int32_t userId_;
    std::string digest_;
    std::int32_t version_;
    AccountInfo()
    {
        bindTime_ = 0;
        userId_ = 0;
        digest_ = "";
        version_ = ACCOUNT_VERSION_DEFAULT;
    }

    explicit AccountInfo(const OhosAccountInfo &ohosAccountInfo)
    {
        ohosAccountInfo_ = ohosAccountInfo;
        bindTime_ = 0;
        userId_ = 0;
        digest_ = "";
        version_ = ACCOUNT_VERSION_DEFAULT;
    }

    bool operator==(const AccountInfo &info)
    {
        return (ohosAccountInfo_.uid_ == info.ohosAccountInfo_.uid_);
    }

    void clear(std::int32_t clrStatus = ACCOUNT_STATE_UNBOUND)
    {
        ohosAccountInfo_.name_ = DEFAULT_OHOS_ACCOUNT_NAME;
        ohosAccountInfo_.uid_ = DEFAULT_OHOS_ACCOUNT_UID;
        ohosAccountInfo_.status_ = clrStatus;
        ohosAccountInfo_.nickname_ = "";
        ohosAccountInfo_.avatar_ = "";
        ohosAccountInfo_.scalableData_ = "";
        ohosAccountInfo_.callingUid_ = DEFAULT_CALLING_UID;
        ohosAccountInfo_.SetRawUid("");
        digest_.clear();
        bindTime_ = 0;
    }

    ~AccountInfo() {}
};

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
struct OsAccountSubspaceInfo : AccountInfo {
    int32_t subspaceId = 0;
    bool isCreateCompleted = false;
    bool toBeRemoved = false;
    int64_t createTime_ = 0;
    int64_t GetCreateTime() const { return createTime_; }
    void SetCreateTime(int64_t createTime) { createTime_ = createTime; }
};
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
} // namespace AccountSA
} // namespace OHOS

#endif // BASE_ACCOUNT_ACCOUNT_INFO_H
