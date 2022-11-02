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

#ifndef BASE_ACCOUNT_ACCOUNT_INFO_H
#define BASE_ACCOUNT_ACCOUNT_INFO_H

#include <ctime>
#include <string>
#include "account_error_no.h"
#include "ohos_account_constants.h"
#include "string_ex.h"
#include "want.h"

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
} OHOS_ACCOUNT_STATE;

// event string
const std::string EVENT_PUBLISH                    = "event publish";
const std::string OHOS_ACCOUNT_EVENT_LOGIN         = "Ohos.account.event.LOGIN";
const std::string OHOS_ACCOUNT_EVENT_LOGOUT        = "Ohos.account.event.LOGOUT";
const std::string OHOS_ACCOUNT_EVENT_TOKEN_INVALID = "Ohos.account.event.TOKEN_INVALID";
const std::string OHOS_ACCOUNT_EVENT_LOGOFF        = "Ohos.account.event.LOGOFF";
const std::string OPERATION_INIT_OPEN_FILE_TO_READ = "InitOpenFileToRead";
const std::string OPERATION_REMOVE_FILE = "RemoveFile";
const std::string OPERATION_OPEN_FILE_TO_READ = "OpenFileToRead";
const std::string OPERATION_OPEN_FILE_TO_WRITE = "OpenFileToWrite";
const std::string OPERATION_CHANGE_MODE_FILE = "ChangeModeFile";
const std::string OPERATION_FORCE_CREATE_DIRECTORY = "ForceCreateDirectory";
const std::string OPERATION_CHANGE_MODE_DIRECTORY = "ChangeModeDirectory";
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
} ACCOUNT_INNER_EVENT_TYPE;

const std::string DEFAULT_OHOS_ACCOUNT_NAME = "ohosAnonymousName"; // default name
const std::string DEFAULT_OHOS_ACCOUNT_UID = "ohosAnonymousUid"; // default UID
constexpr std::int32_t UID_TRANSFORM_DIVISOR = 200000; // local account id = uid / UID_TRANSFORM_DIVISOR
constexpr std::int32_t MAIN_OS_ACCOUNT_LOCAL_ID = 100; // main os account local id = 100

class OhosAccountInfo {
public:
    std::string name_;
    std::string uid_;
    std::int32_t status_;
    std::string nickname_;
    std::string avatar_;
    AAFwk::Want scalableData_;

    OhosAccountInfo(const std::string &name, const std::string &id, std::int32_t status)
        : name_(name), uid_(id), status_(status), rawUid_(id)
    {
        nickname_ = "";
        avatar_ = "";
        scalableData_ = {};
    }

    OhosAccountInfo()
    {
        name_ = "";
        uid_ = "";
        nickname_ = "";
        avatar_ = "";
        scalableData_ = {};
        status_ = ACCOUNT_STATE_UNBOUND;
    }

    ~OhosAccountInfo() {};

    // filtering the input scalableData only
    static std::string GetScalableDataString(const AAFwk::Want &scalableData)
    {
        std::string result = "";
        AAFwk::WantParams wantParams = scalableData.GetParams();
        for (auto it : wantParams.GetParams()) {
            if (it.first != "moduleName") {
                result += it.first;
                int typeId = AAFwk::WantParams::GetDataType(it.second);
                result += wantParams.GetStringByType(it.second, typeId);
            }
        }
        return result;
    }

    bool IsValid() const
    {
        std::string str = GetScalableDataString(scalableData_);
        return (nickname_.size() <= Constants::NICKNAME_MAX_SIZE) && (avatar_.size() <= Constants::AVATAR_MAX_SIZE) &&
            (str.size() <= Constants::SCALABLEDATA_MAX_SIZE);
    }

    std::string GetRawUid() const
    {
        return rawUid_;
    }

    void SetRawUid(std::string rawUid)
    {
        rawUid_ = rawUid;
    }

private:
    std::string rawUid_;
};

class AccountInfo {
public:
    OhosAccountInfo ohosAccountInfo_;
    std::time_t bindTime_;
    std::int32_t userId_;
    std::string digest_;
    AccountInfo()
    {
        bindTime_ = 0;
        userId_ = 0;
        digest_ = "";
    }
    
    AccountInfo(const OhosAccountInfo &ohosAccountInfo)
    {
        ohosAccountInfo_ = ohosAccountInfo;
        bindTime_ = 0;
        userId_ = 0;
        digest_ = "";
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
        ohosAccountInfo_.scalableData_ = {};
        ohosAccountInfo_.SetRawUid("");
        digest_.clear();
        bindTime_ = 0;
    }

    ~AccountInfo() {}
};
} // namespace AccountSA
} // namespace OHOS

#endif // BASE_ACCOUNT_ACCOUNT_INFO_H
