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

#ifndef BASE_ACCOUNT_ACCOUNT_INFO_H
#define BASE_ACCOUNT_ACCOUNT_INFO_H

#include <string>
#include <ctime>

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
const std::string OHOS_ACCOUNT_EVENT_LOGIN         = "Ohos.account.event.LOGIN";
const std::string OHOS_ACCOUNT_EVENT_LOGOUT        = "Ohos.account.event.LOGOUT";
const std::string OHOS_ACCOUNT_EVENT_TOKEN_INVALID = "Ohos.account.event.TOKEN_INVALID";
const std::string OHOS_ACCOUNT_EVENT_LOGOFF        = "Ohos.account.event.LOGOFF";
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

const std::string DEFAULT_OHOS_ACCOUNT_NAME = "anonymous"; // default name
const std::string DEFAULT_OHOS_ACCOUNT_UID = "ohosAnonymousUid"; // default UID

class OhosAccountInfo {
public:
    std::string name_;
    std::string uid_;
    std::int32_t status_;
    OhosAccountInfo(const std::string &name, const std::string &id, std::int32_t status)
        : name_(name), uid_(id), status_(status)
    {
    }
    OhosAccountInfo()
    {
        status_ = ACCOUNT_STATE_UNBOUND;
    };
    ~OhosAccountInfo() {};
};

class AccountInfo {
public:
    std::string ohosAccountName_;
    std::string ohosAccountUid_;
    std::int32_t ohosAccountStatus_;
    std::time_t bindTime_;
    std::int32_t userId_;
    std::string digest_;
    AccountInfo()
    {
        ohosAccountName_.clear();
        ohosAccountUid_.clear();
        digest_.clear();
        ohosAccountStatus_ = ACCOUNT_STATE_UNBOUND;
        bindTime_ = 0;
        userId_ = 0;
    }
    AccountInfo(const std::string& name, const std::string& id, const std::int32_t& status)
        : ohosAccountName_(name), ohosAccountUid_(id), ohosAccountStatus_(status)
    {
        bindTime_ = 0;
        userId_ = 0;
    }

    bool operator==(const AccountInfo &info)
    {
        return ohosAccountUid_ == info.ohosAccountUid_;
    }

    void clear(std::int32_t clrStatus = ACCOUNT_STATE_UNBOUND)
    {
        ohosAccountName_ = DEFAULT_OHOS_ACCOUNT_NAME;
        ohosAccountUid_ = DEFAULT_OHOS_ACCOUNT_UID;
        digest_.clear();
        ohosAccountStatus_ = clrStatus;
        bindTime_ = 0;
        userId_ = 0;
    }

    ~AccountInfo() {};
};
} // namespace AccountSA
} // namespace OHOS

#endif // BASE_ACCOUNT_ACCOUNT_INFO_H
