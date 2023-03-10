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

#include "mock_domain_plugin.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::vector<uint8_t> DEFAULT_PASSWORD = {49, 50, 51, 52, 53};
const int32_t DEFAULT_REMAINING_TIMES = 5;
const int32_t DEFAULT_FREEZING_TIME = 6000;
const int32_t INVALID_CODE = -1;
const std::string VALID_DOMAIN = "china.example.com";
const std::string VALID_ACCOUNT_NAME = "zhangsan";
const std::string STRING_NAME_NEW = "zhangsan555";
const std::string STRING_NAME_INVALID = "zhangsan55";
const std::string STRING_NAME_BIND_INVALID = "lisi";
const std::string ACCOUNT_NAME = "zhangsan5";
}
MockDomainPlugin::MockDomainPlugin() : remainingTimes_(DEFAULT_REMAINING_TIMES), freezingTime_(0)
{}

MockDomainPlugin::~MockDomainPlugin()
{}

void MockDomainPlugin::AuthCommonInterface(const DomainAccountInfo &info, const std::vector<uint8_t> &authData,
    const std::shared_ptr<DomainAuthCallback> &callback, AuthMode authMode)
{
    ACCOUNT_LOGI("start, accountName: %{public}s, domain: %{public}s",
        info.accountName_.c_str(), info.domain_.c_str());
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    DomainAuthResult result = {};
    if ((info.domain_ != VALID_DOMAIN) || (info.accountName_ != VALID_ACCOUNT_NAME)) {
        callback->OnResult(1, result);
        return;
    }
    bool isCorrect = true;
    if (authData.size() == DEFAULT_PASSWORD.size()) {
        for (size_t i = 0; i < authData.size(); ++i) {
            if (authData[i] != DEFAULT_PASSWORD[i]) {
                isCorrect = false;
                break;
            }
        }
    } else {
        isCorrect = false;
    }
    if (authMode == AUTH_WITH_POPUP_MODE) {
        isCorrect = true;
    }
    if (isCorrect) {
        remainingTimes_ = DEFAULT_REMAINING_TIMES;
        freezingTime_ = 0;
    } else {
        remainingTimes_ = remainingTimes_ > 0 ? remainingTimes_ - 1 : 0;
        freezingTime_ = remainingTimes_ > 0 ? 0 : DEFAULT_FREEZING_TIME;
    }
    result.authStatusInfo.remainingTimes = remainingTimes_;
    result.authStatusInfo.freezingTime = freezingTime_;
    callback->OnResult(!isCorrect, result);
}

void MockDomainPlugin::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    AuthCommonInterface(info, password, callback, AUTH_WITH_CREDENTIAL_MODE);
}

void MockDomainPlugin::AuthWithPopup(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAuthCallback> &callback)
{
    AuthCommonInterface(info, {}, callback, AUTH_WITH_POPUP_MODE);
}

void MockDomainPlugin::AuthWithToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
    const std::shared_ptr<DomainAuthCallback> &callback)
{
    AuthCommonInterface(info, token, callback, AUTH_WITH_TOKEN_MODE);
}

void MockDomainPlugin::GetAuthStatusInfo(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
    AuthStatusInfo authStatusInfo;
    if ((info.accountName_ == VALID_ACCOUNT_NAME) && (info.domain_ == VALID_DOMAIN)) {
        authStatusInfo.remainingTimes = remainingTimes_;
        authStatusInfo.freezingTime = freezingTime_;
    } else {
        authStatusInfo.remainingTimes = -1;
        authStatusInfo.freezingTime = -1;
    }
    Parcel parcel;
    authStatusInfo.Marshalling(parcel);
    callback->OnResult(0, parcel);
}

void MockDomainPlugin::GetDomainAccountInfo(
    const std::string &domain, const std::string &accountName, const std::shared_ptr<DomainAccountCallback> &callback)
{
    DomainAccountInfo info;
    Parcel parcel;
    if (accountName == ACCOUNT_NAME) {
        info.accountName_ = accountName;
        info.domain_ = domain;
        info.accountId_ = "222";
        info.Marshalling(parcel);
        callback->OnResult(0, parcel);
    }
    if (accountName == VALID_ACCOUNT_NAME) {
        info.accountName_ = accountName;
        info.domain_ = domain;
        info.accountId_ = "3333";
        info.Marshalling(parcel);
        callback->OnResult(0, parcel);
    }
    if (accountName == STRING_NAME_BIND_INVALID) {
        info.accountName_ = accountName;
        info.domain_ = domain;
        info.accountId_ = "666";
        info.Marshalling(parcel);
        callback->OnResult(0, parcel);
    }
    if (accountName == STRING_NAME_INVALID) {
        info.accountName_ = accountName;
        info.Marshalling(parcel);
        callback->OnResult(INVALID_CODE, parcel);
    }
}

void MockDomainPlugin::OnAccountBound(
    const DomainAccountInfo &info, const int32_t localId, const std::shared_ptr<DomainAccountCallback> &callback)
{
    DomainAccountInfo testInfo;
    Parcel parcel;
    if ((info.accountName_ == VALID_ACCOUNT_NAME) || (info.accountName_ == ACCOUNT_NAME)) {
        testInfo = info;
        testInfo.Marshalling(parcel);
        callback->OnResult(0, parcel);
    } else {
        testInfo.accountName_ = info.accountName_;
        testInfo.Marshalling(parcel);
        callback->OnResult(INVALID_CODE, parcel);
    }
}

void MockDomainPlugin::OnAccountUnBound(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
    DomainAccountInfo testInfo;
    Parcel parcel;
    if (info.accountName_ == VALID_ACCOUNT_NAME) {
        testInfo = info;
        testInfo.Marshalling(parcel);
        callback->OnResult(0, parcel);
    } else {
        testInfo.accountName_ = info.accountName_;
        testInfo.Marshalling(parcel);
        callback->OnResult(INVALID_CODE, parcel);
    }
}
}  // AccountSA
}  // OHOS