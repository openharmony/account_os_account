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
#include "string_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::vector<uint8_t> TOKEN = {1, 2, 3, 4, 5};
const std::vector<uint8_t> DEFAULT_PASSWORD = {49, 50, 51, 52, 53};
const int32_t DEFAULT_REMAINING_TIMES = 5;
const int32_t DEFAULT_FREEZING_TIME = 6000;
const int32_t INVALID_CODE = -1;
const std::string VALID_DOMAIN = "china.example.com";
const std::string VALID_ACCOUNT_NAME = "zhangsan";
const std::string STRING_NAME_NEW = "zhangsan777";
const std::string STRING_NAME_INVALID = "zhangsan55";
const std::string STRING_NAME = "zhangsan666";
const std::string STRING_NAME_BIND_INVALID = "lisi";
const std::string ACCOUNT_NAME = "zhangsan5";
const std::string BUNDLE_NAME = "osaccount_test";
const std::string STRING_DOMAIN_NEW = "test.example.com";
}
MockDomainPlugin::MockDomainPlugin() : remainingTimes_(DEFAULT_REMAINING_TIMES), freezingTime_(0)
{}

MockDomainPlugin::~MockDomainPlugin()
{}

void MockDomainPlugin::AuthCommonInterface(const DomainAccountInfo &info, const std::vector<uint8_t> &authData,
    const std::shared_ptr<DomainAccountCallback> &callback, AuthMode authMode)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Parcel emptyParcel;
    AccountSA::DomainAuthResult emptyResult;
    if (!emptyResult.Marshalling(emptyParcel)) {
        return;
    }
    if ((info.domain_ == STRING_DOMAIN_NEW)) {
        callback->OnResult(0, emptyParcel);
        return;
    }
    if ((info.domain_ != VALID_DOMAIN) || (info.accountName_ != VALID_ACCOUNT_NAME)) {
        callback->OnResult(1, emptyParcel);
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
    AccountSA::DomainAuthResult result;
    result.authStatusInfo.remainingTimes = remainingTimes_;
    result.authStatusInfo.freezingTime = freezingTime_;
    result.token = TOKEN;
    Parcel resultParcel;
    if (!result.Marshalling(resultParcel)) {
        return;
    }
    callback->OnResult(!isCorrect, resultParcel);
}

void MockDomainPlugin::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    AuthCommonInterface(info, password, callback, AUTH_WITH_CREDENTIAL_MODE);
}

void MockDomainPlugin::AuthWithPopup(
    const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback)
{
    AuthCommonInterface(info, {}, callback, AUTH_WITH_POPUP_MODE);
}

void MockDomainPlugin::AuthWithToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
    const std::shared_ptr<DomainAccountCallback> &callback)
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
    const GetDomainAccountInfoOptions &options, const std::shared_ptr<DomainAccountCallback> &callback)
{
    Parcel parcel;
    if (options.accountInfo.accountName_ == ACCOUNT_NAME) {
        AAFwk::WantParams parameters;
        parameters.SetParam("domain", OHOS::AAFwk::String::Box(options.accountInfo.domain_));
        parameters.SetParam("accountName", OHOS::AAFwk::String::Box(options.accountInfo.accountName_));
        parameters.SetParam("accountId", OHOS::AAFwk::String::Box("222"));
        parameters.Marshalling(parcel);
        callback->OnResult(0, parcel);
    }
    if (options.accountInfo.accountName_ == STRING_NAME) {
        AAFwk::WantParams parameters;
        parameters.SetParam("domain", OHOS::AAFwk::String::Box(options.accountInfo.domain_));
        parameters.SetParam("accountName", OHOS::AAFwk::String::Box(options.accountInfo.accountName_));
        parameters.SetParam("accountId", OHOS::AAFwk::String::Box("555"));
        parameters.Marshalling(parcel);
        callback->OnResult(0, parcel);
    }
    if (options.accountInfo.accountName_ == STRING_NAME_NEW) {
        AAFwk::WantParams parameters;
        parameters.SetParam("domain", OHOS::AAFwk::String::Box(options.accountInfo.domain_));
        parameters.SetParam("accountName", OHOS::AAFwk::String::Box(options.accountInfo.accountName_));
        parameters.SetParam("accountId", OHOS::AAFwk::String::Box("444"));
        parameters.Marshalling(parcel);
        callback->OnResult(0, parcel);
    }
    if (options.accountInfo.accountName_ == VALID_ACCOUNT_NAME) {
        AAFwk::WantParams parameters;
        parameters.SetParam("domain", OHOS::AAFwk::String::Box(options.accountInfo.domain_));
        parameters.SetParam("accountName", OHOS::AAFwk::String::Box(options.accountInfo.accountName_));
        parameters.SetParam("accountId", OHOS::AAFwk::String::Box("3333"));
        parameters.Marshalling(parcel);
        callback->OnResult(0, parcel);
    }
    if (options.accountInfo.accountName_ == STRING_NAME_BIND_INVALID) {
        AAFwk::WantParams parameters;
        parameters.SetParam("domain", OHOS::AAFwk::String::Box(options.accountInfo.domain_));
        parameters.SetParam("accountName", OHOS::AAFwk::String::Box(options.accountInfo.accountName_));
        parameters.SetParam("accountId", OHOS::AAFwk::String::Box("666"));
        parameters.Marshalling(parcel);
        callback->OnResult(0, parcel);
    }
    if (options.accountInfo.accountName_ == STRING_NAME_INVALID) {
        AAFwk::WantParams parameters;
        parameters.SetParam("accountName", OHOS::AAFwk::String::Box(options.accountInfo.accountName_));
        parameters.Marshalling(parcel);
        callback->OnResult(INVALID_CODE, parcel);
    }
}

void MockDomainPlugin::OnAccountBound(
    const DomainAccountInfo &info, const int32_t localId, const std::shared_ptr<DomainAccountCallback> &callback)
{
    DomainAccountInfo testInfo;
    Parcel parcel;
    if ((info.accountName_ == VALID_ACCOUNT_NAME) || (info.accountName_ == ACCOUNT_NAME) ||
        (info.accountName_ == STRING_NAME) || (info.accountName_ == STRING_NAME_NEW)) {
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

void MockDomainPlugin::IsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("mock IsAccountTokenValid called");
    Parcel parcel;
    parcel.WriteBool(true);
    callback->OnResult(0, parcel);
}

void MockDomainPlugin::GetAccessToken(const DomainAccountInfo &domainInfo, const std::vector<uint8_t> &accountToken,
    const GetAccessTokenOptions &option, const std::shared_ptr<DomainAccountCallback> &callback)
{
    Parcel parcel;
    if ((domainInfo.accountName_ == STRING_NAME) || (domainInfo.accountId_ == "555")) {
        parcel.WriteUInt8Vector(DEFAULT_PASSWORD);
        callback->OnResult(0, parcel);
    }
    if (domainInfo.accountName_ == STRING_NAME_NEW) {
        std::vector<uint8_t> token;
        parcel.WriteUInt8Vector(token);
        callback->OnResult(INVALID_CODE, parcel);
    }
}
}  // AccountSA
}  // OHOS