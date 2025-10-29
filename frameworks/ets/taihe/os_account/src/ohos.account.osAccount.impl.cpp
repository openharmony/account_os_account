/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "account_error_no.h"
#include "account_iam_client.h"
#include "account_iam_info.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "ani_common_want.h"
#include "bool_wrapper.h"
#include "domain_account_client.h"
#include "iam_common_defines.h"
#include "account_error_no.h"
#include "napi_account_iam_common.h"
#include "napi_account_iam_constant.h"
#include "nlohmann/json.hpp"
#include "ohos.account.distributedAccount.impl.hpp"
#include "ohos.account.distributedAccount.proj.hpp"
#include "ohos.account.osAccount.impl.hpp"
#include "taihe_distributed_account_converter.h"
#include "ohos.account.osAccount.proj.hpp"
#include "ohos_account_kits.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "securec.h"
#include "taihe/runtime.hpp"
#include "taihe_common.h"
#include "taihe_account_info.h"
#include "user_idm_client.h"
#include "user_idm_client_defines.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

using namespace taihe;
using namespace OHOS;
using namespace ohos::account::osAccount;
using namespace ohos::account::distributedAccount;

namespace {
using OHOS::AccountSA::ACCOUNT_LABEL;
const array<uint8_t> DEFAULT_ARRAY = array<uint8_t>::make(0);
constexpr int CONTEXTID_OFFSET = 8;

template <typename T> T TaiheIAMReturn(ErrCode errCode, T result, const T defult)
{
    if (errCode != ERR_OK) {
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        return defult;
    }

    return result;
}

void SetTaiheBusinessErrorFromNativeCode(int32_t nativeErrCode)
{
    if (nativeErrCode == ERR_OK) {
        return;
    }
    int32_t jsErrCode;
    std::string errMsg;
    jsErrCode = GenerateBusinessErrorCode(nativeErrCode);
    errMsg = ConvertToJsErrMsg(jsErrCode);
    taihe::set_business_error(jsErrCode, errMsg.c_str());
}

OsAccountType::key_t ConvertToOsAccountTypeKey(AccountSA::OsAccountType type)
{
    switch (type) {
        case AccountSA::OsAccountType::ADMIN:
            return OsAccountType::key_t::ADMIN;
        case AccountSA::OsAccountType::GUEST:
            return OsAccountType::key_t::GUEST;
        case AccountSA::OsAccountType::PRIVATE:
            return OsAccountType::key_t::PRIVATE;
        case AccountSA::OsAccountType::NORMAL:
        default:
            return OsAccountType::key_t::NORMAL;
    }
}

taihe::array<taihe::string> ConvertConstraints(const std::vector<std::string> &constraints)
{
    std::vector<taihe::string> tempStrings;
    tempStrings.reserve(constraints.size());
    for (const auto &constraint : constraints) {
        tempStrings.emplace_back(taihe::string(constraint.c_str()));
    }
    return taihe::array<taihe::string>(taihe::copy_data_t{}, tempStrings.data(), tempStrings.size());
}

DistributedInfo ConvertDistributedInfo()
{
    std::pair<bool, AccountSA::OhosAccountInfo> dbAccountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (!dbAccountInfo.first) {
        ACCOUNT_LOGE("QueryOhosAccountInfo failed.");
        return AccountSA::ConvertToDistributedInfoTH(AccountSA::OhosAccountInfo{});
    }
    return AccountSA::ConvertToDistributedInfoTH(dbAccountInfo.second);
}

DomainAccountInfo ConvertDomainInfo(const OHOS::AccountSA::OsAccountInfo &innerInfo)
{
    AccountSA::DomainAccountInfo sourceInfo;
    innerInfo.GetDomainInfo(sourceInfo);

    return DomainAccountInfo{
        .domain = taihe::string(sourceInfo.domain_.c_str()),
        .accountName = taihe::string(sourceInfo.accountName_.c_str()),
        .accountId = taihe::optional<taihe::string>(std::in_place_t{}, sourceInfo.accountId_.c_str()),
        .isAuthenticated = taihe::optional<bool>(std::in_place_t{},
            (sourceInfo.status_ != AccountSA::DomainAccountStatus::LOGOUT) &&
            (sourceInfo.status_ < AccountSA::DomainAccountStatus::LOG_END)),
        .serverConfigId = taihe::optional<taihe::string>(std::in_place_t{}, sourceInfo.serverConfigId_.c_str())};
}

OsAccountInfo ConvertOsAccountInfo(const AccountSA::OsAccountInfo &innerInfo)
{
    return OsAccountInfo{
        .localId = innerInfo.GetLocalId(),
        .localName = taihe::string(innerInfo.GetLocalName().c_str()),
        .shortName =
            taihe::optional<taihe::string>(std::in_place_t{}, innerInfo.GetShortName().c_str()),
        .type = OsAccountType(ConvertToOsAccountTypeKey(innerInfo.GetType())),
        .constraints = ConvertConstraints(innerInfo.GetConstraints()),
        .isUnlocked = innerInfo.GetIsVerified(),
        .photo = taihe::string(innerInfo.GetPhoto().c_str()),
        .createTime = innerInfo.GetCreateTime(),
        .lastLoginTime = innerInfo.GetLastLoginTime(),
        .serialNumber = innerInfo.GetSerialNumber(),
        .isActivated = innerInfo.GetIsActived(),
        .isLoggedIn = taihe::optional<bool>(std::in_place_t{}, innerInfo.GetIsLoggedIn()),
        .isCreateCompleted = innerInfo.GetIsCreateCompleted(),
        .distributedInfo = ConvertDistributedInfo(),
        .domainInfo = ConvertDomainInfo(innerInfo)
    };
}

AccountSA::CreateOsAccountOptions ConvertToInnerOptions(optional_view<CreateOsAccountOptions> options)
{
    AccountSA::CreateOsAccountOptions innerOptions;

    if (!options.has_value()) {
        return innerOptions;
    }

    const auto &opts = options.value();

    innerOptions.shortName = std::string(opts.shortName.data(), opts.shortName.size());
    innerOptions.hasShortName = true;

    return innerOptions;
}

inline UserIam::UserAuth::CredentialParameters ConvertToCredentialParameters(
    const ohos::account::osAccount::CredentialInfo &info)
{
    UserIam::UserAuth::CredentialParameters params;
    params.authType = static_cast<UserIam::UserAuth::AuthType>(info.credType.get_value());
    params.pinType = static_cast<UserIam::UserAuth::PinSubType>(info.credSubType.get_value());
    params.token.assign(info.token.data(), info.token.data() + info.token.size());
    return params;
}

inline ohos::account::osAccount::RequestResult ConvertToRequestResult(const UserIam::UserAuth::Attributes &extraInfo)
{
    ohos::account::osAccount::RequestResult result;
    uint64_t credId = 0;
    if (extraInfo.GetUint64Value(UserIam::UserAuth::Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credId)) {
        result.credentialId = taihe::optional<taihe::array<uint8_t>>(
            std::in_place_t{}, taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&credId), sizeof(credId));
    } else {
        result.credentialId = taihe::optional<taihe::array<uint8_t>>();
    }
    return result;
}

class TaiheIDMCallbackAdapter : public AccountSA::IDMCallback {
public:
    explicit TaiheIDMCallbackAdapter(const ohos::account::osAccount::IIdmCallback &taiheCallback)
        : taiheCallback_(taiheCallback)
    {
    }

    ~TaiheIDMCallbackAdapter() = default;

    void OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo) override
    {
        ohos::account::osAccount::RequestResult reqResult = ConvertToRequestResult(extraInfo);
        taiheCallback_.onResult(AccountIAMConvertToJSErrCode(result), reqResult);
    }

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const UserIam::UserAuth::Attributes &extraInfo) override
    {
        if (taiheCallback_.onAcquireInfo.has_value()) {
            std::vector<uint8_t> extraDataVec;
            extraInfo.GetUint8ArrayValue(AccountSA::Attributes::AttributeKey::ATTR_EXTRA_INFO, extraDataVec);
            taihe::array_view<uint8_t> extraDataView(extraDataVec.data(), extraDataVec.size());
            taiheCallback_.onAcquireInfo.value()(module, acquireInfo, extraDataView);
        }
    }

private:
    ohos::account::osAccount::IIdmCallback taiheCallback_;
};

AuthType ConvertToAuthTypeTH(const AccountSA::AuthType &type)
{
    switch (type) {
        case AccountSA::AuthType::PIN:
            return AuthType(AuthType::key_t::PIN);
        case AccountSA::AuthType::FACE:
            return AuthType(AuthType::key_t::FACE);
        case AccountSA::AuthType::FINGERPRINT:
            return AuthType(AuthType::key_t::FINGERPRINT);
        case AccountSA::AuthType::RECOVERY_KEY:
            return AuthType(AuthType::key_t::RECOVERY_KEY);
        case AccountSA::IAMAuthType::DOMAIN:
            return AuthType(AuthType::key_t::DOMAIN);
        default:
            SetTaiheBusinessErrorFromNativeCode(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
            return AuthType(AuthType::key_t::INVALID);
    }
}

AuthSubType ConvertToAuthSubTypeTH(const AccountSA::PinSubType &type)
{
    switch (type) {
        case AccountSA::PinSubType::PIN_SIX:
            return AuthSubType(AuthSubType::key_t::PIN_SIX);
        case AccountSA::PinSubType::PIN_NUMBER:
            return AuthSubType(AuthSubType::key_t::PIN_NUMBER);
        case AccountSA::PinSubType::PIN_MIXED:
            return AuthSubType(AuthSubType::key_t::PIN_MIXED);
        case AccountSA::PinSubType::PIN_FOUR:
            return AuthSubType(AuthSubType::key_t::PIN_FOUR);
        case AccountSA::PinSubType::PIN_PATTERN:
            return AuthSubType(AuthSubType::key_t::PIN_PATTERN);
        case AccountSA::PinSubType::PIN_QUESTION:
            return AuthSubType(AuthSubType::key_t::PIN_QUESTION);
        case AccountJsKit::AuthSubType::FACE_2D:
            return AuthSubType(AuthSubType::key_t::FACE_2D);
        case AccountJsKit::AuthSubType::FACE_3D:
            return AuthSubType(AuthSubType::key_t::FACE_3D);
        case AccountJsKit::AuthSubType::FINGERPRINT_CAPACITIVE:
            return AuthSubType(AuthSubType::key_t::FINGERPRINT_CAPACITIVE);
        case AccountJsKit::AuthSubType::FINGERPRINT_OPTICAL:
            return AuthSubType(AuthSubType::key_t::FINGERPRINT_OPTICAL);
        case AccountJsKit::AuthSubType::FINGERPRINT_ULTRASONIC:
            return AuthSubType(AuthSubType::key_t::FINGERPRINT_ULTRASONIC);
        case AccountSA::IAMAuthSubType::DOMAIN_MIXED:
            return AuthSubType(AuthSubType::key_t::DOMAIN_MIXED);
    }
    return AuthSubType(AuthSubType::key_t::INVALID);
}

std::vector<EnrolledCredInfo> ConvertCredentialInfoArray(const std::vector<AccountSA::CredentialInfo> &infoList)
{
    std::vector<EnrolledCredInfo> result;
    for (auto each : infoList) {
        EnrolledCredInfo info{
            .credentialId = taihe::array<uint8_t>(taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&each.credentialId),
                                                  sizeof(uint64_t)),
            .templateId = taihe::array<uint8_t>(taihe::copy_data_t{}, reinterpret_cast<uint8_t *>(&each.templateId),
                                                sizeof(uint64_t)),
            .authType = ConvertToAuthTypeTH(each.authType),
            .authSubType = ConvertToAuthSubTypeTH(each.pinType.value_or(AccountJsKit::PinSubType::PIN_MAX)),
        };
        result.emplace_back(info);
    }
    return result;
}

class THGetInfoCallback : public AccountSA::GetCredInfoCallback {
public:
    void OnCredentialInfo(int32_t retCode, const std::vector<AccountSA::CredentialInfo> &infoList) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (this->onResultCalled) {
            return;
        }
        onResultCalled = true;
        if (retCode != ERR_OK) {
            this->result = retCode;
            return;
        }
        this->result = ERR_OK;
        this->infoList = ConvertCredentialInfoArray(infoList);
        cv.notify_one();
    }
    int32_t result = -1;
    std::vector<EnrolledCredInfo> infoList;
    std::mutex mutex;
    std::condition_variable cv;
    bool onResultCalled = false;
};

class THGetEnrolledIdCallback : public AccountSA::GetEnrolledIdCallback {
public:
    int32_t errorCode_ = -1;
    array<uint8_t> enrolledID_ = {};
    std::mutex mutex_;
    std::condition_variable cv_;
    bool onEnrolledIdCalled_ = false;
    void OnEnrolledId(int32_t result, uint64_t enrolledIdUint64) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (this->onEnrolledIdCalled_) {
            return;
        }
        this->onEnrolledIdCalled_ = true;
        this->errorCode_ = result;
        if (this->errorCode_ == ERR_OK) {
            this->enrolledID_ = array<uint8_t>(taihe::copy_data_t{},
                reinterpret_cast<uint8_t *>(&enrolledIdUint64), sizeof(uint64_t));
        } else {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(this->errorCode_);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        cv_.notify_one();
    }
};

class UserIdentityManagerImpl {
public:
    UserIdentityManagerImpl()
    {
        bool isSystemApp = OHOS::AccountSA::IsSystemApp();
        if (!isSystemApp) {
            taihe::set_business_error(ERR_JS_IS_NOT_SYSTEM_APP, ConvertToJsErrMsg(ERR_JS_IS_NOT_SYSTEM_APP));
        }
    }

    array<uint8_t> OpenSession()
    {
        return OpenSessionPromise(nullptr);
    }

    array<uint8_t> OpenSessionPromise(optional_view<int32_t> accountId)
    {
        ErrCode errCode = ERR_OK;
        int32_t userId = -1;
        if (accountId) {
            userId = *accountId;
        }
        if (accountId && !OHOS::AccountSA::IsAccountIdValid(userId)) {
            taihe::set_business_error(ERR_JS_ACCOUNT_NOT_FOUND, ConvertToJsErrMsg(ERR_JS_ACCOUNT_NOT_FOUND));
            return DEFAULT_ARRAY;
        }
        std::vector<uint8_t> challenge;
        array<uint8_t> result = DEFAULT_ARRAY;
        errCode = AccountSA::AccountIAMClient::GetInstance().OpenSession(userId, challenge);
        if (errCode == ERR_OK) {
            result = taihe::array<uint8_t>(taihe::copy_data_t{}, challenge.data(), challenge.size());
        }

        return TaiheIAMReturn(errCode, result, DEFAULT_ARRAY);
    }

    void CloseSession(optional_view<int32_t> accountId)
    {
        if (accountId.has_value() && !AccountSA::IsAccountIdValid(accountId.value())) {
            SetTaiheBusinessErrorFromNativeCode(ERR_JS_ACCOUNT_NOT_FOUND);
            return;
        }
        int32_t localId = accountId.value_or(-1);
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().CloseSession(localId);
        if (errCode != ERR_OK) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return;
    }

    ErrCode GetAuthInfoTHInner(const int32_t userId, const AccountSA::AuthType authType,
                               std::vector<EnrolledCredInfo> &infos)
    {
        std::shared_ptr<THGetInfoCallback> idmCallback = std::make_shared<THGetInfoCallback>();
        AccountSA::AccountIAMClient::GetInstance().GetCredentialInfo(userId, authType, idmCallback);
        std::unique_lock<std::mutex> lock(idmCallback->mutex);
        idmCallback->cv.wait(lock, [idmCallback] { return idmCallback->onResultCalled; });
        infos = idmCallback->infoList;
        return idmCallback->result;
    }

    array<EnrolledCredInfo> GetAuthInfoEmpty()
    {
        int32_t userId = -1;
        AccountSA::AuthType authTypeInner;
        std::vector<EnrolledCredInfo> infos;
        ErrCode errCode = GetAuthInfoTHInner(userId, authTypeInner, infos);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetAuthInfoTHInner failed with errCode: %{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            std::vector<EnrolledCredInfo> emptyArr;
            return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, emptyArr.data(), emptyArr.size());
        }
        return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, infos.data(), infos.size());
    }

    array<EnrolledCredInfo> GetAuthInfoTypeSync(AuthType authType)
    {
        return GetAuthInfoType(authType);
    }

    array<EnrolledCredInfo> GetAuthInfoType(AuthType authType)
    {
        int32_t userId = -1;
        AccountSA::AuthType authTypeInner = static_cast<AccountSA::AuthType>(authType.get_value());
        std::vector<EnrolledCredInfo> infos;
        ErrCode errCode = GetAuthInfoTHInner(userId, authTypeInner, infos);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetAuthInfoTHInner failed with errCode: %{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            std::vector<EnrolledCredInfo> emptyArr;
            return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, emptyArr.data(), emptyArr.size());
        }
        return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, infos.data(), infos.size());
    }

    array<EnrolledCredInfo> GetAuthInfoWithOptionsSync(optional_view<GetAuthInfoOptions> options)
    {
        int32_t userId = -1;
        std::vector<EnrolledCredInfo> infos;
        AccountSA::AuthType authTypeInner;
        if (!options.has_value()) {
            return GetAuthInfoEmpty();
        }
        const auto &opts = options.value();
        if (opts.authType.has_value()) {
            authTypeInner = static_cast<AccountSA::AuthType>(opts.authType.value().get_value());
        }
        if (opts.accountId.has_value()) {
            userId = opts.accountId.value();
            if (!AccountSA::IsAccountIdValid(userId)) {
                int32_t jsErrCode = AccountIAMConvertToJSErrCode(JSErrorCode::ERR_JS_ACCOUNT_NOT_FOUND);
                taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
                std::vector<EnrolledCredInfo> emptyArr;
                return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, emptyArr.data(), emptyArr.size());
            }
        }
        ErrCode errCode = GetAuthInfoTHInner(userId, authTypeInner, infos);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("GetAuthInfoTHInner failed with errCode: %{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            std::vector<EnrolledCredInfo> emptyArr;
            return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, emptyArr.data(), emptyArr.size());
        }
        return taihe::array<EnrolledCredInfo>(taihe::copy_data_t{}, infos.data(), infos.size());
    }

    void AddCredential(const CredentialInfo &info, const IIdmCallback &callback)
    {
        AccountSA::CredentialParameters innerCredInfo = ConvertToCredentialParameters(info);
        ErrCode nativeErrCode = ERR_OK;
        std::shared_ptr<AccountSA::IDMCallback> idmCallbackPtr = std::make_shared<TaiheIDMCallbackAdapter>(callback);
        UserIam::UserAuth::Attributes emptyResult;

        int32_t userId = info.accountId.value_or(-1);
        if (info.accountId.has_value() && !AccountSA::IsAccountIdValid(userId)) {
            ACCOUNT_LOGE("AddCredential failed: accountId %{public}d is invalid.", userId);
            idmCallbackPtr->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyResult);
            return;
        }
        AccountSA::AccountIAMClient::GetInstance().AddCredential(userId, innerCredInfo, idmCallbackPtr);
    }

    void UpdateCredential(const CredentialInfo &credentialInfo, const IIdmCallback &callback)
    {
        AccountSA::CredentialParameters innerCredInfo = ConvertToCredentialParameters(credentialInfo);
        std::shared_ptr<AccountSA::IDMCallback> idmCallbackPtr = std::make_shared<TaiheIDMCallbackAdapter>(callback);
        UserIam::UserAuth::Attributes emptyResult;

        int32_t userId = credentialInfo.accountId.value_or(-1);
        if (credentialInfo.accountId.has_value() && !AccountSA::IsAccountIdValid(userId)) {
            ACCOUNT_LOGE("UpdateCredential failed: accountId %{public}d is invalid.", userId);
            idmCallbackPtr->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyResult);
            return;
        }
        AccountSA::AccountIAMClient::GetInstance().UpdateCredential(userId, innerCredInfo, idmCallbackPtr);
    }

    void DelUser(array_view<uint8_t> token, const IIdmCallback &callback)
    {
        const int32_t defaultUserId = -1;
        std::vector<uint8_t> authTokenVec(token.data(), token.data() + token.size());
        std::shared_ptr<AccountSA::IDMCallback> idmCallbackPtr = std::make_shared<TaiheIDMCallbackAdapter>(callback);

        AccountSA::AccountIAMClient::GetInstance().DelUser(defaultUserId, authTokenVec, idmCallbackPtr);
    }

    void CancelWithChallenge(array_view<uint8_t> challenge)
    {
        int32_t ret = AccountSA::AccountIAMClient::GetInstance().Cancel(-1); // -1 indicates the current user
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Failed to cancel account, ret = %{public}d", ret);
            ret = AccountIAMConvertToJSErrCode(ret);
            taihe::set_business_error(ret, ConvertToJsErrMsg(ret));
        }
    }

    void DelCred(array_view<uint8_t> credentialId, array_view<uint8_t> token, IIdmCallback const &callback)
    {
        int32_t accountId = -1;
        uint64_t credentialIdUint64 = 0;
        std::vector<uint8_t> innerToken(token.data(), token.data() + token.size());
        if (credentialId.size() != sizeof(uint64_t)) {
            ACCOUNT_LOGE("credentialId size is invalid.");
            std::string errMsg = "Parameter error. The type of \"credentialId\" must be Uint8Array";
            taihe::set_business_error(ERR_JS_PARAMETER_ERROR, errMsg);
            return;
        }
        for (auto each : credentialId) {
            credentialIdUint64 = (credentialIdUint64 << CONTEXTID_OFFSET);
            credentialIdUint64 += each;
        }
        std::shared_ptr<AccountSA::IDMCallback> idmCallbackPtr = std::make_shared<TaiheIDMCallbackAdapter>(callback);
        AccountSA::AccountIAMClient::GetInstance().DelCred(accountId, credentialIdUint64, innerToken, idmCallbackPtr);
    }

    array<uint8_t> GetEnrolledIdSync(AuthType authType, optional_view<int32_t> accountId)
    {
        int32_t authTypeInner = authType.get_value();
        int32_t innerAccountId = accountId.value_or(-1);
        AccountSA::AuthType innerAuthType = static_cast<AccountSA::AuthType>(authTypeInner);
        std::shared_ptr<THGetEnrolledIdCallback> getEnrolledIdCallback = std::make_shared<THGetEnrolledIdCallback>();
        AccountSA::AccountIAMClient::GetInstance().GetEnrolledId(innerAccountId, innerAuthType, getEnrolledIdCallback);
        std::unique_lock<std::mutex> lock(getEnrolledIdCallback->mutex_);
        getEnrolledIdCallback->cv_.wait(lock,
            [getEnrolledIdCallback] { return getEnrolledIdCallback->onEnrolledIdCalled_;});
        return getEnrolledIdCallback->enrolledID_;
    }
};
class THDomainAccountCallback : public AccountSA::DomainAccountCallback {
public:
    std::mutex mutex;
    std::condition_variable cv;
    explicit THDomainAccountCallback(IUserAuthCallback callback) : callback_(callback){};

    void OnResult(const int32_t errCode, Parcel &parcel) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (this->onResultCalled_) {
            return;
        }
        this->onResultCalled_ = true;
        std::shared_ptr<AccountSA::DomainAuthResult> authResult(AccountSA::DomainAuthResult::Unmarshalling(parcel));
        if (authResult == nullptr) {
            return;
        }
        AuthResult authResultTH;
        if (authResult->authStatusInfo.remainingTimes >= 0) {
            authResultTH.remainTimes = optional<int32_t>(std::in_place_t{}, authResult->authStatusInfo.remainingTimes);
        }
        if (authResult->authStatusInfo.freezingTime >= 0) {
            authResultTH.freezingTime = optional<int32_t>(std::in_place_t{}, authResult->authStatusInfo.freezingTime);
        }
        if (authResult->token.size() > 0) {
            authResultTH.token = optional<array<uint8_t>>(std::in_place_t{}, taihe::copy_data_t{},
                                                          authResult->token.data(), authResult->token.size());
        }
        callback_.onResult(errCode, authResultTH);
    }

private:
    bool onResultCalled_ = false;
    IUserAuthCallback callback_;
};

AccountSA::DomainAccountInfo ConvertToDomainAccountInfoInner(const ohos::account::osAccount::DomainAccountInfo
    &domainAccountInfo)
{
    AccountSA::DomainAccountInfo domainAccountInfoInner(domainAccountInfo.domain.c_str(),
                                                        domainAccountInfo.accountName.c_str());
    if (domainAccountInfo.accountId.has_value()) {
        domainAccountInfoInner.accountId_ = domainAccountInfo.accountId.value();
    }
    if (domainAccountInfo.serverConfigId.has_value()) {
        domainAccountInfoInner.serverConfigId_ = domainAccountInfo.serverConfigId.value();
    }
    return domainAccountInfoInner;
}

class DomainPluginImpl {
public:
    DomainPluginImpl() {}

    void Auth(const DomainAccountInfo &domainAccountInfo, array_view<uint8_t> credential,
        const IUserAuthCallback &callback)
    {
        AccountSA::DomainAccountInfo domainAccountInfoInner = ConvertToDomainAccountInfoInner(domainAccountInfo);
        std::vector<uint8_t> authData(credential.data(), credential.data() + credential.size());
        std::shared_ptr<THDomainAccountCallback> domainAuthCallback =
            std::make_shared<THDomainAccountCallback>(callback);
        ErrCode errCode =
            AccountSA::DomainAccountClient::GetInstance().Auth(domainAccountInfoInner, authData, domainAuthCallback);
        if (errCode != ERR_OK) {
            AuthResult emptyResult;
            callback.onResult(ConvertToJSErrCode(errCode), emptyResult);
        }
        return;
    }
};

class DomainAccountManagerImpl {
private:
    AccountSA::OsAccountManager *osAccountManger_ = nullptr;

public:
    DomainAccountManagerImpl()
    {
        osAccountManger_ = new (std::nothrow) AccountSA::OsAccountManager();
    }

    ~DomainAccountManagerImpl()
    {
        if (osAccountManger_ != nullptr) {
            delete osAccountManger_;
            osAccountManger_ = nullptr;
        }
    }
};

class DomainServerConfigManagerImpl {
private:
    AccountSA::OsAccountManager *osAccountManger_ = nullptr;

public:
    DomainServerConfigManagerImpl()
    {
        osAccountManger_ = new (std::nothrow) AccountSA::OsAccountManager();
    }

    ~DomainServerConfigManagerImpl()
    {
        if (osAccountManger_ != nullptr) {
            delete osAccountManger_;
            osAccountManger_ = nullptr;
        }
    }
};

void RetrieveStringFromAni(ani_env *env, ani_string str, std::string &res)
{
    ani_size sz {};
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        ACCOUNT_LOGE("String_GetUTF8Size Fail! status: %{public}d", status);
        return;
    }
    res.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
        ACCOUNT_LOGE("String_GetUTF8SubString Fail! status: %{public}d", status);
        return;
    }
    res.resize(sz);
}

std::string ConvertMapViewToStringInner(uintptr_t parameters)
{
    ani_env *env = get_env();
    ani_class cls;
    if (env == nullptr) {
        ACCOUNT_LOGE("ani_env is nullptr.");
        return "";
    }

    ani_status status = env->FindClass("Lescompat/JSON;", &cls);
    ani_static_method stringify;
    if (status != ANI_OK) {
        ACCOUNT_LOGE("JSON not found, ret: %{public}d.", status);
        return "";
    }
    status = env->Class_FindStaticMethod(cls, "stringify", "Lstd/core/Object;:Lstd/core/String;", &stringify);
    if (status != ANI_OK) {
        ACCOUNT_LOGE("Stringify not found, ret: %{public}d.", status);
        return "";
    }
    ani_ref result;
    status = env->Class_CallStaticMethod_Ref(cls, stringify, &result, reinterpret_cast<ani_object>(parameters));
    if (status != ANI_OK) {
        ACCOUNT_LOGE("JSON.stringify run failed, ret: %{public}d.", status);
        return "";
    }
    std::string parametersInnerString;
    RetrieveStringFromAni(env, reinterpret_cast<ani_string>(result), parametersInnerString);
    return parametersInnerString;
}

DomainServerConfig ConvertToDomainServerConfigTH(const std::string& id, const std::string& domain,
    const std::string& parameters)
{
    const DomainServerConfig emptyDomainServerConfig = {
        .parameters = 0,
        .id = string(""),
        .domain = string("")
    };
    if (parameters.empty()) {
        ACCOUNT_LOGE("Parameters is invalid.");
        return emptyDomainServerConfig;
    }
    auto parametersJson = nlohmann::json::parse(parameters, nullptr, false);
    if (parametersJson.is_discarded()) {
        ACCOUNT_LOGE("Failed to parse json string");
        return emptyDomainServerConfig;
    }
    ani_env *env = get_env();
    AAFwk::WantParams parametersWantParams;
    from_json(parametersJson, parametersWantParams);
    ani_ref parametersRef = AppExecFwk::WrapWantParams(env, parametersWantParams);
    DomainServerConfig domainServerConfig = DomainServerConfig{
        .id = id,
        .domain = domain,
        .parameters = reinterpret_cast<uintptr_t>(parametersRef),
    };
    return domainServerConfig;
}

class IInputDataImpl {
public:
    std::shared_ptr<AccountSA::IInputerData> inputerData_;

public:
    IInputDataImpl() {}

    explicit IInputDataImpl(int64_t ptr)
    {
        AccountSA::IInputerData* rawPtr = reinterpret_cast<AccountSA::IInputerData*>(ptr);
        inputerData_ = std::shared_ptr<AccountSA::IInputerData>(
            rawPtr,
            [](AccountSA::IInputerData *p) {
                if (p != nullptr) {
                    delete p;
                }
            }
        );
    }

    int64_t GetSpecificImplPtr()
    {
        return reinterpret_cast<int64_t>(this);
    }

    int64_t GetIInputDataPtr()
    {
        return reinterpret_cast<int64_t>(inputerData_.get());
    }

    void OnSetData(AuthSubType authSubType, array_view<uint8_t> data) __attribute__((no_sanitize("cfi")))
    {
        bool isSystemApp = OHOS::AccountSA::IsSystemApp();
        if (!isSystemApp) {
            ACCOUNT_LOGE("Not system app.");
            taihe::set_business_error(ERR_JS_IS_NOT_SYSTEM_APP, ConvertToJsErrMsg(ERR_JS_IS_NOT_SYSTEM_APP));
            return;
        }
        std::vector<uint8_t> authTokenVec(data.data(), data.data() + data.size());
        if (inputerData_ == nullptr) {
            ACCOUNT_LOGE("InputerData_ is nullptr.");
            taihe::set_business_error(ERR_JS_SYSTEM_SERVICE_EXCEPTION,
                ConvertToJsErrMsg(ERR_JS_SYSTEM_SERVICE_EXCEPTION));
            return;
        }
        inputerData_->OnSetData(static_cast<int32_t>(authSubType), authTokenVec);
        inputerData_ = nullptr;
    }
};

IInputData createIInputData(int64_t ptr)
{
    return make_holder<IInputDataImpl, IInputData>(ptr);
}

int64_t getPtrByIInputData(IInputData data)
{
    return data->GetIInputDataPtr();
}

AccountSA::RemoteAuthOptions ConvertToRemoteAuthOptionsInner(const RemoteAuthOptions &options)
{
    AccountSA::RemoteAuthOptions remoteAuthOptionsInner;
    if (options.verifierNetworkId.has_value()) {
        remoteAuthOptionsInner.hasVerifierNetworkId = true;
        remoteAuthOptionsInner.verifierNetworkId = std::string(options.verifierNetworkId.value().c_str());
    }
    if (options.collectorNetworkId.has_value()) {
        remoteAuthOptionsInner.hasCollectorNetworkId = true;
        remoteAuthOptionsInner.collectorNetworkId = std::string(options.collectorNetworkId.value().c_str());
    }
    if (options.collectorTokenId.has_value()) {
        remoteAuthOptionsInner.hasCollectorTokenId = true;
        remoteAuthOptionsInner.collectorTokenId = options.collectorTokenId.value();
    }
    return remoteAuthOptionsInner;
}

AccountSA::AuthOptions ConvertToAuthOptionsInner(const AuthOptions &options)
{
    AccountSA::AuthOptions authOptionsInner;
    if (options.accountId.has_value()) {
        authOptionsInner.hasAccountId = true;
        authOptionsInner.accountId = options.accountId.value();
    }
    if (options.authIntent.has_value()) {
        authOptionsInner.authIntent = static_cast<AccountSA::AuthIntent>(options.authIntent.value().get_value());
    }
    if (options.remoteAuthOptions.has_value()) {
        authOptionsInner.hasRemoteAuthOptions = true;
        authOptionsInner.remoteAuthOptions = ConvertToRemoteAuthOptionsInner(options.remoteAuthOptions.value());
    }
    return authOptionsInner;
}

bool ConvertGetPropertyTypeToAttributeKeyTh(AccountJsKit::GetPropertyType in, AccountSA::Attributes::AttributeKey &out)
{
    static const std::map<AccountJsKit::GetPropertyType, AccountSA::Attributes::AttributeKey> type2Key = {
        {AccountJsKit::GetPropertyType::AUTH_SUB_TYPE, AccountSA::Attributes::AttributeKey::ATTR_PIN_SUB_TYPE},
        {AccountJsKit::GetPropertyType::REMAIN_TIMES, AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES},
        {AccountJsKit::GetPropertyType::FREEZING_TIME, AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME},
        {AccountJsKit::GetPropertyType::ENROLLMENT_PROGRESS, AccountSA::Attributes::AttributeKey::ATTR_ENROLL_PROGRESS},
        {AccountJsKit::GetPropertyType::SENSOR_INFO, AccountSA::Attributes::AttributeKey::ATTR_SENSOR_INFO},
        {AccountJsKit::GetPropertyType::NEXT_PHASE_FREEZING_TIME,
         AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION},
    };

    auto iter = type2Key.find(in);
    if (iter == type2Key.end()) {
        return false;
    } else {
        out = iter->second;
    }
    return true;
}

bool ConvertToGetPropertyRequestInner(const GetPropertyRequest &request,
    AccountSA::GetPropertyRequest &getPropertyRequestInner)
{
    getPropertyRequestInner.authType = static_cast<AccountSA::AuthType>(request.authType.get_value());

    for (GetPropertyType each : request.keys) {
        AccountSA::Attributes::AttributeKey key;
        if (!ConvertGetPropertyTypeToAttributeKeyTh(static_cast<AccountJsKit::GetPropertyType>(each.get_value()),
                                                    key)) {
            return false;
        }
        getPropertyRequestInner.keys.emplace_back(key);
    }
    return true;
}

bool ConvertToSetPropertyRequestInner(const SetPropertyRequest &request,
    AccountSA::SetPropertyRequest &setPropertyRequestInner)
{
    setPropertyRequestInner.authType = static_cast<AccountSA::AuthType>(request.authType.get_value());
    setPropertyRequestInner.mode = static_cast<AccountSA::PropertyMode>(request.key.get_value());

    const auto &taiheSetInfo = request.setInfo;
    std::vector<uint8_t> valueVec(taiheSetInfo.data(), taiheSetInfo.data() + taiheSetInfo.size());
    setPropertyRequestInner.attrs.SetUint8ArrayValue(AccountSA::Attributes::AttributeKey(setPropertyRequestInner.mode),
                                                     valueVec);
    return true;
}

ExecutorProperty CreateEmptyExecutorPropertyTH()
{
    return ExecutorProperty{
        .result = 0,
        .authSubType = AuthSubType(AuthSubType::key_t::INVALID),
        .remainTimes = optional<int32_t>(std::nullopt),
        .freezingTime = optional<int32_t>(std::nullopt),
        .enrollmentProgress = optional<string>(std::nullopt),
        .sensorInfo = optional<string>(std::nullopt),
        .nextPhaseFreezingTime = optional<int32_t>(std::nullopt),
    };
}

ExecutorProperty ConvertToExecutorPropertyTH(
    const AccountJsKit::ExecutorProperty &propertyInfoInner,
    const std::vector<AccountSA::Attributes::AttributeKey> &keys)
{
    ExecutorProperty propertyTH = CreateEmptyExecutorPropertyTH();
    for (const auto &key : keys) {
        switch (key) {
            case AccountSA::Attributes::AttributeKey::ATTR_PIN_SUB_TYPE:
                propertyTH.authSubType =
                    ConvertToAuthSubTypeTH(static_cast<AccountSA::PinSubType>(propertyInfoInner.authSubType));
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES:
                if (propertyInfoInner.remainTimes.has_value()) {
                    propertyTH.remainTimes = optional<int32_t>(
                        std::in_place_t{}, propertyInfoInner.remainTimes.value());
                }
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME:
                if (propertyInfoInner.freezingTime.has_value()) {
                    propertyTH.freezingTime = optional<int32_t>(
                        std::in_place_t{}, propertyInfoInner.freezingTime.value());
                }
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_ENROLL_PROGRESS:
                if (propertyInfoInner.enrollmentProgress.has_value()) {
                propertyTH.enrollmentProgress =
                        optional<string>(std::in_place_t{}, propertyInfoInner.enrollmentProgress.value());
                }
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_SENSOR_INFO:
                if (propertyInfoInner.sensorInfo.has_value()) {
                    propertyTH.sensorInfo = optional<string>(
                        std::in_place_t{}, propertyInfoInner.sensorInfo.value());
                }
                break;
            case AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION:
                if (propertyInfoInner.nextPhaseFreezingTime.has_value()) {
                propertyTH.nextPhaseFreezingTime =
                        optional<int32_t>(std::in_place_t{}, propertyInfoInner.nextPhaseFreezingTime.value());
                }
                break;
            default:
                break;
        }
    }
    return propertyTH;
}

AuthResult CreateEmptyAuthResultTH()
{
    AuthResult authResultTH{
        .token = optional<array<uint8_t>>(std::nullopt),
        .remainTimes = optional<int32_t>(std::nullopt),
        .freezingTime = optional<int32_t>(std::nullopt),
        .nextPhaseFreezingTime = optional<int32_t>(std::nullopt),
        .credentialId = optional<array<uint8_t>>(std::nullopt),
        .accountId = optional<int32_t>(std::nullopt),
        .pinValidityPeriod = optional<int64_t>(std::nullopt),
    };
    return authResultTH;
}

struct AuthCallbackParam {
    int32_t remainTimes = -1;
    int32_t freezingTime = -1;
    std::vector<uint8_t> token;
    bool hasNextPhaseFreezingTime = false;
    bool hasCredentialId = false;
    bool hasAccountId = false;
    bool hasPinValidityPeriod = false;
    int32_t nextPhaseFreezingTime = -1;
    uint64_t credentialId = 0;
    int32_t accountId = -1;
    int64_t pinValidityPeriod = -1;
};

AuthResult ConvertToAuthResultTH(const AccountSA::Attributes &extraInfo)
{
    AuthCallbackParam param;
    extraInfo.GetUint8ArrayValue(AccountSA::Attributes::AttributeKey::ATTR_SIGNATURE, param.token);
    extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES, param.remainTimes);
    extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME, param.freezingTime);
    if (extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION,
                                param.nextPhaseFreezingTime)) {
        param.hasNextPhaseFreezingTime = true;
    }
    if (extraInfo.GetUint64Value(AccountSA::Attributes::AttributeKey::ATTR_CREDENTIAL_ID, param.credentialId)) {
        param.hasCredentialId = true;
    }
    if (extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_USER_ID, param.accountId)) {
        param.hasAccountId = true;
    }
    if (extraInfo.GetInt64Value(AccountSA::Attributes::AttributeKey::ATTR_PIN_EXPIRED_INFO, param.pinValidityPeriod)) {
        param.hasPinValidityPeriod = true;
    }
    AuthResult authResultTH = CreateEmptyAuthResultTH();
    if (param.remainTimes >= 0) {
        authResultTH.remainTimes = optional<int32_t>(std::in_place_t{}, param.remainTimes);
    }
    if (param.freezingTime >= 0) {
        authResultTH.freezingTime = optional<int32_t>(std::in_place_t{}, param.freezingTime);
    }
    if (param.token.size() > 0) {
        authResultTH.token =
            optional<array<uint8_t>>(std::in_place_t{}, taihe::copy_data_t{}, param.token.data(), param.token.size());
    }
    if (param.hasNextPhaseFreezingTime) {
        authResultTH.nextPhaseFreezingTime = optional<int32_t>(std::in_place_t{}, param.nextPhaseFreezingTime);
    }
    if (param.hasCredentialId) {
        authResultTH.credentialId =
            optional<array<uint8_t>>(std::in_place_t{}, taihe::copy_data_t{},
                reinterpret_cast<uint8_t *>(&param.credentialId), sizeof(uint64_t));
    }
    if (param.hasAccountId) {
        authResultTH.accountId = optional<int32_t>(std::in_place_t{}, param.accountId);
    }
    if (param.hasPinValidityPeriod) {
        authResultTH.pinValidityPeriod = optional<int64_t>(std::in_place_t{}, param.pinValidityPeriod);
    }
    return authResultTH;
}

class THUserAuthCallback : public AccountSA::IDMCallback {
public:
    explicit THUserAuthCallback(const IUserAuthCallback &callback) : callback_(callback){};

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (onResultCalled_) {
            return;
        }
        onResultCalled_ = true;

        callback_.onResult(AccountIAMConvertToJSErrCode(result), ConvertToAuthResultTH(extraInfo));
    };

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override
    {
        if (!callback_.onAcquireInfo.has_value()) {
            return;
        }
        std::vector<uint8_t> infoArray;
        extraInfo.GetUint8ArrayValue(AccountSA::Attributes::AttributeKey::ATTR_EXTRA_INFO, infoArray);
        taihe::array<uint8_t> thInfoArray(taihe::copy_data_t{}, infoArray.data(), infoArray.size());
        callback_.onAcquireInfo.value()(module, static_cast<int32_t>(acquireInfo), thInfoArray);
    };

private:
    const IUserAuthCallback callback_;
    std::mutex mutex_;
    bool onResultCalled_ = false;
};

class THGetPropCallback : public AccountSA::GetSetPropCallback {
public:
    std::mutex mutex;
    std::condition_variable cv;
    bool isGetById = false;
    int32_t errCode = 0;
    AccountJsKit::ExecutorProperty propertyInfoInner;
    std::vector<UserIam::UserAuth::Attributes::AttributeKey> keys{};

    explicit THGetPropCallback(std::vector<UserIam::UserAuth::Attributes::AttributeKey> keys) : keys(keys){};

private:
    void ProcessRemainTimes(const UserIam::UserAuth::Attributes &extraInfo,
                           AccountJsKit::ExecutorProperty &propertyInfo)
    {
        int32_t tempValue;
        if (extraInfo.GetInt32Value(
            AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES, tempValue)) {
            propertyInfo.remainTimes = tempValue;
        }
    }

    void ProcessFreezingTime(const UserIam::UserAuth::Attributes &extraInfo,
                            AccountJsKit::ExecutorProperty &propertyInfo)
    {
        int32_t tempValue;
        if (extraInfo.GetInt32Value(
            AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME, tempValue)) {
            propertyInfo.freezingTime = tempValue;
        }
    }

    void ProcessEnrollProgress(const UserIam::UserAuth::Attributes &extraInfo,
                              AccountJsKit::ExecutorProperty &propertyInfo)
    {
        std::string tempValue;
        if (extraInfo.GetStringValue(
            AccountSA::Attributes::AttributeKey::ATTR_ENROLL_PROGRESS, tempValue)) {
            propertyInfo.enrollmentProgress = tempValue;
        }
    }

    void ProcessSensorInfo(const UserIam::UserAuth::Attributes &extraInfo,
                          AccountJsKit::ExecutorProperty &propertyInfo)
    {
        std::string tempValue;
        if (extraInfo.GetStringValue(
            AccountSA::Attributes::AttributeKey::ATTR_SENSOR_INFO, tempValue)) {
            propertyInfo.sensorInfo = tempValue;
        }
    }

    void ProcessNextPhaseFreezingTime(const UserIam::UserAuth::Attributes &extraInfo,
                                     AccountJsKit::ExecutorProperty &propertyInfo)
    {
        int32_t tempValue;
        if (extraInfo.GetInt32Value(
            AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION, tempValue)) {
            propertyInfo.nextPhaseFreezingTime = tempValue;
        }
    }

public:
    void GetExecutorPropertys(const UserIam::UserAuth::Attributes &extraInfo,
        AccountJsKit::ExecutorProperty &propertyInfo)
    {
        for (const auto &key : keys) {
            switch (key) {
                case AccountSA::Attributes::AttributeKey::ATTR_PIN_SUB_TYPE:
                    extraInfo.GetInt32Value(AccountSA::Attributes::AttributeKey::ATTR_PIN_SUB_TYPE,
                        propertyInfo.authSubType);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_REMAIN_TIMES:
                    ProcessRemainTimes(extraInfo, propertyInfo);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_FREEZING_TIME:
                    ProcessFreezingTime(extraInfo, propertyInfo);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_ENROLL_PROGRESS:
                    ProcessEnrollProgress(extraInfo, propertyInfo);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_SENSOR_INFO:
                    ProcessSensorInfo(extraInfo, propertyInfo);
                    break;
                case AccountSA::Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION:
                    ProcessNextPhaseFreezingTime(extraInfo, propertyInfo);
                    break;
                default:
                    break;
            }
        }
    }

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (onResultCalled) {
            return;
        }
        onResultCalled = true;
        GetExecutorPropertys(extraInfo, propertyInfoInner);
        propertyInfoInner.result = result;
        if (!isGetById && (result == IAMResultCode::ERR_IAM_NOT_ENROLLED)) {
            result = ERR_OK;
        }
        if (result != ERR_OK) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(propertyInfoInner.result);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }
        errCode = ERR_OK;
        cv.notify_one();
    }

    bool onResultCalled = false;
};

class THSetPropCallback : public AccountSA::GetSetPropCallback {
public:
    std::mutex mutex;
    std::condition_variable cv;
    bool onResultCalled = false;
    int32_t errCode = 0;

    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (onResultCalled) {
            ACCOUNT_LOGE("OnResult called more than once.");
            return;
        }
        onResultCalled = true;
        errCode = result;
        cv.notify_one();
    }
};

class UserAuthImpl {
public:
    UserAuthImpl()
    {
        bool isSystemApp = OHOS::AccountSA::IsSystemApp();
        if (!isSystemApp) {
            taihe::set_business_error(ERR_JS_IS_NOT_SYSTEM_APP, ConvertToJsErrMsg(ERR_JS_IS_NOT_SYSTEM_APP));
        }
    }

    array<uint8_t> AuthSync(array_view<uint8_t> challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                            const IUserAuthCallback &callback)
    {
        int32_t authTypeInner = authType.get_value();
        int32_t trustLevelInner = authTrustLevel.get_value();
        std::shared_ptr<THUserAuthCallback> callbackInner = std::make_shared<THUserAuthCallback>(callback);
        std::vector<uint8_t> challengeInner(challenge.begin(), challenge.begin() + challenge.size());
        AccountSA::AuthOptions authOptionsInner;
        std::vector<uint8_t> contextId = AccountSA::AccountIAMClient::GetInstance().Auth(
            authOptionsInner, challengeInner, static_cast<AccountSA::AuthType>(authTypeInner),
            static_cast<AccountSA::AuthTrustLevel>(trustLevelInner), callbackInner);
        return taihe::array<uint8_t>(taihe::copy_data_t{}, contextId.data(), contextId.size());
    }

    array<uint8_t> AuthWithOptSync(array_view<uint8_t> challenge, AuthType authType, AuthTrustLevel authTrustLevel,
                                   const AuthOptions &options, const IUserAuthCallback &callback)
    {
        int32_t authTypeInner = authType.get_value();
        int32_t trustLevelInner = authTrustLevel.get_value();
        std::shared_ptr<THUserAuthCallback> callbackInner = std::make_shared<THUserAuthCallback>(callback);
        std::vector<uint8_t> challengeInner(challenge.begin(), challenge.begin() + challenge.size());
        AccountSA::AuthOptions authOptionsInner = ConvertToAuthOptionsInner(options);
        if ((!authOptionsInner.hasRemoteAuthOptions) && (authOptionsInner.hasAccountId) &&
            (!AccountSA::IsAccountIdValid(authOptionsInner.accountId))) {
            AccountSA::Attributes emptyInfo;
            callbackInner->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyInfo);
            return taihe::array<uint8_t>::make(0);
        }
        std::vector<uint8_t> contextId = AccountSA::AccountIAMClient::GetInstance().Auth(
            authOptionsInner, challengeInner, static_cast<AccountSA::AuthType>(authTypeInner),
            static_cast<AccountSA::AuthTrustLevel>(trustLevelInner), callbackInner);
        return taihe::array<uint8_t>(taihe::copy_data_t{}, contextId.data(), contextId.size());
    }

    array<uint8_t> AuthUser(int32_t userId, array_view<uint8_t> challenge, AuthType authType,
                            AuthTrustLevel authTrustLevel, const IUserAuthCallback &callback)
    {
        int32_t authTypeInner = authType.get_value();
        int32_t trustLevelInner = authTrustLevel.get_value();
        std::shared_ptr<THUserAuthCallback> callbackInner = std::make_shared<THUserAuthCallback>(callback);
        std::vector<uint8_t> challengeInner(challenge.begin(), challenge.begin() + challenge.size());
        AccountSA::AuthOptions authOptionsInner;

        if (!AccountSA::IsAccountIdValid(userId)) {
            AccountSA::Attributes emptyInfo;
            callbackInner->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, emptyInfo);
            return taihe::array<uint8_t>::make(0);
        }
        authOptionsInner.accountId = userId;
        std::vector<uint8_t> contextId = AccountSA::AccountIAMClient::GetInstance().AuthUser(
            authOptionsInner, challengeInner, static_cast<AccountSA::AuthType>(authTypeInner),
            static_cast<AccountSA::AuthTrustLevel>(trustLevelInner), callbackInner);
        return taihe::array<uint8_t>(taihe::copy_data_t{}, contextId.data(), contextId.size());
    }

    void CancelAuth(array_view<uint8_t> contextID)
    {
        std::vector<uint8_t> contextId(contextID.data(), contextID.data() + contextID.size());
        if (contextId.empty()) {
            ACCOUNT_LOGE("contextID is empty.");
            std::string errMsg = "Parameter error. The type of \"contextID\" must be Uint8Array";
            taihe::set_business_error(ERR_JS_PARAMETER_ERROR, errMsg);
            return;
        }
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().CancelAuth(contextId);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("CancelAuth failed, ret = %{public}d", errCode);
            errCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(errCode, ConvertToJsErrMsg(errCode));
        }
        return;
    }

    ExecutorProperty GetPropertySync(const GetPropertyRequest &request)
    {
        AccountSA::GetPropertyRequest getPropertyRequestInner;
        if (!ConvertToGetPropertyRequestInner(request, getPropertyRequestInner)) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(ERR_JS_PARAMETER_ERROR);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return CreateEmptyExecutorPropertyTH();
        }

        std::shared_ptr<THGetPropCallback> idmCallback =
            std::make_shared<THGetPropCallback>(getPropertyRequestInner.keys);
        if (request.accountId.has_value() && !AccountSA::IsAccountIdValid(request.accountId.value())) {
            idmCallback->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, AccountSA::Attributes());
            return ConvertToExecutorPropertyTH(idmCallback->propertyInfoInner, idmCallback->keys);
        }
        AccountSA::AccountIAMClient::GetInstance().GetProperty(request.accountId.value_or(-1), getPropertyRequestInner,
                                                               idmCallback);
        std::unique_lock<std::mutex> lock(idmCallback->mutex);
        idmCallback->cv.wait(lock, [idmCallback] { return idmCallback->onResultCalled; });
        return ConvertToExecutorPropertyTH(idmCallback->propertyInfoInner, idmCallback->keys);
    }

    void SetPropertySync(const SetPropertyRequest &request)
    {
        AccountSA::SetPropertyRequest setPropertyRequestInner;
        if (!ConvertToSetPropertyRequestInner(request, setPropertyRequestInner)) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(ERR_JS_PARAMETER_ERROR);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            return;
        }

        std::shared_ptr<THSetPropCallback> callback = std::make_shared<THSetPropCallback>();
        int32_t accountId = -1;
        AccountSA::AccountIAMClient::GetInstance().SetProperty(accountId, setPropertyRequestInner, callback);

        std::unique_lock<std::mutex> lock(callback->mutex);
        callback->cv.wait(lock, [callback] { return callback->onResultCalled; });

        if (callback->errCode != ERR_OK) {
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(callback->errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    int32_t GetVersionSync()
    {
        bool isSystemApp = OHOS::AccountSA::IsSystemApp();
        if (!isSystemApp) {
            taihe::set_business_error(ERR_JS_IS_NOT_SYSTEM_APP, ConvertToJsErrMsg(ERR_JS_IS_NOT_SYSTEM_APP));
        }
        return 0;
    }

    int32_t GetAvailableStatusSync(AuthType authType, AuthTrustLevel authTrustLevel)
    {
        AccountSA::AuthType authTypeInner = static_cast<AccountSA::AuthType>(authType.get_value());
        AccountSA::AuthTrustLevel authSubType = static_cast<AccountSA::AuthTrustLevel>(authTrustLevel.get_value());
        int32_t status = 0;
        ErrCode errorCode = AccountSA::AccountIAMClient::GetInstance().GetAvailableStatus(authTypeInner,
            authSubType, status);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
        return status;
    }

    ExecutorProperty GetPropertyByCredentialIdSync(array_view<uint8_t> credentialId, array_view<GetPropertyType> keys)
    {
        uint64_t id = 0;
        for (auto each : credentialId) {
            id = (id << CONTEXTID_OFFSET);
            id += each;
        }

        std::vector<OHOS::UserIam::UserAuth::Attributes::AttributeKey> getPropertyRequestInner;
        for (GetPropertyType each : keys) {
            AccountSA::Attributes::AttributeKey key;
            if (!ConvertGetPropertyTypeToAttributeKeyTh(static_cast<AccountJsKit::GetPropertyType>(each.get_value()),
                                                        key)) {
                break;
            }
            getPropertyRequestInner.emplace_back(key);
        }

        std::shared_ptr<THGetPropCallback> getPropCallback =
            std::make_shared<THGetPropCallback>(getPropertyRequestInner);
        AccountSA::AccountIAMClient::GetInstance().GetPropertyByCredentialId(id,
            getPropertyRequestInner, getPropCallback);
        std::unique_lock<std::mutex> lock(getPropCallback->mutex);
        getPropCallback->cv.wait(lock, [getPropCallback] { return getPropCallback->onResultCalled; });

        return ConvertToExecutorPropertyTH(getPropCallback->propertyInfoInner, getPropCallback->keys);
    }

    class THPrepareRemoteAuthCallback : public AccountSA::PreRemoteAuthCallback {
    public:

        void OnResult(int32_t result) override
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ACCOUNT_LOGI("Post OnResult task finish");
        }

    private:
        std::mutex mutex_;
    };

    void PrepareRemoteAuthSync(string_view remoteNetworkId)
    {
        std::string innerRemoteNetworkId(remoteNetworkId.data(), remoteNetworkId.size());

        auto prepareRemoteAuthCallback = std::make_shared<THPrepareRemoteAuthCallback>();
        ErrCode errorCode = AccountSA::AccountIAMClient::GetInstance().PrepareRemoteAuth(innerRemoteNetworkId,
            prepareRemoteAuthCallback);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }
};

class TaiheGetDataCallback : public AccountSA::IInputer {
public:
    TaiheGetDataCallback();
    ~TaiheGetDataCallback();

    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
                   const std::shared_ptr<AccountSA::IInputerData> inputerData) override;

    std::shared_ptr<TaiheIInputer> inputer_ = nullptr;
    std::shared_ptr<TaiheIInputData> inputerData_ = nullptr;
};

TaiheGetDataCallback::TaiheGetDataCallback() {}

TaiheGetDataCallback::~TaiheGetDataCallback() {}

void TaiheGetDataCallback::OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
                                     const std::shared_ptr<AccountSA::IInputerData> inputerData)
{
    ACCOUNT_LOGI("Start!");
    if (inputer_ == nullptr) {
        ACCOUNT_LOGE("The onGetData function is undefined");
        return;
    }
    GetInputDataOptions option = {
        optional<array<uint8_t>>(std::in_place_t{}, taihe::copy_data_t{}, challenge.data(), challenge.size())};
    reinterpret_cast<IInputDataImpl *>((*inputerData_)->GetSpecificImplPtr())->inputerData_ = inputerData;
    inputer_->onGetData(AuthSubType::from_value(authSubType), *inputerData_, option);
}

class PINAuthImpl {
public:
    PINAuthImpl() {}

    void RegisterInputer(const IInputer &inputer)
    {
        auto taiheInputer = std::make_shared<TaiheIInputer>(inputer);
        auto taiheCallbackRef = std::make_shared<TaiheGetDataCallback>();
        taiheCallbackRef->inputer_ = taiheInputer;
        taiheCallbackRef->inputerData_ = std::make_shared<IInputData>(make_holder<IInputDataImpl, IInputData>());
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().RegisterPINInputer(taiheCallbackRef);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void UnregisterInputer()
    {
        ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().UnregisterPINInputer();
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to unregister PIN inputer, errCode=%{public}d", errCode);
            int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }
};

class InputerManagerImpl {
public:
    InputerManagerImpl() {}
};

bool IsAuthenticationExpiredSync(const DomainAccountInfo &domainAccountInfo)
{
    AccountSA::DomainAccountInfo domainAccountInfoInner = ConvertToDomainAccountInfoInner(domainAccountInfo);
    bool isExpired = false;
    ErrCode errCode =
        AccountSA::DomainAccountClient::GetInstance().IsAuthenticationExpired(domainAccountInfoInner, isExpired);
    if (errCode != ERR_OK) {
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return false;
    }
    return isExpired;
}

void UnregisterPlugin()
{
    int32_t errorCode = AccountSA::DomainAccountClient::GetInstance().UnregisterPlugin();
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
            ACCOUNT_LOGE("failed to unregister plugin, errCode=%{public}d", errorCode);
        }
}

class DomainAccountCallbackTH final: public AccountSA::DomainAccountCallback {
public:
    explicit DomainAccountCallbackTH(std::shared_ptr<THUserAuthCallback> &callback):callback_(callback) {}

    std::mutex mutex_;
    std::condition_variable cv_;
    bool onResultCalled_ = false;
    bool isHasDomainAccount_ = false;
    int32_t errCode_ = -1;

    void OnResult(const int32_t errCode, Parcel &parcel) override
    {
        std::unique_lock<std::mutex> lock(mutex_);
        this->errCode_ = errCode;
        if (this->onResultCalled_) {
            return;
        }
        this->onResultCalled_ = true;
        if (errCode == ERR_OK) {
            parcel.ReadBool(isHasDomainAccount_);
        }
        cv_.notify_one();
    }
private:
    std::shared_ptr<THUserAuthCallback> callback_;
};

void Auth(DomainAccountInfo const& domainAccountInfo, array_view<uint8_t> credential, IUserAuthCallback const& callback)
{
    AccountSA::DomainAccountInfo domainAccountInfoInner = ConvertToDomainAccountInfoInner(domainAccountInfo);
    std::vector<uint8_t> credentialInner(credential.begin(), credential.begin() + credential.size());
    std::shared_ptr<THDomainAccountCallback> callbackInner =
            std::make_shared<THDomainAccountCallback>(callback);
    int32_t errorCode = AccountSA::DomainAccountClient::GetInstance().Auth(domainAccountInfoInner,
        credentialInner, callbackInner);
    if (!credentialInner.empty()) {
        (void)memset_s(const_cast<uint8_t*>(credentialInner.data()),
            credentialInner.size(), 0, credentialInner.size());
    }
    if (errorCode != ERR_OK) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult emptyResult;
        if (!emptyResult.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("authResult Marshalling failed");
            return;
        }
        callbackInner->OnResult(ConvertToJSErrCode(errorCode), emptyParcel);
    }
}

void AuthWithPopup(IUserAuthCallback const& callback)
{
    std::shared_ptr<THDomainAccountCallback> callbackInner =
            std::make_shared<THDomainAccountCallback>(callback);
    int32_t userId = 0;
    int32_t errorCode = AccountSA::DomainAccountClient::GetInstance().AuthWithPopup(userId, callbackInner);
    if (errorCode != ERR_OK) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult emptyResult;
        if (!emptyResult.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("authResult Marshalling failed");
            return;
        }
        callbackInner->OnResult(ConvertToJSErrCode(errorCode), emptyParcel);
    }
}

void AuthWithPopupWithId(int32_t localId, IUserAuthCallback const& callback)
{
    std::shared_ptr<THDomainAccountCallback> callbackInner =
            std::make_shared<THDomainAccountCallback>(callback);
    int32_t errorCode = AccountSA::DomainAccountClient::GetInstance().AuthWithPopup(localId, callbackInner);
    if (errorCode != ERR_OK) {
        Parcel emptyParcel;
        AccountSA::DomainAuthResult emptyResult;
        if (!emptyResult.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("authResult Marshalling failed");
            return;
        }
        callbackInner->OnResult(ConvertToJSErrCode(errorCode), emptyParcel);
    }
}

bool HasAccountSync(DomainAccountInfo const& domainAccountInfo)
{
    AccountSA::DomainAccountInfo domainAccountInfoInner = ConvertToDomainAccountInfoInner(domainAccountInfo);
    std::shared_ptr<THUserAuthCallback> jsCallback;
    auto callbackInner = std::make_shared<DomainAccountCallbackTH>(jsCallback);
    int errorCode = AccountSA::DomainAccountClient::GetInstance().HasAccount(domainAccountInfoInner, callbackInner);
    if (errorCode != ERR_OK) {
        Parcel emptyParcel;
        callbackInner->OnResult(errorCode, emptyParcel);
        return false;
    }
    std::unique_lock<std::mutex> lock(callbackInner->mutex_);
    callbackInner->cv_.wait(lock, [callbackInner] { return callbackInner->onResultCalled_;});
    return callbackInner->isHasDomainAccount_;
}

void UpdateAccountTokenSync(DomainAccountInfo const &domainAccountInfo, array_view<uint8_t> token)
{
    AccountSA::DomainAccountInfo innerDomainAccountInfo = ConvertToDomainAccountInfoInner(domainAccountInfo);
    std::vector<uint8_t> innerToken(token.begin(), token.begin() + token.size());
    ErrCode errCode =
        AccountSA::DomainAccountClient::GetInstance().UpdateAccountToken(innerDomainAccountInfo, innerToken);
    if (!innerToken.empty()) {
        (void)memset_s(const_cast<uint8_t*>(innerToken.data()), innerToken.size(), 0,
            innerToken.size());
    }
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateAccountTokenSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
    }
}

class THGetAccessTokenCallback : public AccountSA::GetAccessTokenCallback {
public:
    int32_t errorCode_ = -1;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<uint8_t> accessToken_;
    bool onResultCalled_ = false;
    void OnResult(const int32_t errCode, const std::vector<uint8_t> &accessToken)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (this->onResultCalled_) {
            return;
        }
        this->errorCode_ = errCode;
        this->onResultCalled_ = true;
        this->accessToken_ = accessToken;
        cv_.notify_one();
    }
};

array<uint8_t> GetAccessTokenSync(uintptr_t businessParams)
{
    AccountSA::DomainAccountInfo innerDomainInfo;
    AAFwk::WantParams innerGetTokenParams;
    array<uint8_t> accessToken = {};
    ani_env *env = get_env();
    ani_ref businessParamsRef = reinterpret_cast<ani_ref>(businessParams);
    auto status = AppExecFwk::UnwrapWantParams(env, businessParamsRef, innerGetTokenParams);
    if (status == false) {
        ACCOUNT_LOGE("Parameter error. The type of \"businessParams\" must be Record");
        SetTaiheBusinessErrorFromNativeCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
        return array<uint8_t>(taihe::copy_data_t{}, accessToken.data(), accessToken.size());
    }
    innerDomainInfo.domain_ = innerGetTokenParams.GetStringParam("domain");
    innerDomainInfo.accountName_ = innerGetTokenParams.GetStringParam("accountName");
    innerDomainInfo.accountId_ = innerGetTokenParams.GetStringParam("accountId");
    innerDomainInfo.serverConfigId_ = innerGetTokenParams.GetStringParam("serverConfigId");
    std::shared_ptr<THGetAccessTokenCallback> getAccessTokenCallback = std::make_shared<THGetAccessTokenCallback>();
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetAccessToken(
        innerDomainInfo, innerGetTokenParams, getAccessTokenCallback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetAccessTokenSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return array<uint8_t>(taihe::copy_data_t{}, accessToken.data(), accessToken.size());
    }
    std::unique_lock<std::mutex> lock(getAccessTokenCallback->mutex_);
    getAccessTokenCallback->cv_.wait(lock, [getAccessTokenCallback] { return getAccessTokenCallback->onResultCalled_;});
    if (getAccessTokenCallback->errorCode_ != ERR_OK) {
        ACCOUNT_LOGE("GetAccessTokenSync failed with errCode: %{public}d", getAccessTokenCallback->errorCode_);
        SetTaiheBusinessErrorFromNativeCode(getAccessTokenCallback->errorCode_);
        return array<uint8_t>(taihe::copy_data_t{}, accessToken.data(), accessToken.size());
    }
    return array<uint8_t>(taihe::copy_data_t{}, getAccessTokenCallback->accessToken_.data(),
        getAccessTokenCallback->accessToken_.size());
}

class THGetAccountInfoCallback : public AccountSA::DomainAccountCallback {
public:
    int32_t errorCode_ = -1;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool onGetAccountInfoCalled_ = false;
    AAFwk::WantParams getAccountInfoParams_;

    void OnResult(int32_t errCode, Parcel &parcel)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (this->onGetAccountInfoCalled_) {
            return;
        }
        this->onGetAccountInfoCalled_ = true;
        this->errorCode_ = errCode;
        if (errCode == ERR_OK) {
            std::shared_ptr<AAFwk::WantParams> parameters(AAFwk::WantParams::Unmarshalling(parcel));
            if (parameters == nullptr) {
                ACCOUNT_LOGE("Parameters unmarshalling error");
                errCode = ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            } else {
                this->getAccountInfoParams_ = *parameters;
            }
        }
        cv_.notify_one();
    }
};

DomainAccountInfo GetAccountInfoSync(GetDomainAccountInfoOptions const& options)
{
    AccountSA::DomainAccountInfo innerDomainInfo;
    innerDomainInfo.accountName_ = options.accountName;
    if (options.domain.has_value()) {
        innerDomainInfo.domain_ = options.domain.value();
    }
    if (options.serverConfigId.has_value()) {
        innerDomainInfo.serverConfigId_ = options.serverConfigId.value();
    }
    DomainAccountInfo emptyDomainAccountInfo = {
        .domain = string(""),
        .accountName = string(""),
        .accountId = optional<string>(std::in_place, string("")),
        .isAuthenticated = optional<bool>(std::in_place, false),
        .serverConfigId = optional<string>(std::in_place, string("")),
    };
    std::shared_ptr<THGetAccountInfoCallback> getAccountInfoCallback = std::make_shared<THGetAccountInfoCallback>();
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetDomainAccountInfo(innerDomainInfo,
        getAccountInfoCallback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetAccountInfoSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return emptyDomainAccountInfo;
    }
    std::unique_lock<std::mutex> lock(getAccountInfoCallback->mutex_);
    getAccountInfoCallback->cv_.wait(lock, [getAccountInfoCallback] {
        return getAccountInfoCallback->onGetAccountInfoCalled_;
    });
    if (getAccountInfoCallback->errorCode_ != ERR_OK) {
        ACCOUNT_LOGE("GetAccountInfoSync failed with errCode: %{public}d", getAccountInfoCallback->errorCode_);
        SetTaiheBusinessErrorFromNativeCode(getAccountInfoCallback->errorCode_);
        return emptyDomainAccountInfo;
    }
    DomainAccountInfo domainAccountInfo = DomainAccountInfo {
        .domain = getAccountInfoCallback->getAccountInfoParams_.GetStringParam("domain"),
        .accountName = getAccountInfoCallback->getAccountInfoParams_.GetStringParam("accountName"),
        .accountId = optional<string>(std::in_place,
            getAccountInfoCallback->getAccountInfoParams_.GetStringParam("accountId").c_str()),
        .isAuthenticated = optional<bool>(std::in_place,
            getAccountInfoCallback->getAccountInfoParams_.GetIntParam("isAuthenticated", 0)),
        .serverConfigId = optional<string>(std::in_place,
            getAccountInfoCallback->getAccountInfoParams_.GetStringParam("serverConfigId").c_str()),
    };
    auto value = getAccountInfoCallback->getAccountInfoParams_.GetParam("isAuthenticated");
    OHOS::AAFwk::IBoolean *bo = OHOS::AAFwk::IBoolean::Query(value);
    if (bo != nullptr) {
        domainAccountInfo.isAuthenticated =  optional<bool>(std::in_place, OHOS::AAFwk::Boolean::Unbox(bo));
    }
    return domainAccountInfo;
}

void UpdateAccountInfoSync(DomainAccountInfo const &oldAccountInfo, DomainAccountInfo const &newAccountInfo)
{
    AccountSA::DomainAccountInfo innerOldAccountInfo = ConvertToDomainAccountInfoInner(oldAccountInfo);
    AccountSA::DomainAccountInfo innerNewAccountInfo = ConvertToDomainAccountInfoInner(newAccountInfo);
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().UpdateAccountInfo(innerOldAccountInfo,
        innerNewAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateAccountInfoSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
    }
}

DomainServerConfig AddServerConfigSync(uintptr_t parameters)
{
    AccountSA::DomainServerConfig innerDomainServerConfig;
    DomainServerConfig emptyDomainServerConfig = {
        .parameters = 0,
        .id = string(""),
        .domain = string("")
    };
    std::string innerParameters = ConvertMapViewToStringInner(parameters);
    if (innerParameters == "") {
        ACCOUNT_LOGE("Get parameters failed.");
        SetTaiheBusinessErrorFromNativeCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
        return emptyDomainServerConfig;
    }
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().AddServerConfig(
        innerParameters, innerDomainServerConfig);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("AddServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return emptyDomainServerConfig;
    }
    return ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
                                         innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
}

void RemoveServerConfigSync(string_view configId)
{
    std::string innerConfigId(configId.data(), configId.size());
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().RemoveServerConfig(innerConfigId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("RemoveServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
    }
}

DomainServerConfig UpdateServerConfigSync(string_view configId, uintptr_t parameters)
{
    std::string innerConfigId(configId.data(), configId.size());
    AccountSA::DomainServerConfig innerDomainServerConfig;
    DomainServerConfig emptyDomainServerConfig = {
        .parameters = 0,
        .id = string(""),
        .domain = string("")
    };
    std::string innerParameters = ConvertMapViewToStringInner(parameters);
    if (innerParameters == "") {
        ACCOUNT_LOGE("Get parameters failed.");
        SetTaiheBusinessErrorFromNativeCode(JSErrorCode::ERR_JS_PARAMETER_ERROR);
        return emptyDomainServerConfig;
    }
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().UpdateServerConfig(innerConfigId,
        innerParameters, innerDomainServerConfig);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return emptyDomainServerConfig;
    }
    return ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
                                         innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
}

DomainServerConfig GetServerConfigSync(string_view configId)
{
    std::string innerConfigId(configId.data(), configId.size());
    AccountSA::DomainServerConfig innerDomainServerConfig;
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetServerConfig(innerConfigId,
        innerDomainServerConfig);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("getServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        DomainServerConfig emptyDomainServerConfig = {
            .parameters = 0,
            .id = string(""),
            .domain = string("")
        };
        return emptyDomainServerConfig;
    }
    return ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
                                         innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
}

array<DomainServerConfig> GetAllServerConfigsSync()
{
    std::vector<AccountSA::DomainServerConfig> innerDomainServerConfigs;
    std::vector<DomainServerConfig> domainServerConfigsVector;
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetAllServerConfigs(innerDomainServerConfigs);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetAllServerConfigsSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        return array<DomainServerConfig>(taihe::copy_data_t{}, domainServerConfigsVector.data(),
            domainServerConfigsVector.size());
    }
    for (const auto &innerDomainServerConfig : innerDomainServerConfigs) {
        auto domainServerConfig = ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
            innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
        domainServerConfigsVector.push_back(domainServerConfig);
    }
    return array<DomainServerConfig>(taihe::copy_data_t{}, domainServerConfigsVector.data(),
    domainServerConfigsVector.size());
}

DomainServerConfig GetAccountServerConfigSync(DomainAccountInfo const &domainAccountInfo)
{
    AccountSA::DomainAccountInfo innerDomainAccountInfo = ConvertToDomainAccountInfoInner(domainAccountInfo);
    AccountSA::DomainServerConfig innerDomainServerConfig;
    ErrCode errCode = AccountSA::DomainAccountClient::GetInstance().GetAccountServerConfig(innerDomainAccountInfo,
                                                                                           innerDomainServerConfig);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("getAccountServerConfigSync failed with errCode: %{public}d", errCode);
        SetTaiheBusinessErrorFromNativeCode(errCode);
        DomainServerConfig emptyDomainServerConfig = {
            .parameters = 0,
            .id = string(""),
            .domain = string("")
        };
        return emptyDomainServerConfig;
    }
    return ConvertToDomainServerConfigTH(innerDomainServerConfig.id_,
                                         innerDomainServerConfig.domain_, innerDomainServerConfig.parameters_);
}

void RegisterInputer(AuthType authType, const IInputer &inputer)
{
    int32_t type = authType.get_value();
    auto taiheInputer = std::make_shared<TaiheIInputer>(inputer);
    auto taiheCallbackRef = std::make_shared<TaiheGetDataCallback>();
    taiheCallbackRef->inputer_ = taiheInputer;
    taiheCallbackRef->inputerData_ = std::make_shared<IInputData>(make_holder<IInputDataImpl, IInputData>());
    ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().RegisterInputer(type, taiheCallbackRef);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to register inputer, errCode=%{public}d", errCode);
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }
}

void UnregisterInputer(AuthType authType)
{
    int32_t type = authType.get_value();
    ErrCode errCode = AccountSA::AccountIAMClient::GetInstance().UnregisterInputer(type);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to unregister inputer, errCode=%{public}d", errCode);
        int32_t jsErrCode = AccountIAMConvertToJSErrCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }
}

UserIdentityManager CreateUserIdentityManager()
{
    return make_holder<UserIdentityManagerImpl, UserIdentityManager>();
}

UserAuth CreateUserAuth()
{
    return make_holder<UserAuthImpl, UserAuth>();
}

PINAuth CreatePINAuth()
{
    return make_holder<PINAuthImpl, PINAuth>();
}
} // namespace

TH_EXPORT_CPP_API_IsAuthenticationExpiredSync(IsAuthenticationExpiredSync);
TH_EXPORT_CPP_API_UnregisterPlugin(UnregisterPlugin);
TH_EXPORT_CPP_API_Auth(Auth);
TH_EXPORT_CPP_API_AuthWithPopup(AuthWithPopup);
TH_EXPORT_CPP_API_AuthWithPopupWithId(AuthWithPopupWithId);
TH_EXPORT_CPP_API_HasAccountSync(HasAccountSync);
TH_EXPORT_CPP_API_UpdateAccountTokenSync(UpdateAccountTokenSync);
TH_EXPORT_CPP_API_GetAccessTokenSync(GetAccessTokenSync);
TH_EXPORT_CPP_API_GetAccountInfoSync(GetAccountInfoSync);
TH_EXPORT_CPP_API_UpdateAccountInfoSync(UpdateAccountInfoSync);
TH_EXPORT_CPP_API_AddServerConfigSync(AddServerConfigSync);
TH_EXPORT_CPP_API_RemoveServerConfigSync(RemoveServerConfigSync);
TH_EXPORT_CPP_API_UpdateServerConfigSync(UpdateServerConfigSync);
TH_EXPORT_CPP_API_GetServerConfigSync(GetServerConfigSync);
TH_EXPORT_CPP_API_GetAllServerConfigsSync(GetAllServerConfigsSync);
TH_EXPORT_CPP_API_GetAccountServerConfigSync(GetAccountServerConfigSync);
TH_EXPORT_CPP_API_registerInputer(RegisterInputer);
TH_EXPORT_CPP_API_unregisterInputer(UnregisterInputer);
TH_EXPORT_CPP_API_CreateUserIdentityManager(CreateUserIdentityManager);
TH_EXPORT_CPP_API_CreateUserAuth(CreateUserAuth);
TH_EXPORT_CPP_API_CreatePINAuth(CreatePINAuth);
TH_EXPORT_CPP_API_createIInputData(createIInputData);
TH_EXPORT_CPP_API_getPtrByIInputData(getPtrByIInputData);