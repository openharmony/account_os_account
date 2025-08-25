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

#include "account_log_wrapper.h"
#include "ani_common_want.h"
#include "bool_wrapper.h"
#include "domain_account_client.h"
#include "ohos.account.osAccount.proj.hpp"
#include "string_wrapper.h"
#include "taihe_common.h"

using namespace OHOS;
using namespace ohos::account::osAccount;

namespace {
static const char* CLASS_NAME_BUSINESSERROR = "@ohos.base.BusinessError";
using OHOS::AccountSA::ACCOUNT_LABEL;

class DomainPluginImpl {
public:
    explicit DomainPluginImpl(DomainPlugin const& plugin): plugin_(plugin) {}

    void Auth(DomainAccountInfo const& domainAccountInfo,
        array_view<uint8_t> credential, IUserAuthCallback const& callback)
    {
        this->plugin_->Auth(domainAccountInfo, credential, callback);
    }

    void AuthWithPopup(DomainAccountInfo const& domainAccountInfo, IUserAuthCallback const& callback)
    {
        this->plugin_->AuthWithPopup(domainAccountInfo, callback);
    }

    void AuthWithToken(DomainAccountInfo const& domainAccountInfo,
        array_view<uint8_t> token, IUserAuthCallback const& callback)
    {
        this->plugin_->AuthWithToken(domainAccountInfo, token, callback);
    }

    void GetAccountInfo(GetDomainAccountInfoPluginOptions const& options,
        callback_view<void(OptionalError const& err, DomainAccountInfoData const& data)> callback)
    {
        this->plugin_->GetAccountInfo(options, callback);
    }

    void GetAuthStatusInfo(DomainAccountInfo const& domainAccountInfo,
        callback_view<void(OptionalError const& err, AuthStatusInfoData const& data)> callback)
    {
        this->plugin_->GetAuthStatusInfo(domainAccountInfo, callback);
    }

    void BindAccount(DomainAccountInfo const& domainAccountInfo, int32_t localId,
        callback_view<void(OptionalError const& err)> callback)
    {
        this->plugin_->BindAccount(domainAccountInfo, localId, callback);
    }

    void UnbindAccount(DomainAccountInfo const& domainAccountInfo,
        callback_view<void(OptionalError const& err)> callback)
    {
        this->plugin_->UnbindAccount(domainAccountInfo, callback);
    }

    void IsAccountTokenValid(DomainAccountInfo const& domainAccountInfo,
        array_view<uint8_t> token, callback_view<void(OptionalError const& err,
        BoolData const& data)> callback)
    {
        this->plugin_->IsAccountTokenValid(domainAccountInfo, token, callback);
    }

    void GetAccessToken(GetDomainAccessTokenOptions const& options,
        callback_view<void(OptionalError const& err, ArrayData const& data)> callback)
    {
        this->plugin_->GetAccessToken(options, callback);
    }

private:
    DomainPlugin plugin_;
};

class AuthResultCallBack {
public:
    explicit AuthResultCallBack(std::shared_ptr<AccountSA::DomainAccountCallback> const& callback)
        : callback_(callback) {}

    void operator()(const int32_t result, AuthResult const& extraInfo)
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("native callback is nullptr");
            return;
        }

        AccountSA::DomainAuthResult nativeResult;
        if (extraInfo.token.has_value()) {
            const auto& taiheToken = extraInfo.token.value();
            nativeResult.token.assign(taiheToken.data(), taiheToken.data() + taiheToken.size());
        } else {
            nativeResult.token.clear();
        }

        nativeResult.authStatusInfo.remainingTimes = extraInfo.remainTimes.has_value() ?
            extraInfo.remainTimes.value() : -1;
        nativeResult.authStatusInfo.freezingTime = extraInfo.freezingTime.has_value() ?
            extraInfo.freezingTime.value() : -1;

        Parcel parcel;
        if (!nativeResult.Marshalling(parcel)) {
            Parcel emptyParcel;
            callback_->OnResult(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR, emptyParcel);
            nativeResult.token.clear();
            return;
        }
        callback_->OnResult(result, parcel);
        nativeResult.token.clear();
        ACCOUNT_LOGI("Successfully called native callback");
    }

private:
    std::shared_ptr<AccountSA::DomainAccountCallback> callback_;
};

static bool ConvertOptionalError(OptionalError const& err, int32_t& errorCode)
{
    ani_env* env = get_env();
    ani_object ani_obj = reinterpret_cast<ani_object>(err.get_ref<OptionalError::tag_t::error>());
    if (env != nullptr) {
        env->Object_GetPropertyByName_Int(ani_obj, "code", &errorCode);
        return true;
    }
    return false;
}

class AuthStatusInfoCallback {
public:
    explicit AuthStatusInfoCallback(std::shared_ptr<AccountSA::DomainAccountCallback> const& callback)
        : callback_(callback) {}

    void operator()(OptionalError const& err, AuthStatusInfoData const& data)
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("native callback is nullptr");
            return;
        }

        int32_t errorCode = 0;
        if (err.get_tag() == OptionalError::tag_t::error) {
            if (!ConvertOptionalError(err, errorCode)) {
                Parcel emptyParcel;
                callback_->OnResult(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, emptyParcel);
            }
        }

        AccountSA::AuthStatusInfo info;
        if (data.get_tag() == AuthStatusInfoData::tag_t::data) {
            auto authStatusInfo = data.get_ref<AuthStatusInfoData::tag_t::data>();
            info.remainingTimes = authStatusInfo.remainTimes;
            info.freezingTime = authStatusInfo.freezingTime;
        }

        Parcel parcel;
        if (!info.Marshalling(parcel)) {
            Parcel emptyParcel;
            callback_->OnResult(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR, emptyParcel);
            return;
        }
        callback_->OnResult(errorCode, parcel);
    }

private:
    std::shared_ptr<AccountSA::DomainAccountCallback> callback_;
};

class DomainAccountInfoCallback {
public:
    explicit DomainAccountInfoCallback(std::shared_ptr<AccountSA::DomainAccountCallback> const& callback)
        : callback_(callback) {}

    void operator()(OptionalError const& err, DomainAccountInfoData const& data)
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("native callback is nullptr");
            return;
        }

        int32_t errorCode = 0;
        if (err.get_tag() == OptionalError::tag_t::error) {
            if (!ConvertOptionalError(err, errorCode)) {
                Parcel emptyParcel;
                callback_->OnResult(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, emptyParcel);
            }
        }

        AccountSA::DomainAccountInfo info;
        if (data.get_tag() == DomainAccountInfoData::tag_t::data) {
            auto domainAccountInfo = data.get_ref<DomainAccountInfoData::tag_t::data>();
            info.domain_ = domainAccountInfo.domain;
            info.accountName_ = domainAccountInfo.accountName;
            if (domainAccountInfo.accountId.has_value()) {
                info.accountId_ = domainAccountInfo.accountId.value();
            }
            if (domainAccountInfo.isAuthenticated.has_value()) {
                info.isAuthenticated = domainAccountInfo.isAuthenticated.value();
            }
            if (domainAccountInfo.serverConfigId.has_value()) {
                info.serverConfigId_ = domainAccountInfo.serverConfigId.value();
            }
        }

        AAFwk::WantParams getAccountInfoParams;
        getAccountInfoParams.SetParam("domain", AAFwk::String::Box(info.domain_));
        getAccountInfoParams.SetParam("accountName", AAFwk::String::Box(info.accountName_));
        getAccountInfoParams.SetParam("accountId", AAFwk::String::Box(info.accountId_));
        getAccountInfoParams.SetParam("isAuthenticated", AAFwk::Boolean::Box(info.isAuthenticated));
        getAccountInfoParams.SetParam("serverConfigId", AAFwk::String::Box(info.serverConfigId_));

        Parcel parcel;
        if (!getAccountInfoParams.Marshalling(parcel)) {
            Parcel emptyParcel;
            callback_->OnResult(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR, emptyParcel);
            return;
        }
        callback_->OnResult(errorCode, parcel);
    }

private:
    std::shared_ptr<AccountSA::DomainAccountCallback> callback_;
};

class VoidCallBack {
public:
    explicit VoidCallBack(std::shared_ptr<AccountSA::DomainAccountCallback> const& callback): callback_(callback) {}

    void operator()(OptionalError const& err)
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("native callback is nullptr");
            return;
        }

        int32_t errorCode = 0;
        if (err.get_tag() == OptionalError::tag_t::error) {
            if (!ConvertOptionalError(err, errorCode)) {
                Parcel emptyParcel;
                callback_->OnResult(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, emptyParcel);
            }
        }

        AccountSA::DomainAccountInfo info;
        Parcel parcel;
        if (!info.Marshalling(parcel)) {
            Parcel emptyParcel;
            callback_->OnResult(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR, emptyParcel);
            return;
        }
        callback_->OnResult(errorCode, parcel);
    }

private:
    std::shared_ptr<AccountSA::DomainAccountCallback> callback_;
};

class BoolDataCallback {
public:
    explicit BoolDataCallback(std::shared_ptr<AccountSA::DomainAccountCallback> const& callback): callback_(callback) {}

    void operator()(OptionalError const& err, BoolData const& data)
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("native callback is nullptr");
            return;
        }

        int32_t errorCode = 0;
        if (err.get_tag() == OptionalError::tag_t::error) {
            if (!ConvertOptionalError(err, errorCode)) {
                Parcel emptyParcel;
                callback_->OnResult(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, emptyParcel);
            }
        }

        bool isTokenValid = false;
        if (data.get_tag() == BoolData::tag_t::data) {
            auto value = data.get_ref<BoolData::tag_t::data>();
            isTokenValid = value;
        }

        Parcel parcel;
        if (!parcel.WriteBool(isTokenValid)) {
            Parcel emptyParcel;
            callback_->OnResult(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR, emptyParcel);
            return;
        }
        callback_->OnResult(errorCode, parcel);
    }

private:
    std::shared_ptr<AccountSA::DomainAccountCallback> callback_;
};

class ArrayDataCallback {
public:
    explicit ArrayDataCallback(std::shared_ptr<AccountSA::DomainAccountCallback> const& callback)
        : callback_(callback) {}

    void operator()(OptionalError const& err, ArrayData const& data)
    {
        if (callback_ == nullptr) {
            ACCOUNT_LOGE("native callback is nullptr");
            return;
        }

        int32_t errorCode = 0;
        if (err.get_tag() == OptionalError::tag_t::error) {
            if (!ConvertOptionalError(err, errorCode)) {
                Parcel emptyParcel;
                callback_->OnResult(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR, emptyParcel);
            }
        }

        std::vector<uint8_t> accessToken;
        if (data.get_tag() == ArrayData::tag_t::data) {
            auto value = data.get_ref<ArrayData::tag_t::data>();
            std::vector<uint8_t> token(value.data(), value.data() + value.size());
            accessToken = token;
        }

        Parcel parcel;
        if (!parcel.WriteUInt8Vector(accessToken)) {
            Parcel emptyParcel;
            callback_->OnResult(ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR, emptyParcel);
            return;
        }
        callback_->OnResult(errorCode, parcel);
    }

private:
    std::shared_ptr<AccountSA::DomainAccountCallback> callback_;
};

class TaiheDomainAccountPlugin final: public AccountSA::DomainAccountPlugin {
public:
    explicit TaiheDomainAccountPlugin(const DomainPluginImpl &plugin): plugin_(plugin) {}

    void Auth(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &credential,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        auto taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheCredential(taihe::copy_data_t{}, credential.data(), credential.size());
        auto taiheCallback = ConvertToIUserAuthCallback(callback);
        plugin_.Auth(taiheInfo, taiheCredential, taiheCallback);
    }

    void AuthWithPopup(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        auto taiheInfo = ConvertToDomainAccountInfo(info);
        auto taiheCallback = ConvertToIUserAuthCallback(callback);
        plugin_.AuthWithPopup(taiheInfo, taiheCallback);
    }

    void AuthWithToken(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        auto taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheToken(taihe::copy_data_t{}, token.data(), token.size());
        auto taiheCallback = ConvertToIUserAuthCallback(callback);
        plugin_.AuthWithToken(taiheInfo, taiheToken, taiheCallback);
    }

    void GetAuthStatusInfo(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        auto taiheInfo = ConvertToDomainAccountInfo(info);
        ::taihe::callback<void(OptionalError const& err, AuthStatusInfoData const& data)> taiheCallback =
            make_holder<AuthStatusInfoCallback,
            ::taihe::callback<void(OptionalError const& err, AuthStatusInfoData const& data)>>(callback);
        plugin_.GetAuthStatusInfo(taiheInfo, taiheCallback);
    }

    void GetDomainAccountInfo(const AccountSA::GetDomainAccountInfoOptions &options,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        GetDomainAccountInfoOptions option{
            .accountName = options.accountInfo.accountName_.c_str(),
            .domain = optional<string>(std::in_place_t{}, options.accountInfo.domain_),
            .serverConfigId = optional<string>(std::in_place_t{}, options.accountInfo.serverConfigId_),
        };
        GetDomainAccountInfoPluginOptions taiheOptions{
            .options = option,
            .callerUid = options.callingUid,
        };
        ::taihe::callback<void(OptionalError const& err, DomainAccountInfoData const& data)> taiheCallback =
            make_holder<DomainAccountInfoCallback,
            ::taihe::callback<void(OptionalError const& err, DomainAccountInfoData const& data)>>(callback);
        plugin_.GetAccountInfo(taiheOptions, taiheCallback);
    }

    void OnAccountBound(const AccountSA::DomainAccountInfo &info, const int32_t localId,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        auto taiheInfo = ConvertToDomainAccountInfo(info);
        ::taihe::callback<void(OptionalError const& err)> taiheCallback = make_holder<VoidCallBack,
            ::taihe::callback<void(OptionalError const& err)>>(callback);
        plugin_.BindAccount(taiheInfo, localId, taiheCallback);
    }

    void OnAccountUnBound(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        auto taiheInfo = ConvertToDomainAccountInfo(info);
        ::taihe::callback<void(OptionalError const& err)> taiheCallback = make_holder<VoidCallBack,
            ::taihe::callback<void(OptionalError const& err)>>(callback);
        plugin_.UnbindAccount(taiheInfo, taiheCallback);
    }

    void IsAccountTokenValid(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        auto taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheToken(taihe::copy_data_t{}, token.data(), token.size());
        ::taihe::callback<void(OptionalError const& err, BoolData const& data)> taiheCallback =
            make_holder<BoolDataCallback,
            ::taihe::callback<void(OptionalError const& err, BoolData const& data)>>(callback);
        plugin_.IsAccountTokenValid(taiheInfo, taiheToken, taiheCallback);
    }

    void GetAccessToken(const AccountSA::DomainAccountInfo &domainInfo, const std::vector<uint8_t> &accountToken,
        const AccountSA::GetAccessTokenOptions &option,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        taihe::array<uint8_t> taiheToken(taihe::copy_data_t{}, accountToken.data(), accountToken.size());
        AAFwk::WantParams getTokenParams;
        ani_env *env = get_env();
        auto parametersRef = AppExecFwk::WrapWantParams(env, option.getTokenParams_);
        GetDomainAccessTokenOptions domainAccessTokenOptions {
            .domainAccountInfo = ConvertToDomainAccountInfo(domainInfo),
            .domainAccountToken = taiheToken,
            .businessParams = reinterpret_cast<uintptr_t>(parametersRef),
            .callerUid = option.callingUid_,
        };
        ::taihe::callback<void(OptionalError const& err, ArrayData const& data)> taiheCallback =
            make_holder<ArrayDataCallback,
            ::taihe::callback<void(OptionalError const& err, ArrayData const& data)>>(callback);
        plugin_.GetAccessToken(domainAccessTokenOptions, taiheCallback);
    }
private:
    DomainAccountInfo ConvertToDomainAccountInfo(const AccountSA::DomainAccountInfo &domainAccountInfo)
    {
        return DomainAccountInfo{
            .domain = taihe::string(domainAccountInfo.domain_.c_str()),
            .accountName = taihe::string(domainAccountInfo.accountName_.c_str()),
            .accountId = optional<string>(std::in_place_t{}, domainAccountInfo.accountId_),
            .isAuthenticated = optional<bool>(std::in_place_t{}, domainAccountInfo.isAuthenticated),
            .serverConfigId = optional<string>(std::in_place_t{}, domainAccountInfo.serverConfigId_),
        };
    }

    IUserAuthCallback ConvertToIUserAuthCallback(const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        ::taihe::callback<void(int32_t, AuthResult const&)> onResultCallback =
            make_holder<AuthResultCallBack, ::taihe::callback<void(int32_t, AuthResult const&)>>(callback);

        IUserAuthCallback taiheCallback{
            .onResult = onResultCallback,
            .onAcquireInfo = std::nullopt,
        };
        return taiheCallback;
    }

    DomainPluginImpl plugin_;
};

void RegisterPlugin(DomainPlugin const& plugin)
{
    DomainPluginImpl taihePlugin(plugin);
    auto pluginPtr = std::make_shared<TaiheDomainAccountPlugin>(taihePlugin);
    int32_t errCode = AccountSA::DomainAccountClient::GetInstance().RegisterPlugin(pluginPtr);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to register plugin, errCode=%{public}d", errCode);
        int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }
}
} // namespace

TH_EXPORT_CPP_API_RegisterPlugin(RegisterPlugin);
