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
#include "domain_account_client.h"
#include "iam_common_defines.h"
#include "ohos.account.osAccount.impl.hpp"
#include "ohos.account.osAccount.proj.hpp"
#include "ohos_account_kits.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "taihe/runtime.hpp"
#include "taihe_common.h"
#include "taihe_account_info.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

using namespace taihe;
using namespace OHOS;

namespace {
using OHOS::AccountSA::ACCOUNT_LABEL;

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

class OnResultCallbackImpl {
public:
    explicit OnResultCallbackImpl(std::shared_ptr<AccountSA::DomainAccountCallback> callback)
        : callback_(callback) {}

    void operator()(int32_t result, const ::ohos::account::osAccount::AuthResult& extraInfo)
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
            return;
        }
        callback_->OnResult(result, parcel);
        ACCOUNT_LOGI("Successfully called native callback");
    }

private:
    std::shared_ptr<AccountSA::DomainAccountCallback> callback_;
};

class TaiheDomainPluginBridge : public AccountSA::DomainAccountPlugin {
public:
    explicit TaiheDomainPluginBridge(const DomainPlugin& jsPlugin)
        : jsPlugin_(jsPlugin) {}

    void Auth(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &credential,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback) override
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheCredential(taihe::copy_data_t{}, credential.data(), credential.size());
        IUserAuthCallback taiheCallback = ConvertToDomainAccountCallback(callback);
        jsPlugin_.Auth(taiheInfo, taiheCredential, taiheCallback);
    }

    void AuthWithPopup(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        IUserAuthCallback taiheCallback = ConvertToDomainAccountCallback(callback);
        jsPlugin_.AuthWithPopup(taiheInfo, taiheCallback);
    }

    void AuthWithToken(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheToken(taihe::copy_data_t{}, token.data(), token.size());
        IUserAuthCallback taiheCallback = ConvertToDomainAccountCallback(callback);
        jsPlugin_.AuthWithToken(taiheInfo, taiheToken, taiheCallback);
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
        jsPlugin_.GetAccountInfoSync(taiheOptions);
    }

    void GetAuthStatusInfo(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        jsPlugin_.GetAuthStatusInfoSync(taiheInfo);
    }

    void OnAccountBound(const AccountSA::DomainAccountInfo &info, const int32_t localId,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        jsPlugin_.BindAccountSync(taiheInfo, localId);
    }

    void OnAccountUnBound(const AccountSA::DomainAccountInfo &info,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        jsPlugin_.UnbindAccountSync(taiheInfo);
    }

    void IsAccountTokenValid(const AccountSA::DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        DomainAccountInfo taiheInfo = ConvertToDomainAccountInfo(info);
        taihe::array<uint8_t> taiheToken(taihe::copy_data_t{}, token.data(), token.size());
        jsPlugin_.IsAccountTokenValidSync(taiheInfo, taiheToken);
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
        jsPlugin_.GetAccessTokenSync(domainAccessTokenOptions);
    }

private:
    IUserAuthCallback ConvertToDomainAccountCallback(const std::shared_ptr<AccountSA::DomainAccountCallback> &callback)
    {
        ::taihe::callback<void(int32_t, ::ohos::account::osAccount::AuthResult const&)> onResultCallback =
            ::taihe::make_holder<OnResultCallbackImpl, ::taihe::callback<void(int32_t,
                ::ohos::account::osAccount::AuthResult const&)>>(callback);

        ::ohos::account::osAccount::IUserAuthCallback taiheCallback{
            .onResult = onResultCallback,
            .onAcquireInfo = std::nullopt,
        };
        return taiheCallback;
    }
private:
    DomainPlugin jsPlugin_;
};

void RegisterPlugin(DomainPlugin plugin)
{
    std::shared_ptr<TaiheDomainPluginBridge> innerPlugin = std::make_shared<TaiheDomainPluginBridge>(plugin);
    int32_t errCode = AccountSA::DomainAccountClient::GetInstance().RegisterPlugin(innerPlugin);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to register plugin, errCode=%{public}d", errCode);
        int32_t jsErrCode = GenerateBusinessErrorCode(errCode);
        taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
    }
}
} // namespace

TH_EXPORT_CPP_API_RegisterPlugin(RegisterPlugin);