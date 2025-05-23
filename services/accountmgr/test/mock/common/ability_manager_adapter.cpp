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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ability_manager_adapter.h"

#include "account_log_wrapper.h"
#include "app_account_authorization_extension_service.h"
#include "app_account_authorization_extension_stub.h"
#include "mock_app_account_authenticator_stub.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string STRING_BUNDLE = "com.example.name";
const std::string STRING_NORMAL_BUNDLENAME = "com.example.normal.bundle";
const std::string STRING_ABILITY_NAME_WITH_CONNECT_FAILED = "com.example.MainAbilityWithConnectFailed";
const std::string STRING_ABILITY_NAME_WITH_NO_PROXY = "com.example.MainAbilityWithNoProxy";
} // namespace
using namespace AAFwk;

class MockAppAccountAuthorizationExtensionService final : public AppAccountAuthorizationExtensionStub {
public:
    ErrCode StartAuthorization(const AuthorizationRequest &request)
    {
        std::string testValue = request.parameters.GetStringParam("keyStr");
        if (testValue.size() != 0) {
            AAFwk::WantParams errResult;
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
        }
        AAFwk::WantParams errResult;
        AsyncCallbackError businessError;
        request.callback->OnResult(businessError, errResult);
        return ERR_OK;
    }
};

AbilityManagerAdapter *AbilityManagerAdapter::GetInstance()
{
    static AbilityManagerAdapter *instance = new (std::nothrow) AbilityManagerAdapter();
    return instance;
}

AbilityManagerAdapter::AbilityManagerAdapter()
{}

AbilityManagerAdapter::~AbilityManagerAdapter()
{}

ErrCode AbilityManagerAdapter::ConnectAbility(const AAFwk::Want &want, const sptr<AAFwk::IAbilityConnection> &connect,
    const sptr<IRemoteObject> &callerToken, int32_t userId)
{
    if (want.GetBundle() == STRING_BUNDLE) {
        sptr<AccountSA::MockAppAccountAuthenticator> mockServicePtr_ =
            new (std::nothrow) AccountSA::MockAppAccountAuthenticator();
        int resultCode = ERR_OK;
        AppExecFwk::ElementName element = want.GetElement();
        connect->OnAbilityConnectDone(element, mockServicePtr_, resultCode);
    } else if (want.GetBundle() == STRING_NORMAL_BUNDLENAME) {
        ACCOUNT_LOGI("mock enter bundleName = %{public}s", want.GetBundle().c_str());
        int resultCode = ERR_OK;
        AppExecFwk::ElementName element = want.GetElement();
        sptr<MockAppAccountAuthorizationExtensionService> authorizationService =
            new (std::nothrow) MockAppAccountAuthorizationExtensionService();
        if (authorizationService == nullptr) {
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
        }
        ACCOUNT_LOGI("mock enter GetAbilityName = %{public}s", element.GetAbilityName().c_str());
        if (element.GetAbilityName() == STRING_ABILITY_NAME_WITH_CONNECT_FAILED) {
            return ERR_JS_SYSTEM_SERVICE_EXCEPTION;
        }
        if (element.GetAbilityName() == STRING_ABILITY_NAME_WITH_NO_PROXY) {
            connect->OnAbilityConnectDone(element, nullptr, resultCode);
            return ERR_OK;
        }
        connect->OnAbilityConnectDone(element, authorizationService, resultCode);
    } else {
        int resultCode = ERR_OK;
        AppExecFwk::ElementName element = want.GetElement();
        connect->OnAbilityConnectDone(element, nullptr, resultCode);
    }
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::DisconnectAbility(const sptr<AAFwk::IAbilityConnection> &connect)
{
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::StartUser(int accountId, const sptr<AAFwk::IUserCallback> &callback, bool isAppRecovery)
{
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::StopUser(int accountId, const sptr<AAFwk::IUserCallback> &callback)
{
    return ERR_OK;
}

ErrCode AbilityManagerAdapter::LogoutUser(int32_t accountId, const sptr<IUserCallback> &callback)
{
    return ERR_OK;
}

bool AbilityManagerAdapter::IsAllAppDied(int32_t accountId)
{
    return true;
}

void Connect()
{
}

ErrCode DoConnectAbility(
    const sptr<IRemoteObject> proxy,
    const Want &want,
    const sptr<IAbilityConnection> &connect,
    const sptr<IRemoteObject> &callerToken,
    int32_t userId = -1)
{
    return ERR_OK;
}

sptr<IRemoteObject> GetAbilityManager()
{
    sptr<IRemoteObject> iRemoteObject;
    return  iRemoteObject;
}

void ResetProxy(const wptr<IRemoteObject>& remote)
{}
} // namespace AccountSA
} // namespace OHOS