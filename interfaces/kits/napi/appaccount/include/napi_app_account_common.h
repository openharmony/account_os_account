/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_COMMON_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_COMMON_H
#include <mutex>
#include <thread>
#include <uv.h>
#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "app_account_subscriber.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_account_common.h"
#include "want.h"

namespace OHOS {
namespace AccountJsKit {
using namespace OHOS::AccountSA;
constexpr std::int32_t MAX_VALUE_LEN = 4096;
constexpr const std::int32_t STR_MAX_SIZE = 256;
constexpr std::int32_t ARGS_SIZE_ONE = 1;
constexpr std::int32_t ARGS_SIZE_TWO = 2;
constexpr std::int32_t ARGS_SIZE_THREE = 3;
constexpr std::int32_t ARGS_SIZE_FOUR = 4;
constexpr std::int32_t ARGS_SIZE_FIVE = 5;
constexpr std::int32_t ARGS_SIZE_SIX = 6;
constexpr int RESULT_COUNT = 2;
constexpr int PARAMZERO = 0;
constexpr int PARAMONE = 1;
constexpr int PARAMTWO = 2;
constexpr int PARAMTHREE = 3;
constexpr int PARAMFOUR = 4;
constexpr int PARAMFIVE = 5;
const std::string APP_ACCOUNT_CLASS_NAME = "AppAccountManager";
const std::string TYPE_CHANGE = "change";

static const std::int32_t SUBSCRIBE_MAX_PARA = 3;
static const std::int32_t UNSUBSCRIBE_MAX_PARA = 2;

class AppAccountManagerCallback;
struct AsyncContextForSubscribe;
extern std::mutex g_lockForAppAccountSubscribers;
extern std::map<AppAccountManager *, std::vector<AsyncContextForSubscribe *>> g_AppAccountSubscribers;

class SubscriberPtr : public AppAccountSubscriber {
public:
    explicit SubscriberPtr(const AppAccountSubscribeInfo &subscribeInfo);
    ~SubscriberPtr();

    void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts) override;

    void SetEnv(const napi_env &env);
    void SetCallbackRef(const napi_ref &ref);

private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
};

struct AppAccountAsyncContext : public CommonAsyncContext {
    std::string name;
    std::string owner;
    std::string extraInfo;
    std::string bundleName;
    std::string credentialType;
    std::string credential;
    std::string key;
    std::string value;
    std::string subscribeType;
    std::string unSubscribeType;
    bool isAccessible = false;
    bool isEnable = false;
    bool result = false;
};

struct JSAuthCallback {
    napi_ref onResult = nullptr;
    napi_ref onRequestRedirected = nullptr;
    napi_ref onRequestContinued = nullptr;
};

struct OAuthAsyncContext : public CommonAsyncContext {
    std::string name;
    std::string owner;
    std::string sessionId;
    std::string bundleName;
    std::string authType;
    std::string token;
    std::set<std::string> authList;
    bool isVisible = false;
    AAFwk::Want options;
    AuthenticatorInfo authenticatorInfo;
    std::vector<OAuthTokenInfo> oauthTokenInfos;
    JSAuthCallback callback;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
    sptr<IRemoteObject> authenticatorCb = nullptr;
};

struct VerifyCredentialContext : public CommonAsyncContext {
    std::string name;
    std::string owner;
    VerifyCredentialOptions options;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
    JSAuthCallback callback;
};

struct SetPropertiesContext : public CommonAsyncContext {
    std::string owner;
    SetPropertiesOptions options;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
    JSAuthCallback callback;
};

struct SelectAccountsContext : public CommonAsyncContext {
    SelectAccountsOptions options;
    std::vector<AppAccountInfo> appAccountInfos;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
};

struct CheckAccountLabelsContext : public CommonAsyncContext {
    std::string name;
    std::string owner;
    std::vector<std::string> labels;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
};

struct GetAccountsAsyncContext : public CommonAsyncContext {
    std::string owner;
    std::vector<AppAccountInfo> appAccounts;
};

struct CreateAccountContext : public CommonAsyncContext {
public:
    explicit CreateAccountContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    std::string name;
    CreateAccountOptions options;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
};

struct CreateAccountImplicitlyContext : public CommonAsyncContext {
    explicit CreateAccountImplicitlyContext(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    std::string owner;
    CreateAccountImplicitlyOptions options;
    JSAuthCallback callback;
    sptr<IAppAccountAuthenticatorCallback> appAccountMgrCb = nullptr;
};

struct SubscriberAccountsWorker : public CommonAsyncContext {
    explicit SubscriberAccountsWorker(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    napi_ref ref = nullptr;
    std::vector<AppAccountInfo> accounts;
    int code = 0;
    SubscriberPtr *subscriber = nullptr;
};

struct AsyncContextForSubscribe : public CommonAsyncContext {
    explicit AsyncContextForSubscribe(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    std::string type;
    std::vector<std::string> owners;
    AppAccountManager *appAccountManager = nullptr;
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
};

struct AsyncContextForUnsubscribe : public CommonAsyncContext {
    explicit AsyncContextForUnsubscribe(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    std::string type;
    std::vector<std::shared_ptr<SubscriberPtr>> subscribers = {nullptr};
    AppAccountManager *appAccountManager = nullptr;
    size_t argc = 0;
};

struct AuthenticatorCallbackParam : public CommonAsyncContext {
    explicit AuthenticatorCallbackParam(napi_env napiEnv) : CommonAsyncContext(napiEnv) {};
    int32_t resultCode;
    AAFwk::Want result;
    AAFwk::Want request;
    JSAuthCallback callback;
    CommonAsyncContext context;
};

class AuthenticatorAsyncCallback : public AppAccountAuthenticatorCallbackStub {
public:
    explicit AuthenticatorAsyncCallback(const CommonAsyncContext &context, uv_after_work_cb workCb);
    ~AuthenticatorAsyncCallback();

    void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    void OnRequestRedirected(AAFwk::Want &request) override;
    void OnRequestContinued() override;

private:
    std::mutex mutex_;
    bool isDone = false;
    CommonAsyncContext context_;
    uv_after_work_cb workCb_;
};

class AppAccountManagerCallback : public AppAccountAuthenticatorCallbackStub {
public:
    explicit AppAccountManagerCallback(napi_env env, JSAuthCallback callback);
    ~AppAccountManagerCallback();

    void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    void OnRequestRedirected(AAFwk::Want &request) override;
    void OnRequestContinued() override;

private:
    napi_env env_ = nullptr;
    JSAuthCallback callback_;
};

bool InitAuthenticatorWorkEnv(
    napi_env env, uv_loop_s **loop, uv_work_t **work, AuthenticatorCallbackParam **param);

napi_value NapiGetNull(napi_env env);

std::string GetNamedProperty(napi_env env, napi_value obj);

void SetNamedProperty(napi_env env, napi_value dstObj, const char *objName, const char *propName);

void SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char *propName);

napi_value GetErrorCodeValue(napi_env env, int errCode);

bool GetArrayLength(napi_env env, napi_value value, uint32_t &length);

void CheckAccountLabelsOnResultWork(uv_work_t *work, int status);

void SelectAccountsOnResultWork(uv_work_t *work, int status);

void GetAppAccountInfoForResult(napi_env env, const std::vector<AppAccountInfo> &info, napi_value &result);

void GetAuthenticatorInfoForResult(napi_env env, const AuthenticatorInfo &info, napi_value &result);

void GetOAuthTokenInfoForResult(napi_env env, const std::vector<OAuthTokenInfo> &info, napi_value result);

void GetOAuthListForResult(napi_env env, const std::set<std::string> &info, napi_value result);

void GetAuthenticatorCallbackForResult(napi_env env, sptr<IRemoteObject> callback, napi_value *result);

bool ParseContextWithExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextForSetExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextForAuth(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForAuthenticate(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext, size_t argc);

bool ParseContextForDeleteOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextForGetOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextForSetOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextForCheckOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextForGetAuthenticatorInfo(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextForGetAllOAuthTokens(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextForGetOAuthList(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextForGetAuthenticatorCallback(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextForSetOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

bool ParseContextWithBdName(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextForSetAppAccess(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextWithIsEnable(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextWithTwoPara(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextToSetCredential(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextForAssociatedData(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextToGetData(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext);

bool ParseContextWithCredentialType(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

bool ParseContextWithStrCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext);

bool ParseContextForCreateAccount(napi_env env, napi_callback_info cbInfo, CreateAccountContext *context);

bool ParseContextForCreateAccountImplicitly(
    napi_env env, napi_callback_info cbInfo, CreateAccountImplicitlyContext *context);

bool ParseParametersBySubscribe(const napi_env &env, napi_callback_info cbInfo, AsyncContextForSubscribe *context);

bool ParseParametersByUnsubscribe(
    const napi_env &env, napi_callback_info cbInfo, AsyncContextForUnsubscribe *context);

napi_value GetSubscriberByUnsubscribe(const napi_env &env, std::vector<std::shared_ptr<SubscriberPtr>> &subscriber,
    AsyncContextForUnsubscribe *asyncContextForOff, bool &isFind);

bool ParseStringVector(napi_env env, napi_value value, std::vector<std::string> &strVec);
bool ParseAccountVector(napi_env env, napi_value value, std::vector<std::pair<std::string, std::string>> &accountVec);
bool ParseVerifyCredentialOptions(napi_env env, napi_value object, VerifyCredentialOptions &options);
bool ParseSelectAccountsOptions(napi_env env, napi_value object, SelectAccountsOptions &options);
bool ParseSetPropertiesOptions(napi_env env, napi_value object, SetPropertiesOptions &options);
bool ParseCreateAccountOptions(napi_env env, napi_value object, CreateAccountOptions &options);
bool GetNamedFunction(napi_env env, napi_value object, const std::string &name, napi_ref &funcRef);
bool ParseJSAuthCallback(napi_env env, napi_value object, JSAuthCallback &callback);
bool ParseContextForVerifyCredential(napi_env env, napi_callback_info info, VerifyCredentialContext *context);
bool ParseContextForSetProperties(napi_env env, napi_callback_info info, SetPropertiesContext *context);
bool ParseContextForSelectAccount(napi_env env, napi_callback_info info, SelectAccountsContext *context);
bool ParseContextForCheckAccountLabels(napi_env env, napi_callback_info info, CheckAccountLabelsContext *context);

void UnsubscribeExecuteCB(napi_env env, void *data);
void UnsubscribeCallbackCompletedCB(napi_env env, napi_status status, void *data);
void VerifyCredCompleteCB(napi_env env, napi_status status, void *data);
void ProcessOnResultCallback(
    napi_env env, JSAuthCallback &callback, int32_t resultCode, const AAFwk::WantParams &result);
bool GetAbilityName(napi_env env, std::string &abilityName);
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_APPACCOUNT_INCLUDE_NAPI_APP_ACCOUNT_COMMON_H
