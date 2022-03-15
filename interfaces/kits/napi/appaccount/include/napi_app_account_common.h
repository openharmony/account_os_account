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

#ifndef NAPI_APP_ACCOUNT_COMMON
#define NAPI_APP_ACCOUNT_COMMON
#include <mutex>
#include <thread>
#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "app_account_subscriber.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
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

static const std::int32_t SUBSCRIBE_MAX_PARA = 3;
static const std::int32_t UNSUBSCRIBE_MAX_PARA = 2;

class AppAccountManagerCallback;
struct AsyncContextForSubscribe;
static std::mutex g_lockForAppAccountSubscribers;
static std::map<AppAccountManager *, std::vector<AsyncContextForSubscribe *>> g_AppAccountSubscribers;

class SubscriberPtr : public AppAccountSubscriber {
public:
    SubscriberPtr(const AppAccountSubscribeInfo &subscribeInfo);
    ~SubscriberPtr();

    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts) override;

    void SetEnv(const napi_env &env);
    void SetCallbackRef(const napi_ref &ref);

private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
};

struct CommonAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
    int errCode = 0;
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
    bool isEnable = false;
    bool result = false;
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
    sptr<AppAccountManagerCallback> appAccountMgrCb = nullptr;
    sptr<IRemoteObject> authenticatorCb = nullptr;
};

struct GetAccountsAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_status status;
    std::string owner;
    int errCode = 0;
    std::vector<AppAccountInfo> appAccounts;
};

struct SubscriberAccountsWorker {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    std::vector<AppAccountInfo> accounts;
    int code = 0;
};

struct AsyncContextForSubscribe {
    napi_env env;
    napi_async_work work;
    napi_ref callbackRef;
    AppAccountManager *appAccountManager = nullptr;
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
};

struct AsyncContextForUnsubscribe {
    napi_env env;
    napi_async_work work;
    napi_ref callbackRef;
    std::vector<std::shared_ptr<SubscriberPtr>> subscribers = {nullptr};
    AppAccountManager *appAccountManager = nullptr;
    size_t argc = 0;
};

struct ThreadLockInfo {
    std::mutex mutex;
    std::condition_variable condition;
    bool ready = false;
};

struct AuthenticatorCallbackParam {
    napi_env env = nullptr;
    int32_t resultCode;
    AAFwk::WantParams result;
    AAFwk::Want request;
    napi_ref resultRef;
    napi_ref requestRedirectedRef;
    ThreadLockInfo *lockInfo;
};

class AppAccountManagerCallback : public AppAccountAuthenticatorCallbackStub {
public:
    AppAccountManagerCallback();
    ~AppAccountManagerCallback();

    virtual void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    virtual void OnRequestRedirected(AAFwk::Want &request) override;

    void SetEnv(const napi_env &env);
    void SetResultRef(const napi_ref &ref);
    void SetRequestRedirectedRef(const napi_ref &ref);
private:
    napi_env env_ = nullptr;
    napi_ref resultRef_ = nullptr;
    napi_ref requestRedirectedRef_ = nullptr;
};

napi_value NapiGetNull(napi_env env);

std::string GetNamedProperty(napi_env env, napi_value obj);

void SetNamedProperty(napi_env env, napi_value dstObj, const char *objName, const char *propName);

void SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char *propName);

napi_value GetErrorCodeValue(napi_env env, int errCode);

void GetAppAccountInfoForResult(napi_env env, const std::vector<AppAccountInfo> &info, napi_value result);

void GetAuthenticatorInfoForResult(napi_env env, const AuthenticatorInfo &info, napi_value &result);

void GetOAuthTokenInfoForResult(napi_env env, const std::vector<OAuthTokenInfo> &info, napi_value result);

void GetOAuthListForResult(napi_env env, const std::set<std::string> &info, napi_value result);

void GetAuthenticatorCallbackForResult(napi_env env, sptr<IRemoteObject> callback, napi_value *result);

void ParseContextWithExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextForSetExInfo(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextForAuthenticate(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext, size_t argc);

void ParseContextForDeleteOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForGetOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForSetOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForCheckOAuthTokenVisibility(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForGetAuthenticatorInfo(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForGetAllOAuthTokens(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForGetOAuthList(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForGetAuthenticatorCallback(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextForSetOAuthToken(napi_env env, napi_callback_info cbInfo, OAuthAsyncContext *asyncContext);

void ParseContextWithBdName(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextWithIsEnable(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextWithTwoPara(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextToSetCredential(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextForAssociatedData(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextToGetData(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext);

void ParseContextWithCredentialType(napi_env env, napi_callback_info cbInfo, AppAccountAsyncContext *asyncContext);

void ParseContextWithStrCBArray(napi_env env, napi_callback_info cbInfo, GetAccountsAsyncContext *asyncContext);

void ProcessCallbackOrPromise(
    napi_env env, const CommonAsyncContext *asyncContext, napi_value err, napi_value data);

void ProcessCallbackOrPromiseCBArray(
    napi_env env, const GetAccountsAsyncContext *asyncContext, napi_value err, napi_value data);

napi_value ParseParametersBySubscribe(const napi_env &env, const napi_value (&argv)[SUBSCRIBE_MAX_PARA],
    std::vector<std::string> &owners, napi_ref &callback);

napi_value ParseParametersByUnsubscribe(
    const napi_env &env, const size_t &argc, const napi_value (&argv)[UNSUBSCRIBE_MAX_PARA], napi_ref &callback);

napi_value GetSubscriberByUnsubscribe(const napi_env &env, std::vector<std::shared_ptr<SubscriberPtr>> &subscriber,
    AsyncContextForUnsubscribe *asyncContextForOff, bool &isFind);

void SubscribeExecuteCB(napi_env env, void *data);

void UnsubscribeExecuteCB(napi_env env, void *data);

void UnsubscribeCallbackCompletedCB(napi_env env, napi_status status, void *data);
}  // namespace AccountJsKit
}  // namespace OHOS

#endif /* NAPI_APP_ACCOUNT_COMMON */