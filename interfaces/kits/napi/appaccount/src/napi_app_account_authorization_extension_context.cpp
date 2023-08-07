/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "napi_app_account_authorization_extension_context.h"

#include <cstdint>

#include "account_log_wrapper.h"
#include "account_error_no.h"
#include "js_data_struct_converter.h"
#include "js_error_utils.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_account_error.h"
#include "napi_common_start_options.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "start_options.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t ERROR_CODE_ONE = 1;
constexpr int32_t ERROR_CODE_TWO = 2;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
static std::shared_ptr<AppExecFwk::EventHandler> g_handler = nullptr;
static std::map<ConnectionKey, sptr<JSAuthorizationExtensionConnection>, key_compare> g_connects;

void RemoveConnection(int64_t connectId)
{
    auto item = std::find_if(
        g_connects.begin(), g_connects.end(), [&connectId](const auto &obj) { return connectId == obj.first.id; });
    if (item != g_connects.end()) {
        if (item->second) {
            item->second->RemoveConnectionObject();
        }
        g_connects.erase(item);
    } else {
        ACCOUNT_LOGD("remove conn ability not exist");
    }
}

class JsAuthorizationExtensionContext final {
public:
    explicit JsAuthorizationExtensionContext(const std::shared_ptr<AuthorizationExtensionContext> &context)
        : context_(context)
    {
    }
    ~JsAuthorizationExtensionContext() = default;

    static void Finalizer(NativeEngine *engine, void *data, void *hint)
    {
        std::unique_ptr<JsAuthorizationExtensionContext>(static_cast<JsAuthorizationExtensionContext *>(data));
    }

    static NativeValue *DisconnectAbility(NativeEngine *engine, NativeCallbackInfo *info)
    {
        JsAuthorizationExtensionContext *me = CheckParamsAndGetThis<JsAuthorizationExtensionContext>(engine, info);
        return (me != nullptr) ? me->OnDisconnectAbility(*engine, *info) : nullptr;
    }

    static NativeValue *ConnectAbility(NativeEngine *engine, NativeCallbackInfo *info)
    {
        JsAuthorizationExtensionContext *me = CheckParamsAndGetThis<JsAuthorizationExtensionContext>(engine, info);
        return (me != nullptr) ? me->OnConnectAbility(*engine, *info) : nullptr;
    }

private:
    std::weak_ptr<AuthorizationExtensionContext> context_;

    static bool CheckOnDisconnectAbilityParam(NativeEngine &engine, NativeCallbackInfo &info, int64_t &connectId)
    {
        // Check input connection is number type
        if (!AppExecFwk::UnwrapInt64FromJS2(
            reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(info.argv[INDEX_ZERO]), connectId)) {
            ACCOUNT_LOGE("The input connection id is not number type.");
            return false;
        }
        return true;
    }

    static bool CheckWantParam(NativeEngine &engine, NativeValue *value, AAFwk::Want &want)
    {
        if (!OHOS::AppExecFwk::UnwrapWant(
            reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(value), want)) {
            ACCOUNT_LOGE("The input want is invalid.");
            return false;
        }
        return true;
    }

    bool CheckConnectionParam(NativeEngine &engine, NativeValue *value,
        sptr<JSAuthorizationExtensionConnection> &connection, const AAFwk::Want &want) const
    {
        if (ConvertNativeValueTo<NativeObject>(value) == nullptr) {
            ACCOUNT_LOGE("Failed to get connection object");
            return false;
        }
        connection->SetJsConnectionObject(value);
        ConnectionKey key;
        key.id = serialNumber_;
        key.want = want;
        connection->SetConnectionId(key.id);
        connects_.emplace(key, connection);
        if (serialNumber_ < INT32_MAX) {
            serialNumber_++;
        } else {
            serialNumber_ = 0;
        }
        return true;
    }

    void FindConnection(NativeEngine &engine, NativeCallbackInfo &info, AAFwk::Want &want,
        sptr<JSAuthorizationExtensionConnection> &connection, int64_t &connectId) const
    {
        auto item = std::find_if(connects_.begin(), connects_.end(),
            [&connectId](const std::map<ConnectionKey, sptr<JSAuthorizationExtensionConnection>>::value_type &obj) {
                return connectId == obj.first.id;
            });
        if (item != connects_.end()) {
            // match id
            want = item->first.want;
            connection = item->second;
        }
        return;
    }

    static bool UnWrapWant(NativeEngine &engine, NativeValue *argv, AAFwk::Want &want)
    {
        if (argv == nullptr) {
            ACCOUNT_LOGE("UnWrapWant argv == nullptr!");
            return false;
        }
        return AppExecFwk::UnwrapWant(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(argv), want);
    }

    NativeValue *OnConnectAbility(NativeEngine &engine, NativeCallbackInfo &info)
    {
        // Check params count
        if (info.argc < ARGC_TWO) {
            ACCOUNT_LOGE("Connect ability failed, not enough params.");
            ThrowTooFewParametersError(engine);
            return engine.CreateUndefined();
        }
        // Unwrap want and connection
        AAFwk::Want want;
        sptr<JSAuthorizationExtensionConnection> connection =
            new (std::nothrow) JSAuthorizationExtensionConnection(engine);
        if ((connection == nullptr) || (!CheckWantParam(engine, info.argv[0], want)) ||
            (!CheckConnectionParam(engine, info.argv[1], connection, want))) {
            ThrowError(engine, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
            return engine.CreateUndefined();
        }
        int64_t connectId = connection->GetConnectionId();
        AsyncTask::CompleteCallback complete =
            [weak = context_, want, connection, connectId](NativeEngine& engine, AsyncTask& task, int32_t status) {
                auto context = weak.lock();
                if (!context) {
                    ACCOUNT_LOGE("context is released");
                    task.Reject(engine, CreateJsError(engine, ERROR_CODE_ONE, "Context is released"));
                    RemoveConnection(connectId);
                    return;
                }
                auto innerErrorCode = context->ConnectAbility(want, connection);
                int32_t errCode = static_cast<int32_t>(AbilityRuntime::GetJsErrorCodeByNativeError(innerErrorCode));
                if (errCode != 0) {
                    connection->CallJsFailed(errCode);
                    RemoveConnection(connectId);
                }
                task.Resolve(engine, engine.CreateUndefined());
            };
        NativeValue* result = nullptr;
        AsyncTask::Schedule("JsAuthorizationExtensionContext::OnConnectAbility",
            engine, CreateAsyncTaskWithLastParam(engine, nullptr, nullptr, std::move(complete), &result));
        return engine.CreateNumber(connectId);
    }

    NativeValue *OnDisconnectAbility(NativeEngine &engine, NativeCallbackInfo &info)
    {
        if (info.argc < ARGC_ONE) {
            ACCOUNT_LOGE("Disconnect ability failed, not enough params.");
            ThrowTooFewParametersError(engine);
            return engine.CreateUndefined();
        }
        int64_t connectId = -1;
        if (!CheckOnDisconnectAbilityParam(engine, info, connectId)) {
            ACCOUNT_LOGE("CheckOnDisconnectAbilityParam falied");
            ThrowError(engine, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
            return engine.CreateUndefined();
        }

        AAFwk::Want want;
        sptr<JSAuthorizationExtensionConnection> connection = nullptr;
        FindConnection(engine, info, want, connection, connectId);
        // begin disconnect
        AsyncTask::CompleteCallback complete =
            [weak = context_, want, connection](
                NativeEngine& engine, AsyncTask& task, int32_t status) {
                auto context = weak.lock();
                if (!context) {
                    ACCOUNT_LOGW("context is released");
                    task.Reject(engine, CreateJsError(engine, ERROR_CODE_ONE, "Context is released"));
                    return;
                }
                if (connection == nullptr) {
                    ACCOUNT_LOGW("connection nullptr");
                    task.Reject(engine, CreateJsError(engine, ERROR_CODE_TWO, "not found connection"));
                    return;
                }
                auto innerErrorCode = context->DisconnectAbility(want, connection);
                if (innerErrorCode == 0) {
                    task.Resolve(engine, engine.CreateUndefined());
                } else {
                    task.Reject(engine, CreateJsErrorByNativeErr(engine, innerErrorCode));
                }
            };

        NativeValue *lastParam = (info.argc == ARGC_ONE) ? nullptr : info.argv[INDEX_ONE];
        NativeValue *result = nullptr;
        AsyncTask::Schedule("JsAuthorizationExtensionContext::OnDisconnectAbility", engine,
            CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }
};
} // namespace

NativeValue *CreateJsAuthorizationExtensionContext(
    NativeEngine &engine, std::shared_ptr<AuthorizationExtensionContext> context)
{
    if (context != nullptr) {
        auto abilityInfo = context->GetAbilityInfo();
    }
    NativeValue *objValue = CreateJsExtensionContext(engine, context);
    NativeObject *object = ConvertNativeValueTo<NativeObject>(objValue);

    std::unique_ptr<JsAuthorizationExtensionContext> jsContext =
        std::make_unique<JsAuthorizationExtensionContext>(context);
    object->SetNativePointer(jsContext.release(), JsAuthorizationExtensionContext::Finalizer, nullptr);

    // make handler
    g_handler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());

    const char *moduleName = "JsAuthorizationExtensionContext";
    BindNativeFunction(
        engine, *object, "connectServiceExtensionAbility", moduleName, JsAuthorizationExtensionContext::ConnectAbility);
    BindNativeFunction(engine, *object, "disconnectServiceExtensionAbility", moduleName,
        JsAuthorizationExtensionContext::DisconnectAbility);
    return objValue;
}

void JSAuthorizationExtensionConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    ACCOUNT_LOGI("OnAbilityConnectDone, resultCode:%{public}d", resultCode);
    if (g_handler == nullptr) {
        ACCOUNT_LOGI("g_handler nullptr");
        return;
    }
    wptr<JSAuthorizationExtensionConnection> connection = this;
    auto task = [connection, element, remoteObject, resultCode]() {
        sptr<JSAuthorizationExtensionConnection> connectionSptr = connection.promote();
        if (!connectionSptr) {
            ACCOUNT_LOGI("connectionSptr nullptr");
            return;
        }
        connectionSptr->HandleOnAbilityConnectDone(element, remoteObject, resultCode);
    };
    g_handler->PostTask(task, "OnAbilityConnectDone");
}

void JSAuthorizationExtensionConnection::HandleOnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    ACCOUNT_LOGI("HandleOnAbilityConnectDone, resultCode:%{public}d", resultCode);
    // wrap ElementName
    napi_value napiElementName = OHOS::AppExecFwk::WrapElementName(reinterpret_cast<napi_env>(&engine_), element);
    NativeValue *nativeElementName = reinterpret_cast<NativeValue *>(napiElementName);

    // wrap RemoteObject
    napi_value napiRemoteObject =
        NAPI_ohos_rpc_CreateJsRemoteObject(reinterpret_cast<napi_env>(&engine_), remoteObject);
    NativeValue *nativeRemoteObject = reinterpret_cast<NativeValue *>(napiRemoteObject);
    NativeValue *argv[] = {nativeElementName, nativeRemoteObject};
    if (jsConnectionObject_ == nullptr) {
        ACCOUNT_LOGE("jsConnectionObject_ nullptr");
        return;
    }
    NativeValue *value = jsConnectionObject_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        ACCOUNT_LOGE("Failed to get object");
        return;
    }
    NativeValue *methodOnConnect = obj->GetProperty("onConnect");
    if (methodOnConnect == nullptr) {
        ACCOUNT_LOGE("Failed to get onConnect from object");
        return;
    }
    engine_.CallFunction(value, methodOnConnect, argv, ARGC_TWO);
}

void JSAuthorizationExtensionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    if (g_handler == nullptr) {
        ACCOUNT_LOGI("g_handler nullptr");
        return;
    }
    wptr<JSAuthorizationExtensionConnection> connection = this;
    auto task = [connection, element, resultCode]() {
        sptr<JSAuthorizationExtensionConnection> connectionSptr = connection.promote();
        if (!connectionSptr) {
            ACCOUNT_LOGI("connectionSptr nullptr");
            return;
        }
        connectionSptr->HandleOnAbilityDisconnectDone(element, resultCode);
    };
    g_handler->PostTask(task, "OnAbilityDisconnectDone");
}

void JSAuthorizationExtensionConnection::HandleOnAbilityDisconnectDone(
    const AppExecFwk::ElementName &element, int resultCode)
{
    ACCOUNT_LOGI("HandleOnAbilityDisconnectDone, resultCode:%{public}d", resultCode);
    napi_value napiElementName = OHOS::AppExecFwk::WrapElementName(reinterpret_cast<napi_env>(&engine_), element);
    NativeValue *nativeElementName = reinterpret_cast<NativeValue *>(napiElementName);
    NativeValue *argv[] = {nativeElementName};
    if (jsConnectionObject_ == nullptr) {
        ACCOUNT_LOGE("jsConnectionObject_ nullptr");
        return;
    }
    NativeValue *value = jsConnectionObject_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        ACCOUNT_LOGE("Failed to get object");
        return;
    }

    NativeValue *method = obj->GetProperty("onDisconnect");
    if (method == nullptr) {
        ACCOUNT_LOGE("Failed to get onDisconnect from object");
        return;
    }

    // release connect
    ACCOUNT_LOGD("OnAbilityDisconnectDone g_connects.size:%{public}zu", g_connects.size());
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    auto item = std::find_if(
        g_connects.begin(), g_connects.end(), [bundleName, abilityName, connectionId = connectionId_](const auto &obj) {
            return (bundleName == obj.first.want.GetBundle()) &&
                   (abilityName == obj.first.want.GetElement().GetAbilityName()) && connectionId == obj.first.id;
        });
    if (item != g_connects.end()) {
        // match bundlename && abilityname
        g_connects.erase(item);
        ACCOUNT_LOGD("OnAbilityDisconnectDone erase g_connects.size:%{public}zu", g_connects.size());
    }
    engine_.CallFunction(value, method, argv, ARGC_ONE);
}

void JSAuthorizationExtensionConnection::CallJsFailed(int32_t errorCode)
{
    if (jsConnectionObject_ == nullptr) {
        ACCOUNT_LOGE("jsConnectionObject_ nullptr");
        return;
    }
    NativeValue *value = jsConnectionObject_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        ACCOUNT_LOGE("Failed to get object");
        return;
    }

    NativeValue *method = obj->GetProperty("onFailed");
    if (method == nullptr) {
        ACCOUNT_LOGE("Failed to get onFailed from object");
        return;
    }
    NativeValue *argv[] = {engine_.CreateNumber(errorCode)};
    engine_.CallFunction(value, method, argv, ARGC_ONE);
}

int64_t JSAuthorizationExtensionConnection::GetConnectionId()
{
    return connectionId_;
}

JSAuthorizationExtensionConnection::JSAuthorizationExtensionConnection(NativeEngine &engine) : engine_(engine)
{}

void JSAuthorizationExtensionConnection::SetConnectionId(int64_t id)
{
    connectionId_ = id;
}

void JSAuthorizationExtensionConnection::SetJsConnectionObject(NativeValue* jsConnectionObject)
{
    jsConnectionObject_ = std::unique_ptr<NativeReference>(engine_.CreateReference(jsConnectionObject, 1));
}

JSAuthorizationExtensionConnection::~JSAuthorizationExtensionConnection()
{
    if (jsConnectionObject_ == nullptr) {
        return;
    }

    uv_loop_t *loop = engine_.GetUVLoop();
    if (loop == nullptr) {
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }
    work->data = reinterpret_cast<void *>(jsConnectionObject_.release());
    int ret = uv_queue_work(
        loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            if (work == nullptr) {
                return;
            }
            if (work->data == nullptr) {
                delete work;
                work = nullptr;
                return;
            }
            delete reinterpret_cast<NativeReference *>(work->data);
            work->data = nullptr;
            delete work;
            work = nullptr;
        });
    if (ret != 0) {
        delete reinterpret_cast<NativeReference *>(work->data);
        work->data = nullptr;
        delete work;
        work = nullptr;
    }
}

void JSAuthorizationExtensionConnection::RemoveConnectionObject()
{
    jsConnectionObject_.reset();
}
} // namespace AbilityRuntime
} // namespace OHOS