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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAPP_ACCOUNT_SUBSCRIBE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAPP_ACCOUNT_SUBSCRIBE_H

#include "account_error_no.h"
#include "app_account_data_storage.h"
#include "app_account_event_record.h"
#include "bundle_constants.h"
#include "event_handler.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
class IAppAccountSubscribe {
public:
    using EventHandler = OHOS::AppExecFwk::EventHandler;
    using EventRunner = OHOS::AppExecFwk::EventRunner;
    using Callback = OHOS::AppExecFwk::InnerEvent::Callback;

    virtual ErrCode SubscribeAppAccount(const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr,
        const sptr<IRemoteObject> &eventListener, const std::string &bundleName) = 0;
    virtual ErrCode UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener) = 0;

    virtual bool PublishAccount(AppAccountInfo &appAccountInfo, const std::string &bundleName) = 0;
    virtual ErrCode OnAccountsChanged(const std::shared_ptr<AppAccountEventRecord> &record) = 0;

private:
    virtual std::shared_ptr<AppAccountDataStorage> GetDataStorage(
        const bool &autoSync = false, const int32_t uid = AppExecFwk::Constants::INVALID_UID) = 0;
    virtual ErrCode GetStoreId(std::string &storeId, int32_t uid = AppExecFwk::Constants::INVALID_UID) = 0;
    virtual ErrCode GetEventHandler(void) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IAPP_ACCOUNT_SUBSCRIBE_H
