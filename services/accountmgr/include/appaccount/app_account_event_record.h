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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_RECORD_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_RECORD_H

#include "app_account_info.h"
#include "app_account_subscribe_info.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
struct AppAccountSubscribeRecord {
    std::shared_ptr<AppAccountSubscribeInfo> subscribeInfoPtr;
    sptr<IRemoteObject> eventListener;
    std::string bundleName;
    uint32_t appIndex;

    AppAccountSubscribeRecord() : subscribeInfoPtr(nullptr), eventListener(nullptr), appIndex(0)
    {}
};

using AppAccountSubscribeRecordPtr = std::shared_ptr<AppAccountSubscribeRecord>;

struct AppAccountEventRecord {
    std::shared_ptr<AppAccountInfo> info;
    std::vector<AppAccountSubscribeRecordPtr> receivers;

    uid_t uid;
    std::string bundleName;
    uint32_t appIndex;

    AppAccountEventRecord() : info(nullptr), uid(0), appIndex(0)
    {}
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_RECORD_H
