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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IOS_ACCOUNT_SUBSCRIBE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IOS_ACCOUNT_SUBSCRIBE_H

#include "account_error_no.h"
#include "os_account_subscribe_info.h"
#include "iremote_object.h"
#include "event_handler.h"

namespace OHOS {
namespace AccountSA {
struct OsSubscribeRecord {
    std::shared_ptr<OsAccountSubscribeInfo> subscribeInfoPtr_;
    sptr<IRemoteObject> eventListener_;

    OsSubscribeRecord() : subscribeInfoPtr_(nullptr), eventListener_(nullptr)
    {}
    OsSubscribeRecord(std::shared_ptr<OsAccountSubscribeInfo> subscribeInfoPtr, sptr<IRemoteObject> eventListener)
        : subscribeInfoPtr_(subscribeInfoPtr), eventListener_(eventListener)
    {}
};

using OsSubscribeRecordPtr = std::shared_ptr<OsSubscribeRecord>;

class IOsAccountSubscribe {
public:
    virtual ErrCode SubscribeOsAccount(
        const std::shared_ptr<OsAccountSubscribeInfo> &subscribeInfoPtr, const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode GetEventHandler(void) = 0;
    virtual ErrCode PublishActivatedOsAccount(const int id) = 0;
    virtual ErrCode PublishActivatingOsAccount(const int id) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IOS_ACCOUNT_SUBSCRIBE_H
