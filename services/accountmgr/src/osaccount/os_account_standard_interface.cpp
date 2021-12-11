/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return ERR_OK;}
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
#include "common_event_manager.h"
#include "common_event_support.h"
#include "image_packer.h"
#include "pixel_map.h"
#include "want.h"

#include "os_account_standard_interface.h"

namespace OHOS {
namespace AccountSA {
ErrCode OsAccountStandardInterface::SendToAMSAccountStart(std::vector<OsAccountInfo> osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToAMSAccountStart start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToAMSAccountStop(std::vector<OsAccountInfo> osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToAMSAccountStop start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToBMSAccountCreate(std::vector<OsAccountInfo> osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToBMSAccountCreate start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToBMSAccountDelete(std::vector<OsAccountInfo> osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToBMSAccountDelete start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToCESAccountCreate(std::vector<OsAccountInfo> osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountCreate start");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED);
    bool flag = true;
    for (auto it = osAccountInfo.begin(); it != osAccountInfo.end(); ++it) {
        OHOS::EventFwk::CommonEventData data;
        data.SetCode(it->GetId());
        data.SetWant(want);
        if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
            flag = false;
        }
    }
    if (!flag) {
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_CE_ACCOUNT_CREATE_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToCESAccountDelete(std::vector<OsAccountInfo> osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountDelete start");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    bool flag = true;
    for (auto it = osAccountInfo.begin(); it != osAccountInfo.end(); ++it) {
        OHOS::EventFwk::CommonEventData data;
        data.SetCode(it->GetId());
        data.SetWant(want);
        if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
            flag = false;
        }
    }
    if (!flag) {
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_CE_ACCOUNT_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToCESAccountStart(std::vector<OsAccountInfo> osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountStart start");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_STARTED);
    bool flag = true;
    for (auto it = osAccountInfo.begin(); it != osAccountInfo.end(); ++it) {
        OHOS::EventFwk::CommonEventData data;
        data.SetCode(it->GetId());
        data.SetWant(want);
        if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
            flag = false;
        }
    }
    if (!flag) {
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_CE_ACCOUNT_START_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToCESAccountStop(std::vector<OsAccountInfo> osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountStop start");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPED);
    bool flag = true;
    for (auto it = osAccountInfo.begin(); it != osAccountInfo.end(); ++it) {
        OHOS::EventFwk::CommonEventData data;
        data.SetCode(it->GetId());
        data.SetWant(want);
        if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
            flag = false;
        }
    }
    if (!flag) {
        return ERR_OS_ACCOUNT_SERVICE_INTERFACE_TO_CE_ACCOUNT_STOP_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SetPhotoByPathAndByte(
    const std::string &path, std::string &byte, const std::string &photoType)
{
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
