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
#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H

#include <string>
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
namespace Constants {
const std::string PATH_SEPARATOR = "/";
const std::string USER_INFO_BASE = "/data/system/users";
const std::string SYSTEM_ETC_BASE = "/system/etc/account";
const std::string OSACCOUNT_CONSTRAINTS_JSON_PATH = SYSTEM_ETC_BASE + PATH_SEPARATOR + "osaccount_constraints.json";
const std::string CONSTRAINTS_LIST_JSON_PATH = SYSTEM_ETC_BASE + PATH_SEPARATOR + "constraints_list_collection.json";
const std::string ACCOUNT_LIST_FILE_JSON_PATH = USER_INFO_BASE + PATH_SEPARATOR + "account_list.json";
const std::string USER_PHOTO_FILE_PNG_NAME = "fase.png";
const std::string USER_PHOTO_FILE_JPG_NAME = "fase.jpg";
const std::string USER_PHOTO_BASE_JPG_HEAD = "data:image/jpeg;base64,";
const std::string USER_PHOTO_BASE_PNG_HEAD = "data:image/png;base64,";
const std::string USER_INFO_FILE_NAME = "account_info.json";

// distributed database
const std::string APP_ID = "os_account_mgr_service";
const bool SYNC_OS_ACCOUNT_DATABSE = true;
const std::uint32_t DEVICE_UUID_LENGTH = 65;

// uid judgment
const std::int32_t APP_UID_START = 2100;
const std::int32_t MAX_SYSTEM_UID_NUM = 2899;

// subscribe
const int SUBSCRIBER_MAX_SIZE = 100;
// account restrict
const unsigned int LOCAL_NAME_MAX_SIZE = 1024;
const unsigned int LOCAL_PHOTO_MAX_SIZE = 1024 * 4;

// domain info limits
const unsigned int DOMAIN_NAME_MAX_SIZE = 128;
const unsigned int DOMAIN_ACCOUNT_NAME_MAX_SIZE = 512;

const int ADMIN_LOCAL_ID = 0;
const int ADMIN_TYPE = -1;
const std::string ADMIN_LOCAL_NAME = "admin";
const std::string STANDARD_LOCAL_NAME = "user";
const std::int32_t START_USER_ID = 100;
const std::int32_t MAX_USER_ID = 1099;
const std::int32_t INVALID_OS_ACCOUNT_ID = -1;
const size_t MAX_USER_ID_LENGTH = 4;
const int64_t SERIAL_NUMBER_NUM_START_FOR_ADMIN = 20210231;
const int64_t SERIAL_NUMBER_NUM_START = 1;
const int64_t CARRY_NUM = 100000000;
const bool IS_SERIAL_NUMBER_FULL_INIT_VALUE = false;
const int64_t TIME_WAIT_TIME_OUT = 5;
const std::int32_t WAIT_ONE_TIME = 1000;

// type temeplate
const std::string USER_CONSTRATINTS_TEMPLATE = "UserConstraintsTemplate";
const std::string TYPE_LIST = "TypeList";
const std::string ACCOUNT_LIST = "AccountList";
const std::string COUNT_ACCOUNT_NUM = "CountAccountNum";
const std::string MAX_ALLOW_CREATE_ACCOUNT_ID = "MaxAllowCreateAccountID";
const std::string SERIAL_NUMBER_NUM = "SerialNumber";
const std::string IS_MULTI_OS_ACCOUNT_ENABLE = "IsMultiOsAccountEnable";
const std::string IS_SERIAL_NUMBER_FULL = "isSerialNumberFull";
const std::string CONSTANS_LITE = "constraints";
const std::string IS_ALLOWED_CREATE_ADMIN = "IsAllowedCreateAdmin";

// start type
const OS_ACCOUNT_SWITCH_MOD NOW_OS_ACCOUNT_SWITCH_MOD = OS_ACCOUNT_SWITCH_MOD::HOT_SWITCH;
};  // namespace Constants
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H
