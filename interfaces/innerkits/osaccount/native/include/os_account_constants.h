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
#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H

#include <string>
#include <sys/sysinfo.h>
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
namespace Constants {
const std::string PATH_SEPARATOR = "/";
#ifndef ACCOUNT_TEST
const std::string USER_INFO_BASE = "/data/service/el1/public/account";
#else
const std::string USER_INFO_BASE = "/data/service/el1/public/account/test";
#endif // ACCOUNT_TEST
const std::string SYSTEM_ETC_BASE = "/system/etc/account";
const std::string OSACCOUNT_CONSTRAINTS_JSON_PATH = SYSTEM_ETC_BASE + PATH_SEPARATOR + "osaccount_constraints.json";
const std::string CONSTRAINTS_LIST_JSON_PATH = SYSTEM_ETC_BASE + PATH_SEPARATOR + "constraints_list_collection.json";
const std::string ACCOUNT_LIST_FILE_JSON_PATH = USER_INFO_BASE + PATH_SEPARATOR + "account_list.json";
const std::string ACCOUNT_INDEX_JSON_PATH = USER_INFO_BASE + PATH_SEPARATOR + "account_index_info.json";
const std::string ACCOUNT_INFO_DIGEST_FILE_PATH = USER_INFO_BASE + PATH_SEPARATOR + "account_info_digest.json";
const std::string BASE_OSACCOUNT_CONSTRAINTS_JSON_PATH =
    USER_INFO_BASE + PATH_SEPARATOR + "base_os_account_constraints.json";
const std::string GLOBAL_OSACCOUNT_CONSTRAINTS_JSON_PATH =
    USER_INFO_BASE + PATH_SEPARATOR + "global_os_account_constraints.json";
const std::string SPECIFIC_OSACCOUNT_CONSTRAINTS_JSON_PATH =
    USER_INFO_BASE + PATH_SEPARATOR + "specific_os_account_constraints.json";
const char USER_PHOTO_FILE_PNG_NAME[] = "fase.png";
const char USER_PHOTO_FILE_JPG_NAME[] = "fase.jpg";
const char USER_PHOTO_FILE_TXT_NAME[] = "photo.txt";
const char USER_PHOTO_BASE_JPG_HEAD[] = "data:image/jpeg;base64,";
const char USER_PHOTO_BASE_PNG_HEAD[] = "data:image/png;base64,";
const char USER_INFO_FILE_NAME[] = "account_info.json";
const char OPERATION_ACTIVATE[] = "activate";
const char OPERATION_CREATE[] = "create";
const char OPERATION_DELETE[] = "delete";
const char OPERATION_SWITCH[] = "switch";
const char OPERATION_STOP[] = "stop";
const char OPERATION_START[] = "start";
const char OPERATION_UPDATE[] = "update";
const char OPERATION_UNLOCK[] = "unlock";

// distributed database
const char APP_ID[] = "os_account_mgr_service";
const bool SYNC_OS_ACCOUNT_DATABASE = false;
const std::uint32_t DEVICE_UUID_LENGTH = 65;

// uid judgment
const std::int32_t APP_UID_START = 2100;
const std::int32_t MAX_SYSTEM_UID_NUM = 2899;

// subscribe
const int SUBSCRIBER_MAX_SIZE = 100;
// account restrict
const unsigned int LOCAL_NAME_MAX_SIZE = sysconf(_SC_LOGIN_NAME_MAX);
const unsigned int LOCAL_PHOTO_MAX_SIZE = 1024 * 1024 * 10;
const uint32_t SHORT_NAME_MAX_SIZE = 255;

// domain info limits
const unsigned int DOMAIN_NAME_MAX_SIZE = 128;

// constraint limits
const unsigned int CONSTRAINT_MAX_SIZE = 128;

const std::int32_t ADMIN_LOCAL_ID = 0;
const int ADMIN_TYPE = -1;
const char ADMIN_LOCAL_NAME[] = "admin";
const char STANDARD_LOCAL_NAME[] = "user";
const std::int32_t START_USER_ID = 100;
const char START_USER_STRING_ID[] = "100";
const std::int32_t MAX_USER_ID = 1099;
const std::int32_t INVALID_OS_ACCOUNT_ID = -1;
const size_t MAX_USER_ID_LENGTH = 4;
const int64_t SERIAL_NUMBER_NUM_START_FOR_ADMIN = 20210231;
const int64_t SERIAL_NUMBER_NUM_START = 1;
const int64_t CARRY_NUM = 100000000;
const bool IS_SERIAL_NUMBER_FULL_INIT_VALUE = false;
const int64_t TIME_WAIT_TIME_OUT = 5;
const std::int32_t WAIT_ONE_TIME = 1000;
const uint64_t DEFAULT_DISPALY_ID = 0;
const uint64_t INVALID_DISPALY_ID = -1ull;

// type template
const char DEVICE_OWNER_ID[] = "deviceOwnerId";
const char ALL_GLOBAL_CONSTRAINTS[] = "allGlobalConstraints";
const char ALL_SPECIFIC_CONSTRAINTS[] = "allSpecificConstraints";
const char USER_CONSTRAINTS_TEMPLATE[] = "UserConstraintsTemplate";
const char TYPE_LIST[] = "TypeList";
const char ACCOUNT_LIST[] = "AccountList";
const char COUNT_ACCOUNT_NUM[] = "CountAccountNum";
const char MAX_ALLOW_CREATE_ACCOUNT_ID[] = "MaxAllowCreateAccountID";
const char SERIAL_NUMBER_NUM[] = "SerialNumber";
const char IS_MULTI_OS_ACCOUNT_ENABLE[] = "IsMultiOsAccountEnable";
const char IS_SERIAL_NUMBER_FULL[] = "isSerialNumberFull";
const char CONSTRAINTS_LIST[] = "constraints";
const char IS_ALLOWED_CREATE_ADMIN[] = "IsAllowedCreateAdmin";
const char LOCAL_NAME[] = "localName";
const char SHORT_NAME[] = "shortName";


// start type
const OS_ACCOUNT_SWITCH_MOD NOW_OS_ACCOUNT_SWITCH_MOD = OS_ACCOUNT_SWITCH_MOD::HOT_SWITCH;
};  // namespace Constants
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H
