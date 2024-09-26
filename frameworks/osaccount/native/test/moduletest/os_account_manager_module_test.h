/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_MANAGER_MODULETEST_TEST_H
#define OS_ACCOUNT_MANAGER_MODULETEST_TEST_H

#include <cerrno>
#include <filesystem>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "os_account_constants.h"
#include "parameter.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_TEST_NAME_TWO = "test_account_name_2";
const std::uint32_t INVALID_TOKEN_ID = 0;

const std::int32_t ERROR_LOCAL_ID = -1;
const std::int32_t LOCAL_ID = 105;
const std::int64_t INVALID_SERIAL_NUM = 123;
const std::int32_t WAIT_A_MOMENT = 3000;
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::int32_t INVALID_ID = 200;
const std::uint32_t MAX_WAIT_FOR_READY_CNT = 10;
const std::int32_t DEFAULT_API_VERSION = 8;

const std::vector<std::string> CONSTANTS_VECTOR {
    "constraint.print",
    "constraint.screen.timeout.set",
    "constraint.share.into.profile"
};

const std::vector<std::string> CONSTANTS_VECTOR_TEST {
    "constraint.private.dns.set",
};

const std::vector<std::string> PERMISSION_LIST {
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION"
};

const std::string CONSTRAINT_PRIVATE_DNS_SET = "constraint.private.dns.set";
const std::string CONSTANT_WIFI = "constraint.wifi";

const std::string CONSTANT_PRINT = "constraint.print";
const std::string STRING_NAME_OUT_OF_RANGE(1200, '1');  // length 1200
const std::string STRING_PHOTO_OUT_OF_RANGE(1024 * 1024 + 1, '1');  // length 1024*1024*10+1
const std::string STRING_PHOTO_MAX(1024 * 1024, '1');  // length 1024*1024*10+1
const std::string PHOTO_IMG =
    "data:image/"
    "png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AAA"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KMWsPdN7h/"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZRrbja3tDG/"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKdDXUU+"
    "faFUxpblhxYRNRzmd6FNnS0H3/X/VH6j0IIIRxMLJ5k/j/2L/"
    "zchW8pKj7iFAA0R2wajl5d46idlR3+GtPV2XOvQ3bBNvyFs8U39v9PLX0Bp0CN+yY0OAEAAAAASUVORK5CYII=";
const std::string PHOTO_IMG_ERROR =
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AAA"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KMWsPdN7h/"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZRrbja3tDG/"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKdDXUU+"
    "faFUxpblhxYRNRzmd6FNnS0H3/X/VH6j0IIIRxMLJ5k/j/2L/"
    "zchW8pKj7iFAA0R2wajl5d46idlR3+GtPV2XOvQ3bBNvyFs8U39v9PLX0Bp0CN+yY0OAEAAAAASUVORK5CYII=";
const std::string STRING_DOMAIN_NAME_OUT_OF_RANGE(200, '1');  // length 200
const std::string STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE(600, '1');  // length 600
const std::string STRING_DOMAIN_VALID = "TestDomainMT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameMT";
const std::string TEST_ACCOUNT_NAME = "TestAccountNameOS";
const std::string TEST_ACCOUNT_UID = "123456789os";
const std::string TEST_EXPECTED_UID = "4E7FA9CA2E8760692F2ADBA7AE59B37E02E650670E5FA5F3D01232DCD52D3893";

#endif // OS_ACCOUNT_MANAGER_MODULETEST_TEST_H