/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef OS_ACCOUNT_SUBSPACE_COVERAGE_TEST_COMMON_H
#define OS_ACCOUNT_SUBSPACE_COVERAGE_TEST_COMMON_H

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <set>
#include <string>
#include <cstdlib>

#define private public
#define protected public
#include "account_mgr_service.h"
#include "iinner_os_account_manager.h"
#include "ohos_account_manager.h"
#include "os_account_info.h"
#include "os_account_subprofile_client.h"
#include "os_account_subspace_data_deal.h"
#include "os_account_subspace_manager.h"
#include "os_account_subspace_manager_service.h"
#include "os_account_subspace_result.h"
#include "os_account_sub_profile_stub.h"
#include "ohos_account_kits_impl.h"
#undef private
#undef protected

#include "account_file_operator.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "mock_account_mgr_service.h"
#include "mock/mock_space_dependencies.h"
#include "os_account_constants.h"
#include "os_account_control_file_manager.h"
#include "os_account_info_json_parser.h"
#include "token_setproc.h"

namespace {
const std::string TEST_ROOT_DIR = "/data/test/os_account_subspace_coverage_test_dir/";
constexpr int32_t TEST_OS_ACCOUNT_ID = 100;
constexpr int32_t TEST_SUBSPACE_BASE =
    TEST_OS_ACCOUNT_ID * OHOS::AccountSA::Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
} // namespace

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#endif // OS_ACCOUNT_SUBSPACE_COVERAGE_TEST_COMMON_H
