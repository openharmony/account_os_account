/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <ctime>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <new>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include "os_account_manager.h"
#define private public
#include "os_account_control_file_manager.h"
#include "os_account_file_operator.h"
#include "account_file_watcher_manager.h"
#undef private
#include "mock_json_util.h"

namespace OHOS {
namespace AccountSA {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
const std::string TEST_FILE_PATH = "/data/service/el1/public/account/test";
OsAccountControlFileManager *g_controlManager = new (std::nothrow) OsAccountControlFileManager();
const std::string LOCAL_ID_STR = "300";
const std::string ADD_OBJ_METHOD_NAME = "AddObjToJson";
const std::string ADD_VECTOR_METHOD_NAME = "AddVectorStringToJson";
static CJsonUnique g_specificOAConstraintsJson = nullptr;
static CJsonUnique g_globalOAConstraintsJson = nullptr;
}  // namespace
class OsAccountControlFileManagerMockUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::string storeID_ = "os_account_info";
};

void OsAccountControlFileManagerMockUnitTest::SetUpTestCase(void)
{
    ASSERT_NE(g_controlManager, nullptr);
}

void OsAccountControlFileManagerMockUnitTest::TearDownTestCase(void)
{
    std::string cmd = "rm -rf " + TEST_FILE_PATH + "*";
    system(cmd.c_str());
}

void OsAccountControlFileManagerMockUnitTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    g_controlManager->Init();
    ASSERT_EQ(g_controlManager->GetSpecificOAConstraintsFromFile(g_specificOAConstraintsJson), ERR_OK);
    ASSERT_EQ(g_controlManager->GetGlobalOAConstraintsFromFile(g_globalOAConstraintsJson), ERR_OK);
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountControlFileManagerMockUnitTest::TearDown(void)
{
    ASSERT_EQ(g_controlManager->SaveSpecificOAConstraintsToFile(g_specificOAConstraintsJson), ERR_OK);
    ASSERT_EQ(g_controlManager->SaveGlobalOAConstraintsToFile(g_globalOAConstraintsJson), ERR_OK);
}

/**
 * @tc.name: UpdateBaseOAConstraints001
 * @tc.desc: Test SpecificConstraintsDataOperate  GlobalConstraintsDataOperate
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerMockUnitTest, UpdateBaseOAConstraints001, TestSize.Level1)
{
    std::vector<std::string> constraintStr = {
        "constraint.font.set",
        "constraint.print",
    };
    std::string stringJson = "{\"allSpecificConstraints\":[\"constraint.font.set\"],\"constraint.font.set\":[\"300\"]}";
    auto json = CreateJsonFromString(stringJson);
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    g_controlManager->SpecificConstraintsDataOperate("301", LOCAL_ID_STR, constraintStr, true, json.get());
    SetTimes(0, 0, ADD_VECTOR_METHOD_NAME);
    g_controlManager->SpecificConstraintsDataOperate("301", LOCAL_ID_STR, constraintStr, true, json.get());
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    g_controlManager->SpecificConstraintsDataOperate(LOCAL_ID_STR, LOCAL_ID_STR, constraintStr, true, json.get());
    SetTimes(0, 2, ADD_VECTOR_METHOD_NAME);
    g_controlManager->SpecificConstraintsDataOperate(LOCAL_ID_STR, LOCAL_ID_STR, constraintStr, true, json.get());
    stringJson = "{\"allGlobalConstraints\":[\"constraint.font.set\"],\"constraint.font.set\":[\"300\"]}";
    json = CreateJsonFromString(stringJson);
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    g_controlManager->GlobalConstraintsDataOperate("301", constraintStr, true, json);
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    g_controlManager->GlobalConstraintsDataOperate(LOCAL_ID_STR, constraintStr, true, json);
    SetTimes(0, 2, ADD_VECTOR_METHOD_NAME);
    g_controlManager->GlobalConstraintsDataOperate(LOCAL_ID_STR, constraintStr, true, json);
    constraintStr = {
        "constraint.font.set"
    };
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateBaseOAConstraints(LOCAL_ID_STR, constraintStr, true), ERR_OK);
    SetTimes(0, 0, ADD_VECTOR_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateBaseOAConstraints(LOCAL_ID_STR, constraintStr, true), ERR_OK);
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateBaseOAConstraints("100", constraintStr, false), ERR_OK);
    SetTimes(0, 0, ADD_VECTOR_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateBaseOAConstraints("100", constraintStr, false), ERR_OK);
}

/**
 * @tc.name: RemoveConstraintsFromJsonOperate001
 * @tc.desc: Test RemoveConstraintsFromJsonOperate
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerMockUnitTest, RemoveConstraintsFromJsonOperate001, TestSize.Level1)
{
    std::vector<std::string> constraintStr = {
        "constraint.font.set",
        "constraint.print",
    };
    std::string stringJson = "{\"allSpecificConstraints\":[\"constraint.font.set\"],\"constraint.font.set\":[\"300\"]}";
    auto json = CreateJsonFromString(stringJson);
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    g_controlManager->SpecificConstraintsDataOperate(LOCAL_ID_STR, LOCAL_ID_STR, constraintStr, false, json.get());
    RemoveConstraintInfo info = {
        .constraintTypeConstants = "allGlobalConstraints",
        .constraint = "constraint.font.set",
        .idStr = "301"
    };
    json = CreateJsonFromString("");
    std::vector<std::string> waitForErase;
    std::vector<std::string> oldConstraintsList;
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    EXPECT_EQ(g_controlManager->RemoveConstraintsFromJsonOperate(info, json.get(), waitForErase, oldConstraintsList),
        ERR_OK);
    stringJson = "{\"allGlobalConstraints\":[\"constraint.font.set\"],\"constraint.font.set\":[\"300\"]}";
    json = CreateJsonFromString(stringJson);
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    g_controlManager->GlobalConstraintsDataOperate(LOCAL_ID_STR, constraintStr, false, json);
    SetTimes(0, 1, ADD_VECTOR_METHOD_NAME);
    EXPECT_EQ(g_controlManager->RemoveConstraintsFromJsonOperate(info, json.get(), waitForErase, oldConstraintsList),
        ERR_OK);
}

/**
 * @tc.name: UpdateSpecificOAConstraints
 * @tc.desc: Test UpdateSpecificOAConstraints
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountControlFileManagerMockUnitTest, UpdateSpecificOAConstraints001, TestSize.Level1)
{
    std::vector<std::string> constraintStr = {
        "font.set",
        "print",
    };
    SetTimes(0, 1, ADD_OBJ_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateSpecificOAConstraints("302", "302", constraintStr, true), ERR_OK);
    SetTimes(0, 1, ADD_OBJ_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateSpecificOAConstraints("302", "302", constraintStr, false), ERR_OK);
    SetTimes(0, 2, ADD_OBJ_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateSpecificOAConstraints("302", "302", constraintStr, true), ERR_OK);
    SetTimes(0, 2, ADD_OBJ_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateSpecificOAConstraints("302", "302", constraintStr, false), ERR_OK);
    SetTimes(0, 3, ADD_OBJ_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateSpecificOAConstraints("302", "302", constraintStr, true), ERR_OK);
    SetTimes(0, 3, ADD_OBJ_METHOD_NAME);
    EXPECT_EQ(g_controlManager->UpdateSpecificOAConstraints("302", "302", constraintStr, false), ERR_OK);
}
}  // namespace AccountSA
}  // namespace OHOS