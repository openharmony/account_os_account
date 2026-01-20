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

#include <gtest/gtest.h>
#include "privileges_map.h"

using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::AccountSA;

class PrivilegesMapTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PrivilegesMapTest::SetUpTestCase() {}
void PrivilegesMapTest::TearDownTestCase() {}
void PrivilegesMapTest::SetUp() {}
void PrivilegesMapTest::TearDown() {}

/**
 * @tc.name: PrivilegesMapTest001
 * @tc.desc: Test TransferPrivilegeToCode with valid privileges.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegesMapTest, PrivilegesMapTest001, TestSize.Level1)
{
    uint32_t code = 0;
    bool ret = TransferPrivilegeToCode("test.privilege.one", code);
    EXPECT_TRUE(ret);
    EXPECT_EQ(code, 0U);

    ret = TransferPrivilegeToCode("test.privilege.two", code);
    EXPECT_TRUE(ret);
    EXPECT_EQ(code, 1U);
}

/**
 * @tc.name: PrivilegesMapTest002
 * @tc.desc: Test TransferPrivilegeToCode with invalid privileges.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegesMapTest, PrivilegesMapTest002, TestSize.Level1)
{
    uint32_t code = 0;
    bool ret = TransferPrivilegeToCode("invalid.privilege", code);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: PrivilegesMapTest003
 * @tc.desc: Test TransferCodeToPrivilege with valid and invalid codes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegesMapTest, PrivilegesMapTest003, TestSize.Level1)
{
    std::string privilege = TransferCodeToPrivilege(0);
    EXPECT_EQ(privilege, "test.privilege.one");

    privilege = TransferCodeToPrivilege(999);
    EXPECT_EQ(privilege, "");
}

/**
 * @tc.name: PrivilegesMapTest004
 * @tc.desc: Test IsDefinedPrivilege.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegesMapTest, PrivilegesMapTest004, TestSize.Level1)
{
    EXPECT_TRUE(IsDefinedPrivilege("test.privilege.one"));
    EXPECT_FALSE(IsDefinedPrivilege("nonexistent.privilege"));
}

/**
 * @tc.name: PrivilegesMapTest005
 * @tc.desc: Test GetPrivilegeBriefDef by name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegesMapTest, PrivilegesMapTest005, TestSize.Level1)
{
    PrivilegeBriefDef def;
    bool ret = GetPrivilegeBriefDef("test.privilege.one", def);
    EXPECT_TRUE(ret);
    EXPECT_STREQ(def.privilegeName, "test.privilege.one");
    EXPECT_EQ(def.timeout, 300U);
}

/**
 * @tc.name: PrivilegesMapTest006
 * @tc.desc: Test GetDefPrivilegesSize and GetPrivilegeDefVersion.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegesMapTest, PrivilegesMapTest006, TestSize.Level1)
{
    size_t size = GetDefPrivilegesSize();
    EXPECT_GT(size, 0U);

    const char* version = GetPrivilegeDefVersion();
    EXPECT_NE(version, nullptr);
    EXPECT_GT(strlen(version), 0U);
}

/**
 * @tc.name: PrivilegesMapTest007
 * @tc.desc: Test GetPrivilegeBriefDef by code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivilegesMapTest, PrivilegesMapTest007, TestSize.Level1)
{
    PrivilegeBriefDef def;
    // Test valid code
    bool ret = GetPrivilegeBriefDef(0, def);
    EXPECT_TRUE(ret);
    EXPECT_STREQ(def.privilegeName, "test.privilege.one");
    EXPECT_EQ(def.timeout, 300U);

    // Test invalid code
    ret = GetPrivilegeBriefDef(9999, def);
    EXPECT_FALSE(ret);
}
