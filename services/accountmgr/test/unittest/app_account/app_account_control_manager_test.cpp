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

#include <gtest/gtest.h>

using namespace testing::ext;

class AppAccountControlManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountControlManagerTest::SetUpTestCase(void)
{}

void AppAccountControlManagerTest::TearDownTestCase(void)
{}

void AppAccountControlManagerTest::SetUp(void)
{}

void AppAccountControlManagerTest::TearDown(void)
{}

/**
 * @tc.number: AppAccountControlManager_OnPackageRemoved_0100
 * @tc.name: OnPackageRemoved
 * @tc.desc: On package removed with valid data.
 */
HWTEST_F(AppAccountControlManagerTest, AppAccountControlManager_OnPackageRemoved_0100, Function | MediumTest | Level1)
{}
