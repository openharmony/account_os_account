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
#include <gtest/gtest.h>
#include "../../resource/fuzzTest/include/fuzz_test_manager.h"

using namespace testing::ext;
namespace OHOS {
namespace AccountSA {
class ActsAccountFuzzTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ActsAccountFuzzTest::SetUpTestCase()
{}

void ActsAccountFuzzTest::TearDownTestCase()
{}

void ActsAccountFuzzTest::SetUp()
{}

void ActsAccountFuzzTest::TearDown()
{}

HWTEST_F(ActsAccountFuzzTest, ACTS_FuzzTest_0100, Function | MediumTest | Level1)
{
    std::cout << "fuzztest start" << std::endl;
    FuzzTestManager::GetInstance()->StartFuzzTest();
    std::cout << "fuzztest end" << std::endl;
}
}  // namespace AccountSA
}  // namespace OHOS