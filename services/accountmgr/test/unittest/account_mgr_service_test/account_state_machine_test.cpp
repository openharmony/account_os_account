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

#include "account_state_machine.h"

using namespace testing::ext;
using namespace OHOS::AccountSA;

class AccountStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountStateMachineTest::SetUpTestCase() {}

void AccountStateMachineTest::TearDownTestCase() {}

void AccountStateMachineTest::SetUp() {}

void AccountStateMachineTest::TearDown() {}

/**
 * @tc.name: AccountStateMachineTestInitState001
 * @tc.desc: Account state machine initial state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestInitState001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestUnbound2LoginState002
 * @tc.desc: Account state machine transform unbound state to login state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestUnbound2LoginState002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestUnboundBindAccountFailed003
 * @tc.desc: Account state machine keep the last state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestUnboundBindAccountFailed003, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_FAILED_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_FAILED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineUnboundInputUntreatedEvent004
 * @tc.desc: Account state machine keep the last state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineUnboundInputUntreatedEvent004, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_PASSWORD_CHANGED_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_PASSWORD_CHANGED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLoginTokenExpired005
 * @tc.desc: Account state machine transform login state to logout state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLoginTokenExpired005, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_TOKEN_EXPIRED_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_TOKEN_EXPIRED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLoginPasswordChanged006
 * @tc.desc: Account state machine transform login state to logout state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLoginPasswordChanged006, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_PASSWORD_CHANGED_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_PASSWORD_CHANGED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestManualLogout007
 * @tc.desc: Account state machine transform login state to logout state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestManualLogout007, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOUT_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOUT_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLoginManualUnbound008
 * @tc.desc: Account state machine transform login state to unbound state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLoginManualUnbound008, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_UNBOUND_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_UNBOUND_EVT));
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLoginInputUntreatedEvent009
 * @tc.desc: Account state machine keep the last state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLoginInputUntreatedEvent009, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_BIND_FAILED_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_FAILED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLogoutAuthenticateSuccess010
 * @tc.desc: Account state machine transform logout state to login state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLogoutAuthenticateSuccess010, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOUT_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOUT_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step4. Input the event ACCOUNT_AUTHENTICATE_SUCCESS_EVT
     * @tc.expected: step4. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_AUTHENTICATE_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLogoutAuthenticateFailed011
 * @tc.desc: Account state machine keep the last state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLogoutAuthenticateFailed011, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOUT_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOUT_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step4. Input the event ACCOUNT_AUTHENTICATE_FAILED_EVT
     * @tc.expected: step4. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_AUTHENTICATE_FAILED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLogoutInputUntreatedEvent012
 * @tc.desc: Account state machine keep the last state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLogoutInputUntreatedEvent012, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOUT_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOUT_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step4. Input the event ACCOUNT_AUTHENTICATE_FAILED_EVT
     * @tc.expected: step4. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_AUTHENTICATE_FAILED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_BIND_FAILED_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_FAILED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLogoutManualUnbound013
 * @tc.desc: Account state machine transform logout state to unbound state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLogoutManualUnbound013, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOUT_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOUT_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step4. Input the event ACCOUNT_MANUAL_UNBOUND_EVT
     * @tc.expected: step4. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_UNBOUND_EVT));
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLoginManualLogoff014
 * @tc.desc: Account state machine transform login state to logoff state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLoginManualLogoff014, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOFF_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_LOGOFF
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOFF_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLogoutManualLogoff015
 * @tc.desc: Account state machine transform logout state to logoff state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLogoutManualLogoff015, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOUT_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOUT_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step4. Input the event ACCOUNT_MANUAL_LOGOFF_EVT
     * @tc.expected: step4. The current state is AccountStateMachine::ACCOUNT_STATE_LOGOFF
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOFF_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLogoutBindSuccess016
 * @tc.desc: Account state machine transform logout state to login state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLogoutBindSuccess016, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOUT_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_NOTLOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOUT_EVT));
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step4. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step4. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLogoffBindSuccess017
 * @tc.desc: Account state machine transform logoff state to login state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLogoffBindSuccess017, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOFF_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_LOGOFF
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOFF_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, stateMachine.GetAccountState());

    /**
     * @tc.steps: step4. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step4. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());
}

/**
 * @tc.name: AccountStateMachineTestLogoffInputUntreatedEvent018
 * @tc.desc: Account state machine keep the last state
 * @tc.type: FUNC
 * @tc.require: SR000GGV12
 */
HWTEST_F(AccountStateMachineTest, AccountStateMachineTestLogoffInputUntreatedEvent018, TestSize.Level0)
{
    /**
     * @tc.steps: step1. AccountStateMachine init
     * @tc.expected: step1. The current state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    AccountStateMachine stateMachine;
    EXPECT_EQ(ACCOUNT_STATE_UNBOUND, stateMachine.GetAccountState());

    /**
     * @tc.steps: step2. Input the event ACCOUNT_BIND_SUCCESS_EVT
     * @tc.expected: step2. The current state is AccountStateMachine::ACCOUNT_STATE_LOGIN
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_SUCCESS_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGIN, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_MANUAL_LOGOFF_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_LOGOFF
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_MANUAL_LOGOFF_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, stateMachine.GetAccountState());

    /**
     * @tc.steps: step4. Input the event ACCOUNT_AUTHENTICATE_FAILED_EVT
     * @tc.expected: step4. The current state is AccountStateMachine::ACCOUNT_STATE_LOGOFF
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_AUTHENTICATE_FAILED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, stateMachine.GetAccountState());

    /**
     * @tc.steps: step3. Input the event ACCOUNT_BIND_FAILED_EVT
     * @tc.expected: step3. The current state is AccountStateMachine::ACCOUNT_STATE_LOGOFF
     */
    EXPECT_EQ(true, stateMachine.StateChangeProcess(ACCOUNT_BIND_FAILED_EVT));
    EXPECT_EQ(ACCOUNT_STATE_LOGOFF, stateMachine.GetAccountState());
}
