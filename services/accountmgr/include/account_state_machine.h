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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STATE_MACHINE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STATE_MACHINE_H

#include <iostream>
#include <map>
#include "account_state_action.h"
#include "account_info.h"

namespace OHOS {
namespace AccountSA {
/**
 * Account state machine
 */
class AccountStateMachine {
public:

    /**
     * exception event action, to re-init state machine, and get account state from account server.
     */
    class ExceptionAction : public AccountStateAction {
    public:
        /**
         * exception event action Constructor.
         */
        explicit ExceptionAction(int status) : AccountStateAction(status) {}

        /**
          * exception event action Destructor.
          */
        ~ExceptionAction() {}
    };

    /**
     * unbound state action.
     */
    class UnboundAction : public AccountStateAction {
    public:
        /**
         * unbound state action Constructor.
         */
        explicit UnboundAction(int status) : AccountStateAction(status) {}

        /**
          * unbound state action Destructor.
          */
        ~UnboundAction() {}
    };

    /**
     * login state action.
     */
    class LoginAction : public AccountStateAction {
    public:
        /**
         * login state action Constructor.
         */
        explicit LoginAction(int status) : AccountStateAction(status) {}

        /**
          * login state action Destructor.
          */
        ~LoginAction() {}
    };

    /**
     * logout state action.
     */
    class LogoutAction : public AccountStateAction {
    public:
        /**
         * logout state action Constructor.
         */
        explicit LogoutAction(int status) : AccountStateAction(status) {}

        /**
          * logout state action Destructor.
          */
        ~LogoutAction() {}
    };

    /**
     * logoff state action.
     */
    class LogoffAction : public AccountStateAction {
    public:
        /**
         * logoff state action Constructor.
         */
        explicit LogoffAction(int status) : AccountStateAction(status) {}

        /**
          * logoff state action Destructor.
          */
        ~LogoffAction() {}
    };

    /**
      * Account state machine Constructor.
      */
    AccountStateMachine() : currentState_(ACCOUNT_STATE_UNBOUND)
    {
        OnInitialize();
    }

    /**
      * Account state machine Destructor.
      */
    ~AccountStateMachine()
    {
        Clean();
    }

    /**
      * Account state machine initialize.
      */
    void OnInitialize();

    /**
      * Account state machine clean.
      */
    void Clean();

    /**
     * Get account current state
     *
     * @return account current state
     */
    int GetAccountState()
    {
        return currentState_;
    }

    /**
     * Set account current state
     *
     * @param current state
     */
    void SetAccountState(int currentState)
    {
        currentState_ = currentState;
    }

    /**
     * Process an state change event.
     *
     * @param evt the event info
     * @return true if the processing was completed, otherwise false
     */
    bool StateChangeProcess(int evt);

private:
     /**
      * Account current state.
      */
    int currentState_;
    std::map<int, std::map<int, AccountStateAction *>> stateMachineMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_STATE_MACHINE_H
