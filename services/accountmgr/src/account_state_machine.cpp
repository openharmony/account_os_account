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

#include "account_state_machine.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "datetime_ex.h"
#include "perf_stat.h"

namespace OHOS {
namespace AccountSA {
/**
 * Account state machine initialize.
 */
void AccountStateMachine::OnInitialize()
{
    stateMachineMap_ = {
        // ACCOUNT_STATE_UNBOUND state
        std::make_pair(ACCOUNT_STATE_UNBOUND, std::map<int, AccountStateAction *> {
            // normal event, transform to login state
            std::make_pair(ACCOUNT_BIND_SUCCESS_EVT, new (std::nothrow) LoginAction(ACCOUNT_STATE_LOGIN)),
            // normal event, keep in unbound state
            std::make_pair(ACCOUNT_BIND_FAILED_EVT, new (std::nothrow) ExceptionAction(ACCOUNT_STATE_UNBOUND)),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_AUTHENTICATE_SUCCESS_EVT, new (std::nothrow) LoginAction(ACCOUNT_STATE_LOGIN)),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_AUTHENTICATE_FAILED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_TOKEN_EXPIRED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_PASSWORD_CHANGED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_MANUAL_LOGOUT_EVT, nullptr),
            // unexpected event, keep in unbound state
            std::make_pair(ACCOUNT_MANUAL_UNBOUND_EVT, nullptr),
            // unexpected event, keep in unbound state
            std::make_pair(ACCOUNT_MANUAL_LOGOFF_EVT, nullptr)}
        ),
        // ACCOUNT_STATE_LOGIN state
        std::make_pair(ACCOUNT_STATE_LOGIN, std::map<int, AccountStateAction *> {
            // expected event, keep in login state
            std::make_pair(ACCOUNT_BIND_SUCCESS_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_BIND_FAILED_EVT, new (std::nothrow) ExceptionAction(ACCOUNT_STATE_LOGIN)),
            // normal event, keep in login state
            std::make_pair(ACCOUNT_AUTHENTICATE_SUCCESS_EVT, nullptr),
            // normal event, transform to logout state
            std::make_pair(ACCOUNT_AUTHENTICATE_FAILED_EVT, nullptr),
            // expected event, transform to logout state
            std::make_pair(ACCOUNT_TOKEN_EXPIRED_EVT, new (std::nothrow) LogoutAction(ACCOUNT_STATE_NOTLOGIN)),
            // expected event, transform to logout state
            std::make_pair(ACCOUNT_PASSWORD_CHANGED_EVT, new (std::nothrow) LogoutAction(ACCOUNT_STATE_NOTLOGIN)),
            // expected event, transform to logout state
            std::make_pair(ACCOUNT_MANUAL_LOGOUT_EVT, new (std::nothrow) LogoutAction(ACCOUNT_STATE_NOTLOGIN)),
            // expected event, transform to unbound state
            std::make_pair(ACCOUNT_MANUAL_UNBOUND_EVT, new (std::nothrow) UnboundAction(ACCOUNT_STATE_UNBOUND)),
            // expected event, transform to logoff state
            std::make_pair(ACCOUNT_MANUAL_LOGOFF_EVT, new (std::nothrow) LogoffAction(ACCOUNT_STATE_LOGOFF))}
        ),
        // ACCOUNT_STATE_NOTLOGIN state
        std::make_pair(ACCOUNT_STATE_NOTLOGIN, std::map<int, AccountStateAction *> {
            // normal event, transform to login state
            std::make_pair(ACCOUNT_BIND_SUCCESS_EVT, new (std::nothrow) LoginAction(ACCOUNT_STATE_LOGIN)),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_BIND_FAILED_EVT, new (std::nothrow) ExceptionAction(ACCOUNT_STATE_NOTLOGIN)),
            // expected event, transform to login state
            std::make_pair(ACCOUNT_AUTHENTICATE_SUCCESS_EVT, new (std::nothrow) LoginAction(ACCOUNT_STATE_LOGIN)),
            // expected event, keep in logout state
            std::make_pair(ACCOUNT_AUTHENTICATE_FAILED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_TOKEN_EXPIRED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_PASSWORD_CHANGED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_MANUAL_LOGOUT_EVT, nullptr),
            // expected event, transform to unbound state
            std::make_pair(ACCOUNT_MANUAL_UNBOUND_EVT, new (std::nothrow) UnboundAction(ACCOUNT_STATE_UNBOUND)),
            // expected event, transform to logoff state
            std::make_pair(ACCOUNT_MANUAL_LOGOFF_EVT, new (std::nothrow) LogoffAction(ACCOUNT_STATE_LOGOFF))}
        ),
        // ACCOUNT_STATE_LOGOFF state
        std::make_pair(ACCOUNT_STATE_LOGOFF, std::map<int, AccountStateAction *> {
            // normal event, transform to login state
            std::make_pair(ACCOUNT_BIND_SUCCESS_EVT, new (std::nothrow) LoginAction(ACCOUNT_STATE_LOGIN)),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_BIND_FAILED_EVT, new (std::nothrow) ExceptionAction(ACCOUNT_STATE_LOGOFF)),
            // expected event, transform to login state
            std::make_pair(ACCOUNT_AUTHENTICATE_SUCCESS_EVT, nullptr),
            // expected event, keep in logoff state
            std::make_pair(ACCOUNT_AUTHENTICATE_FAILED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_TOKEN_EXPIRED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_PASSWORD_CHANGED_EVT, nullptr),
            // unexpected event, re-initial state machine, check the state from account server
            std::make_pair(ACCOUNT_MANUAL_LOGOUT_EVT, nullptr),
            // expected event, transform to logoff state
            std::make_pair(ACCOUNT_MANUAL_UNBOUND_EVT, nullptr),
            // expected event, transform to logoff state
            std::make_pair(ACCOUNT_MANUAL_LOGOFF_EVT, nullptr)}
        )
    };
}

/**
 * Account state machine clean.
 */
void AccountStateMachine::Clean()
{
    for (auto &currentStateIter : stateMachineMap_) {
        for (auto &eventIter : currentStateIter.second) {
            if (eventIter.second != nullptr) {
                delete eventIter.second;
                eventIter.second = nullptr;
            }
        }
    }
}

/**
 * Process a state change event
 *
 * @param evt the event info
 * @return true if the processing was completed, otherwise false
 */
bool AccountStateMachine::StateChangeProcess(int evt)
{
    // for performance record
    std::string stateRecordStr;
    int64_t processTicks = GetTickCount();
    stateRecordStr.append("state from[").append(std::to_string(currentState_)).append("] to [");

    // get all the current state event action
    auto stateIter = stateMachineMap_.find(currentState_);
    if (stateIter == stateMachineMap_.end()) {
        ACCOUNT_LOGE("current state %{public}d is not in state machine map.", currentState_);
        return false;
    }

    // get the current event action
    auto eventIter = stateIter->second.find(evt);
    if (eventIter == stateIter->second.end()) {
        ACCOUNT_LOGE("event %{public}d is not in state machine map.", evt);
        return false;
    }

    // maybe action is null
    if (eventIter->second == nullptr) {
        ACCOUNT_LOGI("event %{public}d has no action.", evt);
        return true;
    }

    int nextState = eventIter->second->GetNextState();
    if (currentState_ != nextState) {
        ACCOUNT_LOGI("account state change, (oldstate, newstate) = (%{public}d, %{public}d)", currentState_, nextState);
        currentState_ = nextState;
    }

    // Record state change performance
    processTicks = GetTickCount() - processTicks;
    stateRecordStr.append(std::to_string(nextState)).append("], event[").append(std::to_string(evt)).append("] Cost");
    PerfStat::GetInstance().SetAccountStateChangeTime(stateRecordStr, processTicks);

    return true;
}
} // namespace AccountSA
} // namespace OHOS
