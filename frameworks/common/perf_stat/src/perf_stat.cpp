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

#include "perf_stat.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
PerfStat::PerfStat()
{}

PerfStat::~PerfStat()
{
    Reset();
}

/* Account Bind process statistic */
int64_t PerfStat::GetAccountBindStartTime() const
{
    return accountBindBegin_;
}

void PerfStat::SetAccountBindStartTime(int64_t time)
{
    accountBindBegin_ = (time > 0) ? time : 0;
}

int64_t PerfStat::GetAccountBindEndTime() const
{
    return accountBindEnd_;
}

void PerfStat::SetAccountBindEndTime(int64_t time)
{
    accountBindEnd_ = (time > 0 && time > accountBindBegin_) ? time : accountBindBegin_;
}

/* Account Add process statistic */
int64_t PerfStat::GetAccountAddStartTime() const
{
    return accountAddBegin_;
}

void PerfStat::SetAccountAddStartTime(int64_t time)
{
    accountAddBegin_ = (time > 0) ? time : 0;
}

int64_t PerfStat::GetAccountAddEndTime() const
{
    return accountAddEnd_;
}

void PerfStat::SetAccountAddEndTime(int64_t time)
{
    accountAddEnd_ = (time > 0 && time > accountAddBegin_) ? time : accountAddBegin_;
}

/* Account Delete process statistic */
int64_t PerfStat::GetAccountDelStartTime() const
{
    return accountDelBegin_;
}

void PerfStat::SetAccountDelStartTime(int64_t time)
{
    accountDelBegin_ = (time > 0) ? time : 0;
}

int64_t PerfStat::GetAccountDelEndTime() const
{
    return accountDelEnd_;
}

void PerfStat::SetAccountDelEndTime(int64_t time)
{
    accountDelEnd_ = (time > 0 && time > accountDelBegin_) ? time : accountDelBegin_;
}

/* Account Query process statistic */
int64_t PerfStat::GetAccountQueryStartTime() const
{
    return accountQueryBegin_;
}

void PerfStat::SetAccountQueryStartTime(int64_t time)
{
    accountQueryBegin_ = (time > 0) ? time : 0;
}

int64_t PerfStat::GetAccountQueryEndTime() const
{
    return accountQueryEnd_;
}

void PerfStat::SetAccountQueryEndTime(int64_t time)
{
    accountQueryEnd_ = (time > 0 && time > accountQueryBegin_) ? time : accountQueryBegin_;
}

/* Account Service process statistic */
void PerfStat::SetInstanceStartTime(int64_t time)
{
    serviceOnStart_ = time;
}

void PerfStat::SetInstanceStopTime(int64_t time)
{
    serviceOnStop_ = time;
}

void PerfStat::SetInstanceCreateTime(int64_t time)
{
    instanceCreate_ = time;
}

void PerfStat::SetInstanceInitTime(int64_t time)
{
    serviceInit_ = time;
}

/* Account state machine process statistic */
void PerfStat::SetAccountStateChangeTime(const std::string &stateStr, int64_t time)
{
    accountStateChangeRecords_[stateStr] = time;
}

/* Set/Get perf statistic enable state */
bool PerfStat::GetPerfStatEnabled() const
{
    return enableStat_;
}

void PerfStat::SetPerfStatEnabled(bool enable)
{
    enableStat_ = enable;
}

/* reset to default */
void PerfStat::Reset()
{
    accountBindBegin_ = 0;
    accountBindEnd_ = 0;

    accountAddBegin_ = 0;
    accountAddEnd_ = 0;

    accountDelBegin_ = 0;
    accountDelEnd_ = 0;

    accountQueryBegin_ = 0;
    accountQueryEnd_ = 0;

    instanceCreate_ = 0;
    serviceOnStart_ = 0;
    serviceOnStop_ = 0;
    serviceInit_ = 0;

    accountStateChangeRecords_.clear();

    enableStat_ = true;
}

void PerfStat::Dump(std::string& result) const
{
    if (!enableStat_) {
        ACCOUNT_LOGI("statistics disabled!");
        return;
    }

    if (instanceCreate_ > 0) {
        result.append("ServiceInstanceCreateTime: ").append(std::to_string(instanceCreate_)).append("\n");
    }

    if (serviceInit_ > 0) {
        result.append("ServiceInitTick: ").append(std::to_string(serviceInit_)).append("\n");
    }

    if (serviceOnStart_ > 0) {
        result.append("ServiceStartTick: ").append(std::to_string(serviceOnStart_)).append("\n");
    }

    if (serviceOnStop_ > 0) {
        result.append("ServiceStopTick: ").append(std::to_string(serviceOnStop_)).append("\n");
    }

    if (accountBindEnd_ > accountBindBegin_) {
        result.append("AccountBindTime: ")
            .append(std::to_string(accountBindEnd_ - accountBindBegin_))
            .append("\n");
    }

    if (accountAddEnd_ > accountAddBegin_) {
        result.append("AccountAddTime: ")
            .append(std::to_string(accountAddEnd_ - accountAddBegin_))
            .append("\n");
    }

    if (accountDelEnd_ > accountDelBegin_) {
        result.append("AccountDelTime: ")
            .append(std::to_string(accountDelEnd_ - accountDelBegin_))
            .append("\n");
    }

    if (accountQueryEnd_ > accountQueryBegin_) {
        result.append("AccountQueryTime: ")
            .append(std::to_string((accountQueryEnd_ - accountQueryBegin_)))
            .append("\n");
    }

    auto iter = accountStateChangeRecords_.begin();
    for (; iter != accountStateChangeRecords_.end(); iter++) {
        result.append(iter->first.c_str())
            .append(": ")
            .append(std::to_string(iter->second))
            .append(" Ticks\n");
    }
}
} // namespace AccountSA
} // namespace OHOS
