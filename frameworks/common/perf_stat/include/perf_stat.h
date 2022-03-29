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

#ifndef OS_ACCOUNT_FRAMEWORKS_COMMON_PERF_STAT_INCLUDE_PERF_STAT_H
#define OS_ACCOUNT_FRAMEWORKS_COMMON_PERF_STAT_INCLUDE_PERF_STAT_H

#include <cstdint>
#include <map>
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class PerfStat : public Singleton<PerfStat> {
    DECLARE_SINGLETON(PerfStat);

public:
    int64_t GetAccountBindStartTime() const;
    void SetAccountBindStartTime(int64_t time);

    int64_t GetAccountBindEndTime() const;
    void SetAccountBindEndTime(int64_t time);

    int64_t GetAccountAddStartTime() const;
    void SetAccountAddStartTime(int64_t time);

    int64_t GetAccountAddEndTime() const;
    void SetAccountAddEndTime(int64_t time);

    int64_t GetAccountDelStartTime() const;
    void SetAccountDelStartTime(int64_t time);

    int64_t GetAccountDelEndTime() const;
    void SetAccountDelEndTime(int64_t time);

    int64_t GetAccountQueryStartTime() const;
    void SetAccountQueryStartTime(int64_t time);

    int64_t GetAccountQueryEndTime() const;
    void SetAccountQueryEndTime(int64_t time);

    void SetInstanceStopTime(int64_t);
    void SetInstanceStartTime(int64_t);
    void SetInstanceInitTime(int64_t);
    void SetInstanceCreateTime(int64_t);
    void SetAccountStateChangeTime(const std::string &stateStr, int64_t time);

    bool GetPerfStatEnabled() const;
    void SetPerfStatEnabled(bool enable);

    void Reset();
    void Dump(std::string& result) const;

private:
    int64_t accountBindBegin_ = 0;
    int64_t accountBindEnd_ = 0;

    int64_t accountAddBegin_ = 0;
    int64_t accountAddEnd_ = 0;

    int64_t accountDelBegin_ = 0;
    int64_t accountDelEnd_ = 0;

    int64_t accountQueryBegin_ = 0;
    int64_t accountQueryEnd_ = 0;

    int64_t instanceCreate_ = 0;
    int64_t serviceOnStart_ = 0;
    int64_t serviceOnStop_ = 0;
    int64_t serviceInit_ = 0;

    std::map<std::string, int64_t> accountStateChangeRecords_;

    bool enableStat_ = true;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_COMMON_PERF_STAT_INCLUDE_PERF_STAT_H
