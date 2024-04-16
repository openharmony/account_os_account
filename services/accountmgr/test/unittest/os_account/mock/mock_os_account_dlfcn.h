/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef	OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_UNITTEST_OS_ACCOUNT_MOCK_MOCK_OS_ACCOUNT_DLFCN_H
#define	OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_UNITTEST_OS_ACCOUNT_MOCK_MOCK_OS_ACCOUNT_DLFCN_H

#include <features.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTLD_LAZY   1

int  dlclose(void *);
char *dlerror(void);
void *dlopen(const char *, int);
void *dlsym(void *__restrict, const char *__restrict);

#ifdef __cplusplus
}
#endif

#endif