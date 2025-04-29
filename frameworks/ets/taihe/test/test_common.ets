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
import osAccount from '@ohos.account.osAccount';
import { BusinessError } from '@ohos.base';

export function printOsAccountInfo(info: osAccount.OsAccountInfo): void {
  console.log('===== OS Account Information =====');
  
  // Basic identification fields
  try {
    console.log(`ID: localId=${info.localId}, serialNumber=${info.serialNumber}`);
    console.log(`Names: localName="${info.localName}"${info.shortName ? `, shortName="${info.shortName}"` : ''}`);
    console.log(`Type: ${info.type}`);
  } catch (e) {
    console.error('Basic field access failed:', e);
  }
  
  // Time-related fields
  try {
    console.log(`Timestamps: createTime=${info.createTime}, lastLoginTime=${info.lastLoginTime}`);
  } catch (e) {
    console.error('Time field access failed:', e);
  }
  
  // Status fields
  try {
    console.log(`Status: isActivated=${info.isActivated}, isCreateCompleted=${info.isCreateCompleted}`);
    console.log(`Security: isUnlocked=${info.isUnlocked}${info.isLoggedIn !== undefined ? `, isLoggedIn=${info.isLoggedIn}` : ''}`);
  } catch (e) {
    console.error('Status field access failed:', e);
  }
  
  // Resource fields
  try {
    console.log(`Resources: photo="${info.photo}"`);
  } catch (e) {
    console.error('Resource field access failed:', e);
  }
  
  // Array fields
  try {
    if (info.constraints && info.constraints.length > 0) {
      console.log(`Constraints (${info.constraints.length}):`);
      info.constraints.forEach((constraint, index) => {
        console.log(`  ${index + 1}. ${constraint}`);
      });
    } else {
      console.log('Constraints: None or empty array');
    }
  } catch (e) {
    console.error('Constraints array access failed:', e);
  }
  
  // DomainInfo fields
  try {
    console.log('Domain Information:');
    const domainInfo = info.domainInfo;
    console.log(`  Domain: ${domainInfo.domain}`);
    console.log(`  Account Name: ${domainInfo.accountName}`);
    console.log(`  Account ID: ${domainInfo.accountId}`);
    console.log(`  Authenticated: ${domainInfo.isAuthenticated}`);
    console.log(`  Server Config ID: ${domainInfo.serverConfigId}`);
  } catch (e) {
    console.error('Domain info access failed:', e);
  }
  
  // DistributedInfo fields
  try {
    console.log('Distributed Information:');
    const distInfo = info.distributedInfo;
    console.log(`  Name: ${distInfo.name}`);
    console.log(`  ID: ${distInfo.id}`);
    console.log(`  Nickname: ${distInfo.nickname}`);
    console.log(`  Avatar: ${distInfo.avatar}`);
    console.log(`  Status: ${distInfo.status}`);
    console.log(`  Scalable Data: ${distInfo.scalableData}`);
  } catch (e) {
    console.error('Distributed info access failed:', e);
  }
  
  console.log('===== End of Account Information =====');
}