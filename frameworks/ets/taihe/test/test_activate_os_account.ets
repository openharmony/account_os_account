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
import {BusinessError} from '@ohos.base';
let TAG:string = 'OsAccountTaihe:';

export async  function testIAMInputerManager() {
   console.info(TAG+"[testIAMInputerManager] Starting test...");
   try{
      let token = new Uint8Array([0]);
      let inputer: osAccount.IInputer = {
      onGetData :(authSubType:osAccount.AuthSubType, inputData:osAccount.IInputData, options: osAccount.GetInputDataOptions):void =>{
            console.info(TAG+"test onGetData ....");
            inputData.onSetData(osAccount.AuthSubType.PIN_SIX,token);
            console.info(TAG+"after onGetData ....");
         }
      }
      console.info(TAG+"test registerInputer ....start");
      osAccount.InputerManager.registerInputer(osAccount.AuthType.PIN, inputer);
      console.info(TAG+"test InputerManager registerInputer ....end");
   }catch(err:BusinessError){
       console.info(TAG+"test InputerManager registerInputer err ...." + err);
   }
}

export async  function testIAMPINAuth() {
   console.info(TAG+"[testIAMPINAuth] Starting test...");
   try{
      let token = new Uint8Array([0]);
      let inputer: osAccount.IInputer = {
      onGetData :(authSubType:osAccount.AuthSubType, inputData:osAccount.IInputData, options: osAccount.GetInputDataOptions):void =>{
            console.info(TAG+"test onGetData ....");
            inputData.onSetData(osAccount.AuthSubType.PIN_SIX,token);
            console.info(TAG+"after onGetData ....");
         }
      }
      console.info(TAG+"test pinAuth registerInputer ....start");
      let pinAuth = new osAccount.PINAuth();
      pinAuth.registerInputer(inputer);
      console.info(TAG+"test pinAuth registerInputer ....end");
   }catch(err:BusinessError){
       console.info(TAG+"test pinAuth registerInputer err ...." + err.code + " "+ err.message);
   }
}

export async function testIsMainOsAccoun() {
   console.info(TAG+"[testIsMainOsAccoun] Starting test...");
   try{
      let localId = 100;
      console.info(TAG+"test localId ....");
      let account_manager: osAccount.AccountManager = osAccount.getAccountManager();
      console.info(TAG+"test getAccountManager ....");
      let data2 = await account_manager.isMainOsAccount();
         account_manager.isMainOsAccount().then((data:boolean)=>{
            console.info(TAG+"test isMainOsAccount ...."+ JSON.stringify(data));
         });
      console.info(TAG+"test isMainOsAccount ...."+ JSON.stringify(data2));
   }catch(err:BusinessError){
      console.info(TAG+"testIsMainOsAccoun err ...." + err.code + " "+ err.message);
   }
}

export async function testGetOsAccountProfilePhoto() {
   console.info(TAG+"[testGetOsAccountProfilePhoto] Starting test...");
   try{
      let localId = 100;
      console.info(TAG+"test localId ....");
      let account_manager: osAccount.AccountManager = osAccount.getAccountManager();
      console.info(TAG+"test getAccountManager ....");
      let data3 = await account_manager.getOsAccountProfilePhoto(100.0);
      console.info(TAG+"test getOsAccountProfilePhoto ...."+ JSON.stringify(data3));
   }catch(err:BusinessError){
      console.info(TAG+"test testGetOsAccountProfilePhoto err ...." + err.code + " "+ err.message);
   }
}

export async function testGetOsAccountType() {
   console.info(TAG+"[testGetOsAccountType] Starting test...");
   try{
      let localId = 100;
      console.info(TAG+"test localId ....");
      let account_manager: osAccount.AccountManager = osAccount.getAccountManager();
      console.info(TAG+"test getAccountManager ....");
      account_manager.getOsAccountType((err: BusinessError<void>, data:osAccount.OsAccountType)=>{
        console.info(TAG+"test getOsAccountType ...."+ data);
      });

      let data4 = await account_manager.getOsAccountType();
      console.info(TAG+"test getOsAccountType ...."+ JSON.stringify(data4));
   }catch(err:BusinessError){
      console.info(TAG+"test testGetOsAccountTyper err ...." + err.code + " "+ err.message);
   }
}

export async function testOnOff() {
   console.info(TAG+"[testOnOff] Starting test...");
   try{
      let localId = 100;
      console.info(TAG+"test localId ....");
      let account_manager: osAccount.AccountManager = osAccount.getAccountManager();
      console.info(TAG+"test getAccountManager ....");
      account_manager.on("activate","test",(data:number)=>{
      console.info(new Date()+TAG+"test on activate...."+ JSON.stringify(data));
      })
      console.info(formatTime()+TAG+"end on activate.");
      account_manager.on("activating","test",(data:number)=>{
         console.info(TAG+"test on activate...."+ JSON.stringify(data));
      })
      console.info(TAG+"end on activating.");
      account_manager.on("switching" ,(data:osAccount.OsAccountSwitchEventData)=>{
         console.info(TAG+"test on activate...."+ JSON.stringify(data));
      })
      account_manager.on("switched" ,(data:osAccount.OsAccountSwitchEventData)=>{
         console.info(TAG+"test on activate...."+ JSON.stringify(data));
      })
      console.info(new Date()+TAG+"end on.");
      console.info(formatTime());
      sleepSync(1000*30);
      console.info(new Date()+TAG+"start off.");
      account_manager.off("activate","test");
      account_manager.off("activating","test");
      account_manager.off("switching");
      account_manager.off("switched");
   }catch(err:BusinessError){
      console.info(TAG+"test on off err ...." + err.code + " "+ err.message);
   }
}

export async function testActivateOsAccount() {
   console.info(TAG+"[testActivateOsAccount] Starting test...");
   let localId = 100;
   console.info(TAG+"test localId ....");
   let account_manager: osAccount.AccountManager = osAccount.getAccountManager();
   console.info(TAG+"test getAccountManager ....");
}

function sleepSync(delay:number) {
   const start = Date.now();
   while (Date.now() - start < delay) {}
}

function formatTime():string {
   const date = new Date();
   const year = date.getFullYear();
   const month = String(date.getMonth() + 1).padStart(2, '0');
   const day = String(date.getDate()).padStart(2, '0');
   const hours = String(date.getHours()).padStart(2, '0');
   const minutes = String(date.getMinutes()).padStart(2, '0');
   const seconds = String(date.getSeconds()).padStart(2, '0');
   const mseconds = String(date.getMilliseconds());
   return "["+year+"-"+month+"-"+day+" "+hours+":"+minutes+":"+seconds+":"+mseconds+"]";
}

