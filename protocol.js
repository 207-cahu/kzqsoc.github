import { AesSession, fromHex, concat } from './crypto.js';
export const UUID = Object.freeze({
  service: '6e400001-b5a3-f393-e0a9-e50e24dcca9e',
  tx: '6e400002-b5a3-f393-e0a9-e50e24dcca9e',
  rx: '6e400003-b5a3-f393-e0a9-e50e24dcca9e'
});
export const CAPACITY_TABLE = Object.freeze([20000,10500,18000,36000,60000,26000,14000,38000,13000,22000,39000,45000,46000,55000,52000,50000]);
export const FIRMWARE_KEYS = Object.freeze(['dashboard','color','center','meter']);
export const firmwareVersion = value => value == null ? '--' : `${(value >> 8) & 15}.${(value >> 4) & 15}.${value & 15}`;
export function profileVoltage(profile) { return Number.isInteger(profile) && profile >= 0 && profile <= 255 ? [72,60,48][profile & 15] ?? null : null; }
export function profileCapacity(profile) { if (!profileVoltage(profile)) return null; return profile === 0x52 ? 24500 : CAPACITY_TABLE[profile >> 4]; }
export function capacities(voltage) { return [...new Set(CAPACITY_TABLE.map((_, i) => profileCapacity((i << 4) | ({72:0,60:1,48:2}[voltage] ?? 15))).filter(v => v != null))].sort((a,b) => a-b).map(v => v/1000); }
export function targetProfile(voltage, capacityAh, currentProfile = -1) {
  const low = {72:0,60:1,48:2}[voltage], target = Math.round(capacityAh * 1000);
  if (low == null || !Number.isFinite(capacityAh) || Math.abs(capacityAh*1000-target) > 0.001) throw new Error('无效的目标电压或容量');
  const preferred = ((currentProfile >> 4) << 4) | low;
  if (currentProfile >= 0 && profileCapacity(preferred) === target) return preferred;
  for (let i=0;i<16;i++) { const p = (i<<4)|low; if (profileCapacity(p) === target) return p; }
  throw new Error('原 APK 没有此电压/容量的精确档位，已拒绝写入');
}
export function dashboardVoltage(config) { return Number.isInteger(config) && config >= 0 && config <= 255 ? ({1:72,2:60,3:48}[config&15] ?? null) : null; }
export function dashboardTarget(config, voltage) {
  if (!dashboardVoltage(config) || ![48,60,72].includes(voltage)) throw new Error('仪表当前配置或目标电压不能识别');
  return (config & 0xf0) | ({72:1,60:2,48:3}[voltage]);
}
export const readOnlySN = sn => String(sn).trim().toUpperCase().startsWith('N');
export const sameFirmware = (a,b) => FIRMWARE_KEYS.every(key => (a?.[key] ?? null) === (b?.[key] ?? null));
const u16 = (bytes, offset=7) => bytes[offset] | (bytes[offset+1]<<8);
const ascii = bytes => new TextDecoder('ascii').decode(bytes).replace(/\0/g, '').trim();
const staleError = () => new DOMException('蓝牙会话已失效；旧操作已取消，请重新连接认证', 'AbortError');
export function frame(source, destination, command, register, payload = []) {
  if (payload.length > 255) throw new Error('帧过长');
  return Uint8Array.from([0x5a,0xa5,payload.length,source,destination,command,register,...payload]);
}
export function isResponse(bytes, source, command, register, length = 0) {
  return bytes.length >= 7+length && bytes[0] === 0x5a && bytes[1] === 0xa5 && bytes[3] === source && bytes[4] === 0x3e && bytes[5] === command && bytes[6] === register;
}

export function snapshotEligibility(s, kind='meter', voltage=60, capacity=26) {
  if (!s || !s.sn) return {ok:false,reason:'请先完成车辆认证和数据读取'};
  if (s.demo) return {ok:false,reason:'界面演示模式不会发送任何车辆写入指令'};
  if (readOnlySN(s.sn)) return {ok:false,reason:'原协议将 N 开头的车辆设为只读，网页版同样禁止写入'};

  if (kind === 'dashboard') {
    const required = ['dashboard','color','center','meter'];
    const missing = required.filter(key => s.firmware?.[key] == null || typeof s.firmware[key] !== 'number');
    if (missing.length) {
      return {ok:false,reason:`以下模块固件未成功读取，无法校验：${missing.map(k=>({dashboard:'仪表',color:'彩屏',center:'中控',meter:'计量'})[k]).join('、')}。请重新读取后再试`};
    }
    if (!dashboardVoltage(s.dashboardConfig)) {
      return {ok:false,reason:'仪表电压配置尚未成功读取或不能识别'};
    }
    let target;
    try { target = dashboardTarget(s.dashboardConfig, voltage); }
    catch(e) { return {ok:false,reason:e.message}; }
    
    return {ok:true,reason:'四模块固件已读取，已允许写入（硬件风险需自行承担）',target};
  }

  if (kind !== 'meter') return {ok:false,reason:'未知模块'};
  const expectedCapacity = profileCapacity(s.profile);
  if (expectedCapacity == null || !Number.isInteger(s.soc) || s.soc < 0 || s.soc > 100 || s.capacityCore !== expectedCapacity) {
    return {ok:false,reason:'Profile、SOC 或容量回读不一致。本版拒绝在未知通信组合上写入'};
  }
  try { return {ok:true,reason:'Profile、SOC 与 capacity_core 一致，支持临时档位写入',target:targetProfile(voltage,capacity,s.profile)}; }
  catch(e) { return {ok:false,reason:e.message}; }
}

export function validateBackup(b) {
  if (!b || b.format!=='ninebot-web-backup' || b.version!==1 || b.source!=='vehicle-readback' || typeof b.sn!=='string' || !/^[A-Z0-9]{14}$/.test(b.sn) || b.demo) throw new Error('不是本工具支持的真实车辆备份');
  const optionalInt=(v,max,label)=>{if(v==null)return null;if(!Number.isInteger(v)||v<0||v>max)throw new Error(`备份${label}无效`);return v;};
  if (!b.firmware || typeof b.firmware!=='object' || Array.isArray(b.firmware)) throw new Error('备份固件记录无效');
  const firmware=Object.fromEntries(FIRMWARE_KEYS.map(key=>[key,optionalInt(b.firmware[key],65535,'固件记录')]));
  return {format:b.format,version:1,source:b.source,sn:b.sn,createdAt:typeof b.createdAt==='string'?b.createdAt:null,firmware,
    profile:optionalInt(b.profile,255,'档位'),capacityCore:optionalInt(b.capacityCore,65535,'容量'),dashboardConfig:optionalInt(b.dashboardConfig,65535,'仪表配置'),
    warning:'配置记录不是固件镜像；不含密钥，备份不保证硬件损坏后可恢复。'};
}
export function buildBackup(s) {
  if (!s || s.demo) throw new Error('不能导出演示数据为真实车辆备份');
  return validateBackup({format:'ninebot-web-backup',version:1,createdAt:new Date().toISOString(),sn:s.sn,firmware:s.firmware,
    profile:s.profile,capacityCore:s.capacityCore,dashboardConfig:s.dashboardConfig,source:'vehicle-readback'});
}
export function backupRestoreEligibility(b,s) {
  let record;try{record=validateBackup(b);}catch(e){return {ok:false,reason:e.message};}
  if (!s || s.demo || s.sn!==record.sn) return {ok:false,reason:'备份与当前真实车辆不一致'};
  if (FIRMWARE_KEYS.some(key=>record.firmware[key]==null||s.firmware?.[key]==null) || !sameFirmware(record.firmware,s.firmware)) return {ok:false,reason:'恢复需要备份及当前车辆四项固件完整且一致'};
  if (!profileVoltage(record.profile) || record.capacityCore!==profileCapacity(record.profile)) return {ok:false,reason:'此记录档位或容量不完整/不一致，仅供查看，不允许恢复'};
  const check=snapshotEligibility(s,'meter',profileVoltage(record.profile),record.capacityCore/1000);
  return check.ok ? {...check,target:record.profile} : check;
}

export class VehicleClient {
  constructor({log=()=>{},status=()=>{},disconnected=()=>{}} = {}) {
    this.log=log;this.status=status;this.onDisconnect=disconnected;this.device=null;this.crypto=null;this.tx=null;this.rx=null;
    this.authenticated=false;this.sn='';this.snapshot=null;this.counter=2;this.highestReceived=-1;this.pending=null;
    this.buffer=new Uint8Array();this.receiveChain=Promise.resolve();this.operation=null;this.epoch=0;
    this.controller=new AbortController();this.connecting=null;this.removeListeners=null;
  }
  get connected() { return !!this.device?.gatt?.connected && !!this.tx; }
  assertSession(epoch=this.epoch) { if(epoch!==this.epoch || this.controller.signal.aborted)throw staleError(); }
  async wait(ms,epoch=this.epoch) {
    this.assertSession(epoch);const signal=this.controller.signal;
    await new Promise((resolve,reject)=>{let timer;const abort=()=>{clearTimeout(timer);reject(staleError());};
      timer=setTimeout(()=>{signal.removeEventListener('abort',abort);resolve();},ms);
      signal.addEventListener('abort',abort,{once:true});});
    this.assertSession(epoch);
  }
  async scoped(promise,epoch=this.epoch,timeout=10000) {
    this.assertSession(epoch);const signal=this.controller.signal;
    return new Promise((resolve,reject)=>{
      let timer,done=false;
      const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);signal.removeEventListener('abort',abort);if(error)reject(error);else resolve(value);};
      const abort=()=>finish(staleError());
      signal.addEventListener('abort',abort,{once:true});
      if(timeout>0)timer=setTimeout(()=>{
        const error=new Error('蓝牙底层操作超时，连接已停止；已发送写入的结果未确认');
        finish(error);if(epoch===this.epoch)this.fail(error);
      },timeout);
      Promise.resolve(promise).then(value=>{try{this.assertSession(epoch);finish(null,value);}catch(e){finish(e);}},error=>finish(error));
    });
  }
  async connect(expectedSN='') {
    if (!globalThis.isSecureContext || !navigator.bluetooth) throw new Error('请使用 HTTPS 和支持 Web Bluetooth 的浏览器（例如安卓 Chrome）');
    if (this.connected || this.connecting || this.operation) throw new Error('请先断开当前车辆或等待连接结束');
    this.invalidate('开始新连接');
    const epoch=this.epoch,token={epoch};this.connecting=token;this.expectedSN=expectedSN.trim().toUpperCase();
    let selected,tx,rx,session;
    try {
      selected=await this.scoped(navigator.bluetooth.requestDevice({acceptAllDevices:true,optionalServices:[UUID.service]}),epoch,0);
      
      // 【优化1】获取设备后，增加200ms延迟，等系统蓝牙服务稳定，防止立刻连接导致断开
      await this.wait(200, epoch); 
      
      this.assertSession(epoch);this.device=selected;
      const disconnected=()=>{if(this.epoch!==epoch||this.device!==selected)return;this.invalidate('蓝牙已断开；未确认的写入不可视为成功');this.onDisconnect();};
      selected.addEventListener('gattserverdisconnected',disconnected);
      this.removeListeners=()=>{selected.removeEventListener('gattserverdisconnected',disconnected);};
      this.status('正在建立蓝牙 GATT 连接…');
      const connecting=selected.gatt.connect();
      Promise.resolve(connecting).then(()=>{if(epoch!==this.epoch&&selected!==this.device&&selected.gatt.connected)selected.gatt.disconnect();},()=>{});
      const server=await this.scoped(connecting,epoch);this.assertSession(epoch);
      const service=await this.scoped(server.getPrimaryService(UUID.service),epoch);this.assertSession(epoch);
      tx=await this.scoped(service.getCharacteristic(UUID.tx),epoch);this.assertSession(epoch);
      rx=await this.scoped(service.getCharacteristic(UUID.rx),epoch);this.assertSession(epoch);
      const name=selected.name;
      if (!name || !/^[\x20-\x7e]+$/.test(name)) throw new Error('浏览器未提供有效的蓝牙广播名称，无法精确派生加密参数');
      session=new AesSession(name);await session.init();this.assertSession(epoch);
      this.crypto=session;
      const notified=event=>{
        if(epoch!==this.epoch)return;
        const value=event.target.value,copy=new Uint8Array(value.buffer,value.byteOffset,value.byteLength).slice();
        const requestToken=this.pending;
        this.receiveChain=this.receiveChain.then(()=>{if(epoch===this.epoch)return this.receive(copy,epoch,requestToken);}).catch(e=>{if(epoch===this.epoch)this.fail(e);});
      };
      rx.addEventListener('characteristicvaluechanged',notified);
      const removeDevice=this.removeListeners;
      this.removeListeners=()=>{removeDevice();rx.removeEventListener('characteristicvaluechanged',notified);};
      await this.scoped(rx.startNotifications(),epoch);this.assertSession(epoch);
      this.tx=tx;this.rx=rx;
      this.log('蓝牙通道已连接，尚未通过车辆认证');
      this.status('蓝牙已连接，请选择临时配对或使用已有密钥认证');
    } catch(e) {
      session?.destroy();
      if(epoch===this.epoch)this.disconnect();
      else if(selected && selected!==this.device && selected.gatt?.connected)selected.gatt.disconnect();
      throw e;
    } finally {if(this.connecting===token)this.connecting=null;}
  }
  invalidate(message) {
    this.epoch++;this.controller.abort();this.controller=new AbortController();
    this.removeListeners?.();this.removeListeners=null;this.authenticated=false;this.snapshot=null;this.sn='';this.expectedSN='';
    this.tx=null;this.rx=null;this.crypto?.destroy();this.crypto=null;this.buffer=new Uint8Array();this.counter=2;this.highestReceived=-1;
    this.receiveChain=Promise.resolve();this.operation=null;this.connecting=null;
    if(this.pending){const p=this.pending;this.pending=null;clearTimeout(p.timer);p.reject(new Error(message));}
  }
  disconnect() {
    const device=this.device;this.invalidate('连接已终止，旧操作已取消');this.device=null;
    if(device?.gatt?.connected)device.gatt.disconnect();
  }
  fail(error) {
    this.log(error.message,'error');
    if(this.pending){const p=this.pending;this.pending=null;clearTimeout(p.timer);p.reject(error);}
    this.disconnect();this.onDisconnect(error);
  }
  async exclusive(name,work) {
    if(this.operation)throw new Error(`正在${this.operation.name}，请等待完成`);
    if(!this.connected)throw new Error('蓝牙未连接');
    const token={name,epoch:this.epoch};this.operation=token;
    try{const result=await work(token.epoch);this.assertSession(token.epoch);return result;}
    finally{if(this.operation===token)this.operation=null;}
  }
  async writeWire(bytes,epoch=this.epoch) {
    this.assertSession(epoch);if(!this.connected)throw new Error('蓝牙未连接');
    const tx=this.tx;
    if(tx.properties.writeWithoutResponse)await this.scoped(tx.writeValueWithoutResponse(bytes),epoch);
    else if(tx.properties.write)await this.scoped(tx.writeValueWithResponse(bytes),epoch);
    else throw new Error('车辆特征不支持写入通道');
    this.assertSession(epoch);
  }
  async send(plain,initial=false,epoch=this.epoch,requestToken=null) {
    this.assertSession(epoch);const session=this.crypto;if(!session)throw new Error('加密会话未初始化');
    let wire;
    if(initial)wire=await session.encryptInitial(plain);
    else{const counter=this.counter++;if(counter>65535)throw new Error('会话计数器已用尽，请重新连接');wire=await session.encrypt(counter,plain);}
    this.assertSession(epoch);
    if(requestToken && this.pending!==requestToken)throw new Error('请求已结束，取消迟到的发送');
    const sensitive=plain[4]===4 && [0x5b,0x5c,0x5d].includes(plain[5]);
    this.log(sensitive?'发送鉴权/配对帧（内容不记录）':`发送模块 0x${plain[4].toString(16)} 寄存器 0x${plain[6].toString(16)} ${plain[5]===2?'写入':'读取'}`);
    await this.writeWire(wire,epoch);this.assertSession(epoch);
  }
  request(plain,predicate,{initial=false,timeout=5000,onInterim=null,epoch=this.epoch,soft=false}={}) {
    try{this.assertSession(epoch);}catch(e){return Promise.reject(e);}
    if(this.pending)return Promise.reject(new Error('前一请求尚未结束'));
    return new Promise((resolve,reject)=>{
      const p={resolve,reject,predicate,initial,onInterim,timer:null,epoch};
      this.buffer=new Uint8Array();this.pending=p;
      p.timer=setTimeout(()=>{
        if(this.pending!==p)return;
        this.pending=null;
        if(soft){
          reject(new Error('模块响应超时（可选模块，不中断连接）'));
        }else{
          this.fail(new Error('车辆响应超时，连接已停止；请重新认证读取，写入结果未确认'));
        }
      },timeout);
      this.send(plain,initial,epoch,p).catch(e=>{if(this.pending===p){this.pending=null;clearTimeout(p.timer);reject(e);}});
    });
  }
  async receive(chunk,epoch=this.epoch,requestToken=this.pending) {
    this.assertSession(epoch);
    if(!requestToken||this.pending!==requestToken){this.log('忽略不属于当前请求的车辆通知');return;}
    this.buffer=concat(this.buffer,chunk);
    if(this.buffer.length>2048)throw new Error('蓝牙接收缓冲异常');
    while(this.buffer.length>=3){
      this.assertSession(epoch);
      if(this.pending!==requestToken){this.buffer=new Uint8Array();return;}
      if(this.buffer[0]!==0x5a||this.buffer[1]!==0xa5){this.buffer=this.buffer.slice(1);continue;}
      const length=this.buffer[2]+13;
      if(this.buffer.length<length)break;
      const frame=this.buffer.slice(0,length);
      this.buffer=this.buffer.slice(length);
      let decrypted;
      try{decrypted=await this.crypto.decrypt(frame);}catch(e){this.fail(e);return;}
      if(!decrypted.valid)throw new Error('车辆响应校验失败，已停止操作');
      const reply=decrypted.plain;
      if(requestToken.onInterim&&requestToken.onInterim(reply))continue;
      if(requestToken.predicate(reply)){
        this.pending=null;clearTimeout(requestToken.timer);
        requestToken.resolve(reply);return;
      }
    }
  }
  async precomm(epoch=this.epoch) {
    this.assertSession(epoch);
    // 【优化2】首条指令发送前，增加300ms延迟，等待车辆主控准备好接收指令
    await this.wait(300, epoch);
    const reply=await this.request(frame(0x3e,4,1,0x5b,[30]),b=>isResponse(b,4,0x5b,b[6],30),{initial:true,epoch});
    this.assertSession(epoch);
    const snBytes=reply.slice(23,37),sn=ascii(snBytes).toUpperCase();
    if(!/^[A-Z0-9]{14}$/.test(sn))throw new Error('车辆未返回合法的 14 位序列号');
    if(this.expectedSN&&sn!==this.expectedSN)throw new Error('实际车辆序列号与输入值不一致，已停止操作');
    if(this.sn&&sn!==this.sn)throw new Error('连接车辆身份发生变化，已停止操作');
    this.sn=sn;return {saved:reply[6]!==0,auth:reply.slice(7,23),snBytes};
  }
  async authenticate(snBytes,epoch=this.epoch) {
    this.assertSession(epoch);
    const reply=await this.request(concat(fromHex('5AA50E3E045D00'),snBytes),b=>isResponse(b,4,0x5d,b[6]),{timeout:6000,epoch});
    this.assertSession(epoch);
    if(reply[6]!==1)throw new Error('车辆拒绝了认证');
    this.authenticated=true;
    this.log('车辆认证成功；本次尚未写入电量参数');
    this.status('认证成功，可以读取车辆参数');
  }
  async pair() {
    return this.exclusive('配对',async epoch=>{
      const identity=await this.precomm(epoch);this.assertSession(epoch);
      const secret=crypto.getRandomValues(new Uint8Array(32)),session=this.crypto;
      let pairingFrame;
      try{
        await session.establish(secret.slice(0,16),identity.auth);this.assertSession(epoch);this.counter=2;this.highestReceived=-1;
        for(let i=0;i<3;i++){await this.send(concat(fromHex('5AA50E3E045D00'),identity.snBytes),false,epoch);await this.wait(510,epoch);}
        await session.establishPairing(identity.auth);this.assertSession(epoch);this.highestReceived=-1;
        this.status('配对请求已发出，请在车辆上按键确认（60 秒内）');
        pairingFrame=concat(fromHex('5AA5203E045C00'),secret);
        const reply=await this.request(pairingFrame,b=>isResponse(b,4,0x5c,b[6])&&b[6]!==0,{timeout:60000,epoch,
          onInterim:b=>{if(isResponse(b,4,0x5c,0))this.status('等待车上按键确认，尚未修改电量参数…');}});
        this.assertSession(epoch);
        if(reply[6]!==1)throw new Error('车辆拒绝配对');
        await session.establish(secret.slice(0,16),identity.auth);this.assertSession(epoch);
        await this.authenticate(identity.snBytes,epoch);
      }finally{secret.fill(0);pairingFrame?.fill(0);}
    });
  }
  async login(keyHex) {
    return this.exclusive('认证',async epoch=>{
      const key=fromHex(keyHex);
      try{
        if(key.length!==16)throw new Error('已有密钥必须为16字节（32个十六进制字符）');
        const identity=await this.precomm(epoch);this.assertSession(epoch);
        if(!identity.saved)throw new Error('车辆没有已保存的 BLE 密钥，请先进行临时配对');
        const session=this.crypto;await session.establish(key,identity.auth);this.assertSession(epoch);
        this.counter=2;this.highestReceived=-1;await this.authenticate(identity.snBytes,epoch);
      }finally{key.fill(0);}
    });
  }
  async readRegister(module,register,length=2,timeout=4000,epoch=this.epoch,soft=false) {
    this.assertSession(epoch);if(!this.authenticated)throw new Error('请先通过车辆认证');
    const reply=await this.request(frame(0x3e,module,1,register,[length]),b=>isResponse(b,module,4,register,length),{timeout,epoch,soft});
    this.assertSession(epoch);
    return length===1?reply[7]:u16(reply);
  }
  async readSnapshot() {return this.exclusive('读取',epoch=>this.readSnapshotInternal(epoch));}
  async readSnapshotInternal(epoch=this.epoch) {
    this.assertSession(epoch);if(!this.authenticated)throw new Error('请先通过车辆认证');
    const s={sn:this.sn,firmware:{},timestamp:new Date().toISOString(),profile:null,soc:null,capacityCore:null,dashboardConfig:null,remainingCapacity:null,batteryVoltage:null,dashboardSoc:null};
    const criticalJobs=[
      ['profile',0x10,0,1],
      ['soc',0x10,2,1],
      ['capacityCore',0x10,0x1c,2],
      ['firmware.dashboard',1,0x1a,2],
      ['dashboardEnergy',1,0x1e,2],
      ['remainingCapacity',1,0x44,2],
      ['dashboardSoc',1,0xb5,2],
      ['batteryVoltage',1,0xb1,2],
      ['firmware.meter',1,0x3d,2],
      ['firmware.color',1,0xd1,2],
      ['firmware.center',9,2,2],
      ['dashboardConfig',1,0x92,2],
    ];
    for(const [key,module,register,length] of criticalJobs){
      this.assertSession(epoch);this.status(`正在读取 ${key}…`);
      try{
        const value=await this.readRegister(module,register,length,4000,epoch);this.assertSession(epoch);
        if(key.startsWith('firmware.'))s.firmware[key.split('.')[1]]=value;else s[key]=value;
      }catch(e){
        this.assertSession(epoch);if(!this.connected||!this.authenticated)throw e;
        this.log(`${key} 未读到：${e.message}`,'warning');
      }
      await this.wait(60,epoch);
    }
    this.assertSession(epoch);if(!this.connected||!this.authenticated)throw new Error('读取期间连接已失效');
    this.snapshot=s;this.status('读取完成，请核对实际车辆与电池规格');return structuredClone(s);
  }
  async writeParameters(kind,voltage,capacity,before,{confirmed=false,restoreProfile=null}={}) {
    return this.exclusive('写入',async epoch=>{
      if(!confirmed)throw new Error('未完成写入风险确认');
      const current=await this.readSnapshotInternal(epoch);this.assertSession(epoch);
      if(!before||before.sn!==current.sn||before.profile!==current.profile||before.capacityCore!==current.capacityCore||before.dashboardConfig!==current.dashboardConfig||!sameFirmware(before.firmware,current.firmware))throw new Error('确认后车辆配置发生变化，本次未发送写入，请重新读取');
      const check=snapshotEligibility(current,kind,voltage,capacity);if(!check.ok)throw new Error(check.reason);
      let target=check.target;
      if(restoreProfile!==null){
        if(kind!=='meter'||profileVoltage(restoreProfile)!==voltage||profileCapacity(restoreProfile)!==Math.round(capacity*1000))throw new Error('备份档位无法精确恢复，不提供近似替代');
        target=restoreProfile;
      }
      if((kind==='meter'&&current.profile===target)||(kind==='dashboard'&&current.dashboardConfig===target))return {changed:false,snapshot:current};
      this.status('正在发送参数写入；只有回读匹配才会显示成功');
      if(kind==='meter'){
        await this.send(frame(0x3e,0x10,2,0,[target]),false,epoch);await this.wait(2400,epoch);
        let matched=false;for(let i=0;i<4;i++){const p=await this.readRegister(0x10,0,1,4500,epoch);if(p===target){matched=true;break;}await this.wait(1000,epoch);}
        if(!matched)throw new Error('参数写入已发送，但4次Profile回读未匹配。结果未确认，请重新连接读取，勿盲目重试');
        const capacityAfter=await this.readRegister(0x10,0x1c,2,4500,epoch);if(capacityAfter!==profileCapacity(target))throw new Error('档位已变更，但容量回读不匹配。结果未确认，不可视为成功');
      }else{
        await this.send(frame(0x3e,1,2,0x92,[target,0]),false,epoch);await this.wait(2200,epoch);
        let matched=false;for(let i=0;i<4;i++){const config=await this.readRegister(1,0x92,2,4500,epoch);if(config===target){matched=true;break;}await this.wait(1000,epoch);}
        if(!matched)throw new Error('仪表写入已发送，但配置回读未匹配。结果未确认；备份不保证恢复');
      }
      const after=await this.readSnapshotInternal(epoch);this.assertSession(epoch);
      if(kind==='meter'?(after.profile!==target||after.capacityCore!==profileCapacity(target)):after.dashboardConfig!==target)throw new Error('最终读取与目标不一致，结果未确认');
      return {changed:true,snapshot:after};
    });
  }
}
