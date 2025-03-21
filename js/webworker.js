/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019-2020, 2024 MlesTalk WebWorker developers
 * Copyright (c) 2020-2022 Zpinc developers
 */

importScripts(
  "cbor.js",
  "blake2b.js",
  "scrypt-async.js",
  "nacl.js",
  "ristretto255.js",
  "wipe.js",
  "int.js",
  "binary.js",
);

let gWebSocket = {};
let gMyAddr = {};
let gMyPort = {};
let gMyUid = {};
let gMyChannel = {};
let gChannelKey = {};
let gMsgCryptKey = {};
const ISFULL = 0x8000;
const ISDATA = 0x4000;
const ISPRESENCE = 0x2000;
const ISPRESENCEACK = 0x1000;
const ISMULTI = 0x800;
const ISFIRST = 0x400;
const ISLAST = 0x200;
const ISBDONE = 0x100;
const ISBDACK = 0x80;
const ALLISSET = 0x7f;
const BEGIN = new Date(Date.UTC(2018, 0, 1, 0, 0, 0));
const HMAC_LEN = 12;
const NONCE_LEN = 32;
const DOMAIN_ENCKEY = StringToUint8("Zpinc-WebWorkerEncryptDom!v1");
const DOMAIN_CHANKEY = StringToUint8("Zpinc-WebWorkerChannelDom!v1");
const DOMAIN_AUTHKEY = StringToUint8("Zpinc-WebWorkerAuthDom!v1");

/* For static uid and channel we use static nonces */
const UIDNONCE = new Uint8Array([
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
  73, 79, 83, 89,
]);
const CHANONCE = new Uint8Array([
  0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03,
  0x70, 0x73, 0x44, 0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0,
]);
const SALTSTR = StringToUint8("ZpincSaltDomain1");
const PERSTR = StringToUint8("ZpincAppDomainv1");
const PERBDSTR = StringToUint8("ZpincBdDomain!v1");
const HDRLEN = 18;

/* Msg type flags */
const MSGISFULL = 0x1;
const MSGISPRESENCE = 0x1 << 1;
const MSGISDATA = 0x1 << 2;
const MSGISMULTIPART = 0x1 << 3;
const MSGISFIRST = 0x1 << 4;
const MSGISLAST = 0x1 << 5;
const MSGISPRESENCEACK = 0x1 << 6;
const MSGPRESACKREQ = 0x1 << 7;
const MSGISBDONE = 0x1 << 8;
const MSGISBDACK = 0x1 << 9;

let SEED;

const SCRYPT_SALTLEN = 32;
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 32;

const DH_BITS = 256; //32 bytes

let gMyDhKey = {};
let gSidDb = {};
let gDhDb = {};
let gBdDb = {};
let gBdAckDb = {};

function createFlagstamp(valueofdate, weekstamp, timestamp) {
  let begin = BEGIN;
  let this_time = new Date(
    begin.valueOf() +
      weekstamp * 1000 * 60 * 60 * 24 * 7 +
      timestamp * 1000 * 60,
  );
  let flagstamp = parseInt((valueofdate - this_time) / 1000);
  return flagstamp;
}

function createTimestamp(valueofdate, weekstamp) {
  let begin = BEGIN;
  let this_week = new Date(
    begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7,
  );
  let timestamp = parseInt((valueofdate - this_week) / 1000 / 60);
  return timestamp;
}

function createWeekstamp(valueofdate) {
  let begin = BEGIN;
  let now = new Date(valueofdate);
  let weekstamp = parseInt((now - begin) / 1000 / 60 / 60 / 24 / 7);
  return weekstamp;
}

function readTimestamp(timestamp, weekstamp, flagstamp) {
  let begin = BEGIN;
  let weeks = new Date(begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7);
  let extension = timestamp * 1000 * 60 + flagstamp * 1000;
  let time = new Date(weeks.valueOf() + extension);
  return time;
}

function isEqualHmacs(hmac, rhmac) {
  let mac1 = new BLAKE2b(HMAC_LEN);
  let mac2 = new BLAKE2b(HMAC_LEN);

  mac1.update(hmac);
  mac2.update(rhmac);

  let hmac1 = mac1.digest();
  let hmac2 = mac2.digest();

  for (let i = 0; i < hmac1.byteLength; i++) {
    if (hmac1[i] != hmac2[i]) {
      return false;
    }
  }
  return true;
}

function StringToUint8(str) {
  let arr = new Uint8Array(str.length);
  let len = str.length;
  for (let i = 0; i < len; i++) {
    arr[i] = str.charCodeAt(i);
  }
  return arr;
}

function Uint8ToString(arr) {
  let str = new String("");
  if (!arr) return str;
  for (let i = 0; i < arr.length; i++) {
    str += String.fromCharCode(arr[i]);
  }
  return str;
}

function StringToUint16Val(str) {
  return ((str.charCodeAt(0) & 0xff) << 8) | (str.charCodeAt(1) & 0xff);
}

function Uint16ValToString(val) {
  let str = new String("");
  str += String.fromCharCode((val & 0xff00) >> 8);
  str += String.fromCharCode(val & 0xff);
  return str;
}

function Uint8ArrayToUint16Val(arr) {
  return ((arr[0] & 0xff) << 8) | (arr[1] & 0xff);
}

function Uint16ValToUint8Array(val) {
  let arr = new Uint8Array(2);
  arr[0] = (val & 0xff00) >> 8;
  arr[1] = val & 0xff;
  return arr;
}

function initBd(channel) {
  gBdDb[channel] = {};
  gBdAckDb[channel] = {};
  gMyDhKey[channel].secret = null;
  gMyDhKey[channel].secretAcked = false;
  gMyDhKey[channel].bd = null;
  gMyDhKey[channel].bdMsgCryptKey = null;
  if (gMyDhKey[channel].fsInformed) {
    processOnForwardSecrecyOff(channel);
    gMyDhKey[channel].fsInformed = false;
  }
}

function initSid(channel) {
  gSidDb[channel] = {};
  gMyDhKey[channel].sid = null;
  gMyDhKey[channel].public = null;
  gMyDhKey[channel].group = null;
  gMyDhKey[channel].private = null;
  initBd(channel);
}

function initDhBd(channel, myuid) {
  gDhDb[channel] = {};
  if (gMyDhKey[channel].public) {
    gDhDb[channel][myuid] = gMyDhKey[channel].public;
  }
  initBd(channel);
}

function setDhPublic(channel, myuid, sid) {
  let siddb_sorted = Object.fromEntries(Object.entries(gSidDb[channel]).sort());

  let pubok = true;
  let cnt = 0;
  let users = "";
  for (let userid in siddb_sorted) {
    //console.log("Found sid " +  gSidDb[channel][userid] + " for user " + userid);
    if (!Uint8ArrayIsEqual(gSidDb[channel][userid], sid)) {
      pubok = false;
      break;
    }
    users += userid;
    cnt++;
  }
  if (pubok && cnt > 1) {
    //console.log("Setting public key for sid " + sid + " cnt " + cnt);
    let sid16 = new Uint8Array(16);
    sid16.set(sid, 0);
    const digest64B = new BLAKE2b(64, {
      salt: sid16,
      personalization: PERBDSTR,
      key: gMsgCryptKey[channel],
    });
    gMyDhKey[channel].group = ristretto255.fromHash(digest64B.digest());
    gMyDhKey[channel].private = ristretto255.scalar.getRandom();
    gMyDhKey[channel].public = ristretto255.scalarMult(
      gMyDhKey[channel].private,
      gMyDhKey[channel].group,
    );
    gMyDhKey[channel].secret = null;
    gMyDhKey[channel].secretAcked = false;
    initBd(channel);
  }
}

function initPrevDhBd(channel, myuid) {
  gMyDhKey[channel].prevBdChannelKey = null;
  gMyDhKey[channel].prevBdMsgCryptKey = null;
}

function bdSetZeroes() {
  let bdin = new Uint8Array(DH_BITS / 8);
  for (let i = 0; i < bdin.length; i++) {
    bdin[i] = 0;
  }
  return bdin;
}

function Uint8ArrayIsEqual(arr1, arr2) {
  if (arr1.length !== arr2.length) {
    return false;
  }
  return arr1.every((value, index) => value === arr2[index]);
}

const BDDEBUG = false;
function processBd(channel, myuid, uid, msgtype, key_array) {
  let init = false;

  if (uid == myuid) {
    //received own message, init due to resyncing
    initDhBd(channel, myuid);
    init = true;
  } else if (
    key_array.length == DH_BITS / 8 ||
    key_array.length == 2 * (DH_BITS / 8)
  ) {
    if (BDDEBUG)
      console.log("Got " + uid + " public+bd key, len " + key_array.length);

    if (
      key_array.length == DH_BITS / 8 &&
      0 == (msgtype & MSGISBDONE) &&
      0 == (msgtype & MSGISBDACK)
    ) {
      if (msgtype & MSGISPRESENCE && 0 == (msgtype & MSGISPRESENCEACK)) {
        //msgtype |= MSGPRESACKREQ; // inform upper layer about presence ack requirement
        if (BDDEBUG)
          console.log("Request presence ack for " + myuid + "@" + channel);
      }
      //if (BDDEBUG) console.log("!!! bd invalidated in short message !!!");
      //initBd(channel);
    }

    let pub = key_array.slice(0, DH_BITS / 8);
    if (null == gDhDb[channel][uid]) {
      gDhDb[channel][uid] = pub;
    } else if (
      false == Uint8ArrayIsEqual(gDhDb[channel][uid], pub) ||
      (key_array.length == DH_BITS / 8 &&
        0 == (msgtype & MSGISBDONE) &&
        gDhDb[channel][uid] &&
        gBdDb[channel][uid])
    ) {
      initDhBd(channel, myuid);
      if (BDDEBUG)
        console.log(
          "!!! skey invalidated in short message as with existing bd!!!",
        );
      gDhDb[channel][uid] = pub;
      init = true;
    } else if (false == init) {
      //calculate bd key
      if (!gBdDb[channel]) gBdDb[channel] = {};
      let prevkey = null;
      let nextkey = null;
      let index = 0;
      let pubcnt = 0;
      let dhdb_sorted = Object.fromEntries(
        Object.entries(gDhDb[channel]).sort(),
      );
      let keys = [];
      for (let userid in dhdb_sorted) {
        if (userid == myuid) {
          if (BDDEBUG) console.log("Myuid " + myuid + " index " + pubcnt);
          index = pubcnt;
        }
        keys.push(gDhDb[channel][userid]);
        if (BDDEBUG)
          console.log(
            "Key for pubcnt " +
              pubcnt +
              " user " +
              userid +
              ":" +
              gDhDb[channel][userid].toString(),
          );
        pubcnt++;
      }

      const len = keys.length;
      if (index == 0) {
        prevkey = keys[len - 1];
        nextkey = keys[index + 1];
      } else if (index == len - 1) {
        prevkey = keys[index - 1];
        nextkey = keys[0];
      } else {
        prevkey = keys[index - 1];
        nextkey = keys[index + 1];
      }
      if (prevkey && nextkey) {
        let step = ristretto255.sub(nextkey, prevkey);
        gMyDhKey[channel].bd = ristretto255.scalarMult(
          gMyDhKey[channel].private,
          step,
        );
        if (BDDEBUG) console.log("Setting Bd " + gMyDhKey[channel].bd);
        gBdDb[channel][myuid] = gMyDhKey[channel].bd;
      }

      if (
        key_array.length == 2 * (DH_BITS / 8) ||
        (key_array.length == DH_BITS / 8 && msgtype & MSGISBDONE)
      ) {
        let bd = bdSetZeroes();
        let len = 0;
        if (key_array.length == 2 * (DH_BITS / 8)) len = (2 * DH_BITS) / 8;

        if (len) bd = key_array.slice(DH_BITS / 8, len);

        if (
          gBdDb[channel][uid] != null &&
          !Uint8ArrayIsEqual(gBdDb[channel][uid], bd)
        ) {
          if (BDDEBUG)
            console.log(
              "!!! skey invalidated in mismatching bd !!! " +
                gBdDb[channel][uid] +
                " vs " +
                bd,
            );
          //start again
          initBd(channel);
          //if(BDDEBUG)
          //	console.log("!!! skey invalidated in mismatching bd !!!");
          gDhDb[channel][uid] = pub;
        } else if (
          (pubcnt > 2 && bdIsZeroes(bd)) ||
          (pubcnt == 2 && !bdIsZeroes(bd))
        ) {
          initDhBd(channel, myuid);
          if (BDDEBUG)
            console.log(
              "!!! skey invalidated in mismatching bd length!!! pubcnt " +
                pubcnt,
            );
          gDhDb[channel][uid] = pub;
          if (msgtype & MSGISPRESENCE && 0 == (msgtype & MSGISPRESENCEACK)) {
            //msgtype |= MSGPRESACKREQ; // inform upper layer about presence ack requirement
            if (BDDEBUG)
              console.log("Request presence ack for " + myuid + "@" + channel);
          }
        } else if (
          bd != null &&
          gBdDb[channel][uid] != null &&
          Uint8ArrayIsEqual(gBdDb[channel][uid], bd) &&
          gMyDhKey[channel].secret
        ) {
          //BD matches, do nothing
          if (BDDEBUG) console.log("BD matches and acked");
        } else {
          gBdDb[channel][uid] = bd;

          let bdcnt = 0;
          let xkeys = [];
          let bddb_sorted = Object.fromEntries(
            Object.entries(gBdDb[channel]).sort(),
          );
          for (let userid in bddb_sorted) {
            if (BDDEBUG)
              console.log("!!!BD user " + userid + " bdcnt " + bdcnt);
            if (userid == myuid) {
              index = bdcnt;
            }
            xkeys.push(gBdDb[channel][userid]);
            bdcnt++;
          }

          if (bdcnt == pubcnt && !gMyDhKey[channel].bdMsgCryptKey) {
            //multiply by len
            const len = xkeys.length;
            let skey = ristretto255.scalarMult(
              gMyDhKey[channel].private,
              prevkey,
            );
            let step = skey;

            for (let j = 0; j < len - 1; j++)
              skey = ristretto255.add(skey, step);
            //console.log("Step 1 " + skey1)
            let sub = 1;
            for (let i = 0; i < len; i++) {
              let base = xkeys[(i + index) % len];

              let step = base;
              for (let j = 0; j < len - sub; j++) {
                base = ristretto255.add(base, step);
              }

              skey = ristretto255.add(base, skey);
              sub++;
            }
            //console.log("Skey " + skey);

            //console.log("!!! My skey " + skey.toString(16) + " !!!");
            gMyDhKey[channel].secret = skey;

            let rnd = new BLAKE2b(32, {
              salt: SALTSTR,
              personalization: PERSTR,
              key: gChannelKey[channel],
            });
            rnd.update(gMyDhKey[channel].secret);

            gMyDhKey[channel].bdChannelKey = createChannelKey(rnd.digest());
            let key = createMessageKey(rnd.digest());

            gMyDhKey[channel].bdMsgCryptKey = key;
            if (BDDEBUG)
              console.log(
                "!!!!Created key msg crypt! " +
                  key +
                  " len " +
                  key.length +
                  " bdcnt " +
                  bdcnt +
                  " pubcnt " +
                  pubcnt,
              );

            //wipe unused
            wipe(rnd);
          }
        }
        //if bd handling fails, ignore large handling
        if (false == init && msgtype & MSGISBDACK) {
          if (gMyDhKey[channel].secretAcked) {
            //do nothing, already acked
            //console.log("Nothing to do, already acked");
          } else {
            if (!gBdAckDb[channel]) gBdAckDb[channel] = {};
            //check first that pub and bd are ok
            if (gDhDb[channel][uid] && gBdDb[channel][uid]) {
              gBdAckDb[channel][uid] = true;
              let pubcnt = Object.keys(gDhDb[channel]).length;
              let bdcnt = Object.keys(gBdDb[channel]).length;
              let ackcnt = Object.keys(gBdAckDb[channel]).length;
              //ack received from everyone else?
              if (BDDEBUG)
                console.log(
                  "Ackcnt " + ackcnt + " pubcnt " + pubcnt + " bdcnt " + bdcnt,
                );
              if (
                gMyDhKey[channel].bdMsgCryptKey &&
                gMyDhKey[channel].secret &&
                pubcnt == bdcnt &&
                ackcnt == pubcnt &&
                ((key_array.length == DH_BITS / 8 &&
                  msgtype & MSGISBDACK &&
                  msgtype & MSGISBDONE &&
                  pubcnt == 2) ||
                  (key_array.length == 2 * (DH_BITS / 8) &&
                    msgtype & MSGISBDACK &&
                    pubcnt > 2))
              ) {
                if (BDDEBUG)
                  console.log(
                    "Ack count matches to pub&bdcnt, enabling send encryption!",
                  );
                gMyDhKey[channel].secretAcked = true;
              }
            } else {
              //start again
              initBd(channel);
              if (BDDEBUG) console.log("!!! bds invalidated in ack !!!");
              gDhDb[channel][uid] = pub;
            }
          }
        }
      }
    }
  }
  return msgtype;
}

function processOnMessageData(channel, msg) {
  //sanity
  if (
    msg.message.byteLength <= NONCE_LEN ||
    msg.message.byteLength > 0xffffff
  ) {
    return;
  }

  let fsEnabled = false;
  let noncem = msg.message.slice(0, NONCE_LEN);
  let arr = msg.message.slice(NONCE_LEN, msg.message.byteLength - HMAC_LEN);
  let hmac = msg.message.slice(
    msg.message.byteLength - HMAC_LEN,
    msg.message.byteLength,
  );
  let message = arr;

  //verify first hmac
  let hmacarr = new Uint8Array(noncem.byteLength + arr.byteLength);
  hmacarr.set(noncem, 0);
  hmacarr.set(arr, noncem.byteLength);
  let hmacok = false;
  let crypt; //selected crypt object

  //try all three options
  if (gMyDhKey[channel].bdMsgCryptKey) {
    let blakehmac = new BLAKE2b(HMAC_LEN, {
      salt: SALTSTR,
      personalization: PERSTR,
      key: gMyDhKey[channel].bdChannelKey,
    });
    blakehmac.update(DOMAIN_AUTHKEY);
    blakehmac.update(noncem.slice(24));
    blakehmac.update(hmacarr);
    let rhmac = blakehmac.digest();
    if (true == isEqualHmacs(hmac, rhmac)) {
      hmacok = true;
      crypt = gMyDhKey[channel].bdMsgCryptKey;
      //console.log("Current crypt matches " + crypt);
      fsEnabled = true;
    }
  }
  if (!hmacok && gMyDhKey[channel].prevBdMsgCryptKey) {
    let blakehmac = new BLAKE2b(HMAC_LEN, {
      salt: SALTSTR,
      personalization: PERSTR,
      key: gMyDhKey[channel].prevBdChannelKey,
    });
    blakehmac.update(DOMAIN_AUTHKEY);
    blakehmac.update(noncem.slice(24));
    blakehmac.update(hmacarr);
    let rhmac = blakehmac.digest();
    if (true == isEqualHmacs(hmac, rhmac)) {
      hmacok = true;
      crypt = gMyDhKey[channel].prevBdMsgCryptKey;
      //console.log("Prevbd crypt matches " + crypt);
      fsEnabled = true;
    }
  }
  if (!hmacok) {
    let blakehmac = new BLAKE2b(HMAC_LEN, {
      salt: SALTSTR,
      personalization: PERSTR,
      key: gChannelKey[channel],
    });
    blakehmac.update(DOMAIN_AUTHKEY);
    blakehmac.update(noncem.slice(24));
    blakehmac.update(hmacarr);
    let rhmac = blakehmac.digest();
    if (false == isEqualHmacs(hmac, rhmac)) {
      return;
    }
    crypt = gMsgCryptKey[channel];
    //console.log("Msg crypt matches " + crypt);
  }

  let uid = Uint8ToString(
    nacl.secretbox.open(
      StringToUint8(atob(msg.uid)),
      UIDNONCE,
      gChannelKey[channel],
    ),
  );
  let decrypted = nacl.secretbox.open(message, noncem.slice(0, 24), crypt);
  if (decrypted.length < HDRLEN) {
    //console.log("Dropping")
    return;
  }

  let msgsz = Uint8ArrayToUint16Val(decrypted.slice(0, 2)); //includes also version which is zero
  let sid = decrypted.slice(2, 10);
  let keysz = Uint8ArrayToUint16Val(decrypted.slice(10, 12));

  //let padsz = decrypted.length - msgsz - keysz;
  //console.log("RX: Msgsize " + msgsz + " Sid " + sid + " Keysz " + keysz + " Pad size " + padsz);

  let timeU16 = Uint8ArrayToUint16Val(decrypted.slice(12, 14));
  let weekU16 = Uint8ArrayToUint16Val(decrypted.slice(14, 16));
  let flagU16 = Uint8ArrayToUint16Val(decrypted.slice(16, HDRLEN));

  let msgDate = readTimestamp(timeU16, weekU16, flagU16 & ALLISSET);

  message = new TextDecoder().decode(decrypted.slice(HDRLEN, msgsz));

  let msgtype = 0;
  if (flagU16 & ISFULL) msgtype |= MSGISFULL;
  if (flagU16 & ISDATA) msgtype |= MSGISDATA;
  if (flagU16 & ISPRESENCE) msgtype |= MSGISPRESENCE;
  if (flagU16 & ISPRESENCEACK) msgtype |= MSGISPRESENCEACK;
  if (flagU16 & ISMULTI) msgtype |= MSGISMULTIPART;
  if (flagU16 & ISFIRST) msgtype |= MSGISFIRST;
  if (flagU16 & ISLAST) msgtype |= MSGISLAST;
  if (flagU16 & ISBDONE) msgtype |= MSGISBDONE;
  if (flagU16 & ISBDACK) msgtype |= MSGISBDACK;

  const myuid = Uint8ToString(
    nacl.secretbox.open(
      StringToUint8(atob(gMyUid[channel])),
      UIDNONCE,
      gChannelKey[channel],
    ),
  );
  if (myuid == uid) {
    //resync
    initSid(channel);
    initDhBd(channel, uid);
  } else if (uid != myuid) {
    if (
      !gMyDhKey[channel].sid ||
      !Uint8ArrayIsEqual(gMyDhKey[channel].sid, sid)
    ) {
      initSid(channel);
      initDhBd(channel, myuid);
      setSid(channel, myuid, sid);
      if (BDDEBUG)
        console.log(
          "RX: setting sid to " + sid + " mysid " + gMyDhKey[channel].sid,
        );
      if (!(msgtype & MSGISPRESENCEACK)) {
        //msgtype |= MSGPRESACKREQ; // inform upper layer about presence ack requirement
      }
    }
    if (!gSidDb[channel][uid]) {
      gSidDb[channel][uid] = sid;
      if (gMyDhKey[channel].public) {
        if (BDDEBUG) console.log("Resetting public key for sid " + sid);
        setDhPublic(channel, myuid, sid);
      }
    } else if (
      Uint8ArrayIsEqual(gSidDb[channel][uid], sid) &&
      !gMyDhKey[channel].public
    ) {
      if (BDDEBUG)
        console.log("Resetting mismatching public key for sid " + sid);
      setDhPublic(channel, myuid, sid);
    }
  }

  if (gMyDhKey[channel].public && keysz > 0) {
    const key_array = decrypted.slice(msgsz, msgsz + keysz);
    msgtype = processBd(channel, myuid, uid, msgtype, key_array);
  }

  postMessage([
    "data",
    uid,
    channel,
    msgDate.valueOf(),
    message,
    msgtype,
    fsEnabled,
  ]);
}

function msgDecode(data) {
  try {
    return CBOR.decode(data);
  } catch (err) {
    return null;
  }
}

function msgEncode(obj) {
  try {
    return CBOR.encode(obj);
  } catch (err) {
    return null;
  }
}

function processOnClose(channel) {
  gWebSocket[channel].close();
  let uid = Uint8ToString(
    nacl.secretbox.open(
      StringToUint8(atob(gMyUid[channel])),
      UIDNONCE,
      gChannelKey[channel],
    ),
  );
  postMessage(["close", uid, channel]);
}

function processOnOpen(channel, reopen) {
  //send mlesv2 init
  let join =
    '{"uid":"' + gMyUid[channel] + '","channel":"' + gMyChannel[channel] + '"}';
  gWebSocket[channel].send(join);

  let uid = Uint8ToString(
    nacl.secretbox.open(
      StringToUint8(atob(gMyUid[channel])),
      UIDNONCE,
      gChannelKey[channel],
    ),
  );
  if (false == reopen) {
    postMessage(["init", uid, channel]);
  } else {
    postMessage(["resync", uid, channel]);
  }
}

function processOnForwardSecrecy(channel, bdKey) {
  let uid = Uint8ToString(
    nacl.secretbox.open(
      StringToUint8(atob(gMyUid[channel])),
      UIDNONCE,
      gChannelKey[channel],
    ),
  );
  postMessage(["forwardsecrecy", uid, channel, bdKey.toString(16)]);
}

function processOnForwardSecrecyOff(channel) {
  let uid = Uint8ToString(
    nacl.secretbox.open(
      StringToUint8(atob(gMyUid[channel])),
      UIDNONCE,
      gChannelKey[channel],
    ),
  );
  postMessage(["forwardsecrecyoff", uid, channel]);
}

function isSocketOpen(channel) {
  if (
    gWebSocket[channel] !== undefined &&
    gWebSocket[channel].readyState == WebSocket.OPEN
  ) {
    return true;
  }
  return false;
}

function openSocket(channel, port, addr, reopen = false) {
  if (isSocketOpen(channel) && false == reopen) {
    return;
  }

  if (gWebSocket[channel] !== undefined) {
    gWebSocket[channel].close();
  }

  gWebSocket[channel] = new WebSocket(
    "wss://" + addr + ":" + port,
    "mles-websocket",
  );
  gWebSocket[channel].binaryType = "arraybuffer";
  gWebSocket[channel].onopen = function (event) {
    let ret = processOnOpen(channel, reopen);
    if (ret < 0) console.log("Process on open failed: " + ret);
  };

  gWebSocket[channel].onmessage = function (event) {
    if (event.data) {
      let msg = msgDecode(event.data);
      if (!msg) return;

      let ret = processOnMessageData(channel, msg);
      if (ret < 0) console.log("Process on message data failed: " + ret);
    }
  };

  gWebSocket[channel].onclose = function (event) {
    let ret = processOnClose(channel);
    if (ret < 0) console.log("Process on close failed: " + ret);
  };
}

function createChannelKey(key) {
  if (key.length > 32) throw new RangeError("Too large key " + key.length);
  let round = new BLAKE2b(32, {
    salt: SALTSTR,
    personalization: PERSTR,
    key: key,
  });
  round.update(DOMAIN_CHANKEY);
  let blakecb = new BLAKE2b(32, key);
  blakecb.update(DOMAIN_CHANKEY);
  blakecb.update(round.digest());
  return blakecb.digest();
}

function createMessageKey(key) {
  if (key.length > 32) throw new RangeError("Too large key " + key.length);
  let blakecbc = new BLAKE2b(32, {
    salt: SALTSTR,
    personalization: PERSTR,
    key: key,
  });
  blakecbc.update(DOMAIN_ENCKEY);
  return blakecbc.digest();
}

const MAXRND = 0x3ff;
/* Padmé: https://lbarman.ch/blog/padme/ */
function padme(msgsize) {
  //const L = msgsize + (rnd & ~msgsize & MAXRND); //with random
  const L = msgsize;
  const E = Math.floor(Math.log2(L));
  const S = Math.floor(Math.log2(E)) + 1;
  const lastBits = E - S;
  const bitMask = 2 ** lastBits - 1;
  return (L + bitMask) & ~bitMask;
}

function createPrevBd(channel, prevBdKey, channelKey) {
  let rnd = new BLAKE2b(32, {
    salt: SALTSTR,
    personalization: PERSTR,
    key: channelKey,
  });
  rnd.update(StringToUint8(prevBdKey));

  gMyDhKey[channel].prevBdChannelKey = createChannelKey(rnd.digest());
  let key = createMessageKey(rnd.digest());
  gMyDhKey[channel].prevBdMsgCryptKey = key;
}

function bdIsZeroes(bd) {
  if (null == bd) return false;
  for (let i = 0; i < bd.length; i++) {
    if (bd[i] != 0) return false;
  }
  return true;
}

function pseudoRandBytes(byteLength) {
  if (byteLength <= 0) throw new RangeError("byteLength MUST be > 0");

  let buf = new Uint8Array(byteLength);
  if (!SEED) {
    SEED = new Uint8Array(32);
    self.crypto.getRandomValues(SEED); // Use a strong initial seed
  }

  let val = new BLAKE2b(64, {
    salt: SALTSTR,
    personalization: PERSTR,
    key: SEED,
  });

  let bleft = byteLength;
  let blen = 0;

  while (bleft > 0) {
    let v = val.digest();
    let len = Math.min(v.length, bleft);
    buf.set(v.slice(0, len), blen);
    blen += len;
    bleft -= len;
    if (bleft > 0) {
      val = new BLAKE2b(64, {
        salt: SALTSTR,
        personalization: PERSTR,
        key: val.digest(),
      });
    }
  }

  // Update the global seed for next iteration
  SEED = val.digest();

  return buf;
}

function getSid(channel, myuid) {
  if (null == gMyDhKey[channel].sid) {
    let sid = new Uint8Array(8);
    self.crypto.getRandomValues(sid);
    if (null == gSidDb[channel]) initSid(channel);
    setSid(channel, myuid, sid);
  }
  //console.log("Getting getsid " +  gMyDhKey[channel].sid);
  return gMyDhKey[channel].sid;
}

function setSid(channel, myuid, sid) {
  //console.log("Setting setsid to " + sid);
  gMyDhKey[channel].bdpw = gMsgCryptKey[channel];
  gMyDhKey[channel].sid = sid;
  gSidDb[channel][myuid] = sid;
}

onmessage = function (e) {
  let cmd = e.data[0];
  let data = e.data[1];

  switch (cmd) {
    case "init":
      {
        let addr = e.data[2];
        let port = e.data[3];
        let uid = e.data[4];
        let channel = e.data[5];
        let passwd = StringToUint8(e.data[6]);
        let prevBdKey = e.data[7];
        gMyDhKey[channel] = {
          pw: null,
          bdpw: null,
          sid: null,
          group: null,
          private: null,
          public: null,
          bd: null,
          secret: null,
          secretAcked: false,
          bdMsgCryptKey: null,
          bdChannelKey: null,
          prevBdMsgCryptKey: null,
          prevBdChannelKey: null,
          fsInformed: false,
        };
        gMyAddr[channel] = addr;
        gMyPort[channel] = port;

        //salt
        let salt = new BLAKE2b(SCRYPT_SALTLEN, {
          salt: SALTSTR,
          personalization: PERSTR,
          key: passwd.slice(0, 32),
        });
        salt.update(passwd);

        //scrypt
        scrypt(
          passwd,
          salt.digest(),
          {
            N: SCRYPT_N,
            r: SCRYPT_R,
            p: SCRYPT_P,
            dkLen: SCRYPT_DKLEN,
            encoding: "binary",
          },
          function (derivedKey) {
            passwd = derivedKey;
          },
        );

        gMyDhKey[channel].pw = passwd;

        gChannelKey[channel] = createChannelKey(passwd);
        if (prevBdKey) {
          createPrevBd(channel, prevBdKey, gChannelKey[channel]);
        }

        let messageKey = createMessageKey(passwd);

        gMsgCryptKey[channel] = messageKey;
        gMyUid[channel] = btoa(
          Uint8ToString(
            nacl.secretbox(StringToUint8(uid), UIDNONCE, gChannelKey[channel]),
          ),
        );

        //wipe unused
        wipe(salt);
        wipe(passwd);
        prevBdKey = null;

        gMyChannel[channel] = btoa(
          Uint8ToString(
            nacl.secretbox(
              StringToUint8(channel),
              CHANONCE,
              gChannelKey[channel],
            ),
          ),
        );
        openSocket(channel, port, addr);
      }
      break;
    case "reconnect":
      {
        let uid = e.data[2];
        let channel = e.data[3];
        let prevBdKey = e.data[4];
        if (isSocketOpen(channel)) {
          //do not reconnect if socket is already connected
          break;
        }

        if (prevBdKey) {
          createPrevBd(channel, prevBdKey, gChannelKey[channel]);
        }

        //init databases
        initSid(channel);
        initDhBd(channel, uid);

        //wipe unused
        prevBdKey = "";

        let myuid = btoa(
          Uint8ToString(
            nacl.secretbox(StringToUint8(uid), UIDNONCE, gChannelKey[channel]),
          ),
        );
        let mychannel = btoa(
          Uint8ToString(
            nacl.secretbox(
              StringToUint8(channel),
              CHANONCE,
              gChannelKey[channel],
            ),
          ),
        );

        // verify that we have already opened the channel earlier
        if (gMyUid[channel] === myuid && gMyChannel[channel] === mychannel) {
          openSocket(channel, gMyPort[channel], gMyAddr[channel]);
        }
      }
      break;
    case "resync":
      {
        let uid = e.data[2];
        let channel = e.data[3];
        let prevBdKey = e.data[4];

        if (prevBdKey) {
          createPrevBd(channel, prevBdKey, gChannelKey[channel]);
        }

        //init databases
        initSid(channel);
        initDhBd(channel, uid);

        //wipe unused
        prevBdKey = "";

        let myuid = btoa(
          Uint8ToString(
            nacl.secretbox(StringToUint8(uid), UIDNONCE, gChannelKey[channel]),
          ),
        );
        let mychannel = btoa(
          Uint8ToString(
            nacl.secretbox(
              StringToUint8(channel),
              CHANONCE,
              gChannelKey[channel],
            ),
          ),
        );

        // verify that we have already opened the channel earlier
        if (gMyUid[channel] === myuid && gMyChannel[channel] === mychannel) {
          openSocket(channel, gMyPort[channel], gMyAddr[channel], true);
        }
      }
      break;
    case "send":
    case "resend_prev":
      {
        let uid = e.data[2];
        let channel = e.data[3];
        let msgtype = e.data[4];
        let valueofdate = e.data[5];
        let keysz = 0;

        let data_array = new TextEncoder().encode(data);

        let nonce = new Uint8Array(32);
        self.crypto.getRandomValues(nonce);

        let weekstamp = createWeekstamp(valueofdate);
        let timestamp = createTimestamp(valueofdate, weekstamp);
        let flagstamp = createFlagstamp(valueofdate, weekstamp, timestamp); //include seconds to flagstamp

        if (msgtype & MSGISFULL) flagstamp |= ISFULL;

        if (msgtype & MSGISDATA) flagstamp |= ISDATA;

        if (msgtype & MSGISPRESENCE) flagstamp |= ISPRESENCE;

        if (msgtype & MSGISPRESENCEACK) flagstamp |= ISPRESENCEACK;

        if (msgtype & MSGISMULTIPART) {
          flagstamp |= ISMULTI;
          if (msgtype & MSGISFIRST) {
            flagstamp |= ISFIRST;
          }
          if (msgtype & MSGISLAST) {
            flagstamp |= ISLAST;
          }
        }

        const msgsz = data_array.length + HDRLEN;
        let keys_array = new Uint8Array(2 * (DH_BITS / 8));
        let crypt;
        let channel_key;
        let padlen = 0;
        if (cmd == "send") {
          //add public key, if it exists
          if (gMyDhKey[channel].public) {
            let pub = gMyDhKey[channel].public;
            gDhDb[channel][uid] = pub;
            keys_array.set(pub);
            keysz += pub.length;
            if (BDDEBUG)
              console.log(
                "TX: Adding pub key " + gMyDhKey[channel].public.toString(),
              );
          } else {
            //console.log("TX: Pub key is null!");
            padlen += DH_BITS / 8;
          }
          //add BD key, if it exists
          if (gMyDhKey[channel].bd && 0 == (msgtype & MSGISPRESENCEACK)) {
            let sidcnt = Object.keys(gSidDb[channel]).length;
            if (bdIsZeroes(gMyDhKey[channel].bd)) {
              if (sidcnt == 2) {
                if (BDDEBUG) console.log("Adding ISDBONE flag");
                flagstamp |= ISBDONE;
                padlen += DH_BITS / 8;
              }
            } else {
              let bd = gMyDhKey[channel].bd;
              if (BDDEBUG) console.log("TX: Bd " + bd);
              keys_array.set(bd, keysz);
              keysz += bd.length;
            }
            let pubcnt = Object.keys(gDhDb[channel]).length;
            let bdcnt = Object.keys(gBdDb[channel]).length;
            if (BDDEBUG)
              console.log(
                "During send sidcnt " +
                  sidcnt +
                  " pubcnt " +
                  pubcnt +
                  " bdcnt " +
                  bdcnt,
              );
            if (
              sidcnt == pubcnt &&
              pubcnt == bdcnt &&
              gMyDhKey[channel].secret != null
            ) {
              flagstamp |= ISBDACK;
              if (BDDEBUG) console.log("Acking and Adding self to bdack db");
              gBdAckDb[channel][uid] = true;
            }
          } else {
            padlen += DH_BITS / 8;
          }
          if (
            gMyDhKey[channel].bdMsgCryptKey &&
            gMyDhKey[channel].secret &&
            gMyDhKey[channel].secretAcked
          ) {
            if (!gMyDhKey[channel].fsInformed) {
              processOnForwardSecrecy(channel, gMyDhKey[channel].secret);
              gMyDhKey[channel].fsInformed = true;
            }
            crypt = gMyDhKey[channel].bdMsgCryptKey;
            channel_key = gMyDhKey[channel].bdChannelKey;
          } else {
            crypt = gMsgCryptKey[channel];
            channel_key = gChannelKey[channel];
          }
        } else if (
          gMyDhKey[channel].prevBdMsgCryptKey &&
          gMyDhKey[channel].prevBdChannelKey
        ) {
          //resend_prev
          crypt = gMyDhKey[channel].prevBdMsgCryptKey;
          channel_key = gMyDhKey[channel].prevBdChannelKey;
        }

        if (!crypt || !channel_key) {
          //ignore msg
          break;
        }

        const csize = HDRLEN + data_array.length + keysz;
        //padmé padding
        const padsz = padme(csize + padlen) - csize;
        //version and msg size
        let clen = 0;
        let hdr_data_keys = new Uint8Array(
          HDRLEN + data_array.length + keysz + padsz,
        );
        hdr_data_keys.set(Uint16ValToUint8Array(msgsz));
        clen += 2;
        //sid
        const sid = getSid(channel, uid);
        hdr_data_keys.set(sid, clen);
        clen += sid.length;
        //keysz
        hdr_data_keys.set(Uint16ValToUint8Array(keysz), clen);
        clen += 2;
        //stamps
        hdr_data_keys.set(Uint16ValToUint8Array(timestamp), clen);
        clen += 2;
        hdr_data_keys.set(Uint16ValToUint8Array(weekstamp), clen);
        clen += 2;
        hdr_data_keys.set(Uint16ValToUint8Array(flagstamp), clen);
        clen += 2;
        hdr_data_keys.set(data_array, clen);
        hdr_data_keys.set(keys_array.slice(0, keysz), clen + data_array.length);

        if (padsz > 0) {
          const pad_array = pseudoRandBytes(padsz); // avoid using real random for padding
          hdr_data_keys.set(pad_array, clen + data_array.length + keysz);
        }
        let encrypted = nacl.secretbox(
          hdr_data_keys,
          nonce.slice(0, 24),
          crypt,
        );

        // calculate hmac
        let hmacarr = new Uint8Array(nonce.byteLength + encrypted.byteLength);
        hmacarr.set(nonce, 0);
        hmacarr.set(encrypted, nonce.byteLength);

        let blakehmac = new BLAKE2b(HMAC_LEN, {
          salt: SALTSTR,
          personalization: PERSTR,
          key: channel_key,
        });
        blakehmac.update(DOMAIN_AUTHKEY);
        blakehmac.update(nonce.slice(24));
        blakehmac.update(hmacarr);
        let hmac = blakehmac.digest();

        let newarr = new Uint8Array(
          nonce.byteLength + encrypted.byteLength + hmac.byteLength,
        );
        newarr.set(nonce, 0);
        newarr.set(encrypted, nonce.byteLength);
        newarr.set(hmac, nonce.byteLength + encrypted.byteLength);
        //console.log("Send message " + arr);
        //encrypted = nacl.secretbox(StringToUint8(newmessage), nonce.slice(0,24), crypt);
        let obj = {
          uid: btoa(
            Uint8ToString(
              nacl.secretbox(
                StringToUint8(uid),
                UIDNONCE,
                gChannelKey[channel],
              ),
            ),
          ),
          channel: btoa(
            Uint8ToString(
              nacl.secretbox(
                StringToUint8(channel),
                CHANONCE,
                gChannelKey[channel],
              ),
            ),
          ),
          message: newarr,
        };
        let encodedMsg = msgEncode(obj);
        if (!encodedMsg) break;
        try {
          gWebSocket[channel].send(encodedMsg);
        } catch (err) {
          break;
        }
        postMessage([
          "send",
          uid,
          channel,
          msgtype & MSGISMULTIPART ? true : false,
        ]);
      }
      break;
    case "close":
      {
        let uid = e.data[2];
        let channel = e.data[3];
        gWebSocket[channel].close();
        initSid(channel);
        initDhBd(channel, uid);
        initPrevDhBd(channel, uid);
      }
      break;
  }
};
