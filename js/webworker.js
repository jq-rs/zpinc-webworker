/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019-2020, 2024 MlesTalk WebWorker developers
 * Copyright (c) 2020-2022 Zpinc developers
 */


importScripts('cbor.js', 'blake2b.js', 'scrypt-async.js', 'nacl.js', 'ristretto255.js', 'wipe.js', 'int.js', 'binary.js');

let gWebSocket = {};
let gMyAddr = {};
let gMyPort = {};
let gMyUid = {};
let gMyChannel = {};
let gChannelKey = {};
let gMsgCryptKey = {};
const ISFULL = 0x8000
const ISDATA = 0x4000;
const ISPRESENCE = 0x2000;
const ISPRESENCEACK = 0x1000;
const ISMULTI = 0x800;
const ISFIRST = 0x400;
const ISLAST = 0x200;
const ISBDONE = 0x100;
const ISBDACK = 0x80;
const ALLISSET = 0X7F;
const BEGIN = new Date(Date.UTC(2018, 0, 1, 0, 0, 0));
const HMAC_LEN = 12;
const NONCE_LEN = 32;
const DOMAIN_ENCKEY = StringToUint8("Zpinc-WebWorkerEncryptDom!v1");
const DOMAIN_CHANKEY = StringToUint8("Zpinc-WebWorkerChannelDom!v1");
const DOMAIN_AUTHKEY = StringToUint8("Zpinc-WebWorkerAuthDom!v1");

/* For static uid and channel we use static nonces */
const UIDNONCE = new Uint8Array([ 2,   3,   5,   7,  11,  13,  17,  19,
								 23,  29,  31,  37,  41,  43,  47,  53,
								 59,  61,  67,  71,  73,  79,  83,  89]);
const CHANONCE = new Uint8Array([0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
								 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
								 0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0]);
const SALTSTR = StringToUint8("ZpincSaltDomain1");
const PERSTR = StringToUint8('ZpincAppDomainv1');
const PERBDSTR = StringToUint8('ZpincBdDomain!v1');
const HDRLEN = 18;

/* Msg type flags */
const MSGISFULL =         0x1;
const MSGISPRESENCE =    (0x1 << 1);
const MSGISDATA =        (0x1 << 2);
const MSGISMULTIPART =   (0x1 << 3);
const MSGISFIRST =       (0x1 << 4);
const MSGISLAST =        (0x1 << 5);
const MSGISPRESENCEACK = (0x1 << 6);
const MSGPRESACKREQ =    (0x1 << 7);
const MSGISBDONE =       (0x1 << 8);
const MSGISBDACK =	 (0x1 << 9);

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

function utf8Decode(string) {
	return decodeURIComponent(string);
}

function utf8Encode(utftext) {
	return encodeURIComponent(utftext);
}

function createFlagstamp(valueofdate, weekstamp, timestamp) {
	let begin = BEGIN;
	let this_time = new Date(begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7 + timestamp * 1000 * 60);
	let flagstamp = parseInt((valueofdate - this_time) / 1000);
	return flagstamp;
}

function createTimestamp(valueofdate, weekstamp) {
	let begin = BEGIN;
	let this_week = new Date(begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7);
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

function isEqualSid(sid1, sid2) {
	for (let i = 0; i < sid1.byteLength; i++) {
		if (sid1[i] != sid2[i]) {
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
	let str = new String('');
	if(!arr)
		return str;
	for (let i = 0; i < arr.length; i++) {
		str += String.fromCharCode(arr[i]);
	}
	return str;
}

function StringToUint16Val(str) {
	return ((str.charCodeAt(0) & 0xff) << 8) | (str.charCodeAt(1) & 0xff);
}

function Uint16ValToString(val) {
	let str = new String('');
	str += String.fromCharCode((val & 0xff00) >> 8);
	str += String.fromCharCode(val & 0xff);
	return str;
}

function initBd(channel, myuid) {
	gBdDb[channel] = {};
	gBdAckDb[channel] = {};
	gMyDhKey[channel].secret = null;
	gMyDhKey[channel].secretAcked = false;
	gMyDhKey[channel].bd = null;
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
}

function initDhBd(channel, myuid) {
	gDhDb[channel] = {};
	gBdDb[channel] = {};
	gBdAckDb[channel] = {};
	if (gMyDhKey[channel].public) {
		gDhDb[channel][myuid] = Uint8ToString(gMyDhKey[channel].public);
	}
	gMyDhKey[channel].secret = null;
	gMyDhKey[channel].secretAcked = false;
	gMyDhKey[channel].bd = null;
	gMyDhKey[channel].bdMsgCryptKey = null;
	if (gMyDhKey[channel].fsInformed) {
		processOnForwardSecrecyOff(channel);
		gMyDhKey[channel].fsInformed = false;
	}
}

function setDhPublic(channel, myuid, sid) {
	let siddb_sorted = Object.fromEntries(Object.entries(gSidDb[channel]).sort());

	let pubok = true;
	let cnt = 0;
	let users = "";
	for (let userid in siddb_sorted) {
		console.log("Found sid " +  gSidDb[channel][userid] + " for user " + userid);
		if(!isEqualSid(gSidDb[channel][userid], sid)) {
			pubok = false;
			break;
		}
		users += userid;
		cnt++;
	}
	if(pubok && cnt > 1) {
		//console.log("Setting public key for sid " + sid + " cnt " + cnt);
		let sid16 = new Uint8Array(16);
		sid16.set(sid, 0);
		const userarr = StringToUint8(users);
		let arr = new Uint8Array(userarr.byteLength);
		arr.set(userarr, 0);
		const digest64B = new BLAKE2b(64, { salt: sid16, personalization: PERBDSTR, key: gMsgCryptKey[channel] });
		gMyDhKey[channel].group = ristretto255.fromHash(digest64B.digest());
		gMyDhKey[channel].private = ristretto255.scalar.getRandom();
		gMyDhKey[channel].public = ristretto255.scalarMult(gMyDhKey[channel].private, gMyDhKey[channel].group);
		gDhDb[channel][myuid] = Uint8ToString(gMyDhKey[channel].public);
	}
}

function initPrevDhBd(channel, myuid) {
	gMyDhKey[channel].prevBdChannelKey = null;
	gMyDhKey[channel].prevBdMsgCryptKey = null;
}

function bdSetZeroes() {
	let bdin = new Uint8Array(DH_BITS/8);
	for (let i = 0; i < bdin.length; i++) {
		bdin[i] = 0;
	}
	return Uint8ToString(bdin);
}

const BDDEBUG = true;
function processBd(channel, myuid, uid, msgtype, message) {
	let init = false;

	if(uid == myuid) {  //received own message, init due to resyncing
		initDhBd(channel, myuid);
		init = true;
	}
	else if (message.length == DH_BITS/8 || message.length == 2 * (DH_BITS/8)) {
		if(BDDEBUG)
			console.log("Got " + uid + " public+bd key, len " + message.length);

		if (message.length == DH_BITS/8 && 0 == (msgtype & MSGISBDONE) && 0 == (msgtype & MSGISBDACK)) {
			if ((msgtype & MSGISPRESENCE) && 0 == (msgtype & MSGISPRESENCEACK)) {
				msgtype |= MSGPRESACKREQ; // inform upper layer about presence ack requirement
				if(BDDEBUG)
					console.log("Request presence ack for " + myuid + "@" + channel);
			}
			if(BDDEBUG)
				console.log("!!! bd invalidated in short message !!!");
			initBd(channel, myuid);
		}

		let pub = message.substring(0, DH_BITS/8);
		if (null == gDhDb[channel][uid]) {
			gDhDb[channel][uid] = pub;
		}
		else if (message.length == DH_BITS/8 && 0 == (msgtype & MSGISBDONE) && gDhDb[channel][uid] && gBdDb[channel][uid]) {
			initDhBd(channel, myuid);
			if(BDDEBUG)
				console.log("!!! skey invalidated in short message as with existing bd!!!");
			gDhDb[channel][uid] = pub;
			init = true;
		}
		else if(false == init) {
			//calculate bd key
			if(!gBdDb[channel])
				gBdDb[channel] = {};
			let prevkey = null;
			let nextkey = null;
			let index = 0;
			let pubcnt = 0;
			let dhdb_sorted = Object.fromEntries(Object.entries(gDhDb[channel]).sort());
			let keys = [];
			for (let userid in dhdb_sorted) {
				if (userid == myuid) {
					index = pubcnt;
				}
				keys.push(StringToUint8(gDhDb[channel][userid]));
				pubcnt++;
			}

			const len = keys.length;
			if (index == 0) {
				prevkey = keys[len - 1];
				nextkey = keys[index + 1];
			}
			else if (index == len - 1) {
				prevkey = keys[index - 1];
				nextkey = keys[0];
			}
			else {
				prevkey = keys[index - 1];
				nextkey = keys[index + 1];
			}
			if (prevkey && nextkey) {
				let step = ristretto255.sub(nextkey, prevkey);
				gMyDhKey[channel].bd = ristretto255.scalarMult(gMyDhKey[channel].private, step);
				//console.log("Setting Bd " + gMyDhKey[channel].bd);
				gBdDb[channel][myuid] = Uint8ToString(gMyDhKey[channel].bd);
			}

			if (message.length == 2 * (DH_BITS/8) || (message.length == DH_BITS/8 && (msgtype & MSGISBDONE))) {
				let bd = bdSetZeroes();
				let len = 0;
				if (message.length == 2 * (DH_BITS/8))
					len = 2 * DH_BITS/8;

				if(len)
					bd = message.substring(DH_BITS/8, len);

				if (gBdDb[channel][uid] != null && gBdDb[channel][uid] != bd) {
					//start again
					initBd(channel, myuid);
					if(BDDEBUG)
						console.log("!!! skey invalidated in mismatching bd !!!");
					gDhDb[channel][uid] = pub;
				}
				else if ((pubcnt > 2 && bdIsZeroes(StringToUint8(bd))) || (pubcnt == 2 && !bdIsZeroes(StringToUint8(bd)))) {
					initDhBd(channel, myuid);
					if(BDDEBUG)
						console.log("!!! skey invalidated in mismatching bd length!!! pubcnt " + pubcnt);
					gDhDb[channel][uid] = pub;
					if ((msgtype & MSGISPRESENCE) && 0 == (msgtype & MSGISPRESENCEACK)) {
						msgtype |= MSGPRESACKREQ; // inform upper layer about presence ack requirement
						if(BDDEBUG)
							console.log("Request presence ack for " + myuid + "@" + channel);
					}
					init = true;
				}
				else if (gBdDb[channel][uid] == bd) {
					//BD matches, do nothing
				}
				else {
					gBdDb[channel][uid] = bd;

					let bdcnt = 0;
					let xkeys = [];
					let bddb_sorted = Object.fromEntries(Object.entries(gBdDb[channel]).sort());
					for (let userid in bddb_sorted) {
						if (userid == myuid) {
							index = bdcnt;
						}
						xkeys.push(StringToUint8(gBdDb[channel][userid]));
						bdcnt++;
					}

					if (bdcnt == pubcnt) {
						//multiply by len
						const len = xkeys.length;
						let skey = ristretto255.scalarMult(gMyDhKey[channel].private, prevkey);
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

						let rnd = new BLAKE2b(32, { salt: SALTSTR, personalization: PERSTR, key: gChannelKey[channel]});
						rnd.update(StringToUint8(gMyDhKey[channel].secret.toString(16)));

						gMyDhKey[channel].bdChannelKey = createChannelKey(rnd.digest());
						let key = createMessageKey(rnd.digest());

						gMyDhKey[channel].bdMsgCryptKey = key;
						console.log("Created key msg crypt! " + key)

						//wipe unused
						wipe(rnd);
						wipe(key);
					}
				}
				//if bd handling fails, ignore large handling
				if (false == init && ((message.length == DH_BITS/8 && msgtype & MSGISBDACK) || message.length == 2 * (DH_BITS/8))) {
					if (gMyDhKey[channel].secretAcked) {
						//do nothing, already acked
						//console.log("Nothing to do, already acked");
					}
					else {
						if(!gBdAckDb[channel])
							gBdAckDb[channel] = {};
						//check first that pub and bd are ok
						if (gDhDb[channel][uid] && gBdDb[channel][uid]) {
							gBdAckDb[channel][uid] = true;
							let pubcnt = Object.keys(gDhDb[channel]).length;
							let bdcnt = Object.keys(gBdDb[channel]).length;
							let ackcnt = Object.keys(gBdAckDb[channel]).length;
							//ack received from everyone else?
							console.log("Ackcnt " + ackcnt + " pubcnt " + pubcnt + " bdcnt " + bdcnt);
							if (pubcnt == bdcnt && ackcnt == pubcnt &&
								(message.length == DH_BITS/8 && (msgtype & MSGISBDACK) && (msgtype & MSGISBDONE) && pubcnt == 2 ||
								 message.length == 2 * (DH_BITS/8) && (msgtype & MSGISBDACK) && pubcnt > 2)) {

								console.log("Ack count matches to pub&bdcnt, enabling send encryption!");
								gMyDhKey[channel].secretAcked = true;
							}
						}
						else {
							//start again
							initBd(channel, myuid);
							if(BDDEBUG)
								console.log("!!! bds invalidated in ack !!!");
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
	if (msg.message.byteLength <= NONCE_LEN || msg.message.byteLength > 0xffffff) {
		return;
	}

	let fsEnabled = false;
	let noncem = msg.message.slice(0, NONCE_LEN);
	let arr = msg.message.slice(NONCE_LEN, msg.message.byteLength - HMAC_LEN);
	let hmac = msg.message.slice(msg.message.byteLength - HMAC_LEN, msg.message.byteLength)
	let message = arr;

	//verify first hmac
	let hmacarr = new Uint8Array(noncem.byteLength + arr.byteLength);
	hmacarr.set(noncem, 0);
	hmacarr.set(arr, noncem.byteLength);
	let hmacok = false;
	let crypt; //selected crypt object

	//try all three options
	if(gMyDhKey[channel].bdMsgCryptKey) {
		let blakehmac = new BLAKE2b(HMAC_LEN, { salt: SALTSTR, personalization: PERSTR, key: gMyDhKey[channel].bdChannelKey });
		blakehmac.update(DOMAIN_AUTHKEY);
		blakehmac.update(noncem.slice(24));
		blakehmac.update(hmacarr);
		let rhmac = blakehmac.digest();
		if (true == isEqualHmacs(hmac, rhmac)) {
			hmacok = true;
			crypt = gMyDhKey[channel].bdMsgCryptKey;
			//console.log("Current crypt matches");
			fsEnabled = true;
		}
	}
	if(!hmacok && gMyDhKey[channel].prevBdMsgCryptKey) {
		let blakehmac = new BLAKE2b(HMAC_LEN, { salt: SALTSTR, personalization: PERSTR, key: gMyDhKey[channel].prevBdChannelKey });
		blakehmac.update(DOMAIN_AUTHKEY);
		blakehmac.update(noncem.slice(24));
		blakehmac.update(hmacarr);
		let rhmac = blakehmac.digest();
		if (true == isEqualHmacs(hmac, rhmac)) {
			hmacok = true;
			crypt = gMyDhKey[channel].prevBdMsgCryptKey;
			//console.log("Prev crypt matches");
			fsEnabled = true;
		}
	}
	if(!hmacok) {
		let blakehmac = new BLAKE2b(HMAC_LEN, { salt: SALTSTR, personalization: PERSTR, key: gChannelKey[channel] });
		blakehmac.update(DOMAIN_AUTHKEY);
		blakehmac.update(noncem.slice(24));
		blakehmac.update(hmacarr);
		let rhmac = blakehmac.digest();
		if (false == isEqualHmacs(hmac, rhmac)) {
			console.log("Dropping");
			return;
		}
		crypt = gMsgCryptKey[channel];
	}

	let uid = utf8Decode(Uint8ToString(nacl.secretbox.open(StringToUint8(atob(msg.uid)), UIDNONCE, gChannelKey[channel])));
	//let channel = utf8Decode(Uint8ToString(nacl.secretbox.open(StringToUint8(atob(msg.channel)), CHANONCE, gChannelKey[channel])));
	let decrypted = Uint8ToString(nacl.secretbox.open(message, noncem.slice(0,24), crypt));

	if (decrypted.length < HDRLEN) {
		console.log("Dropping 2");
		return;
	}

	let msgsz = StringToUint16Val(decrypted.slice(0, 2)); //includes also version which is zero
	let sid = StringToUint8(decrypted.slice(2, 10));
	let keysz = StringToUint16Val(decrypted.slice(10, 12));
	
	//let padsz = decrypted.length - msgsz - keysz;
	//console.log("RX: Msgsize " + msgsz + " Sid " + sid + " Keysz " + keysz + " Pad size " + padsz);

	let timeU16 = StringToUint16Val(decrypted.slice(12, 14));
	let weekU16 = StringToUint16Val(decrypted.slice(14, 16));
	let flagU16 = StringToUint16Val(decrypted.slice(16, HDRLEN));

	let msgDate = readTimestamp(timeU16, weekU16, flagU16 & ALLISSET);

	message = utf8Decode(decrypted.slice(HDRLEN, msgsz));

	let msgtype = 0;
	if (flagU16 & ISFULL)
		msgtype |= MSGISFULL;
	if (flagU16 & ISDATA)
		msgtype |= MSGISDATA;
	if (flagU16 & ISPRESENCE)
		msgtype |= MSGISPRESENCE;
	if (flagU16 & ISPRESENCEACK)
		msgtype |= MSGISPRESENCEACK;
	if (flagU16 & ISMULTI)
		msgtype |= MSGISMULTIPART;
	if (flagU16 & ISFIRST)
		msgtype |= MSGISFIRST;
	if (flagU16 & ISLAST)
		msgtype |= MSGISLAST;
	if (flagU16 & ISBDONE)
		msgtype |= MSGISBDONE;
	if (flagU16 & ISBDACK)
		msgtype |= MSGISBDACK;

	const myuid = utf8Decode(Uint8ToString(nacl.secretbox.open(StringToUint8(atob(gMyUid[channel])), UIDNONCE, gChannelKey[channel])));
	if(myuid == uid) { //resync
		initSid(channel);
		initDhBd(channel, uid);
	}
	else if (uid != myuid) {
		if (!gMyDhKey[channel].sid || !isEqualSid(gMyDhKey[channel].sid, sid)) {
			initSid(channel);
			initDhBd(channel, myuid);
			setSid(channel, myuid, sid);
			//console.log("RX: setting sid to " + sid + " mysid " + gMyDhKey[channel].sid);
			if (!(msgtype & MSGISPRESENCEACK)) {
				msgtype |= MSGPRESACKREQ; // inform upper layer about presence ack requirement
			}
		}
		if(!gSidDb[channel][uid]) {
			gSidDb[channel][uid] = sid;
			if(gMyDhKey[channel].public) {
				console.log("Resetting public key for sid " + sid);
				setDhPublic(channel, myuid, sid);
			}
		}
		else if(isEqualSid(gSidDb[channel][uid], sid) && !gMyDhKey[channel].public) {
			setDhPublic(channel, myuid, sid);
		}
	}

	if(gMyDhKey[channel].public && keysz > 0) {
		const keystr = decrypted.slice(msgsz, msgsz+keysz);
		msgtype = processBd(channel, myuid, uid, msgtype, keystr);
	}

	postMessage(["data", uid, channel, msgDate.valueOf(), message, msgtype, fsEnabled]);
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
	let uid = utf8Decode(Uint8ToString(nacl.secretbox.open(StringToUint8(atob(gMyUid[channel])), UIDNONCE, gChannelKey[channel])));
	postMessage(["close", uid, channel]);
}

function processOnOpen(channel, reopen) {
	//send mlesv2 init
	let join = '{"uid":"' + gMyUid[channel] + '","channel":"' + gMyChannel[channel] + '"}';
	gWebSocket[channel].send(join);

	let uid = utf8Decode(Uint8ToString(nacl.secretbox.open(StringToUint8(atob(gMyUid[channel])), UIDNONCE, gChannelKey[channel])));
	if(false == reopen) {
		postMessage(["init", uid, channel]);
	}
	else {
		postMessage(["resync", uid, channel]);
	}
}

function processOnForwardSecrecy(channel, bdKey) {
	let uid = utf8Decode(Uint8ToString(nacl.secretbox.open(StringToUint8(atob(gMyUid[channel])), UIDNONCE, gChannelKey[channel])));
	postMessage(["forwardsecrecy", uid, channel, bdKey.toString(16)]);
}

function processOnForwardSecrecyOff(channel) {
	let uid = utf8Decode(Uint8ToString(nacl.secretbox.open(StringToUint8(atob(gMyUid[channel])), UIDNONCE, gChannelKey[channel])));
	postMessage(["forwardsecrecyoff", uid, channel]);
}

function isSocketOpen(channel) {
	if (gWebSocket[channel] !== undefined && gWebSocket[channel].readyState == WebSocket.OPEN) {
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

	gWebSocket[channel] = new WebSocket("wss://" + addr + ":" + port, "mles-websocket");
	gWebSocket[channel].binaryType = "arraybuffer";
	gWebSocket[channel].onopen = function (event) {
		let ret = processOnOpen(channel, reopen);
		if(ret < 0)
			console.log("Process on open failed: " + ret);

	};

	gWebSocket[channel].onmessage = function (event) {
		if (event.data) {
			let msg = msgDecode(event.data);
			if(!msg)
				return;

			let ret = processOnMessageData(channel, msg);
			if(ret < 0)
				console.log("Process on message data failed: " + ret);
		}
	};

	gWebSocket[channel].onclose = function (event) {
		let ret = processOnClose(channel);
		if(ret < 0)
			console.log("Process on close failed: " + ret)
	};
}

function createChannelKey(key) {
	if(key.length > 32)
		throw new RangeError("Too large key " + key.length);
	let round = new BLAKE2b(32, { salt: SALTSTR, personalization: PERSTR, key: key });
	round.update(DOMAIN_CHANKEY);
	let blakecb = new BLAKE2b(32, key);
	blakecb.update(DOMAIN_CHANKEY);
	blakecb.update(round.digest());
	return blakecb.digest();
}

function createMessageKey(key) {
	if(key.length > 32)
		throw new RangeError("Too large key " + key.length);
	let blakecbc = new BLAKE2b(32, { salt: SALTSTR, personalization: PERSTR, key: key });
	blakecbc.update(DOMAIN_ENCKEY);
	return blakecbc.digest();
}

const MAXRND = 0x3ff;
/* Padmé: https://lbarman.ch/blog/padme/ */
function padme(msgsize) {
	//const L = msgsize + (rnd & ~msgsize & MAXRND); //with random
	const L = msgsize;
	const E = Math.floor(Math.log2(L));
	const S = Math.floor(Math.log2(E))+1;
	const lastBits = E-S;
	const bitMask = 2 ** lastBits - 1;
	return (L + bitMask) & ~bitMask;
}

function createPrevBd(channel, prevBdKey, channelKey) {
	let rnd = new BLAKE2b(32, { salt: SALTSTR, personalization: PERSTR, key: channelKey });
	rnd.update(StringToUint8(prevBdKey));

	//console.log("Setting prev channel key and crypt");
	gMyDhKey[channel].prevBdChannelKey = createChannelKey(rnd.digest());
	let key = createMessageKey(rnd.digest());
	gMyDhKey[channel].prevBdMsgCryptKey = key;
}

function bdIsZeroes(bd) {
	if (null == bd)
		return false;
	for(let i = 0; i < bd.length; i++) {
		if(bd[i] != 0)
			return false;
	}
	return true;
}

function pseudoRandBytes(byteLength) {
	if (byteLength <= 0)
		throw new RangeError('byteLength MUST be > 0');

	let blen = 0;
	let bleft = byteLength;
	let buf = new Uint8Array(byteLength);
	if (!SEED) {
		SEED = new Uint8Array(32);
		self.crypto.getRandomValues(SEED); // avoid using extensive amount of secure random
	}
	let val = new BLAKE2b(64, { salt: SALTSTR, personalization: PERSTR, key: SEED });

	while (bleft > 0) {
		for (let i = 0; i < 64; i++) {
			let v = val.digest();
			buf[blen++] = v[i];
			bleft--;
			if (0 == bleft) {
				SEED = val.digest();
				break;
			}
			val = new BLAKE2b(64, { salt: SALTSTR, personalization: PERSTR, key: val.digest() });
		}
	}
	return buf;
}

function getSid(channel, myuid) {
	if (null == gMyDhKey[channel].sid) {
		let sid = new Uint8Array(8);
		self.crypto.getRandomValues(sid);
		if (null == gSidDb[channel])
			initSid(channel);
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
				let uid = utf8Encode(e.data[4]);
				let channel = utf8Encode(e.data[5]);
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
				       fsInformed: false
				};
				gMyAddr[channel] = addr;
				gMyPort[channel] = port;

				//salt
				let salt = new BLAKE2b(SCRYPT_SALTLEN, { salt: SALTSTR, personalization: PERSTR, key: passwd.slice(0, 32) });
				salt.update(passwd);

				//scrypt
				scrypt(passwd, salt.digest(), {
					N: SCRYPT_N,
					r: SCRYPT_R,
					p: SCRYPT_P,
					dkLen: SCRYPT_DKLEN,
					encoding: 'binary'
				}, function(derivedKey) {
					passwd = derivedKey;
				});

				gMyDhKey[channel].pw = passwd;

				gChannelKey[channel] = createChannelKey(passwd);
				if(prevBdKey) {
					createPrevBd(channel, prevBdKey, gChannelKey[channel]);
				}

				let messageKey = createMessageKey(passwd);

				gMsgCryptKey[channel] = messageKey;
				gMyUid[channel] = btoa(Uint8ToString(nacl.secretbox(StringToUint8(uid), UIDNONCE, gChannelKey[channel])));

				//wipe unused
				wipe(salt);
				wipe(passwd);
				wipe(messageKey);
				prevBdKey = null;

				gMyChannel[channel] = btoa(Uint8ToString(nacl.secretbox(StringToUint8(channel), CHANONCE, gChannelKey[channel])));
				openSocket(channel, port, addr);
			}
			break;
		case "reconnect":
			{
				let uid = utf8Encode(e.data[2]);
				let channel = utf8Encode(e.data[3]);
				let prevBdKey = e.data[4];
				if(isSocketOpen(channel)) { //do not reconnect if socket is already connected
					break;
				}

				if(prevBdKey) {
					createPrevBd(channel, prevBdKey, gChannelKey[channel]);
				}
				gMyDhKey[channel].private = ristretto255.scalar.getRandom();
				gMyDhKey[channel].public = ristretto255.scalarMult(gMyDhKey[channel].private, gMyDhKey[channel].group);

				//init databases
				initSid(channel);
				initDhBd(channel, uid);

				//wipe unused
				prevBdKey="";

				uid = btoa(Uint8ToString(nacl.secretbox(StringToUint8(uid), UIDNONCE, gChannelKey[channel])));
				channel = btoa(Uint8ToString(nacl.secretbox(StringToUint8(channel), CHANONCE, gChannelKey[channel])));

				// verify that we have already opened the channel earlier
				if (gMyUid[channel] === uid && gMyChannel[channel] === channel) {
					openSocket(channel, gMyPort[channel], gMyAddr[channel]);
				}
			}
			break;
		case "send":
		case "resend_prev":
			{
				let uid = utf8Encode(e.data[2]);
				let channel = utf8Encode(e.data[3]);
				let msgtype = e.data[4];
				let valueofdate = e.data[5];
				let keysz = 0;

				data = utf8Encode(data);

				let nonce = new Uint8Array(32);
				self.crypto.getRandomValues(nonce);

				let weekstamp = createWeekstamp(valueofdate);
				let timestamp = createTimestamp(valueofdate, weekstamp);
				let flagstamp = createFlagstamp(valueofdate, weekstamp, timestamp); //include seconds to flagstamp

				if (msgtype & MSGISFULL)
					flagstamp |= ISFULL;

				if (msgtype & MSGISDATA)
					flagstamp |= ISDATA;

				if (msgtype & MSGISPRESENCE)
					flagstamp |= ISPRESENCE;

				if (msgtype & MSGISPRESENCEACK)
					flagstamp |= ISPRESENCEACK;

				if (msgtype & MSGISMULTIPART) {
					flagstamp |= ISMULTI;
					if (msgtype & MSGISFIRST) {
						flagstamp |= ISFIRST;
					}
					if (msgtype & MSGISLAST) {
						flagstamp |= ISLAST;
					}
				}

				const msgsz = data.length + HDRLEN;
				let newmessage;
				let encrypted;
				let crypt;
				let channel_key;
				let padlen = 0;
				if(cmd == "send") {
					//add public key, if it exists
					if (gMyDhKey[channel].public) {
						let pub = Uint8ToString(gMyDhKey[channel].public);
						keysz += pub.length;
						data += pub;
						console.log("TX: Adding pub key");
					}
					else {
						//console.log("TX: Pub key is null!");
						padlen += DH_BITS/8;
					}
					//add BD key, if it exists
					if (gMyDhKey[channel].bd && 0 == (msgtype & MSGISPRESENCEACK)) {
						let sidcnt = Object.keys(gSidDb[channel]).length;
						if(bdIsZeroes(gMyDhKey[channel].bd)) {
							if (sidcnt == 2) {
								console.log("Adding ISDBONE flag");
								flagstamp |= ISBDONE;
								padlen += DH_BITS/8;
							}
						}
						else {
							let bd = Uint8ToString(gMyDhKey[channel].bd);
							console.log("TX: Bd");
							keysz += bd.length;
							data += bd;
						}
						let pubcnt = Object.keys(gDhDb[channel]).length;
						let bdcnt = Object.keys(gBdDb[channel]).length;
						console.log("During send sidcnt " + sidcnt + " pubcnt " + pubcnt + " bdcnt " + bdcnt);
						if (sidcnt == pubcnt && pubcnt == bdcnt && gMyDhKey[channel].secret != null) {
							flagstamp |= ISBDACK;
							if (gBdAckDb[channel][uid] == null) {
								console.log("Adding self to bdack db");
								gBdAckDb[channel][uid] = true;
							}
						}
					}
					else {
						padlen += DH_BITS/8;
					}
					if (gMyDhKey[channel].bdMsgCryptKey && gMyDhKey[channel].secret && gMyDhKey[channel].secretAcked) {
						if (!gMyDhKey[channel].fsInformed) {
							processOnForwardSecrecy(channel, gMyDhKey[channel].secret);
							gMyDhKey[channel].fsInformed = true;
						}
						crypt = gMyDhKey[channel].bdMsgCryptKey;
						channel_key = gMyDhKey[channel].bdChannelKey;
					}
					else {
						crypt = gMsgCryptKey[channel];
						channel_key = gChannelKey[channel];
					}
				}
				else if (gMyDhKey[channel].prevBdMsgCryptKey && gMyDhKey[channel].prevBdChannelKey) { //resend_prev
					crypt = gMyDhKey[channel].prevBdMsgCryptKey;
					channel_key = gMyDhKey[channel].prevBdChannelKey;
				}

				if(!crypt || !channel_key) {
					//ignore msg
					break;
				}

				//version and msg size
				newmessage = Uint16ValToString(msgsz);
				//sid
				const sid = getSid(channel, uid);
				newmessage += Uint8ToString(sid);
				//keysz
				newmessage += Uint16ValToString(keysz);
				//stamps
				newmessage += Uint16ValToString(timestamp);
				newmessage += Uint16ValToString(weekstamp);
				newmessage += Uint16ValToString(flagstamp);

				//message itself
				newmessage += data;

				const msglen = msgsz + keysz;
				//padmé padding
				const padsz = padme(msglen + padlen) - msglen;
				//console.log("TX: Msgsize " + msgsz + " Sid " + sid + " padding sz " + padsz + " keysz " + keysz)
				if(padsz > 0) {
					let padding = pseudoRandBytes(padsz); // avoid using real random for padding
					newmessage += Uint8ToString(padding);
				}

				encrypted = nacl.secretbox(StringToUint8(newmessage), nonce.slice(0,24), crypt);
				let arr = encrypted;

				// calculate hmac
				let hmacarr = new Uint8Array(nonce.byteLength + arr.byteLength);
				hmacarr.set(nonce, 0);
				hmacarr.set(arr, nonce.byteLength);

				let blakehmac = new BLAKE2b(HMAC_LEN, { salt: SALTSTR, personalization: PERSTR, key: channel_key });
				blakehmac.update(DOMAIN_AUTHKEY);
				blakehmac.update(nonce.slice(24));
				blakehmac.update(hmacarr);
				let hmac = blakehmac.digest();

				let newarr = new Uint8Array(nonce.byteLength + arr.byteLength + hmac.byteLength);
				newarr.set(nonce, 0);
				newarr.set(arr, nonce.byteLength);
				newarr.set(hmac, nonce.byteLength + arr.byteLength);
				let obj = {
					uid: btoa(Uint8ToString(nacl.secretbox(StringToUint8(uid), UIDNONCE, gChannelKey[channel]))),
					channel: btoa(Uint8ToString(nacl.secretbox(StringToUint8(channel), CHANONCE, gChannelKey[channel]))),
					message: newarr
				};
				let encodedMsg = msgEncode(obj);
				if(!encodedMsg)
					break;
				try {
					gWebSocket[channel].send(encodedMsg);
				} catch (err) {
					break;
				}
				postMessage(["send", utf8Decode(uid), utf8Decode(channel), msgtype & MSGISMULTIPART ? true : false]);
			}
			break;
		case "close":
			{
				let uid = utf8Encode(e.data[2]);
				let channel = e.data[3];
				gWebSocket[channel].close();
				initSid(channel);
				initDhBd(channel, uid);
				initPrevDhBd(channel, uid);
			}
			break;
	}
}
