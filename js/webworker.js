/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019-2020,2024-2025 MlesTalk WebWorker developers
 * Copyright (c) 2020-2021 Zpinc developers
 */

/**
 * Zpinc WebWorker - Zero-Trust Secure Group Messaging Protocol
 *
 * This implementation follows the Zpinc protocol specification for secure
 * messaging without requiring trust in server infrastructure.
 *
 * The protocol provides:
 * - Confidentiality and integrity through authenticated encryption
 * - Forward secrecy and post-compromise security via ephemeral keys
 * - Group authentication with shared secret keys
 * - Asynchronous messaging capability
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

// Module structure using IIFE pattern to reduce global state
const ZpincWorker = (function () {
  // =========================================================================
  // Constants
  // =========================================================================
  const CONSTANTS = {
    // Protocol flags
    ISFULL: 0x8000,
    ISDATA: 0x4000,
    ISPRESENCE: 0x2000,
    ISPRESENCEACK: 0x1000,
    ISMULTI: 0x800,
    ISFIRST: 0x400,
    ISLAST: 0x200,
    ISBDONE: 0x100,
    ISBDACK: 0x80,
    ALLISSET: 0x7f,

    // Message type flags
    MSGISFULL: 0x1,
    MSGISPRESENCE: 0x1 << 1,
    MSGISDATA: 0x1 << 2,
    MSGISMULTIPART: 0x1 << 3,
    MSGISFIRST: 0x1 << 4,
    MSGISLAST: 0x1 << 5,
    MSGISPRESENCEACK: 0x1 << 6,
    RESERVED: 0x1 << 7,
    MSGISBDONE: 0x1 << 8,
    MSGISBDACK: 0x1 << 9,

    // Cryptographic parameters
    HMAC_LEN: 12,
    NONCE_LEN: 32,
    HDRLEN: 18,
    DH_BITS: 256, // 32 bytes

    // Domains for key derivation
    DOMAIN_ENCKEY: null, // Will be initialized in init()
    DOMAIN_CHANKEY: null, // Will be initialized in init()
    DOMAIN_AUTHKEY: null, // Will be initialized in init()

    // Info strings for HKDF
    INFO_CHANNEL: null, // Will be initialized in init()
    INFO_CHANNEL_NONCE: null, // Will be initialized in init()
    INFO_UID: null, // Will be initialized in init()
    INFO_UID_NONCE: null, // Will be initialized in init()

    // Scrypt parameters
    SCRYPT_SALTLEN: 32,
    SCRYPT_N: 32768,
    SCRYPT_R: 8,
    SCRYPT_P: 1,
    SCRYPT_DKLEN: 32,

    // Date constants
    BEGIN: new Date(Date.UTC(2018, 0, 1, 0, 0, 0)),
  };

  // Initialize string constants
  function initializeConstants() {
    CONSTANTS.DOMAIN_ENCKEY = StringUtil.toUint8Array(
      "Zpinc-WebWorkerEncryptDom!v1",
    );
    CONSTANTS.DOMAIN_CHANKEY = StringUtil.toUint8Array(
      "Zpinc-WebWorkerChannelDom!v1",
    );
    CONSTANTS.DOMAIN_AUTHKEY = StringUtil.toUint8Array(
      "Zpinc-WebWorkerAuthDom!v1",
    );

    CONSTANTS.INFO_CHANNEL = StringUtil.toUint8Array(
      "Zpinc-ChannelDerivation-v1",
    );
    CONSTANTS.INFO_CHANNEL_NONCE = StringUtil.toUint8Array(
      "Zpinc-ChannelNonceDerivation-v1",
    );
    CONSTANTS.INFO_UID = StringUtil.toUint8Array("Zpinc-UidDerivation-v1");
    CONSTANTS.INFO_UID_NONCE = StringUtil.toUint8Array(
      "Zpinc-UidNonceDerivation-v1",
    );

    CONSTANTS.SALTSTR = StringUtil.toUint8Array("ZpincSaltDomain1");
    CONSTANTS.PERSTR = StringUtil.toUint8Array("ZpincAppDomainv1");
    CONSTANTS.PERBDSTR = StringUtil.toUint8Array("ZpincBdDomain!v1");
  }

  // =========================================================================
  // State Management
  // =========================================================================
  const State = {
    // Connection state for each channel
    connections: {},

    // Cryptographic state
    crypto: {
      seed: null, // Secure random seed for pseudorandom generation

      // Per-channel cryptographic state
      channels: {},
    },

    // Initialize or reset the state for a channel
    initChannel(channel) {
      if (!this.connections[channel]) {
        this.connections[channel] = {
          webSocket: null,
          address: null,
          port: null,
          uid: null,
          channelId: null,
        };
      }

      if (!this.crypto.channels[channel]) {
        this.crypto.channels[channel] = {
          // Channel keys
          channelKey: null,
          msgCryptKey: null,

          // Session information
          sidDb: {},
          sid: null,

          // DH state
          dhDb: {},
          dhKey: {
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
          },

          // BD state
          bdDb: {},
          bdAckDb: {},
        };
      }

      return {
        connection: this.connections[channel],
        crypto: this.crypto.channels[channel],
      };
    },

    // Securely clean up state for a channel
    cleanupChannel(channel) {
      if (this.crypto.channels[channel]) {
        // Wipe sensitive cryptographic material
        const crypto = this.crypto.channels[channel];

        wipe(crypto.channelKey);
        wipe(crypto.msgCryptKey);

        if (crypto.dhKey) {
          wipe(crypto.dhKey.pw);
          wipe(crypto.dhKey.bdpw);
          wipe(crypto.dhKey.private);
          wipe(crypto.dhKey.secret);
          wipe(crypto.dhKey.bdMsgCryptKey);
          wipe(crypto.dhKey.bdChannelKey);
          wipe(crypto.dhKey.prevBdMsgCryptKey);
          wipe(crypto.dhKey.prevBdChannelKey);
        }

        // Clear state objects
        this.crypto.channels[channel] = null;
      }

      if (this.connections[channel]) {
        if (this.connections[channel].webSocket) {
          try {
            this.connections[channel].webSocket.close();
          } catch (e) {
            // Ignore errors during close
          }
        }
        this.connections[channel] = null;
      }
    },

    // Initialize session ID state
    initSid(channel) {
      const crypto = this.crypto.channels[channel];
      if (!crypto) return;

      crypto.sidDb = {};
      crypto.dhKey.sid = null;
      crypto.dhKey.public = null;
      crypto.dhKey.group = null;
      crypto.dhKey.private = null;

      this.initBd(channel);
    },

    // Initialize BD state
    initBd(channel) {
      const crypto = this.crypto.channels[channel];
      if (!crypto) return;

      crypto.bdDb = {};
      crypto.bdAckDb = {};
      crypto.dhKey.secret = null;
      crypto.dhKey.secretAcked = false;
      crypto.dhKey.bd = null;
      crypto.dhKey.bdMsgCryptKey = null;
      crypto.dhKey.bdChannelKey = null;

      if (crypto.dhKey.fsInformed) {
        EventHandler.processOnForwardSecrecyOff(channel);
        crypto.dhKey.fsInformed = false;
      }
    },

    // Initialize DH-BD state
    initDhBd(channel, myuid) {
      const crypto = this.crypto.channels[channel];
      if (!crypto) return;

      crypto.dhDb = {};
      if (crypto.dhKey.public) {
        crypto.dhDb[myuid] = crypto.dhKey.public;
      }

      this.initBd(channel);
    },

    // Initialize previous BD state
    initPrevDhBd(channel) {
      const crypto = this.crypto.channels[channel];
      if (!crypto) return;

      crypto.dhKey.prevBdChannelKey = null;
      crypto.dhKey.prevBdMsgCryptKey = null;
    },
  };

  // =========================================================================
  // Logging
  // =========================================================================
  const LogLevel = {
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3,
    TRACE: 4,
  };

  const Logger = {
    level: LogLevel.ERROR, // Default level - can be changed at runtime

    sanitize(obj) {
      if (!obj) return obj;

      // Create a copy to avoid modifying the original
      const copy = Array.isArray(obj) ? [...obj] : { ...obj };

      // Sanitize potentially sensitive fields
      const sensitiveFields = [
        "key",
        "keys",
        "secret",
        "password",
        "pw",
        "private",
        "channelKey",
        "msgCryptKey",
        "bdMsgCryptKey",
        "bdChannelKey",
      ];

      for (const field of sensitiveFields) {
        if (field in copy && copy[field]) {
          if (copy[field] instanceof Uint8Array) {
            copy[field] = "[REDACTED BINARY]";
          } else if (typeof copy[field] === "string") {
            copy[field] = "[REDACTED]";
          }
        }
      }

      return copy;
    },

    error(message, context = {}) {
      if (this.level >= LogLevel.ERROR) {
        console.error("[ERROR]", message, this.sanitize(context));
      }
    },

    warn(message, context = {}) {
      if (this.level >= LogLevel.WARN) {
        console.warn("[WARN]", message, this.sanitize(context));
      }
    },

    info(message, context = {}) {
      if (this.level >= LogLevel.INFO) {
        console.info("[INFO]", message, this.sanitize(context));
      }
    },

    debug(message, context = {}) {
      if (this.level >= LogLevel.DEBUG) {
        console.debug("[DEBUG]", message, this.sanitize(context));
      }
    },

    trace(message, context = {}) {
      if (this.level >= LogLevel.TRACE) {
        console.log("[TRACE]", message, this.sanitize(context));
      }
    },

    setLevel(level) {
      if (Object.values(LogLevel).includes(level)) {
        this.level = level;
        this.info(`Log level set to ${level}`);
      } else {
        this.warn(`Invalid log level: ${level}`);
      }
    },
  };

  // =========================================================================
  // String and Binary Utilities
  // =========================================================================
  const StringUtil = {
    /**
     * Convert a string to a Uint8Array
     * @param {string} str - Input string
     * @return {Uint8Array} Resulting byte array
     */
    toUint8Array(str) {
      const arr = new Uint8Array(str.length);
      for (let i = 0; i < str.length; i++) {
        arr[i] = str.charCodeAt(i);
      }
      return arr;
    },

    /**
     * Convert a Uint8Array to a string
     * @param {Uint8Array} arr - Input byte array
     * @return {string} Resulting string
     */
    fromUint8Array(arr) {
      if (!arr) return "";
      let str = "";
      for (let i = 0; i < arr.length; i++) {
        str += String.fromCharCode(arr[i]);
      }
      return str;
    },

    /**
     * Convert a string to a 16-bit integer value
     * @param {string} str - Input string (must be at least 2 characters)
     * @return {number} 16-bit integer value
     */
    toUint16Val(str) {
      return ((str.charCodeAt(0) & 0xff) << 8) | (str.charCodeAt(1) & 0xff);
    },

    /**
     * Convert a 16-bit integer value to a string
     * @param {number} val - 16-bit integer value
     * @return {string} Resulting 2-character string
     */
    fromUint16Val(val) {
      let str = "";
      str += String.fromCharCode((val & 0xff00) >> 8);
      str += String.fromCharCode(val & 0xff);
      return str;
    },
  };

  const BinaryUtil = {
    /**
     * Convert a Uint8Array to a 16-bit integer value
     * @param {Uint8Array} arr - Input byte array (must have at least 2 bytes)
     * @return {number} 16-bit integer value
     */
    toUint16Val(arr) {
      return ((arr[0] & 0xff) << 8) | (arr[1] & 0xff);
    },

    /**
     * Convert a 16-bit integer value to a Uint8Array
     * @param {number} val - 16-bit integer value
     * @return {Uint8Array} 2-byte array
     */
    fromUint16Val(val) {
      const arr = new Uint8Array(2);
      arr[0] = (val & 0xff00) >> 8;
      arr[1] = val & 0xff;
      return arr;
    },

    /**
     * Check if two Uint8Arrays are equal (constant-time comparison)
     * @param {Uint8Array} arr1 - First array
     * @param {Uint8Array} arr2 - Second array
     * @return {boolean} True if arrays are equal
     */
    isEqual(arr1, arr2) {
      if (!arr1 || !arr2 || arr1.length !== arr2.length) {
        return false;
      }

      let result = 0;
      for (let i = 0; i < arr1.length; i++) {
        result |= arr1[i] ^ arr2[i];
      }
      return result === 0;
    },

    /**
     * Check if two HMACs are equal (constant-time comparison)
     * @param {Uint8Array} hmac1 - First HMAC
     * @param {Uint8Array} hmac2 - Second HMAC
     * @return {boolean} True if HMACs are equal
     */
    isEqualHmacs(hmac1, hmac2) {
      if (!hmac1 || !hmac2 || hmac1.length !== hmac2.length) {
        return false;
      }

      let diff = 0;
      for (let i = 0; i < hmac1.length; i++) {
        diff |= hmac1[i] ^ hmac2[i];
      }
      return diff === 0;
    },

    /**
     * Create a Uint8Array filled with zeroes
     * @param {number} size - Size of the array
     * @return {Uint8Array} Zero-filled array
     */
    createZeroArray(size) {
      const arr = new Uint8Array(size);
      for (let i = 0; i < arr.length; i++) {
        arr[i] = 0;
      }
      return arr;
    },

    /**
     * Check if a Uint8Array contains only zeroes (constant-time)
     * @param {Uint8Array} arr - Input array
     * @return {boolean} True if array contains only zeroes
     */
    isZeroArray(arr) {
      if (!arr) return false;

      let result = 0;
      for (let i = 0; i < arr.length; i++) {
        result |= arr[i];
      }
      return result === 0;
    },
  };

  // =========================================================================
  // Timestamp Management
  // =========================================================================
  const TimeUtil = {
    /**
     * Create a flagstamp from a date
     * @param {Date} valueofdate - Date value
     * @param {number} weekstamp - Week stamp
     * @param {number} timestamp - Timestamp in minutes
     * @return {number} Flagstamp value
     */
    createFlagstamp(valueofdate, weekstamp, timestamp) {
      const begin = CONSTANTS.BEGIN;
      const this_time = new Date(
        begin.valueOf() +
          weekstamp * 1000 * 60 * 60 * 24 * 7 +
          timestamp * 1000 * 60,
      );
      const flagstamp = Math.floor((valueofdate - this_time) / 1000);
      return flagstamp;
    },

    /**
     * Create a timestamp (in minutes) from a date
     * @param {Date} valueofdate - Date value
     * @param {number} weekstamp - Week stamp
     * @return {number} Timestamp value in minutes
     */
    createTimestamp(valueofdate, weekstamp) {
      const begin = CONSTANTS.BEGIN;
      const this_week = new Date(
        begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7,
      );
      const timestamp = Math.floor((valueofdate - this_week) / 1000 / 60);
      return timestamp;
    },

    /**
     * Create a weekstamp from a date
     * @param {Date} valueofdate - Date value
     * @return {number} Weekstamp value
     */
    createWeekstamp(valueofdate) {
      const begin = CONSTANTS.BEGIN;
      const now = new Date(valueofdate);
      const weekstamp = Math.floor((now - begin) / 1000 / 60 / 60 / 24 / 7);
      return weekstamp;
    },

    /**
     * Read a timestamp into a Date
     * @param {number} timestamp - Timestamp in minutes
     * @param {number} weekstamp - Week stamp
     * @param {number} flagstamp - Flag stamp in seconds
     * @return {Date} Resulting date
     */
    readTimestamp(timestamp, weekstamp, flagstamp) {
      const begin = CONSTANTS.BEGIN;
      const weeks = new Date(
        begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7,
      );
      const extension = timestamp * 1000 * 60 + flagstamp * 1000;
      const time = new Date(weeks.valueOf() + extension);
      return time;
    },
  };

  // =========================================================================
  // Cryptographic Operations
  // =========================================================================
  const CryptoUtil = {
    /**
     * Generate a pseudo-random byte array
     * @param {number} byteLength - Length of the array
     * @return {Uint8Array} Random byte array
     */
    pseudoRandBytes(byteLength) {
      if (byteLength <= 0) throw new RangeError("byteLength MUST be > 0");

      // Create buffer of the requested size
      let buf = new Uint8Array(byteLength);

      // Fill it with cryptographically secure random values
      self.crypto.getRandomValues(buf);

      return buf;
    },

    /**
     * Derive key using HKDF-like construction (constant-time)
     * @param {Uint8Array} inputKey - Input key material
     * @param {Uint8Array} info - Context and application specific information
     * @param {number} length - Length of output key material
     * @return {Uint8Array} Derived key
     */
    deriveKey(inputKey, info, length = 32) {
      if (!inputKey || !info) {
        Logger.error("Invalid parameters for key derivation");
        throw new Error("Invalid parameters for key derivation");
      }

      try {
        // PRK = HMAC-Hash(salt, IKM)
        const prk = new BLAKE2b(32, {
          salt: CONSTANTS.SALTSTR,
          personalization: CONSTANTS.PERSTR,
          key: inputKey,
        }).digest();

        // Output = T(1) | T(2) | T(3) | ... where T(N) = HMAC-Hash(PRK, T(N-1) | info | N)
        let output = new Uint8Array(length);
        let T = new Uint8Array(0);
        let pos = 0;
        let counter = 1;

        // Process in fixed-size chunks to maintain constant time
        const chunkSize = 32;
        const requiredChunks = Math.ceil(length / chunkSize);

        for (let i = 0; i < requiredChunks; i++) {
          const hmac = new BLAKE2b(32, {
            key: prk,
          });

          hmac.update(T);
          hmac.update(info);
          hmac.update(new Uint8Array([counter]));

          T = hmac.digest();

          // Copy to output, handling the final chunk carefully
          const remaining = length - pos;
          const bytesToCopy = Math.min(chunkSize, remaining);
          output.set(T.slice(0, bytesToCopy), pos);
          pos += bytesToCopy;
          counter++;
        }

        // Clean up
        wipe(prk);
        wipe(T);

        return output;
      } catch (error) {
        Logger.error("Key derivation failed", { error: error.message });
        throw new Error("Key derivation failed");
      }
    },

    /**
     * Create a channel key from input key material
     * @param {Uint8Array} key - Input key material
     * @return {Uint8Array} Channel key
     */
    createChannelKey(key) {
      return this.deriveKey(key, CONSTANTS.DOMAIN_CHANKEY);
    },

    /**
     * Create a message key from input key material
     * @param {Uint8Array} key - Input key material
     * @return {Uint8Array} Message key
     */
    createMessageKey(key) {
      return this.deriveKey(key, CONSTANTS.DOMAIN_ENCKEY);
    },

    /**
     * Encrypt a channel name
     * @param {string} channel - Channel name
     * @param {Uint8Array} channelKey - Channel key
     * @return {string} Encrypted channel (base64)
     */
    encryptChannel(channel, channelKey) {
      const key = this.deriveKey(channelKey, CONSTANTS.INFO_CHANNEL);
      const nonce = this.deriveKey(
        channelKey,
        CONSTANTS.INFO_CHANNEL_NONCE,
        24,
      );

      const ciphertext = nacl.secretbox(
        StringUtil.toUint8Array(channel),
        nonce,
        key,
      );

      // Clean up
      wipe(key);
      wipe(nonce);

      return btoa(StringUtil.fromUint8Array(ciphertext));
    },

    /**
     * Decrypt a channel name
     * @param {string} encrypted - Encrypted channel (base64)
     * @param {Uint8Array} channelKey - Channel key
     * @return {string} Decrypted channel name
     */
    decryptChannel(encrypted, channelKey) {
      const derivedKey = this.deriveKey(channelKey, CONSTANTS.INFO_CHANNEL);
      const nonce = this.deriveKey(
        channelKey,
        CONSTANTS.INFO_CHANNEL_NONCE,
        24,
      );

      try {
        const ciphertext = StringUtil.toUint8Array(atob(encrypted));
        const decrypted = nacl.secretbox.open(ciphertext, nonce, derivedKey);

        if (!decrypted) {
          throw new Error("Channel decryption failed");
        }

        // Clean up
        wipe(derivedKey);
        wipe(nonce);

        return StringUtil.fromUint8Array(decrypted);
      } catch (error) {
        Logger.error("Channel decryption failed", { error: error.message });
        throw new Error(
          "Channel decryption failed. Invalid key or corrupted data.",
        );
      }
    },

    /**
     * Encrypt a user ID
     * @param {string} uid - User ID
     * @param {Uint8Array} channelKey - Channel key
     * @return {string} Encrypted UID (base64)
     */
    encryptUid(uid, channelKey) {
      const key = this.deriveKey(channelKey, CONSTANTS.INFO_UID);
      const nonce = this.deriveKey(channelKey, CONSTANTS.INFO_UID_NONCE, 24);

      const ciphertext = nacl.secretbox(
        StringUtil.toUint8Array(uid),
        nonce,
        key,
      );

      // Clean up
      wipe(key);
      wipe(nonce);

      return btoa(StringUtil.fromUint8Array(ciphertext));
    },

    /**
     * Decrypt a user ID
     * @param {string} encrypted - Encrypted UID (base64)
     * @param {Uint8Array} channelKey - Channel key
     * @return {string} Decrypted user ID
     */
    decryptUid(encrypted, channelKey) {
      const derivedKey = this.deriveKey(channelKey, CONSTANTS.INFO_UID);
      const nonce = this.deriveKey(channelKey, CONSTANTS.INFO_UID_NONCE, 24);

      try {
        const ciphertext = StringUtil.toUint8Array(atob(encrypted));
        const decrypted = nacl.secretbox.open(ciphertext, nonce, derivedKey);

        if (!decrypted) {
          throw new Error("UID decryption failed");
        }

        // Clean up
        wipe(derivedKey);
        wipe(nonce);

        return StringUtil.fromUint8Array(decrypted);
      } catch (error) {
        Logger.error("UID decryption failed", { error: error.message });
        throw new Error(
          "Uid decryption failed. Invalid key or corrupted data.",
        );
      }
    },

    /**
     * Calculate Padmé padding (constant-time)
     * @param {number} msgsize - Message size
     * @return {number} Padded size
     */
    padme(msgsize) {
      const L = msgsize;
      const E = Math.floor(Math.log2(L));
      const S = Math.floor(Math.log2(E)) + 1;
      const lastBits = E - S;
      const bitMask = 2 ** lastBits - 1;
      return (L + bitMask) & ~bitMask;
    },

    /**
     * Create previous BD key
     * @param {string} channel - Channel name
     * @param {string} prevBdKey - Previous BD key (hex string)
     * @param {Uint8Array} channelKey - Channel key
     */
    createPrevBd(channel, prevBdKey, channelKey) {
      try {
        const crypto = State.crypto.channels[channel];
        if (!crypto) {
          throw new Error("Channel not initialized");
        }

        const rnd = new BLAKE2b(32, {
          salt: CONSTANTS.SALTSTR,
          personalization: CONSTANTS.PERSTR,
          key: channelKey,
        });

        rnd.update(StringUtil.toUint8Array(prevBdKey));
        const digest = rnd.digest();

        crypto.dhKey.prevBdChannelKey = this.createChannelKey(digest);
        crypto.dhKey.prevBdMsgCryptKey = this.createMessageKey(digest);

        // Clean up
        wipe(digest);
        wipe(rnd);

        Logger.debug("Previous BD keys created successfully", { channel });
      } catch (error) {
        Logger.error("Failed to create previous BD keys", {
          channel,
          error: error.message,
        });
        throw error;
      }
    },
  };

  // =========================================================================
  // Session ID Management
  // =========================================================================
  const SessionManager = {
    /**
     * Get a session ID, generating a new one if necessary
     * @param {string} channel - Channel name
     * @param {string} myuid - User ID
     * @return {Uint8Array} Session ID
     */
    getSid(channel, myuid) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) {
        Logger.error("Channel not initialized", { channel });
        throw new Error("Channel not initialized");
      }

      if (!crypto.dhKey.sid) {
        const sid = new Uint8Array(8);
        self.crypto.getRandomValues(sid);
        if (!crypto.sidDb) {
          State.initSid(channel);
        }
        this.setSid(channel, myuid, sid);
      }

      return crypto.dhKey.sid;
    },

    /**
     * Set a session ID
     * @param {string} channel - Channel name
     * @param {string} myuid - User ID
     * @param {Uint8Array} sid - Session ID
     */
    setSid(channel, myuid, sid) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) {
        Logger.error("Channel not initialized", { channel });
        throw new Error("Channel not initialized");
      }

      crypto.dhKey.bdpw = crypto.msgCryptKey;
      crypto.dhKey.sid = sid;
      crypto.sidDb[myuid] = sid;

      Logger.debug("Session ID set", {
        channel,
        uid: myuid,
        sidLength: sid?.length || 0,
      });
    },
  };

  // =========================================================================
  // Burmester-Desmedt protocol implementation
  // =========================================================================
  const BdKeyManager = {
    /**
     * Process a BD message
     * @param {string} channel - Channel name
     * @param {string} myuid - Local user ID
     * @param {string} uid - Sender user ID
     * @param {number} msgtype - Message type flags
     * @param {Uint8Array} keyArray - Key data array
     * @return {number} Updated message type
     */
    processBd(channel, myuid, uid, msgtype, keyArray) {
      // Preserve original BD processing logic
      const crypto = State.crypto.channels[channel];
      if (!crypto) {
        Logger.error("Channel not initialized", { channel });
        return msgtype;
      }

      if (uid === myuid) {
        Logger.debug(
          `Reinitializing DH-BD for own message in channel ${channel}`,
        );
        State.initDhBd(channel, myuid);
        return msgtype;
      }

      // Validate key array length
      if (!this.isValidKeyArrayLength(keyArray.length)) {
        return msgtype;
      }

      // Extract public key
      const pub = keyArray.slice(0, CONSTANTS.DH_BITS / 8);

      Logger.debug(`Processing BD message from ${uid} in channel ${channel}`, {
        keyLength: keyArray.length,
        messageType: msgtype,
      });

      // Handle key mismatch (original logic preserved)
      if (crypto.dhDb[uid]) {
        const keyMismatch = !BinaryUtil.isEqual(crypto.dhDb[uid], pub);
        const isShortMessageWithExistingBd =
          keyArray.length === CONSTANTS.DH_BITS / 8 &&
          !(msgtype & CONSTANTS.MSGISBDONE) &&
          crypto.dhDb[uid] &&
          crypto.bdDb &&
          crypto.bdDb[uid];

        if (keyMismatch || isShortMessageWithExistingBd) {
          Logger.info(`Reinitializing DH-BD due to key mismatch for ${uid}`);
          State.initDhBd(channel, myuid);
          crypto.dhDb[uid] = pub;
          return msgtype;
        }
      }

      // Store the public key if it's new
      if (!crypto.dhDb[uid]) {
        Logger.debug(`Initializing new public key for ${uid}`);
        crypto.dhDb[uid] = pub;
        return msgtype;
      }

      // Calculate our BD key
      this.calculateBdKey(channel, myuid, uid);

      // Process the BD message if appropriate
      if (this.shouldProcessBdMessage(keyArray, msgtype, channel)) {
        this.processBdMessage(channel, myuid, uid, keyArray, pub, msgtype);
      }

      return msgtype;
    },

    /**
     * Check if key array length is valid
     * @param {number} length - Key array length
     * @return {boolean} True if valid
     */
    isValidKeyArrayLength(length) {
      return (
        length === CONSTANTS.DH_BITS / 8 ||
        length === 2 * (CONSTANTS.DH_BITS / 8)
      );
    },

    /**
     * Check if DH-BD state should be reset
     * @param {string} channel - Channel name
     * @param {string} uid - Sender user ID
     * @param {Uint8Array} pub - Public key
     * @param {number} msgtype - Message type flags
     * @param {Uint8Array} keyArray - Key data array
     * @return {boolean} True if reset needed
     */
    shouldResetDhBd(channel, uid, pub, msgtype, keyArray) {
      const crypto = State.crypto.channels[channel];
      if (!crypto || !crypto.dhDb) return false;

      const existingKey = crypto.dhDb[uid];
      if (!existingKey) return false;

      // Check for key mismatch
      const keyMismatch = !BinaryUtil.isEqual(existingKey, pub);

      // Check for short message with existing BD
      const isShortMessageWithExistingBd =
        keyArray.length === CONSTANTS.DH_BITS / 8 &&
        !(msgtype & CONSTANTS.MSGISBDONE) &&
        crypto.dhDb[uid] &&
        crypto.bdDb &&
        crypto.bdDb[uid];

      if (keyMismatch || isShortMessageWithExistingBd) {
        Logger.debug("DH-BD reset required", {
          reason: keyMismatch
            ? "key mismatch"
            : "short message with existing BD",
          channel,
          uid,
          messageType: msgtype,
          keyLength: keyArray.length,
        });
        return true;
      }

      return false;
    },

    /**
     * Check if we should process this as a BD message
     * @param {Uint8Array} keyArray - Key data array
     * @param {number} msgtype - Message type flags
     * @param {string} channel - Channel name
     * @return {boolean} True if should process
     */
    shouldProcessBdMessage(keyArray, msgtype, channel) {
      const pubcnt = this.countParticipants(channel);
      const isTwoParticipants = pubcnt === 2;

      const isLongMessage = keyArray.length === 2 * (CONSTANTS.DH_BITS / 8);
      const isShortMessageWithBdFlag =
        keyArray.length === CONSTANTS.DH_BITS / 8 &&
        msgtype & CONSTANTS.MSGISBDONE;

      Logger.debug("BD message processing check", {
        participants: pubcnt,
        messageLength: keyArray.length,
        hasBdFlag: Boolean(msgtype & CONSTANTS.MSGISBDONE),
        isLongMessage,
        isShortMessageWithBdFlag,
      });

      // For 2 participants, only accept short messages with BDONE flag
      if (isTwoParticipants) {
        return isShortMessageWithBdFlag;
      }

      // For >2 participants, accept either format
      return isLongMessage || isShortMessageWithBdFlag;
    },

    /**
     * Count participants in a channel
     * @param {string} channel - Channel name
     * @return {number} Participant count
     */
    countParticipants(channel) {
      const crypto = State.crypto.channels[channel];
      if (!crypto || !crypto.dhDb) {
        Logger.debug("No participants found in channel", { channel });
        return 0;
      }

      const count = Object.keys(crypto.dhDb).length;
      Logger.trace("Counted participants", {
        channel,
        count,
      });

      return count;
    },

    /**
     * Calculate BD key
     * @param {string} channel - Channel name
     * @param {string} myuid - Local user ID
     * @param {string} uid - Sender user ID
     */
    calculateBdKey(channel, myuid, uid) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return;

      if (!crypto.bdDb) {
        Logger.debug(`Initializing BD database for channel ${channel}`);
        crypto.bdDb = {};
      }

      const { prevkey, nextkey, pubcnt, index } = this.calculateKeyIndices(
        channel,
        myuid,
      );

      Logger.debug(`Calculated key indices for ${myuid}`, {
        participantCount: pubcnt,
        userIndex: index,
      });

      if (prevkey && nextkey) {
        try {
          const step = ristretto255.sub(nextkey, prevkey);
          crypto.dhKey.bd = ristretto255.scalarMult(crypto.dhKey.private, step);

          crypto.bdDb[myuid] = crypto.dhKey.bd;
          Logger.debug(`BD key calculated successfully for ${myuid}`);
        } catch (error) {
          Logger.error("BD key calculation failed", {
            channel,
            myuid,
            error: error.message,
          });
        }
      }
    },

    /**
     * Calculate key indices for BD
     * @param {string} channel - Channel name
     * @param {string} myuid - Local user ID
     * @return {Object} Calculated indices and keys
     */
    calculateKeyIndices(channel, myuid) {
      const crypto = State.crypto.channels[channel];
      if (!crypto || !crypto.dhDb) {
        return { prevkey: null, nextkey: null, pubcnt: 0, index: -1 };
      }

      // Sort the DH database to ensure consistent ordering
      const dhdb_sorted = Object.fromEntries(
        Object.entries(crypto.dhDb).sort(),
      );

      const keys = [];
      let index = -1;
      let pubcnt = 0;

      for (let userid in dhdb_sorted) {
        if (userid === myuid) {
          index = pubcnt;
          Logger.debug(`User ${myuid} found at index ${index}`);
        }
        keys.push(crypto.dhDb[userid]);
        Logger.trace(`Added key for user ${userid} at position ${pubcnt}`);
        pubcnt++;
      }

      // Determine adjacent keys
      let prevkey = null,
        nextkey = null;

      if (pubcnt > 1 && index >= 0) {
        if (index === 0) {
          prevkey = keys[pubcnt - 1];
          nextkey = keys[index + 1];
        } else if (index === pubcnt - 1) {
          prevkey = keys[index - 1];
          nextkey = keys[0];
        } else {
          prevkey = keys[index - 1];
          nextkey = keys[index + 1];
        }

        Logger.debug(`Adjacent keys determined`, {
          position: index,
          totalParticipants: pubcnt,
        });
      }

      return { prevkey, nextkey, pubcnt, index };
    },

    /**
     * Process a BD message
     * @param {string} channel - Channel name
     * @param {string} myuid - Local user ID
     * @param {string} uid - Sender user ID
     * @param {Uint8Array} keyArray - Key data array
     * @param {Uint8Array} pub - Public key
     * @param {number} msgtype - Message type flags
     */
    processBdMessage(channel, myuid, uid, keyArray, pub, msgtype) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return;

      // Extract BD value
      const bd = this.extractBdValue(keyArray);

      Logger.debug("Processing BD message", {
        channel,
        participants: this.countParticipants(channel),
        messageLength: keyArray.length,
        messageType: msgtype,
        hasBdFlag: Boolean(msgtype & CONSTANTS.MSGISBDONE),
      });

      // Check if we need to reset BD due to mismatch
      if (this.shouldResetBd(channel, uid, bd)) {
        Logger.warn(`BD mismatch detected for ${uid}, resetting BD state`, {
          channel,
        });
        State.initBd(channel);
        crypto.dhDb[uid] = pub;
        return;
      }

      // Check if we need to reset DH-BD based on BD value
      if (this.shouldResetDhBd(channel, uid, bd)) {
        Logger.warn("Resetting DH-BD state", {
          channel,
          uid,
        });
        State.initDhBd(channel, myuid);
        crypto.dhDb[uid] = pub;

        if (this.shouldRequestPresenceAck(msgtype)) {
          Logger.debug("Requesting presence acknowledgment", {
            uid: myuid,
            channel,
          });
        }
        return;
      }

      // Skip if BD already processed
      if (
        this.isBdMatchedAndAcked(channel, uid, bd) &&
        crypto.dhKey.secret &&
        crypto.dhKey.secretAcked
      ) {
        Logger.debug("BD fully processed and acknowledged", {
          channel,
          uid,
          hasSecret: Boolean(crypto.dhKey.secret),
          isSecretAcked: Boolean(crypto.dhKey.secretAcked),
        });
        return;
      }

      // Update BD database and calculate keys
      this.updateBdDbAndCalculateKeys(channel, myuid, uid, bd);

      // Process acknowledgment if present
      if (msgtype & CONSTANTS.MSGISBDACK) {
        this.processBdAck(channel, uid, keyArray, pub, msgtype);
      }
    },

    /**
     * Extract BD value from key array
     * @param {Uint8Array} keyArray - Key data array
     * @return {Uint8Array} BD value
     */
    extractBdValue(keyArray) {
      let bd = BinaryUtil.createZeroArray(CONSTANTS.DH_BITS / 8);

      if (keyArray.length === 2 * (CONSTANTS.DH_BITS / 8)) {
        bd = keyArray.slice(CONSTANTS.DH_BITS / 8, keyArray.length);
        Logger.debug("Extracted BD value from long message", {
          bdLength: bd.length,
          messageLength: keyArray.length,
        });
      } else {
        Logger.debug("Using zero BD value for short message", {
          messageLength: keyArray.length,
        });
      }

      return bd;
    },

    /**
     * Check if BD should be reset (constant-time)

     * @param {string} channel - Channel name
     * @param {string} uid - Sender user ID
     * @param {Uint8Array} bd - BD value
     * @return {boolean} True if reset needed
     */
    shouldResetBd(channel, uid, bd) {
      const crypto = State.crypto.channels[channel];
      if (!crypto || !crypto.bdDb || !crypto.bdDb[uid]) {
        return false;
      }

      const existingBd = crypto.bdDb[uid];

      // Use constant-time comparison
      return !BinaryUtil.isEqual(existingBd, bd);
    },

    /**
     * Check if DH-BD should be reset based on BD value (constant-time)
     * @param {string} channel - Channel name
     * @param {string} uid - Sender user ID
     * @param {Uint8Array} bd - BD value
     * @return {boolean} True if reset needed
     */
    shouldResetDhBd(channel, uid, bd) {
      const pubcnt = this.countParticipants(channel);

      // Case 1: More than 2 participants but BD is all zeros
      const hasMultipleParticipants = pubcnt > 2;
      const hasBdZeroes = BinaryUtil.isZeroArray(bd);

      // Case 2: Exactly 2 participants but BD is not zeros
      const hasExactlyTwoParticipants = pubcnt === 2;
      const hasBdNonZeroes = !BinaryUtil.isZeroArray(bd);

      // Compute both conditions in constant time
      const condition1 = hasMultipleParticipants & hasBdZeroes;
      const condition2 = hasExactlyTwoParticipants & hasBdNonZeroes;

      // Combine using bitwise OR to maintain constant time
      return (condition1 | condition2) !== 0;
    },

    /**
     * Check if we should request presence acknowledgment
     * @param {number} msgtype - Message type flags
     * @return {boolean} True if ack needed
     */
    shouldRequestPresenceAck(msgtype) {
      // Check if message has presence flag but no presence ack flag
      const isPresence = Boolean(msgtype & CONSTANTS.MSGISPRESENCE);
      const hasPresenceAck = Boolean(msgtype & CONSTANTS.MSGISPRESENCEACK);
      const needsAck = isPresence && !hasPresenceAck;

      Logger.trace("Presence ack check", {
        isPresence,
        hasPresenceAck,
        needsAck,
      });

      return needsAck;
    },

    /**
     * Check if BD is matched and acknowledged
     * @param {string} channel - Channel name
     * @param {string} uid - Sender user ID
     * @param {Uint8Array} bd - BD value
     * @return {boolean} True if matched and acked
     */
    isBdMatchedAndAcked(channel, uid, bd) {
      const crypto = State.crypto.channels[channel];
      if (!crypto || !crypto.bdDb) return false;

      // Check BD match
      if (!bd || !crypto.bdDb[uid]) {
        return false;
      }

      const bdsMatch = BinaryUtil.isEqual(crypto.bdDb[uid], bd);

      Logger.debug("BD match status", {
        channel,
        uid,
        bdsMatch,
        hasExistingBd: Boolean(crypto.bdDb[uid]),
      });

      return bdsMatch;
    },

    /**
     * Update BD database and calculate keys
     * @param {string} channel - Channel name
     * @param {string} myuid - Local user ID
     * @param {string} uid - Sender user ID
     * @param {Uint8Array} bd - BD value
     */
    updateBdDbAndCalculateKeys(channel, myuid, uid, bd) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return;

      const currentState = {
        hasMsgCryptKey: Boolean(crypto.dhKey.bdMsgCryptKey),
        hasSecret: Boolean(crypto.dhKey.secret),
        isSecretAcked: Boolean(crypto.dhKey.secretAcked),
      };

      // Initialize BD database if needed
      if (!crypto.bdDb) {
        crypto.bdDb = {};
      }

      // Store BD value
      crypto.bdDb[uid] = bd;

      Logger.debug("Updated BD database", {
        channel,
        myuid,
        uid,
        bdLength: bd.length,
        currentState,
      });

      // Collect BD keys and check counts
      const { bdcnt, pubcnt } = this.collectBdKeys(channel, myuid);

      // Only skip if we have everything completely set up
      const shouldSkip =
        bdcnt !== pubcnt ||
        (currentState.hasMsgCryptKey &&
          currentState.hasSecret &&
          currentState.isSecretAcked);

      if (shouldSkip) {
        Logger.debug("Skipping key calculation", {
          reason:
            bdcnt !== pubcnt ? "count mismatch" : "already fully initialized",
          bdCount: bdcnt,
          pubCount: pubcnt,
          state: currentState,
        });
        return;
      }

      try {
        // Calculate secret key if all conditions are met
        this.calculateSecretKey(channel, myuid);

        Logger.debug("Key calculation completed", {
          channel,
          myuid,
          newState: {
            hasMsgCryptKey: Boolean(crypto.dhKey.bdMsgCryptKey),
            hasSecret: Boolean(crypto.dhKey.secret),
            isSecretAcked: Boolean(crypto.dhKey.secretAcked),
          },
        });
      } catch (error) {
        Logger.error("Key calculation failed", {
          channel,
          myuid,
          error: error.message,
        });

        // Clear everything on error
        crypto.dhKey.secret = null;
        crypto.dhKey.bdMsgCryptKey = null;
        crypto.dhKey.bdChannelKey = null;
        crypto.dhKey.secretAcked = false;
      }
    },

    /**
     * Collect BD keys
     * @param {string} channel - Channel name
     * @param {string} myuid - Local user ID
     * @return {Object} Collected BD keys information
     */
    collectBdKeys(channel, myuid) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) {
        return { bdcnt: 0, pubcnt: 0, index: -1, xkeys: [] };
      }

      let bdcnt = 0;
      let index = -1;
      const xkeys = [];

      // Sort BD database entries for consistent ordering
      const bddb_sorted = Object.fromEntries(
        Object.entries(crypto.bdDb || {}).sort(),
      );

      // Collect BD keys
      for (let userid in bddb_sorted) {
        if (userid === myuid) {
          index = bdcnt;
        }
        Logger.trace("Collecting BD key", {
          userid,
          bdIndex: bdcnt,
        });
        xkeys.push(crypto.bdDb[userid]);
        bdcnt++;
      }

      const pubcnt = Object.keys(crypto.dhDb || {}).length;

      Logger.debug("Collected BD keys", {
        bdCount: bdcnt,
        pubCount: pubcnt,
        userIndex: index,
      });

      return { bdcnt, pubcnt, index, xkeys };
    },

    /**
     * Calculate secret key
     * @param {string} channel - Channel name
     * @param {string} myuid - Local user ID
     */
    calculateSecretKey(channel, myuid) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return;

      // Check if we're in a valid state for calculation
      const currentState = {
        hasMsgCryptKey: Boolean(crypto.dhKey.bdMsgCryptKey),
        hasSecret: Boolean(crypto.dhKey.secret),
        isSecretAcked: Boolean(crypto.dhKey.secretAcked),
      };

      // Only skip if we have everything AND they're acknowledged
      if (
        currentState.hasMsgCryptKey &&
        currentState.hasSecret &&
        currentState.isSecretAcked
      ) {
        Logger.debug(
          "Skipping key calculation - already completed and acknowledged",
          {
            channel,
            myuid,
            state: currentState,
          },
        );
        return;
      }

      // Get collected keys
      const { index, xkeys } = this.collectBdKeys(channel, myuid);
      if (index < 0 || !xkeys || xkeys.length === 0) {
        Logger.error("Invalid BD key collection", {
          channel,
          myuid,
          index,
          keyCount: xkeys?.length || 0,
        });
        return;
      }

      const len = xkeys.length;

      // Clear existing state
      crypto.dhKey.secret = null;
      crypto.dhKey.bdMsgCryptKey = null;
      crypto.dhKey.bdChannelKey = null;
      crypto.dhKey.secretAcked = false;

      Logger.debug("Starting secret key calculation", {
        channel,
        keyCount: len,
        index,
      });

      try {
        // Calculate initial secret key
        let skey = this.calculateInitialSecretKey(channel, len, myuid);
        if (!skey) {
          Logger.error("Initial secret key calculation failed");
          return;
        }

        // Calculate final secret key
        let finalSkey = this.calculateFinalSecretKey(skey, xkeys, index, len);
        if (!finalSkey) {
          Logger.error("Final secret key calculation failed");
          return;
        }

        // Set new keys
        crypto.dhKey.secret = finalSkey;
        this.generateCryptoKeys(channel, finalSkey);

        Logger.info("Secret key calculated successfully", {
          channel,
          myuid,
        });
      } catch (error) {
        Logger.error("Secret key calculation failed", {
          channel,
          myuid,
          error: error.message,
        });
      }
    },

    /**
     * Calculate initial secret key
     * @param {string} channel - Channel name
     * @param {number} len - Number of participants
     * @param {string} myuid - Local user ID
     * @return {Uint8Array} Initial secret key
     */
    calculateInitialSecretKey(channel, len, myuid) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return null;

      const { prevkey } = this.calculateKeyIndices(channel, myuid);
      if (!prevkey) {
        Logger.error("Previous key not found");
        return null;
      }

      try {
        let skey = ristretto255.scalarMult(crypto.dhKey.private, prevkey);
        let step = skey;

        for (let j = 0; j < len - 1; j++) {
          skey = ristretto255.add(skey, step);
        }

        return skey;
      } catch (error) {
        Logger.error("Initial secret key calculation failed", {
          error: error.message,
        });
        return null;
      }
    },

    /**
     * Calculate final secret key (constant-time)
     * @param {Uint8Array} skey - Initial secret key
     * @param {Array<Uint8Array>} xkeys - Array of BD keys
     * @param {number} index - Participant index
     * @param {number} len - Number of participants
     * @return {Uint8Array} Final secret key
     */
    calculateFinalSecretKey(skey, xkeys, index, len) {
      if (!skey || !xkeys || !xkeys.length) {
        Logger.error("Invalid inputs for final secret calculation");
        return null;
      }

      try {
        let resultSkey = skey;
        let sub = 1;
        let isValid = true;

        for (let i = 0; i < len; i++) {
          let adjustedIndex = (i + index) % len;
          let base = xkeys[adjustedIndex];

          // Check if base exists - constant time
          let baseExists = base !== undefined && base !== null;

          // Only update isValid, don't exit the loop
          isValid = isValid & baseExists;

          // Always perform calculation - will be invalid if base doesn't exist
          // but will still take the same amount of time
          let step = base || new Uint8Array(32); // Use dummy if missing
          let tempBase = base || new Uint8Array(32);

          for (let j = 0; j < len - sub; j++) {
            tempBase = ristretto255.add(tempBase, step);
          }

          // Only use the result if valid
          if (baseExists) {
            resultSkey = ristretto255.add(tempBase, resultSkey);
          }

          sub++;
        }

        // Only return a value if everything was valid
        return isValid ? resultSkey : null;
      } catch (error) {
        Logger.error("Error in final secret calculation", {
          error: error.message,
          index,
          len,
        });
        return null;
      }
    },

    /**
     * Generate crypto keys from secret key (constant-time)
     * @param {string} channel - Channel name
     * @param {Uint8Array} skey - Secret key
     */
    generateCryptoKeys(channel, skey) {
      const crypto = State.crypto.channels[channel];

      // Early validation
      const isValid = !!channel && !!skey && !!crypto && !!crypto.channelKey;

      if (!isValid) {
        Logger.error("Invalid inputs for crypto key generation");
        return;
      }

      try {
        // Create random number generator with channel key
        let rnd = new BLAKE2b(32, {
          salt: CONSTANTS.SALTSTR,
          personalization: CONSTANTS.PERSTR,
          key: crypto.channelKey,
        });

        // Update with secret key
        rnd.update(skey);
        const digest = rnd.digest();

        // Generate keys - will only be written if digest exists
        if (digest) {
          crypto.dhKey.bdChannelKey = CryptoUtil.createChannelKey(digest);
          crypto.dhKey.bdMsgCryptKey = CryptoUtil.createMessageKey(digest);

          Logger.info("Crypto keys generated successfully", {
            channel,
            hasChannelKey: Boolean(crypto.dhKey.bdChannelKey),
            hasMessageKey: Boolean(crypto.dhKey.bdMsgCryptKey),
          });
        }

        // Clean up sensitive data
        wipe(rnd);
        wipe(digest);
      } catch (error) {
        Logger.error("Error generating crypto keys", {
          channel,
          error: error.message,
        });
      }
    },

    /**
     * Process BD acknowledgment
     * @param {string} channel - Channel name
     * @param {string} uid - Sender user ID
     * @param {Uint8Array} keyArray - Key data array
     * @param {Uint8Array} pub - Public key
     * @param {number} msgtype - Message type flags
     */
    processBdAck(channel, uid, keyArray, pub, msgtype) {
      const crypto = State.crypto.channels[channel];
      if (!crypto || crypto.dhKey.secretAcked) {
        Logger.debug(`BD already acknowledged for ${uid}`);
        return;
      }

      if (!crypto.bdAckDb) {
        crypto.bdAckDb = {};
      }

      // Check if we have the required keys
      if (
        !crypto.dhDb ||
        !crypto.dhDb[uid] ||
        !crypto.bdDb ||
        !crypto.bdDb[uid]
      ) {
        Logger.warn(
          `Missing required keys for BD acknowledgment, resetting state`,
          {
            channel,
            uid,
          },
        );
        State.initBd(channel);
        crypto.dhDb[uid] = pub;
        return;
      }

      // Store acknowledgment
      crypto.bdAckDb[uid] = true;

      const stats = {
        publicKeyCount: Object.keys(crypto.dhDb).length,
        bdKeyCount: Object.keys(crypto.bdDb).length,
        ackCount: Object.keys(crypto.bdAckDb).length,
      };

      Logger.debug(`BD acknowledgment processed`, stats);

      // Check if all acknowledgments are complete
      if (this.shouldFinalizeAck(channel, keyArray, stats, msgtype)) {
        Logger.info(
          `BD key exchange completed successfully for channel ${channel}`,
        );
        crypto.dhKey.secretAcked = true;
      }
    },

    /**
     * Check if we should finalize acknowledgment
     * @param {string} channel - Channel name
     * @param {Uint8Array} keyArray - Key data array
     * @param {Object} stats - Statistics about keys and acks
     * @param {number} msgtype - Message type flags
     * @return {boolean} True if should finalize
     */
    shouldFinalizeAck(channel, keyArray, stats, msgtype) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return false;

      // Check if all required components are present
      const hasRequiredComponents =
        crypto.dhKey.bdMsgCryptKey && crypto.dhKey.secret;

      // Check if counts match
      const countsMatch =
        stats.publicKeyCount === stats.bdKeyCount &&
        stats.ackCount === stats.publicKeyCount;

      // Check message type conditions
      const isShortMessageAck =
        stats.publicKeyCount === 2 &&
        keyArray.length === CONSTANTS.DH_BITS / 8 &&
        msgtype & CONSTANTS.MSGISBDACK &&
        msgtype & CONSTANTS.MSGISBDONE;

      const isLongMessageAck =
        stats.publicKeyCount > 2 &&
        keyArray.length === 2 * (CONSTANTS.DH_BITS / 8) &&
        msgtype & CONSTANTS.MSGISBDACK;

      const hasValidMessageType = isShortMessageAck || isLongMessageAck;

      const shouldFinalize =
        hasRequiredComponents && countsMatch && hasValidMessageType;

      Logger.debug("BD acknowledgment finalization check", {
        channel,
        hasRequiredComponents,
        countsMatch,
        isShortMessageAck,
        isLongMessageAck,
        stats,
        msgtype: msgtype,
      });

      return shouldFinalize;
    },
  };

  // =========================================================================
  // Message Processing
  // =========================================================================
  const MessageProcessor = {
    /**
     * Process an incoming message
     * @param {string} channel - Channel name
     * @param {Object} msg - Message object
     */
    processMessage(channel, msg) {
      //sanity check
      if (
        msg.message.byteLength <= CONSTANTS.NONCE_LEN ||
        msg.message.byteLength > 0xffffff
      ) {
        Logger.warn("Invalid message size", {
          channel,
          size: msg.message.byteLength,
        });
        return;
      }

      try {
        // Extract message components
        let fsEnabled = false;
        let noncem = msg.message.slice(0, CONSTANTS.NONCE_LEN);
        let arr = msg.message.slice(
          CONSTANTS.NONCE_LEN,
          msg.message.byteLength - CONSTANTS.HMAC_LEN,
        );
        let hmac = msg.message.slice(
          msg.message.byteLength - CONSTANTS.HMAC_LEN,
          msg.message.byteLength,
        );
        let message = arr;

        // Verify HMAC
        const crypt = this.verifyMessageHmac(channel, noncem, arr, hmac);
        if (!crypt) {
          Logger.warn("HMAC verification failed", { channel });
          return;
        }

        // Forward secrecy enabled?
        const crypto = State.crypto.channels[channel];
        fsEnabled =
          crypt === crypto.dhKey.bdMsgCryptKey ||
          crypt === crypto.dhKey.prevBdMsgCryptKey;

        // Decrypt user ID
        const uid = CryptoUtil.decryptUid(msg.uid, crypto.channelKey);

        // Decrypt message content
        let decrypted = nacl.secretbox.open(
          message,
          noncem.slice(0, 24),
          crypt,
        );
        if (!decrypted || decrypted.length < CONSTANTS.HDRLEN) {
          Logger.warn("Message decryption failed or invalid size", {
            channel,
            size: decrypted?.length,
          });
          return;
        }

        // Extract message headers
        let msgsz = BinaryUtil.toUint16Val(decrypted.slice(0, 2)); //includes also version which is zero
        let sid = decrypted.slice(2, 10);
        let keysz = BinaryUtil.toUint16Val(decrypted.slice(10, 12));

        let timeU16 = BinaryUtil.toUint16Val(decrypted.slice(12, 14));
        let weekU16 = BinaryUtil.toUint16Val(decrypted.slice(14, 16));
        let flagU16 = BinaryUtil.toUint16Val(
          decrypted.slice(16, CONSTANTS.HDRLEN),
        );

        let msgDate = TimeUtil.readTimestamp(
          timeU16,
          weekU16,
          flagU16 & CONSTANTS.ALLISSET,
        );

        // Extract message text
        message = new TextDecoder().decode(
          decrypted.slice(CONSTANTS.HDRLEN, msgsz),
        );

        // Convert flags to message type
        let msgtype = this.convertFlagsToMessageType(flagU16);

        // Process session ID and DH state
        this.processSidAndDh(
          channel,
          uid,
          sid,
          keysz,
          decrypted,
          msgsz,
          msgtype,
        );

        // Send message to client
        postMessage([
          "data",
          uid,
          channel,
          msgDate.valueOf(),
          message,
          msgtype,
          fsEnabled,
        ]);
      } catch (error) {
        Logger.error("Error processing message", {
          channel,
          error: error.message,
        });
      }
    },

    /**
     * Verify message HMAC
     * @param {string} channel - Channel name
     * @param {Uint8Array} noncem - Nonce
     * @param {Uint8Array} arr - Message data
     * @param {Uint8Array} hmac - HMAC to verify
     * @return {Uint8Array|null} Crypto key to use, or null if verification fails
     */
    verifyMessageHmac(channel, noncem, arr, hmac) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return null;

      // Create HMAC input array
      let hmacarr = new Uint8Array(noncem.byteLength + arr.byteLength);
      hmacarr.set(noncem, 0);
      hmacarr.set(arr, noncem.byteLength);

      // Always calculate all three HMACs to maintain constant time
      let bdHmac = null;
      if (crypto.dhKey.bdMsgCryptKey) {
        let blakehmac = new BLAKE2b(CONSTANTS.HMAC_LEN, {
          salt: CONSTANTS.SALTSTR,
          personalization: CONSTANTS.PERSTR,
          key: crypto.dhKey.bdChannelKey,
        });
        blakehmac.update(CONSTANTS.DOMAIN_AUTHKEY);
        blakehmac.update(noncem.slice(24));
        blakehmac.update(hmacarr);
        bdHmac = blakehmac.digest();
      } else {
        bdHmac = new Uint8Array(CONSTANTS.HMAC_LEN);
      }

      let prevBdHmac = null;
      if (crypto.dhKey.prevBdMsgCryptKey) {
        let blakehmac = new BLAKE2b(CONSTANTS.HMAC_LEN, {
          salt: CONSTANTS.SALTSTR,
          personalization: CONSTANTS.PERSTR,
          key: crypto.dhKey.prevBdChannelKey,
        });
        blakehmac.update(CONSTANTS.DOMAIN_AUTHKEY);
        blakehmac.update(noncem.slice(24));
        blakehmac.update(hmacarr);
        prevBdHmac = blakehmac.digest();
      } else {
        prevBdHmac = new Uint8Array(CONSTANTS.HMAC_LEN);
      }

      let regularHmac = new BLAKE2b(CONSTANTS.HMAC_LEN, {
        salt: CONSTANTS.SALTSTR,
        personalization: CONSTANTS.PERSTR,
        key: crypto.channelKey,
      });
      regularHmac.update(CONSTANTS.DOMAIN_AUTHKEY);
      regularHmac.update(noncem.slice(24));
      regularHmac.update(hmacarr);
      regularHmac = regularHmac.digest();

      // Constant-time comparison for all HMACs
      const isBdMatch = BinaryUtil.isEqualHmacs(hmac, bdHmac);
      const isPrevBdMatch = BinaryUtil.isEqualHmacs(hmac, prevBdHmac);
      const isRegularMatch = BinaryUtil.isEqualHmacs(hmac, regularHmac);

      // Select the right key in constant time
      let crypt = null;

      // Only perform these assignments if the corresponding key exists
      if (crypto.dhKey.bdMsgCryptKey && isBdMatch) {
        crypt = crypto.dhKey.bdMsgCryptKey;
      }

      if (crypto.dhKey.prevBdMsgCryptKey && isPrevBdMatch) {
        crypt = crypto.dhKey.prevBdMsgCryptKey;
      }

      if (isRegularMatch) {
        crypt = crypto.msgCryptKey;
      }

      return crypt;
    },

    /**
     * Convert flags to message type
     * @param {number} flagU16 - Flag value
     * @return {number} Message type
     */
    convertFlagsToMessageType(flagU16) {
      let msgtype = 0;
      if (flagU16 & CONSTANTS.ISFULL) msgtype |= CONSTANTS.MSGISFULL;
      if (flagU16 & CONSTANTS.ISDATA) msgtype |= CONSTANTS.MSGISDATA;
      if (flagU16 & CONSTANTS.ISPRESENCE) msgtype |= CONSTANTS.MSGISPRESENCE;
      if (flagU16 & CONSTANTS.ISPRESENCEACK)
        msgtype |= CONSTANTS.MSGISPRESENCEACK;
      if (flagU16 & CONSTANTS.ISMULTI) msgtype |= CONSTANTS.MSGISMULTIPART;
      if (flagU16 & CONSTANTS.ISFIRST) msgtype |= CONSTANTS.MSGISFIRST;
      if (flagU16 & CONSTANTS.ISLAST) msgtype |= CONSTANTS.MSGISLAST;
      if (flagU16 & CONSTANTS.ISBDONE) msgtype |= CONSTANTS.MSGISBDONE;
      if (flagU16 & CONSTANTS.ISBDACK) msgtype |= CONSTANTS.MSGISBDACK;

      return msgtype;
    },

    /**
     * Process session ID and DH
     * @param {string} channel - Channel name
     * @param {string} uid - Sender user ID
     * @param {Uint8Array} sid - Session ID
     * @param {number} keysz - Key size
     * @param {Uint8Array} decrypted - Decrypted message
     * @param {number} msgsz - Message size
     * @param {number} msgtype - Message type
     */
    processSidAndDh(channel, uid, sid, keysz, decrypted, msgsz, msgtype) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return;

      const myuid = CryptoUtil.decryptUid(
        State.connections[channel].uid,
        crypto.channelKey,
      );

      // If message from self, just reinitialize
      if (myuid == uid) {
        // Use original logic for own messages
        State.initSid(channel);
        State.initDhBd(channel, uid);
        return;
      }

      // Use original SID and DH logic
      if (!crypto.dhKey.sid || !BinaryUtil.isEqual(crypto.dhKey.sid, sid)) {
        State.initSid(channel);
        State.initDhBd(channel, myuid);
        SessionManager.setSid(channel, myuid, sid);
        Logger.trace(
          "RX: setting sid to " + sid + " mysid " + crypto.dhKey.sid,
        );
      }

      if (!crypto.sidDb[uid]) {
        crypto.sidDb[uid] = sid;
        if (crypto.dhKey.public) {
          Logger.debug("Resetting public key for sid", { sid: sid });
          this.setDhPublic(channel, myuid, sid);
        }
      } else if (
        BinaryUtil.isEqual(crypto.sidDb[uid], sid) &&
        !crypto.dhKey.public
      ) {
        Logger.debug("Resetting mismatching public key for sid", { sid: sid });
        this.setDhPublic(channel, myuid, sid);
      }

      // Process BD if needed
      if (crypto.dhKey.public && keysz > 0) {
        const key_array = decrypted.slice(msgsz, msgsz + keysz);
        msgtype = BdKeyManager.processBd(
          channel,
          myuid,
          uid,
          msgtype,
          key_array,
        );
      }
    },

    /**
     * Set DH public key
     * @param {string} channel - Channel name
     * @param {string} myuid - Local user ID
     * @param {Uint8Array} sid - Session ID
     */
    setDhPublic(channel, myuid, sid) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return;

      // Use the original public key logic exactly as implemented
      const siddb_sorted = Object.fromEntries(
        Object.entries(crypto.sidDb).sort(),
      );

      let pubok = true;
      let cnt = 0;
      let users = "";

      for (let userid in siddb_sorted) {
        if (!BinaryUtil.isEqual(crypto.sidDb[userid], sid)) {
          pubok = false;
          break;
        }
        users += userid;
        cnt++;
      }

      if (pubok && cnt > 1) {
        // Create group key using original approach
        let sid16 = new Uint8Array(16);
        sid16.set(sid, 0);
        const digest64B = new BLAKE2b(64, {
          salt: sid16,
          personalization: CONSTANTS.PERBDSTR,
          key: crypto.msgCryptKey,
        });

        crypto.dhKey.group = ristretto255.fromHash(digest64B.digest());
        crypto.dhKey.private = ristretto255.scalar.getRandom();
        crypto.dhKey.public = ristretto255.scalarMult(
          crypto.dhKey.private,
          crypto.dhKey.group,
        );

        crypto.dhKey.secret = null;
        crypto.dhKey.secretAcked = false;

        State.initBd(channel);

        Logger.debug("Public key set for sid", { sid: sid });
      }
    },

    /**
     * Prepare and send message
     * @param {string} channel - Channel name
     * @param {string} uid - User ID
     * @param {string} data - Message data
     * @param {number} msgtype - Message type
     * @param {Date} valueofdate - Message date
     * @param {boolean} usePrevKey - Use previous BD key
     */
    prepareAndSendMessage(
      channel,
      uid,
      data,
      msgtype,
      valueofdate,
      usePrevKey = false,
    ) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) {
        Logger.error("Channel not initialized", { channel });
        return;
      }

      try {
        const data_array = new TextEncoder().encode(data);
        let nonce = new Uint8Array(32);
        self.crypto.getRandomValues(nonce);

        // Create timestamps
        const weekstamp = TimeUtil.createWeekstamp(valueofdate);
        const timestamp = TimeUtil.createTimestamp(valueofdate, weekstamp);
        let flagstamp = TimeUtil.createFlagstamp(
          valueofdate,
          weekstamp,
          timestamp,
        );

        // Set flags
        flagstamp = this.setMessageFlags(flagstamp, msgtype);

        // Prepare keys and data
        const { keysz, flagstamp: updatedFlagstamp } = this.prepareKeysAndData(
          channel,
          uid,
          msgtype,
          flagstamp,
        );
        flagstamp = updatedFlagstamp; // Update flagstamp with BD flags

        const keys_array = this.createKeyArray(channel, uid, msgtype, keysz);

        // Select crypto keys
        let { crypt, channel_key } = this.selectCryptoKeys(channel, usePrevKey);
        if (!crypt || !channel_key) {
          Logger.error("Missing crypto keys", {
            channel,
            usePrevKey,
          });
          return;
        }

        // Construct message
        const { hdr_data_keys, msgsz } = this.constructMessageData(
          channel,
          uid,
          data_array,
          keys_array,
          keysz,
          timestamp,
          weekstamp,
          flagstamp,
        );

        // Encrypt message
        const encrypted = nacl.secretbox(
          hdr_data_keys,
          nonce.slice(0, 24),
          crypt,
        );

        // Calculate HMAC
        const hmac = this.calculateMessageHmac(nonce, encrypted, channel_key);

        // Combine message components
        const messageData = this.combineMessageComponents(
          nonce,
          encrypted,
          hmac,
        );

        // Create message object
        const obj = {
          uid: CryptoUtil.encryptUid(uid, crypto.channelKey),
          channel: CryptoUtil.encryptChannel(channel, crypto.channelKey),
          message: messageData,
        };

        // Encode and send message
        this.encodeSendMessage(channel, obj, uid, msgtype);
      } catch (error) {
        Logger.error("Error preparing message", {
          channel,
          uid,
          error: error.message,
        });
      }
    },

    /**
     * Set message flags
     * @param {number} flagstamp - Current flagstamp
     * @param {number} msgtype - Message type
     * @return {number} Updated flagstamp
     */
    setMessageFlags(flagstamp, msgtype) {
      // Apply flags to flagstamp
      if (msgtype & CONSTANTS.MSGISFULL) flagstamp |= CONSTANTS.ISFULL;
      if (msgtype & CONSTANTS.MSGISDATA) flagstamp |= CONSTANTS.ISDATA;
      if (msgtype & CONSTANTS.MSGISPRESENCE) flagstamp |= CONSTANTS.ISPRESENCE;
      if (msgtype & CONSTANTS.MSGISPRESENCEACK)
        flagstamp |= CONSTANTS.ISPRESENCEACK;

      if (msgtype & CONSTANTS.MSGISMULTIPART) {
        flagstamp |= CONSTANTS.ISMULTI;
        if (msgtype & CONSTANTS.MSGISFIRST) {
          flagstamp |= CONSTANTS.ISFIRST;
        }
        if (msgtype & CONSTANTS.MSGISLAST) {
          flagstamp |= CONSTANTS.ISLAST;
        }
      }

      return flagstamp;
    },

    /**
     * Prepare keys and data
     * @param {string} channel - Channel name
     * @param {string} uid - User ID
     * @param {number} msgtype - Message type
     * @param {number} flagstamp - Current flagstamp value
     * @return {Object} Updated key size and flagstamp
     */
    prepareKeysAndData(channel, uid, msgtype, flagstamp) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return { keysz: 0, flagstamp };

      let keysz = 0;

      // Check if we have public key
      if (crypto.dhKey.public) {
        keysz += CONSTANTS.DH_BITS / 8;

        // Check if we have BD key and not presence ack
        if (crypto.dhKey.bd && !(msgtype & CONSTANTS.MSGISPRESENCEACK)) {
          const sidcnt = Object.keys(crypto.sidDb).length;

          // For two participants, just set BD flag
          if (sidcnt === 2) {
            flagstamp |= CONSTANTS.ISBDONE;
          } else {
            // For more participants, include BD key
            keysz += CONSTANTS.DH_BITS / 8;
          }

          // Set BD ack flag if appropriate
          const pubcnt = Object.keys(crypto.dhDb).length;
          const bdcnt = Object.keys(crypto.bdDb || {}).length;

          if (sidcnt === pubcnt && pubcnt === bdcnt && crypto.dhKey.secret) {
            flagstamp |= CONSTANTS.ISBDACK;
            crypto.bdAckDb[uid] = true;
          }
        }
      }

      return { keysz, flagstamp };
    },

    /**
     * Create key array
     * @param {string} channel - Channel name
     * @param {string} uid - User ID
     * @param {number} msgtype - Message type
     * @param {number} keysz - Key size
     * @return {Uint8Array} Key array
     */
    createKeyArray(channel, uid, msgtype, keysz) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return new Uint8Array(0);

      const keys_array = new Uint8Array(2 * (CONSTANTS.DH_BITS / 8));
      let keyIdx = 0;

      // Add public key if it exists
      if (crypto.dhKey.public) {
        keys_array.set(crypto.dhKey.public, keyIdx);
        crypto.dhDb[uid] = crypto.dhKey.public;
        keyIdx += CONSTANTS.DH_BITS / 8;
      }

      // Add BD key if appropriate
      if (crypto.dhKey.bd && !(msgtype & CONSTANTS.MSGISPRESENCEACK)) {
        const sidcnt = Object.keys(crypto.sidDb).length;

        // For more than 2 participants, include BD key
        if (sidcnt > 2) {
          keys_array.set(crypto.dhKey.bd, keyIdx);
        }
      }

      return keys_array;
    },

    /**
     * Select appropriate crypto keys
     * @param {string} channel - Channel name
     * @param {boolean} usePrevKey - Use previous BD key
     * @return {Object} Selected crypto keys
     */
    selectCryptoKeys(channel, usePrevKey) {
      const crypto = State.crypto.channels[channel];
      if (!crypto) return { crypt: null, channel_key: null };

      // Default to regular keys
      let crypt = crypto.msgCryptKey;
      let channel_key = crypto.channelKey;

      // Check BD keys availability - preserve original boolean logic
      const hasBdKeys =
        crypto.dhKey.bdMsgCryptKey &&
        crypto.dhKey.secret &&
        crypto.dhKey.secretAcked;

      const hasPrevBdKeys =
        crypto.dhKey.prevBdMsgCryptKey && crypto.dhKey.prevBdChannelKey;

      // Use original logic with conditionals - these are not security sensitive
      // as they don't compare secret values, just check for existence
      if (!usePrevKey) {
        if (hasBdKeys) {
          // Enable forward secrecy notification
          if (!crypto.dhKey.fsInformed) {
            EventHandler.processOnForwardSecrecy(channel, crypto.dhKey.secret);
            crypto.dhKey.fsInformed = true;
          }

          // Use BD keys
          crypt = crypto.dhKey.bdMsgCryptKey;
          channel_key = crypto.dhKey.bdChannelKey;
        }
      } else if (hasPrevBdKeys) {
        // Use previous BD keys
        crypt = crypto.dhKey.prevBdMsgCryptKey;
        channel_key = crypto.dhKey.prevBdChannelKey;
      }

      return { crypt, channel_key };
    },

    /**
     * Construct message data
     * @param {string} channel - Channel name
     * @param {string} uid - User ID
     * @param {Uint8Array} data_array - Message data
     * @param {Uint8Array} keys_array - Key data
     * @param {number} keysz - Key size
     * @param {number} timestamp - Timestamp
     * @param {number} weekstamp - Weekstamp
     * @param {number} flagstamp - Flagstamp
     * @return {Object} Message data
     */
    constructMessageData(
      channel,
      uid,
      data_array,
      keys_array,
      keysz,
      timestamp,
      weekstamp,
      flagstamp,
    ) {
      const msgsz = data_array.length + CONSTANTS.HDRLEN;
      const csize = CONSTANTS.HDRLEN + data_array.length + keysz;

      // Calculate padding size
      const padlen = 0; // Zero for now to simplify
      const padsz = CryptoUtil.padme(csize + padlen) - csize;

      // Create header + data + keys array
      const hdr_data_keys = new Uint8Array(
        CONSTANTS.HDRLEN + data_array.length + keysz + padsz,
      );

      let clen = 0;

      // Version and message size
      hdr_data_keys.set(BinaryUtil.fromUint16Val(msgsz), clen);
      clen += 2;

      // Session ID
      const sid = SessionManager.getSid(channel, uid);
      hdr_data_keys.set(sid, clen);
      clen += sid.length;

      // Key size
      hdr_data_keys.set(BinaryUtil.fromUint16Val(keysz), clen);
      clen += 2;

      // Timestamps
      hdr_data_keys.set(BinaryUtil.fromUint16Val(timestamp), clen);
      clen += 2;
      hdr_data_keys.set(BinaryUtil.fromUint16Val(weekstamp), clen);
      clen += 2;
      hdr_data_keys.set(BinaryUtil.fromUint16Val(flagstamp), clen);
      clen += 2;

      // Data and keys
      hdr_data_keys.set(data_array, clen);
      hdr_data_keys.set(keys_array.slice(0, keysz), clen + data_array.length);

      // Add padding if needed
      if (padsz > 0) {
        const pad_array = CryptoUtil.pseudoRandBytes(padsz);
        hdr_data_keys.set(pad_array, clen + data_array.length + keysz);
      }

      return { hdr_data_keys, msgsz };
    },

    /**
     * Calculate message HMAC
     * @param {Uint8Array} nonce - Nonce
     * @param {Uint8Array} encrypted - Encrypted data
     * @param {Uint8Array} channel_key - Channel key
     * @return {Uint8Array} HMAC
     */
    calculateMessageHmac(nonce, encrypted, channel_key) {
      // Create HMAC input array
      const hmacarr = new Uint8Array(nonce.byteLength + encrypted.byteLength);
      hmacarr.set(nonce, 0);
      hmacarr.set(encrypted, nonce.byteLength);

      // Calculate HMAC
      const blakehmac = new BLAKE2b(CONSTANTS.HMAC_LEN, {
        salt: CONSTANTS.SALTSTR,
        personalization: CONSTANTS.PERSTR,
        key: channel_key,
      });

      blakehmac.update(CONSTANTS.DOMAIN_AUTHKEY);
      blakehmac.update(nonce.slice(24));
      blakehmac.update(hmacarr);

      return blakehmac.digest();
    },

    /**
     * Combine message components
     * @param {Uint8Array} nonce - Nonce
     * @param {Uint8Array} encrypted - Encrypted data
     * @param {Uint8Array} hmac - HMAC
     * @return {Uint8Array} Combined message
     */
    combineMessageComponents(nonce, encrypted, hmac) {
      const messageData = new Uint8Array(
        nonce.byteLength + encrypted.byteLength + hmac.byteLength,
      );

      messageData.set(nonce, 0);
      messageData.set(encrypted, nonce.byteLength);
      messageData.set(hmac, nonce.byteLength + encrypted.byteLength);

      return messageData;
    },

    /**
     * Encode and send message
     * @param {string} channel - Channel name
     * @param {Object} obj - Message object
     * @param {string} uid - User ID
     * @param {number} msgtype - Message type
     */
    encodeSendMessage(channel, obj, uid, msgtype) {
      const connection = State.connections[channel];
      if (!connection || !connection.webSocket) {
        Logger.error("No connection available", { channel });
        return;
      }

      try {
        // Encode message
        const encodedMsg = this.encodeMessage(obj);
        if (!encodedMsg) {
          Logger.error("Message encoding failed", { channel });
          return;
        }

        // Send message
        connection.webSocket.send(encodedMsg);

        // Notify that message was sent
        postMessage([
          "send",
          uid,
          channel,
          msgtype & CONSTANTS.MSGISMULTIPART ? true : false,
        ]);
      } catch (error) {
        Logger.error("Error sending message", {
          channel,
          error: error.message,
        });
      }
    },

    /**
     * Encode a message
     * @param {Object} obj - Message object
     * @return {Uint8Array} Encoded message
     */
    encodeMessage(obj) {
      try {
        return CBOR.encode(obj);
      } catch (error) {
        Logger.error("Message encoding failed", { error: error.message });
        return null;
      }
    },

    /**
     * Decode a message
     * @param {Uint8Array} data - Encoded message data
     * @return {Object} Decoded message
     */
    decodeMessage(data) {
      try {
        return CBOR.decode(data);
      } catch (error) {
        Logger.error("Message decoding failed", { error: error.message });
        return null;
      }
    },
  };

  // =========================================================================
  // WebSocket Connection Management
  // =========================================================================
  const ConnectionManager = {
    /**
     * Check if socket is open
     * @param {string} channel - Channel name
     * @return {boolean} True if socket is open
     */
    isSocketOpen(channel) {
      const connection = State.connections[channel];
      if (
        connection &&
        connection.webSocket &&
        connection.webSocket.readyState === WebSocket.OPEN
      ) {
        return true;
      }
      return false;
    },

    /**
     * Open a socket connection
     * @param {string} channel - Channel name
     * @param {number} port - Port number
     * @param {string} addr - Server address
     * @param {boolean} reopen - True if reopening an existing connection
     */
    openSocket(channel, port, addr, reopen = false) {
      if (this.isSocketOpen(channel) && !reopen) {
        Logger.debug("Socket already open", { channel });
        return;
      }

      const connection = State.connections[channel];
      if (!connection) {
        Logger.error("Channel not initialized", { channel });
        return;
      }

      if (connection.webSocket) {
        try {
          connection.webSocket.close();
        } catch (e) {
          // Ignore errors during close
        }
      }

      try {
        // Create new WebSocket
        connection.webSocket = new WebSocket(
          "wss://" + addr + ":" + port,
          "mles-websocket",
        );
        connection.webSocket.binaryType = "arraybuffer";

        // Set up event handlers
        this.setupSocketEventHandlers(channel, reopen);

        Logger.info("Socket opening", {
          channel,
          address: addr,
          port,
          reopen,
        });
      } catch (error) {
        Logger.error("Failed to open socket", {
          channel,
          addr,
          port,
          error: error.message,
        });
      }
    },

    /**
     * Set up WebSocket event handlers
     * @param {string} channel - Channel name
     * @param {boolean} reopen - True if reopening
     */
    setupSocketEventHandlers(channel, reopen) {
      const connection = State.connections[channel];
      if (!connection || !connection.webSocket) return;

      // Handle socket open
      connection.webSocket.onopen = function (event) {
        try {
          EventHandler.processOnOpen(channel, reopen);
        } catch (error) {
          Logger.error("Error in open handler", {
            channel,
            error: error.message,
          });
        }
      };

      // Handle incoming messages
      connection.webSocket.onmessage = function (event) {
        try {
          if (!event.data) return;

          const msg = MessageProcessor.decodeMessage(event.data);
          if (!msg) {
            Logger.warn("Failed to decode message", { channel });
            return;
          }

          MessageProcessor.processMessage(channel, msg);
        } catch (error) {
          Logger.error("Error in message handler", {
            channel,
            error: error.message,
          });
        }
      };

      // Handle connection close
      connection.webSocket.onclose = function (event) {
        try {
          EventHandler.processOnClose(channel);
        } catch (error) {
          Logger.error("Error in close handler", {
            channel,
            error: error.message,
          });
        }
      };

      // Handle errors
      connection.webSocket.onerror = function (event) {
        Logger.error("WebSocket error", {
          channel,
          code: event.code,
          reason: event.reason,
        });
      };
    },
  };

  // =========================================================================
  // Event Handlers
  // =========================================================================
  const EventHandler = {
    /**
     * Process socket open event
     * @param {string} channel - Channel name
     * @param {boolean} reopen - True if reopening
     */
    processOnOpen(channel, reopen) {
      const connection = State.connections[channel];
      const crypto = State.crypto.channels[channel];

      if (!connection || !crypto) {
        Logger.error("Channel not initialized", { channel });
        return;
      }

      try {
        // Send join message
        const join = JSON.stringify({
          uid: connection.uid,
          channel: connection.channelId,
        });

        connection.webSocket.send(join);

        // Notify client
        const uid = CryptoUtil.decryptUid(connection.uid, crypto.channelKey);

        if (reopen) {
          postMessage(["resync", uid, channel]);
        } else {
          postMessage(["init", uid, channel]);
        }

        Logger.info("Connection established", {
          channel,
          reopen,
        });
      } catch (error) {
        Logger.error("Failed to process open event", {
          channel,
          error: error.message,
        });
      }
    },

    /**
     * Process socket close event
     * @param {string} channel - Channel name
     */
    processOnClose(channel) {
      const connection = State.connections[channel];
      const crypto = State.crypto.channels[channel];

      if (!connection || !crypto) {
        Logger.error("Channel not initialized", { channel });
        return;
      }

      try {
        // Close socket
        if (connection.webSocket) {
          connection.webSocket.close();
        }

        // Notify client
        const uid = CryptoUtil.decryptUid(connection.uid, crypto.channelKey);
        postMessage(["close", uid, channel]);

        Logger.info("Connection closed", { channel });
      } catch (error) {
        Logger.error("Failed to process close event", {
          channel,
          error: error.message,
        });
      }
    },

    /**
     * Process forward secrecy enabled
     * @param {string} channel - Channel name
     * @param {Uint8Array} bdKey - BD key
     */
    processOnForwardSecrecy(channel, bdKey) {
      const connection = State.connections[channel];
      const crypto = State.crypto.channels[channel];

      if (!connection || !crypto) {
        Logger.error("Channel not initialized", { channel });
        return;
      }

      try {
        // Convert BD key to hex string
        let bdKeyHex;
        if (typeof bdKey === "object" && bdKey.toString) {
          bdKeyHex = bdKey.toString(16);
        } else {
          bdKeyHex = String(bdKey);
        }

        // Notify client
        const uid = CryptoUtil.decryptUid(connection.uid, crypto.channelKey);
        postMessage(["forwardsecrecy", uid, channel, bdKeyHex]);

        Logger.info("Forward secrecy enabled", { channel });
      } catch (error) {
        Logger.error("Failed to process forward secrecy event", {
          channel,
          error: error.message,
        });
      }
    },

    /**
     * Process forward secrecy disabled
     * @param {string} channel - Channel name
     */
    processOnForwardSecrecyOff(channel) {
      const connection = State.connections[channel];
      const crypto = State.crypto.channels[channel];

      if (!connection || !crypto) {
        Logger.error("Channel not initialized", { channel });
        return;
      }

      try {
        // Notify client
        const uid = CryptoUtil.decryptUid(connection.uid, crypto.channelKey);
        postMessage(["forwardsecrecyoff", uid, channel]);

        Logger.info("Forward secrecy disabled", { channel });
      } catch (error) {
        Logger.error("Failed to process forward secrecy off event", {
          channel,
          error: error.message,
        });
      }
    },
  };

  // =========================================================================
  // Command Handlers
  // =========================================================================
  const CommandHandler = {
    /**
     * Handle init command
     * @param {Array} data - Command data
     */
    handleInit(data) {
      try {
        // Extract parameters
        const addr = data[2];
        const port = data[3];
        const uid = data[4];
        const channel = data[5];
        const password = StringUtil.toUint8Array(data[6]);
        const prevBdKey = data[7];

        // Initialize channel state
        const state = State.initChannel(channel);

        // Setup connection parameters
        state.connection.address = addr;
        state.connection.port = port;

        // Initialize cryptographic state
        const crypto = state.crypto;

        // Generate salt
        const salt = new BLAKE2b(CONSTANTS.SCRYPT_SALTLEN, {
          salt: CONSTANTS.SALTSTR,
          personalization: CONSTANTS.PERSTR,
          key: password.slice(0, 32),
        });
        salt.update(password);
        salt.update(StringUtil.toUint8Array(channel));

        // Run scrypt
        scrypt(
          password,
          salt.digest(),
          {
            N: CONSTANTS.SCRYPT_N,
            r: CONSTANTS.SCRYPT_R,
            p: CONSTANTS.SCRYPT_P,
            dkLen: CONSTANTS.SCRYPT_DKLEN,
            encoding: "binary",
          },
          function (derivedKey) {
            // We only expect one parameter (the derived key)
            try {
              // Check if derivedKey is present
              if (!derivedKey) {
                Logger.error("Key derivation failed", {
                  error: "No derived key was returned",
                });
                return;
              }

              // Store password hash
              crypto.dhKey.pw = derivedKey;

              // Derive channel and message keys
              crypto.channelKey = CryptoUtil.createChannelKey(derivedKey);
              crypto.msgCryptKey = CryptoUtil.createMessageKey(derivedKey);

              // Set up previous BD key if provided
              if (prevBdKey) {
                CryptoUtil.createPrevBd(channel, prevBdKey, crypto.channelKey);
              }

              // Encrypt and store UID and channel
              state.connection.uid = CryptoUtil.encryptUid(
                uid,
                crypto.channelKey,
              );
              state.connection.channelId = CryptoUtil.encryptChannel(
                channel,
                crypto.channelKey,
              );

              // Clean up sensitive data
              wipe(salt);
              wipe(password);
              wipe(derivedKey);

              // Open socket connection
              ConnectionManager.openSocket(channel, port, addr);

              Logger.info("Channel initialized", {
                channel,
                address: addr,
                port,
              });
            } catch (err) {
              Logger.error("Key processing failed", {
                error: err.message,
                stack: err.stack || "No stack trace",
              });

              // Clean up any sensitive data
              if (salt) wipe(salt);
              if (password) wipe(password);
              if (derivedKey) wipe(derivedKey);
            }
          },
        );
      } catch (error) {
        Logger.error("Init command failed", {
          error: error.message,
        });
      }
    },

    /**
     * Handle reconnect command
     * @param {Array} data - Command data
     */
    handleReconnect(data) {
      try {
        // Extract parameters
        const uid = data[2];
        const channel = data[3];
        const prevBdKey = data[4];

        // Check if socket is already connected
        if (ConnectionManager.isSocketOpen(channel)) {
          Logger.debug("Socket already connected, skipping reconnect", {
            channel,
          });
          return;
        }

        // Set up previous BD key if provided
        if (prevBdKey) {
          const crypto = State.crypto.channels[channel];
          if (crypto && crypto.channelKey) {
            CryptoUtil.createPrevBd(channel, prevBdKey, crypto.channelKey);
          }
        }

        // Initialize session state
        State.initSid(channel);
        State.initDhBd(channel, uid);

        // Verify channel state
        const connection = State.connections[channel];
        const crypto = State.crypto.channels[channel];

        if (!connection || !crypto) {
          Logger.error("Channel not initialized", { channel });
          return;
        }

        // Check encrypted UID
        const myuid = CryptoUtil.encryptUid(uid, crypto.channelKey);
        const mychannel = CryptoUtil.encryptChannel(channel, crypto.channelKey);

        // Verify that we have already opened the channel earlier
        if (connection.uid === myuid && connection.channelId === mychannel) {
          ConnectionManager.openSocket(
            channel,
            connection.port,
            connection.address,
          );

          Logger.info("Channel reconnected", { channel });
        } else {
          Logger.error("Channel verification failed", { channel });
        }
      } catch (error) {
        Logger.error("Reconnect command failed", {
          error: error.message,
        });
      }
    },

    /**
     * Handle resync command
     * @param {Array} data - Command data
     */
    handleResync(data) {
      try {
        // Extract parameters
        const uid = data[2];
        const channel = data[3];
        const prevBdKey = data[4];

        // Set up previous BD key if provided
        if (prevBdKey) {
          const crypto = State.crypto.channels[channel];
          if (crypto && crypto.channelKey) {
            CryptoUtil.createPrevBd(channel, prevBdKey, crypto.channelKey);
          }
        }

        // Initialize session state
        State.initSid(channel);
        State.initDhBd(channel, uid);

        // Verify channel state
        const connection = State.connections[channel];
        const crypto = State.crypto.channels[channel];

        if (!connection || !crypto) {
          Logger.error("Channel not initialized", { channel });
          return;
        }

        // Check encrypted UID
        const myuid = CryptoUtil.encryptUid(uid, crypto.channelKey);
        const mychannel = CryptoUtil.encryptChannel(channel, crypto.channelKey);

        // Verify that we have already opened the channel earlier
        if (connection.uid === myuid && connection.channelId === mychannel) {
          ConnectionManager.openSocket(
            channel,
            connection.port,
            connection.address,
            true,
          );

          Logger.info("Channel resynced", { channel });
        } else {
          Logger.error("Channel verification failed", { channel });
        }
      } catch (error) {
        Logger.error("Resync command failed", {
          error: error.message,
        });
      }
    },

    /**
     * Handle send/resend_prev command
     * @param {string} cmd - Command name
     * @param {Array} data - Command data
     */
    handleSend(cmd, data) {
      try {
        // Extract parameters
        const messageData = data[1];
        const uid = data[2];
        const channel = data[3];
        const msgtype = data[4];
        const valueofdate = data[5];

        // Determine if using previous key
        const usePrevKey = cmd === "resend_prev";

        // Prepare and send message
        MessageProcessor.prepareAndSendMessage(
          channel,
          uid,
          messageData,
          msgtype,
          valueofdate,
          usePrevKey,
        );
      } catch (error) {
        Logger.error("Send command failed", {
          cmd,
          error: error.message,
        });
      }
    },

    /**
     * Handle close command
     * @param {Array} data - Command data
     */
    handleClose(data) {
      try {
        // Extract parameters
        const uid = data[2];
        const channel = data[3];

        // Close WebSocket
        const connection = State.connections[channel];
        if (connection && connection.webSocket) {
          connection.webSocket.close();
        }

        // Reset state
        State.initSid(channel);
        State.initDhBd(channel, uid);
        State.initPrevDhBd(channel);

        Logger.info("Channel closed", { channel });
      } catch (error) {
        Logger.error("Close command failed", {
          error: error.message,
        });
      }
    },
  };

  // =========================================================================
  // Main Message Handler
  // =========================================================================

  /**
   * Main message handler
   * @param {MessageEvent} e - Message event
   */
  function handleMessage(e) {
    try {
      const cmd = e.data[0];
      const data = e.data;

      Logger.debug(`Received command: ${cmd}`);

      switch (cmd) {
        case "init":
          CommandHandler.handleInit(data);
          break;

        case "reconnect":
          CommandHandler.handleReconnect(data);
          break;

        case "resync":
          CommandHandler.handleResync(data);
          break;

        case "send":
        case "resend_prev":
          CommandHandler.handleSend(cmd, data);
          break;

        case "close":
          CommandHandler.handleClose(data);
          break;

        case "set_log_level":
          Logger.setLevel(data[1]);
          break;

        default:
          Logger.warn(`Unknown command: ${cmd}`);
          break;
      }
    } catch (error) {
      Logger.error("Error handling message", {
        error: error.message,
        stack: error.stack,
      });
    }
  }

  // =========================================================================
  // Initialization
  // =========================================================================

  /**
   * Initialize the worker
   */
  function init() {
    // Initialize constants
    initializeConstants();

    // Set up message handler
    self.onmessage = handleMessage;

    Logger.info("Zpinc WebWorker initialized");
  }

  // Public API
  return {
    init,
  };
})();

// Initialize the worker when loaded
ZpincWorker.init();
