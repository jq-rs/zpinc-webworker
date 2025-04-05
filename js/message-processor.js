const MessageProcessor = {
  /**
   * Process an incoming message
   * @param {string} channel - Channel name
   * @param {Object} msg - Message object
   */
  processMessage(channel, msg) {
    //sanity check
    if (
      msg.message.byteLength <= Constants.CONSTANTS.NONCE_LEN ||
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
      let noncem = msg.message.slice(0, Constants.CONSTANTS.NONCE_LEN);
      let arr = msg.message.slice(
        Constants.CONSTANTS.NONCE_LEN,
        msg.message.byteLength - Constants.CONSTANTS.HMAC_LEN,
      );
      let hmac = msg.message.slice(
        msg.message.byteLength - Constants.CONSTANTS.HMAC_LEN,
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
      let decrypted = nacl.secretbox.open(message, noncem.slice(0, 24), crypt);
      if (!decrypted || decrypted.length < Constants.CONSTANTS.HDRLEN) {
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
        decrypted.slice(16, Constants.CONSTANTS.HDRLEN),
      );

      let msgDate = TimeUtil.readTimestamp(
        timeU16,
        weekU16,
        flagU16 & Constants.CONSTANTS.ALLISSET,
      );

      // Extract message text
      message = new TextDecoder().decode(
        decrypted.slice(Constants.CONSTANTS.HDRLEN, msgsz),
      );

      // Convert flags to message type
      let msgtype = this.convertFlagsToMessageType(flagU16);

      // Process session ID and DH state
      this.processSidAndDh(channel, uid, sid, keysz, decrypted, msgsz, msgtype);

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
      let blakehmac = new BLAKE2b(Constants.CONSTANTS.HMAC_LEN, {
        salt: Constants.CONSTANTS.SALTSTR,
        personalization: Constants.CONSTANTS.PERSTR,
        key: crypto.dhKey.bdChannelKey,
      });
      blakehmac.update(Constants.CONSTANTS.DOMAIN_AUTHKEY);
      blakehmac.update(noncem.slice(24));
      blakehmac.update(hmacarr);
      bdHmac = blakehmac.digest();
    } else {
      bdHmac = new Uint8Array(Constants.CONSTANTS.HMAC_LEN);
    }

    let prevBdHmac = null;
    if (crypto.dhKey.prevBdMsgCryptKey) {
      let blakehmac = new BLAKE2b(Constants.CONSTANTS.HMAC_LEN, {
        salt: Constants.CONSTANTS.SALTSTR,
        personalization: Constants.CONSTANTS.PERSTR,
        key: crypto.dhKey.prevBdChannelKey,
      });
      blakehmac.update(Constants.CONSTANTS.DOMAIN_AUTHKEY);
      blakehmac.update(noncem.slice(24));
      blakehmac.update(hmacarr);
      prevBdHmac = blakehmac.digest();
    } else {
      prevBdHmac = new Uint8Array(Constants.CONSTANTS.HMAC_LEN);
    }

    let regularHmac = new BLAKE2b(Constants.CONSTANTS.HMAC_LEN, {
      salt: Constants.CONSTANTS.SALTSTR,
      personalization: Constants.CONSTANTS.PERSTR,
      key: crypto.channelKey,
    });
    regularHmac.update(Constants.CONSTANTS.DOMAIN_AUTHKEY);
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
    if (flagU16 & Constants.CONSTANTS.ISFULL)
      msgtype |= Constants.CONSTANTS.MSGISFULL;
    if (flagU16 & Constants.CONSTANTS.ISDATA)
      msgtype |= Constants.CONSTANTS.MSGISDATA;
    if (flagU16 & Constants.CONSTANTS.ISPRESENCE)
      msgtype |= Constants.CONSTANTS.MSGISPRESENCE;
    if (flagU16 & Constants.CONSTANTS.ISPRESENCEACK)
      msgtype |= Constants.CONSTANTS.MSGISPRESENCEACK;
    if (flagU16 & Constants.CONSTANTS.ISMULTI)
      msgtype |= Constants.CONSTANTS.MSGISMULTIPART;
    if (flagU16 & Constants.CONSTANTS.ISFIRST)
      msgtype |= Constants.CONSTANTS.MSGISFIRST;
    if (flagU16 & Constants.CONSTANTS.ISLAST)
      msgtype |= Constants.CONSTANTS.MSGISLAST;
    if (flagU16 & Constants.CONSTANTS.ISBDONE)
      msgtype |= Constants.CONSTANTS.MSGISBDONE;
    if (flagU16 & Constants.CONSTANTS.ISBDACK)
      msgtype |= Constants.CONSTANTS.MSGISBDACK;

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
      Logger.trace("RX: setting sid to " + sid + " mysid " + crypto.dhKey.sid);
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
      msgtype = BdKeyManager.processBd(channel, myuid, uid, msgtype, key_array);
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
        personalization: Constants.CONSTANTS.PERBDSTR,
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
      const messageData = this.combineMessageComponents(nonce, encrypted, hmac);

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
    if (msgtype & Constants.CONSTANTS.MSGISFULL)
      flagstamp |= Constants.CONSTANTS.ISFULL;
    if (msgtype & Constants.CONSTANTS.MSGISDATA)
      flagstamp |= Constants.CONSTANTS.ISDATA;
    if (msgtype & Constants.CONSTANTS.MSGISPRESENCE)
      flagstamp |= Constants.CONSTANTS.ISPRESENCE;
    if (msgtype & Constants.CONSTANTS.MSGISPRESENCEACK)
      flagstamp |= Constants.CONSTANTS.ISPRESENCEACK;

    if (msgtype & Constants.CONSTANTS.MSGISMULTIPART) {
      flagstamp |= Constants.CONSTANTS.ISMULTI;
      if (msgtype & Constants.CONSTANTS.MSGISFIRST) {
        flagstamp |= Constants.CONSTANTS.ISFIRST;
      }
      if (msgtype & Constants.CONSTANTS.MSGISLAST) {
        flagstamp |= Constants.CONSTANTS.ISLAST;
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
      keysz += Constants.CONSTANTS.DH_BITS / 8;

      // Check if we have BD key and not presence ack
      if (
        crypto.dhKey.bd &&
        !(msgtype & Constants.CONSTANTS.MSGISPRESENCEACK)
      ) {
        const sidcnt = Object.keys(crypto.sidDb).length;

        // For two participants, just set BD flag
        if (sidcnt === 2) {
          flagstamp |= Constants.CONSTANTS.ISBDONE;
        } else {
          // For more participants, include BD key
          keysz += Constants.CONSTANTS.DH_BITS / 8;
        }

        // Set BD ack flag if appropriate
        const pubcnt = Object.keys(crypto.dhDb).length;
        const bdcnt = Object.keys(crypto.bdDb || {}).length;

        if (sidcnt === pubcnt && pubcnt === bdcnt && crypto.dhKey.secret) {
          flagstamp |= Constants.CONSTANTS.ISBDACK;
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

    const keys_array = new Uint8Array(2 * (Constants.CONSTANTS.DH_BITS / 8));
    let keyIdx = 0;

    // Add public key if it exists
    if (crypto.dhKey.public) {
      keys_array.set(crypto.dhKey.public, keyIdx);
      crypto.dhDb[uid] = crypto.dhKey.public;
      keyIdx += Constants.CONSTANTS.DH_BITS / 8;
    }

    // Add BD key if appropriate
    if (crypto.dhKey.bd && !(msgtype & Constants.CONSTANTS.MSGISPRESENCEACK)) {
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
    const msgsz = data_array.length + Constants.CONSTANTS.HDRLEN;
    const csize = Constants.CONSTANTS.HDRLEN + data_array.length + keysz;

    // Calculate padding size
    const padlen = 0; // Zero for now to simplify
    const padsz = CryptoUtil.padme(csize + padlen) - csize;

    // Create header + data + keys array
    const hdr_data_keys = new Uint8Array(
      Constants.CONSTANTS.HDRLEN + data_array.length + keysz + padsz,
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
    const blakehmac = new BLAKE2b(Constants.CONSTANTS.HMAC_LEN, {
      salt: Constants.CONSTANTS.SALTSTR,
      personalization: Constants.CONSTANTS.PERSTR,
      key: channel_key,
    });

    blakehmac.update(Constants.CONSTANTS.DOMAIN_AUTHKEY);
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
        msgtype & Constants.CONSTANTS.MSGISMULTIPART ? true : false,
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
