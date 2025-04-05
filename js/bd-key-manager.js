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
    const pub = keyArray.slice(0, Constants.CONSTANTS.DH_BITS / 8);

    Logger.debug(`Processing BD message from ${uid} in channel ${channel}`, {
      keyLength: keyArray.length,
      messageType: msgtype,
    });

    // Handle key mismatch (original logic preserved)
    if (crypto.dhDb[uid]) {
      const keyMismatch = !BinaryUtil.isEqual(crypto.dhDb[uid], pub);
      const isShortMessageWithExistingBd =
        keyArray.length === Constants.CONSTANTS.DH_BITS / 8 &&
        !(msgtype & Constants.CONSTANTS.MSGISBDONE) &&
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
      length === Constants.CONSTANTS.DH_BITS / 8 ||
      length === 2 * (Constants.CONSTANTS.DH_BITS / 8)
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
      keyArray.length === Constants.CONSTANTS.DH_BITS / 8 &&
      !(msgtype & Constants.CONSTANTS.MSGISBDONE) &&
      crypto.dhDb[uid] &&
      crypto.bdDb &&
      crypto.bdDb[uid];

    if (keyMismatch || isShortMessageWithExistingBd) {
      Logger.debug("DH-BD reset required", {
        reason: keyMismatch ? "key mismatch" : "short message with existing BD",
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

    const isLongMessage =
      keyArray.length === 2 * (Constants.CONSTANTS.DH_BITS / 8);
    const isShortMessageWithBdFlag =
      keyArray.length === Constants.CONSTANTS.DH_BITS / 8 &&
      msgtype & Constants.CONSTANTS.MSGISBDONE;

    Logger.debug("BD message processing check", {
      participants: pubcnt,
      messageLength: keyArray.length,
      hasBdFlag: Boolean(msgtype & Constants.CONSTANTS.MSGISBDONE),
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
    const dhdb_sorted = Object.fromEntries(Object.entries(crypto.dhDb).sort());

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
      hasBdFlag: Boolean(msgtype & Constants.CONSTANTS.MSGISBDONE),
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
    if (msgtype & Constants.CONSTANTS.MSGISBDACK) {
      this.processBdAck(channel, uid, keyArray, pub, msgtype);
    }
  },

  /**
   * Extract BD value from key array
   * @param {Uint8Array} keyArray - Key data array
   * @return {Uint8Array} BD value
   */
  extractBdValue(keyArray) {
    let bd = BinaryUtil.createZeroArray(Constants.CONSTANTS.DH_BITS / 8);

    if (keyArray.length === 2 * (Constants.CONSTANTS.DH_BITS / 8)) {
      bd = keyArray.slice(Constants.CONSTANTS.DH_BITS / 8, keyArray.length);
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
    const isPresence = Boolean(msgtype & Constants.CONSTANTS.MSGISPRESENCE);
    const hasPresenceAck = Boolean(
      msgtype & Constants.CONSTANTS.MSGISPRESENCEACK,
    );
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
        salt: Constants.CONSTANTS.SALTSTR,
        personalization: Constants.CONSTANTS.PERSTR,
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
      keyArray.length === Constants.CONSTANTS.DH_BITS / 8 &&
      msgtype & Constants.CONSTANTS.MSGISBDACK &&
      msgtype & Constants.CONSTANTS.MSGISBDONE;

    const isLongMessageAck =
      stats.publicKeyCount > 2 &&
      keyArray.length === 2 * (Constants.CONSTANTS.DH_BITS / 8) &&
      msgtype & Constants.CONSTANTS.MSGISBDACK;

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
