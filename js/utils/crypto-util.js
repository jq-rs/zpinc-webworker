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
        salt: Constants.CONSTANTS.SALTSTR,
        personalization: Constants.CONSTANTS.PERSTR,
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
    return this.deriveKey(key, Constants.CONSTANTS.DOMAIN_CHANKEY);
  },

  /**
   * Create a message key from input key material
   * @param {Uint8Array} key - Input key material
   * @return {Uint8Array} Message key
   */
  createMessageKey(key) {
    return this.deriveKey(key, Constants.CONSTANTS.DOMAIN_ENCKEY);
  },

  /**
   * Encrypt a channel name
   * @param {string} channel - Channel name
   * @param {Uint8Array} channelKey - Channel key
   * @return {string} Encrypted channel (base64)
   */
  encryptChannel(channel, channelKey) {
    const key = this.deriveKey(channelKey, Constants.CONSTANTS.INFO_CHANNEL);
    const nonce = this.deriveKey(
      channelKey,
      Constants.CONSTANTS.INFO_CHANNEL_NONCE,
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
    const derivedKey = this.deriveKey(
      channelKey,
      Constants.CONSTANTS.INFO_CHANNEL,
    );
    const nonce = this.deriveKey(
      channelKey,
      Constants.CONSTANTS.INFO_CHANNEL_NONCE,
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
    const key = this.deriveKey(channelKey, Constants.CONSTANTS.INFO_UID);
    const nonce = this.deriveKey(
      channelKey,
      Constants.CONSTANTS.INFO_UID_NONCE,
      24,
    );

    const ciphertext = nacl.secretbox(StringUtil.toUint8Array(uid), nonce, key);

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
    const derivedKey = this.deriveKey(channelKey, Constants.CONSTANTS.INFO_UID);
    const nonce = this.deriveKey(
      channelKey,
      Constants.CONSTANTS.INFO_UID_NONCE,
      24,
    );

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
      throw new Error("Uid decryption failed. Invalid key or corrupted data.");
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
        salt: Constants.CONSTANTS.SALTSTR,
        personalization: Constants.CONSTANTS.PERSTR,
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
