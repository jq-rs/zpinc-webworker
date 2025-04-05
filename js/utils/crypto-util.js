const CryptoUtil = {
  /**
   * Generate a pseudo-random byte array
   * @param {number} byteLength - Length of the array
   * @return {Uint8Array|null} Random byte array or null on error
   */
  pseudoRandBytes(byteLength) {
    try {
      if (byteLength <= 0) {
        Logger.warn("Invalid byteLength for pseudoRandBytes", { byteLength });
        return null;
      }

      // Create buffer of the requested size
      let buf = new Uint8Array(byteLength);

      // Fill it with cryptographically secure random values
      self.crypto.getRandomValues(buf);

      return buf;
    } catch (error) {
      Logger.error("Failed to generate random bytes", { error: error.message });
      return null;
    }
  },

  /**
   * Derive key using HKDF-like construction (constant-time)
   * @param {Uint8Array} inputKey - Input key material
   * @param {Uint8Array} info - Context and application specific information
   * @param {number} length - Length of output key material
   * @return {Uint8Array|null} Derived key or null on error
   */
  deriveKey(inputKey, info, length = 32) {
    if (!inputKey || !info) {
      Logger.error("Invalid parameters for key derivation");
      return null;
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
      return null;
    }
  },

  /**
   * Create a channel key from input key material
   * @param {Uint8Array} key - Input key material
   * @return {Uint8Array|null} Channel key or null on error
   */
  createChannelKey(key) {
    try {
      const channelKey = this.deriveKey(
        key,
        Constants.CONSTANTS.DOMAIN_CHANKEY,
      );
      if (!channelKey) {
        Logger.error("Failed to create channel key");
        return null;
      }
      return channelKey;
    } catch (error) {
      Logger.error("Channel key creation failed", { error: error.message });
      return null;
    }
  },

  /**
   * Create a message key from input key material
   * @param {Uint8Array} key - Input key material
   * @return {Uint8Array|null} Message key or null on error
   */
  createMessageKey(key) {
    try {
      const messageKey = this.deriveKey(key, Constants.CONSTANTS.DOMAIN_ENCKEY);
      if (!messageKey) {
        Logger.error("Failed to create message key");
        return null;
      }
      return messageKey;
    } catch (error) {
      Logger.error("Message key creation failed", { error: error.message });
      return null;
    }
  },

  /**
   * Encrypt a channel name
   * @param {string} channel - Channel name
   * @param {Uint8Array} channelKey - Channel key
   * @return {string|null} Encrypted channel (base64) or null on error
   */
  encryptChannel(channel, channelKey) {
    try {
      const key = this.deriveKey(channelKey, Constants.CONSTANTS.INFO_CHANNEL);
      if (!key) {
        Logger.error("Failed to derive key for channel encryption");
        return null;
      }

      const nonce = this.deriveKey(
        channelKey,
        Constants.CONSTANTS.INFO_CHANNEL_NONCE,
        24,
      );
      if (!nonce) {
        Logger.error("Failed to derive nonce for channel encryption");
        wipe(key);
        return null;
      }

      const ciphertext = nacl.secretbox(
        StringUtil.toUint8Array(channel),
        nonce,
        key,
      );

      // Clean up
      wipe(key);
      wipe(nonce);

      return btoa(StringUtil.fromUint8Array(ciphertext));
    } catch (error) {
      Logger.error("Channel encryption failed", { error: error.message });
      return null;
    }
  },

  /**
   * Decrypt a channel name
   * @param {string} encrypted - Encrypted channel (base64)
   * @param {Uint8Array} channelKey - Channel key
   * @return {string|null} Decrypted channel name or null on error
   */
  decryptChannel(encrypted, channelKey) {
    let derivedKey = null;
    let nonce = null;

    try {
      derivedKey = this.deriveKey(channelKey, Constants.CONSTANTS.INFO_CHANNEL);
      if (!derivedKey) {
        Logger.error("Failed to derive key for channel decryption");
        return null;
      }

      nonce = this.deriveKey(
        channelKey,
        Constants.CONSTANTS.INFO_CHANNEL_NONCE,
        24,
      );
      if (!nonce) {
        Logger.error("Failed to derive nonce for channel decryption");
        wipe(derivedKey);
        return null;
      }

      try {
        const ciphertext = StringUtil.toUint8Array(atob(encrypted));
        const decrypted = nacl.secretbox.open(ciphertext, nonce, derivedKey);

        if (!decrypted) {
          Logger.error("Channel decryption failed - invalid data");
          return null;
        }

        return StringUtil.fromUint8Array(decrypted);
      } catch (error) {
        Logger.error("Channel decryption failed", { error: error.message });
        return null;
      }
    } catch (error) {
      Logger.error("Channel decryption preparation failed", {
        error: error.message,
      });
      return null;
    } finally {
      // Always clean up sensitive data
      if (derivedKey) wipe(derivedKey);
      if (nonce) wipe(nonce);
    }
  },

  /**
   * Encrypt a user ID
   * @param {string} uid - User ID
   * @param {Uint8Array} channelKey - Channel key
   * @return {string|null} Encrypted UID (base64) or null on error
   */
  encryptUid(uid, channelKey) {
    try {
      const key = this.deriveKey(channelKey, Constants.CONSTANTS.INFO_UID);
      if (!key) {
        Logger.error("Failed to derive key for UID encryption");
        return null;
      }

      const nonce = this.deriveKey(
        channelKey,
        Constants.CONSTANTS.INFO_UID_NONCE,
        24,
      );
      if (!nonce) {
        Logger.error("Failed to derive nonce for UID encryption");
        wipe(key);
        return null;
      }

      const ciphertext = nacl.secretbox(
        StringUtil.toUint8Array(uid),
        nonce,
        key,
      );

      // Clean up
      wipe(key);
      wipe(nonce);

      return btoa(StringUtil.fromUint8Array(ciphertext));
    } catch (error) {
      Logger.error("UID encryption failed", { error: error.message });
      return null;
    }
  },

  /**
   * Decrypt a user ID
   * @param {string} encrypted - Encrypted UID (base64)
   * @param {Uint8Array} channelKey - Channel key
   * @return {string|null} Decrypted user ID or null on error
   */
  decryptUid(encrypted, channelKey) {
    let derivedKey = null;
    let nonce = null;

    try {
      derivedKey = this.deriveKey(channelKey, Constants.CONSTANTS.INFO_UID);
      if (!derivedKey) {
        Logger.error("Failed to derive key for UID decryption");
        return null;
      }

      nonce = this.deriveKey(
        channelKey,
        Constants.CONSTANTS.INFO_UID_NONCE,
        24,
      );
      if (!nonce) {
        Logger.error("Failed to derive nonce for UID decryption");
        wipe(derivedKey);
        return null;
      }

      try {
        const ciphertext = StringUtil.toUint8Array(atob(encrypted));
        const decrypted = nacl.secretbox.open(ciphertext, nonce, derivedKey);

        if (!decrypted) {
          Logger.error("UID decryption failed - invalid data");
          return null;
        }

        return StringUtil.fromUint8Array(decrypted);
      } catch (error) {
        Logger.error("UID decryption failed", { error: error.message });
        return null;
      }
    } catch (error) {
      Logger.error("UID decryption preparation failed", {
        error: error.message,
      });
      return null;
    } finally {
      // Always clean up sensitive data
      if (derivedKey) wipe(derivedKey);
      if (nonce) wipe(nonce);
    }
  },

  /**
   * Calculate Padmé padding (constant-time)
   * @param {number} msgsize - Message size
   * @return {number} Padded size
   */
  padme(msgsize) {
    try {
      const L = msgsize;
      if (L <= 0) {
        Logger.warn("Invalid message size for padme", { msgsize });
        return msgsize; // Return original size instead of failing
      }
      const E = Math.floor(Math.log2(L));
      const S = Math.floor(Math.log2(E)) + 1;
      const lastBits = E - S;
      const bitMask = 2 ** lastBits - 1;
      return (L + bitMask) & ~bitMask;
    } catch (error) {
      Logger.error("Padding calculation failed", { error: error.message });
      return msgsize; // Return original size as fallback
    }
  },

  /**
   * Create previous BD key
   * @param {string} channel - Channel name
   * @param {string} prevBdKey - Previous BD key (hex string)
   * @param {Uint8Array} channelKey - Channel key
   * @return {boolean} Success status
   */
  createPrevBd(channel, prevBdKey, channelKey) {
    let rnd = null;
    let digest = null;

    try {
      const crypto = State.crypto.channels[channel];
      if (!crypto) {
        Logger.error("Channel not initialized", { channel });
        return false;
      }

      rnd = new BLAKE2b(32, {
        salt: Constants.CONSTANTS.SALTSTR,
        personalization: Constants.CONSTANTS.PERSTR,
        key: channelKey,
      });

      rnd.update(StringUtil.toUint8Array(prevBdKey));
      digest = rnd.digest();

      const prevBdChannelKey = this.createChannelKey(digest);
      if (!prevBdChannelKey) {
        Logger.error("Failed to create previous BD channel key", { channel });
        return false;
      }

      const prevBdMsgCryptKey = this.createMessageKey(digest);
      if (!prevBdMsgCryptKey) {
        Logger.error("Failed to create previous BD message key", { channel });
        wipe(prevBdChannelKey);
        return false;
      }

      crypto.dhKey.prevBdChannelKey = prevBdChannelKey;
      crypto.dhKey.prevBdMsgCryptKey = prevBdMsgCryptKey;

      Logger.debug("Previous BD keys created successfully", { channel });
      return true;
    } catch (error) {
      Logger.error("Failed to create previous BD keys", {
        channel,
        error: error.message,
      });
      return false;
    } finally {
      // Clean up sensitive data
      if (digest) wipe(digest);
      if (rnd) wipe(rnd);
    }
  },
};
