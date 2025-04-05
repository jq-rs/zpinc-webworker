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
