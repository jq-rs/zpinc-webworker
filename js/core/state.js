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
