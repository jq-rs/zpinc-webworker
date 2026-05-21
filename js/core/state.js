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
        sidDb: Object.create(null),
        sid: null,

        // DH state
        dhDb: Object.create(null),
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
        joinDb: Object.create(null),

        // BD state
        bdDb: Object.create(null),
        bdAckDb: Object.create(null),
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

    crypto.sidDb = Object.create(null);
    wipe(crypto.dhKey.sid);
    crypto.dhKey.sid = null;
    wipe(crypto.dhKey.public);
    crypto.dhKey.public = null;
    wipe(crypto.dhKey.group);
    crypto.dhKey.group = null;
    wipe(crypto.dhKey.private);
    crypto.dhKey.private = null;

    this.initBd(channel);
  },

  // Initialize BD state
  initBd(channel) {
    const crypto = this.crypto.channels[channel];
    if (!crypto) return;

    crypto.bdDb = Object.create(null);
    crypto.bdAckDb = Object.create(null);
    wipe(crypto.dhKey.secret);
    crypto.dhKey.secret = null;
    crypto.dhKey.secretAcked = false;
    wipe(crypto.dhKey.bd);
    crypto.dhKey.bd = null;
    wipe(crypto.dhKey.bdMsgCryptKey);
    crypto.dhKey.bdMsgCryptKey = null;
    wipe(crypto.dhKey.bdChannelKey);
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

    crypto.dhDb = Object.create(null);
    if (crypto.dhKey.public) {
      crypto.dhDb[myuid] = crypto.dhKey.public;
    }

    this.initBd(channel);
  },

  // Initialize previous BD state
  initPrevDhBd(channel) {
    const crypto = this.crypto.channels[channel];
    if (!crypto) return;

    wipe(crypto.dhKey.prevBdChannelKey);
    crypto.dhKey.prevBdChannelKey = null;
    wipe(crypto.dhKey.prevBdMsgCryptKey);
    crypto.dhKey.prevBdMsgCryptKey = null;
  },
};
