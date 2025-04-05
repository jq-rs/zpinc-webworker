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
      const salt = new BLAKE2b(Constants.CONSTANTS.SCRYPT_SALTLEN, {
        salt: Constants.CONSTANTS.SALTSTR,
        personalization: Constants.CONSTANTS.PERSTR,
        key: password.slice(0, 32),
      });
      salt.update(password);
      salt.update(StringUtil.toUint8Array(channel));

      // Run scrypt
      scrypt(
        password,
        salt.digest(),
        {
          N: Constants.CONSTANTS.SCRYPT_N,
          r: Constants.CONSTANTS.SCRYPT_R,
          p: Constants.CONSTANTS.SCRYPT_P,
          dkLen: Constants.CONSTANTS.SCRYPT_DKLEN,
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
