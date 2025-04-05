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
