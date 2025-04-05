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
