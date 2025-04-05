/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2019-2020,2024-2025 MlesTalk WebWorker developers
 * Copyright (c) 2020-2021 Zpinc developers
 */

/**
 * Zpinc WebWorker - Zero-Trust Secure Group Messaging Protocol
 *
 * This implementation follows the Zpinc protocol specification for secure
 * messaging without requiring trust in server infrastructure.
 *
 * The protocol provides:
 * - Confidentiality and integrity through authenticated encryption
 * - Forward secrecy and post-compromise security via ephemeral keys
 * - Group authentication with shared secret keys
 * - Asynchronous messaging capability
 */

importScripts(
  "cbor.js",
  "blake2b.js",
  "scrypt-async.js",
  "nacl.js",
  "ristretto255.js",
  "wipe.js",
  "int.js",
  "binary.js",
  "utils/string-util.js",
  "core/constants.js",
  "core/logger.js",
  "utils/binary-util.js",
  "utils/time-util.js",
  "utils/crypto-util.js",
  "core/state.js",
  "protocol/session-manager.js",
  "protocol/bd-key-manager.js",
  "protocol/message-processor.js",
  "network/connection-manager.js",
  "network/event-handler.js",
  "commands/command-handler.js",
);

const ZpincWorker = (function () {
  function handleMessage(e) {
    try {
      const cmd = e.data[0];
      const data = e.data;

      Logger.debug(`Received command: ${cmd}`);

      switch (cmd) {
        case "init":
          CommandHandler.handleInit(data);
          break;

        case "reconnect":
          CommandHandler.handleReconnect(data);
          break;

        case "resync":
          CommandHandler.handleResync(data);
          break;

        case "send":
        case "resend_prev":
          CommandHandler.handleSend(cmd, data);
          break;

        case "close":
          CommandHandler.handleClose(data);
          break;

        case "set_log_level":
          Logger.setLevel(data[1]);
          break;

        default:
          Logger.warn(`Unknown command: ${cmd}`);
          break;
      }
    } catch (error) {
      Logger.error("Error handling message", {
        error: error.message,
        stack: error.stack,
      });
    }
  }

  function init() {
    Constants.initialize();
    self.onmessage = handleMessage;
    Logger.info("Zpinc WebWorker initialized");
  }

  return {
    init,
  };
})();

ZpincWorker.init();
