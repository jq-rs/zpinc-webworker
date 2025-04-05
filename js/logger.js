const Logger = (function () {
  const LogLevel = {
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3,
    TRACE: 4,
  };

  let level = LogLevel.DEBUG;

  function sanitize(obj) {
    if (!obj) return obj;

    // Create a copy to avoid modifying the original
    const copy = Array.isArray(obj) ? [...obj] : { ...obj };

    // Sanitize potentially sensitive fields
    const sensitiveFields = [
      "key",
      "keys",
      "secret",
      "password",
      "pw",
      "private",
      "channelKey",
      "msgCryptKey",
      "bdMsgCryptKey",
      "bdChannelKey",
    ];

    for (const field of sensitiveFields) {
      if (field in copy && copy[field]) {
        if (copy[field] instanceof Uint8Array) {
          copy[field] = "[REDACTED BINARY]";
        } else if (typeof copy[field] === "string") {
          copy[field] = "[REDACTED]";
        }
      }
    }

    return copy;
  }

  function error(message, context = {}) {
    if (level >= LogLevel.ERROR) {
      console.error("[ERROR]", message, sanitize(context));
    }
  }

  function warn(message, context = {}) {
    if (level >= LogLevel.WARN) {
      console.warn("[WARN]", message, sanitize(context));
    }
  }

  function info(message, context = {}) {
    if (level >= LogLevel.INFO) {
      console.info("[INFO]", message, sanitize(context));
    }
  }

  function debug(message, context = {}) {
    if (level >= LogLevel.DEBUG) {
      console.debug("[DEBUG]", message, sanitize(context));
    }
  }

  function trace(message, context = {}) {
    if (level >= LogLevel.TRACE) {
      console.log("[TRACE]", message, sanitize(context));
    }
  }

  function setLevel(newLevel) {
    if (Object.values(LogLevel).includes(newLevel)) {
      level = newLevel;
      info(`Log level set to ${newLevel}`);
    } else {
      warn(`Invalid log level: ${newLevel}`);
    }
  }

  return {
    LogLevel,
    error,
    warn,
    info,
    debug,
    trace,
    setLevel,
  };
})();
