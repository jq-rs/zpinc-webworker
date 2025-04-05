const Constants = (function () {
  let CONSTANTS = {
    // To be populated
  };
  function initialize() {
    CONSTANTS = {
      // Protocol flags
      ISFULL: 0x8000,
      ISDATA: 0x4000,
      ISPRESENCE: 0x2000,
      ISPRESENCEACK: 0x1000,
      ISMULTI: 0x800,
      ISFIRST: 0x400,
      ISLAST: 0x200,
      ISBDONE: 0x100,
      ISBDACK: 0x80,
      ALLISSET: 0x7f,

      // Message type flags
      MSGISFULL: 0x1,
      MSGISPRESENCE: 0x1 << 1,
      MSGISDATA: 0x1 << 2,
      MSGISMULTIPART: 0x1 << 3,
      MSGISFIRST: 0x1 << 4,
      MSGISLAST: 0x1 << 5,
      MSGISPRESENCEACK: 0x1 << 6,
      RESERVED: 0x1 << 7,
      MSGISBDONE: 0x1 << 8,
      MSGISBDACK: 0x1 << 9,

      // Cryptographic parameters
      HMAC_LEN: 12,
      NONCE_LEN: 32,
      HDRLEN: 18,
      DH_BITS: 256,

      // Domains for key derivation
      DOMAIN_ENCKEY: StringUtil.toUint8Array("Zpinc-WebWorkerEncryptDom!v1"),
      DOMAIN_CHANKEY: StringUtil.toUint8Array("Zpinc-WebWorkerChannelDom!v1"),
      DOMAIN_AUTHKEY: StringUtil.toUint8Array("Zpinc-WebWorkerAuthDom!v1"),

      // Info strings for HKDF
      INFO_CHANNEL: StringUtil.toUint8Array("Zpinc-ChannelDerivation-v1"),
      INFO_CHANNEL_NONCE: StringUtil.toUint8Array(
        "Zpinc-ChannelNonceDerivation-v1",
      ),
      INFO_UID: StringUtil.toUint8Array("Zpinc-UidDerivation-v1"),
      INFO_UID_NONCE: StringUtil.toUint8Array("Zpinc-UidNonceDerivation-v1"),

      // Scrypt parameters
      SCRYPT_SALTLEN: 32,
      SCRYPT_N: 32768,
      SCRYPT_R: 8,
      SCRYPT_P: 1,
      SCRYPT_DKLEN: 32,
      SALTSTR: StringUtil.toUint8Array("ZpincSaltDomain1"),
      PERSTR: StringUtil.toUint8Array("ZpincAppDomainv1"),
      PERBDSTR: StringUtil.toUint8Array("ZpincBdDomain!v1"),
      BEGIN: new Date(Date.UTC(2018, 0, 1, 0, 0, 0)),
    };
  }

  return {
    get CONSTANTS() {
      return CONSTANTS;
    },
    initialize,
  };
})();
