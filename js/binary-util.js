const BinaryUtil = {
  /**
   * Convert a Uint8Array to a 16-bit integer value
   * @param {Uint8Array} arr - Input byte array (must have at least 2 bytes)
   * @return {number} 16-bit integer value
   */ 
  toUint16Val(arr) {
    return ((arr[0] & 0xff) << 8) | (arr[1] & 0xff);
  },

  /**
   * Convert a 16-bit integer value to a Uint8Array
   * @param {number} val - 16-bit integer value 
   * @return {Uint8Array} 2-byte array
   */
  fromUint16Val(val) {
    const arr = new Uint8Array(2);
    arr[0] = (val & 0xff00) >> 8; 
    arr[1] = val & 0xff;
    return arr;
  },

  /**
   * Check if two Uint8Arrays are equal (constant-time comparison)
   * @param {Uint8Array} arr1 - First array 
   * @param {Uint8Array} arr2 - Second array
   * @return {boolean} True if arrays are equal
   */
  isEqual(arr1, arr2) {
    if (!arr1 || !arr2 || arr1.length !== arr2.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < arr1.length; i++) {
      result |= arr1[i] ^ arr2[i];  
    }
    return result === 0;
  },

  /**
   * Check if two HMACs are equal (constant-time comparison)
   * @param {Uint8Array} hmac1 - First HMAC
   * @param {Uint8Array} hmac2 - Second HMAC 
   * @return {boolean} True if HMACs are equal
   */
  isEqualHmacs(hmac1, hmac2) {
    if (!hmac1 || !hmac2 || hmac1.length !== hmac2.length) {
      return false;
    }

    let diff = 0;
    for (let i = 0; i < hmac1.length; i++) {
      diff |= hmac1[i] ^ hmac2[i];
    }
    return diff === 0;
  },

  /**
   * Create a Uint8Array filled with zeroes
   * @param {number} size - Size of the array 
   * @return {Uint8Array} Zero-filled array
   */
  createZeroArray(size) {
    const arr = new Uint8Array(size);
    for (let i = 0; i < arr.length; i++) {
      arr[i] = 0;
    }
    return arr;  
  },

  /**
   * Check if a Uint8Array contains only zeroes (constant-time)
   * @param {Uint8Array} arr - Input array
   * @return {boolean} True if array contains only zeroes  
   */
  isZeroArray(arr) {
    if (!arr) return false;

    let result = 0;
    for (let i = 0; i < arr.length; i++) {
      result |= arr[i];
    }
    return result === 0;
  }
};
