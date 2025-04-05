const StringUtil = {
  /**
   * Convert a string to a Uint8Array
   * @param {string} str - Input string
   * @return {Uint8Array} Resulting byte array
   */
  toUint8Array(str) {
    const arr = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      arr[i] = str.charCodeAt(i);
    }
    return arr;
  },

  /**
   * Convert a Uint8Array to a string
   * @param {Uint8Array} arr - Input byte array
   * @return {string} Resulting string
   */
  fromUint8Array(arr) {
    if (!arr) return "";
    let str = "";
    for (let i = 0; i < arr.length; i++) {
      str += String.fromCharCode(arr[i]);
    }
    return str;
  },

  /**
   * Convert a string to a 16-bit integer value
   * @param {string} str - Input string (must be at least 2 characters)
   * @return {number} 16-bit integer value
   */
  toUint16Val(str) {
    return ((str.charCodeAt(0) & 0xff) << 8) | (str.charCodeAt(1) & 0xff);
  },

  /**
   * Convert a 16-bit integer value to a string
   * @param {number} val - 16-bit integer value
   * @return {string} Resulting 2-character string
   */
  fromUint16Val(val) {
    let str = "";
    str += String.fromCharCode((val & 0xff00) >> 8);
    str += String.fromCharCode(val & 0xff);
    return str;
  },
};
