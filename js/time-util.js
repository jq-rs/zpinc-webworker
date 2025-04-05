const TimeUtil = {
  /**
   * Create a flagstamp from a date
   * @param {Date} valueofdate - Date value
   * @param {number} weekstamp - Week stamp
   * @param {number} timestamp - Timestamp in minutes
   * @return {number} Flagstamp value
   */
  createFlagstamp(valueofdate, weekstamp, timestamp) {
    const begin = Constants.CONSTANTS.BEGIN;
    const this_time = new Date(
      begin.valueOf() +
        weekstamp * 1000 * 60 * 60 * 24 * 7 +
        timestamp * 1000 * 60,
    );
    const flagstamp = Math.floor((valueofdate - this_time) / 1000);
    return flagstamp;
  },

  /**
   * Create a timestamp (in minutes) from a date
   * @param {Date} valueofdate - Date value
   * @param {number} weekstamp - Week stamp
   * @return {number} Timestamp value in minutes
   */
  createTimestamp(valueofdate, weekstamp) {
    const begin = Constants.CONSTANTS.BEGIN;
    const this_week = new Date(
      begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7,
    );
    const timestamp = Math.floor((valueofdate - this_week) / 1000 / 60);
    return timestamp;
  },

  /**
   * Create a weekstamp from a date
   * @param {Date} valueofdate - Date value
   * @return {number} Weekstamp value
   */
  createWeekstamp(valueofdate) {
    const begin = Constants.CONSTANTS.BEGIN;
    const now = new Date(valueofdate);
    const weekstamp = Math.floor((now - begin) / 1000 / 60 / 60 / 24 / 7);
    return weekstamp;
  },

  /**
   * Read a timestamp into a Date
   * @param {number} timestamp - Timestamp in minutes
   * @param {number} weekstamp - Week stamp
   * @param {number} flagstamp - Flag stamp in seconds
   * @return {Date} Resulting date
   */
  readTimestamp(timestamp, weekstamp, flagstamp) {
    const begin = Constants.CONSTANTS.BEGIN;
    const weeks = new Date(
      begin.valueOf() + weekstamp * 1000 * 60 * 60 * 24 * 7,
    );
    const extension = timestamp * 1000 * 60 + flagstamp * 1000;
    const time = new Date(weeks.valueOf() + extension);
    return time;
  },
};
