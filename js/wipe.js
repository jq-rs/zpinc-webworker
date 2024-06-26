"use strict";
// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.
//Object.defineProperty(exports, "__esModule", { value: true });
//exports.wipe = void 0;
/**
 * Sets all values in the given array to zero and returns it.
 *
 * The fact that it sets bytes to zero can be relied on.
 *
 * There is no guarantee that this function makes data disappear from memory,
 * as runtime implementation can, for example, have copying garbage collector
 * that will make copies of sensitive data before we wipe it. Or that an
 * operating system will write our data to swap or sleep image. Another thing
 * is that an optimizing compiler can remove calls to this function or make it
 * no-op. There's nothing we can do with it, so we just do our best and hope
 * that everything will be okay and good will triumph over evil.
 */
function wipe(array) {
    // Right now it's similar to array.fill(0). If it turns
    // out that runtimes optimize this call away, maybe
    // we can try something else.
    for (var i = 0; (array != null) && i < array.length; i++) {
        array[i] = 0;
    }
    return array;
}
//exports.wipe = wipe;
