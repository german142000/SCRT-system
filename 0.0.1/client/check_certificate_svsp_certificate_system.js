/*
 * check_certificate_svsp_certificate_system.js: a library that allows you to check 
 * the validity of the certificate of the certification system svsp
 * https://github.com/german142000/SCRT-system
 *
 * Copyright (c) 2023 Fonteyn German
 *
 * Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/
 */
'use strict';
(function($) {

    function safeAdd(x, y) {
        var lsw = (x & 0xffff) + (y & 0xffff)
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
        return (msw << 16) | (lsw & 0xffff)
    }

    function bitRotateLeft(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt))
    }

    function md5cmn(q, a, b, x, s, t) {
        return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b)
    }

    function md5ff(a, b, c, d, x, s, t) {
        return md5cmn((b & c) | (~b & d), a, b, x, s, t)
    }

    function md5gg(a, b, c, d, x, s, t) {
        return md5cmn((b & d) | (c & ~d), a, b, x, s, t)
    }

    function md5hh(a, b, c, d, x, s, t) {
        return md5cmn(b ^ c ^ d, a, b, x, s, t)
    }

    function md5ii(a, b, c, d, x, s, t) {
        return md5cmn(c ^ (b | ~d), a, b, x, s, t)
    }

    function binlMD5(x, len) {
        x[len >> 5] |= 0x80 << len % 32
        x[(((len + 64) >>> 9) << 4) + 14] = len

        var i
        var olda
        var oldb
        var oldc
        var oldd
        var a = 1732584193
        var b = -271733879
        var c = -1732584194
        var d = 271733878

        for (i = 0; i < x.length; i += 16) {
            olda = a
            oldb = b
            oldc = c
            oldd = d

            a = md5ff(a, b, c, d, x[i], 7, -680876936)
            d = md5ff(d, a, b, c, x[i + 1], 12, -389564586)
            c = md5ff(c, d, a, b, x[i + 2], 17, 606105819)
            b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330)
            a = md5ff(a, b, c, d, x[i + 4], 7, -176418897)
            d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426)
            c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341)
            b = md5ff(b, c, d, a, x[i + 7], 22, -45705983)
            a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416)
            d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417)
            c = md5ff(c, d, a, b, x[i + 10], 17, -42063)
            b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162)
            a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682)
            d = md5ff(d, a, b, c, x[i + 13], 12, -40341101)
            c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290)
            b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329)

            a = md5gg(a, b, c, d, x[i + 1], 5, -165796510)
            d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632)
            c = md5gg(c, d, a, b, x[i + 11], 14, 643717713)
            b = md5gg(b, c, d, a, x[i], 20, -373897302)
            a = md5gg(a, b, c, d, x[i + 5], 5, -701558691)
            d = md5gg(d, a, b, c, x[i + 10], 9, 38016083)
            c = md5gg(c, d, a, b, x[i + 15], 14, -660478335)
            b = md5gg(b, c, d, a, x[i + 4], 20, -405537848)
            a = md5gg(a, b, c, d, x[i + 9], 5, 568446438)
            d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690)
            c = md5gg(c, d, a, b, x[i + 3], 14, -187363961)
            b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501)
            a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467)
            d = md5gg(d, a, b, c, x[i + 2], 9, -51403784)
            c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473)
            b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734)

            a = md5hh(a, b, c, d, x[i + 5], 4, -378558)
            d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463)
            c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562)
            b = md5hh(b, c, d, a, x[i + 14], 23, -35309556)
            a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060)
            d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353)
            c = md5hh(c, d, a, b, x[i + 7], 16, -155497632)
            b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640)
            a = md5hh(a, b, c, d, x[i + 13], 4, 681279174)
            d = md5hh(d, a, b, c, x[i], 11, -358537222)
            c = md5hh(c, d, a, b, x[i + 3], 16, -722521979)
            b = md5hh(b, c, d, a, x[i + 6], 23, 76029189)
            a = md5hh(a, b, c, d, x[i + 9], 4, -640364487)
            d = md5hh(d, a, b, c, x[i + 12], 11, -421815835)
            c = md5hh(c, d, a, b, x[i + 15], 16, 530742520)
            b = md5hh(b, c, d, a, x[i + 2], 23, -995338651)

            a = md5ii(a, b, c, d, x[i], 6, -198630844)
            d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415)
            c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905)
            b = md5ii(b, c, d, a, x[i + 5], 21, -57434055)
            a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571)
            d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606)
            c = md5ii(c, d, a, b, x[i + 10], 15, -1051523)
            b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799)
            a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359)
            d = md5ii(d, a, b, c, x[i + 15], 10, -30611744)
            c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380)
            b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649)
            a = md5ii(a, b, c, d, x[i + 4], 6, -145523070)
            d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379)
            c = md5ii(c, d, a, b, x[i + 2], 15, 718787259)
            b = md5ii(b, c, d, a, x[i + 9], 21, -343485551)

            a = safeAdd(a, olda)
            b = safeAdd(b, oldb)
            c = safeAdd(c, oldc)
            d = safeAdd(d, oldd)
        }
        return [a, b, c, d]
    }

    function binl2rstr(input) {
        var i
        var output = ''
        var length32 = input.length * 32
        for (i = 0; i < length32; i += 8) {
            output += String.fromCharCode((input[i >> 5] >>> i % 32) & 0xff)
        }
        return output
    }

    function rstr2binl(input) {
        var i
        var output = []
        output[(input.length >> 2) - 1] = undefined
        for (i = 0; i < output.length; i += 1) {
            output[i] = 0
        }
        var length8 = input.length * 8
        for (i = 0; i < length8; i += 8) {
            output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << i % 32
        }
        return output
    }

    function rstrMD5(s) {
        return binl2rstr(binlMD5(rstr2binl(s), s.length * 8))
    }

    function rstrHMACMD5(key, data) {
        var i
        var bkey = rstr2binl(key)
        var ipad = []
        var opad = []
        var hash
        ipad[15] = opad[15] = undefined
        if (bkey.length > 16) {
            bkey = binlMD5(bkey, key.length * 8)
        }
        for (i = 0; i < 16; i += 1) {
            ipad[i] = bkey[i] ^ 0x36363636
            opad[i] = bkey[i] ^ 0x5c5c5c5c
        }
        hash = binlMD5(ipad.concat(rstr2binl(data)), 512 + data.length * 8)
        return binl2rstr(binlMD5(opad.concat(hash), 512 + 128))
    }

    function rstr2hex(input) {
        var hexTab = '0123456789abcdef'
        var output = ''
        var x
        var i
        for (i = 0; i < input.length; i += 1) {
            x = input.charCodeAt(i)
            output += hexTab.charAt((x >>> 4) & 0x0f) + hexTab.charAt(x & 0x0f)
        }
        return output
    }

    function str2rstrUTF8(input) {
        return unescape(encodeURIComponent(input))
    }

    function rawMD5(s) {
        return rstrMD5(str2rstrUTF8(s))
    }

    function hexMD5(s) {
        return rstr2hex(rawMD5(s))
    }

    function rawHMACMD5(k, d) {
        return rstrHMACMD5(str2rstrUTF8(k), str2rstrUTF8(d))
    }

    function hexHMACMD5(k, d) {
        return rstr2hex(rawHMACMD5(k, d))
    }

    function md5(string, key, raw) {
        if (!key) {
            if (!raw) {
                return hexMD5(string)
            }
            return rawMD5(string)
        }
        if (!raw) {
            return hexHMACMD5(key, string)
        }
        return rawHMACMD5(key, string)
    }

    if (typeof define === 'function' && define.amd) {
        define(function() {
            return md5
        })
    } else if (typeof module === 'object' && module.exports) {
        module.exports = md5
    } else {
        $.md5 = md5
    }
})(this);

/*
 * aes.js: implements AES - Advanced Encryption Standard
 * from the SlowAES project, http://code.google.com/p/slowaes/
 * 
 * Copyright (c) 2008 	Josh Davis ( http://www.josh-davis.org ),
 *						Mark Percival ( http://mpercival.com ),
 *
 * Ported from C code written by Laurent Haan ( http://www.progressive-coding.com )
 * 
 * Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/
 */
//edited
var slowAES = {

    aes: {
        keySize: {
            SIZE_128: 16,
            SIZE_192: 24,
            SIZE_256: 32
        },

        sbox: [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ],

        rsbox: [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ],

        rotate: function(word) {
            var c = word[0];
            for (var i = 0; i < 3; i++)
                word[i] = word[i + 1];
            word[3] = c;

            return word;
        },

        Rcon: [
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
            0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
            0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
            0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
            0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
            0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
            0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
            0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
        ],

        G2X: [
            0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16,
            0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
            0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46,
            0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
            0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76,
            0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
            0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6,
            0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
            0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6,
            0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
            0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 0x1b, 0x19, 0x1f, 0x1d,
            0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
            0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d,
            0x23, 0x21, 0x27, 0x25, 0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
            0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, 0x7b, 0x79, 0x7f, 0x7d,
            0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
            0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d,
            0x83, 0x81, 0x87, 0x85, 0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
            0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5, 0xdb, 0xd9, 0xdf, 0xdd,
            0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
            0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed,
            0xe3, 0xe1, 0xe7, 0xe5
        ],

        G3X: [
            0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d,
            0x14, 0x17, 0x12, 0x11, 0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39,
            0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21, 0x60, 0x63, 0x66, 0x65,
            0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
            0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d,
            0x44, 0x47, 0x42, 0x41, 0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9,
            0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1, 0xf0, 0xf3, 0xf6, 0xf5,
            0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
            0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd,
            0xb4, 0xb7, 0xb2, 0xb1, 0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99,
            0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81, 0x9b, 0x98, 0x9d, 0x9e,
            0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
            0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6,
            0xbf, 0xbc, 0xb9, 0xba, 0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2,
            0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea, 0xcb, 0xc8, 0xcd, 0xce,
            0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
            0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46,
            0x4f, 0x4c, 0x49, 0x4a, 0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62,
            0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a, 0x3b, 0x38, 0x3d, 0x3e,
            0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
            0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16,
            0x1f, 0x1c, 0x19, 0x1a
        ],

        G9X: [
            0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53,
            0x6c, 0x65, 0x7e, 0x77, 0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf,
            0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7, 0x3b, 0x32, 0x29, 0x20,
            0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
            0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8,
            0xc7, 0xce, 0xd5, 0xdc, 0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49,
            0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01, 0xe6, 0xef, 0xf4, 0xfd,
            0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
            0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e,
            0x21, 0x28, 0x33, 0x3a, 0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2,
            0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa, 0xec, 0xe5, 0xfe, 0xf7,
            0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
            0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f,
            0x10, 0x19, 0x02, 0x0b, 0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8,
            0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0, 0x47, 0x4e, 0x55, 0x5c,
            0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
            0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9,
            0xf6, 0xff, 0xe4, 0xed, 0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35,
            0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d, 0xa1, 0xa8, 0xb3, 0xba,
            0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
            0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62,
            0x5d, 0x54, 0x4f, 0x46
        ],

        GBX: [
            0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45,
            0x74, 0x7f, 0x62, 0x69, 0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81,
            0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9, 0x7b, 0x70, 0x6d, 0x66,
            0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
            0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e,
            0xbf, 0xb4, 0xa9, 0xa2, 0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7,
            0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f, 0x46, 0x4d, 0x50, 0x5b,
            0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
            0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8,
            0xf9, 0xf2, 0xef, 0xe4, 0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c,
            0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54, 0xf7, 0xfc, 0xe1, 0xea,
            0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
            0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02,
            0x33, 0x38, 0x25, 0x2e, 0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd,
            0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5, 0x3c, 0x37, 0x2a, 0x21,
            0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
            0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44,
            0x75, 0x7e, 0x63, 0x68, 0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80,
            0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8, 0x7a, 0x71, 0x6c, 0x67,
            0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
            0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f,
            0xbe, 0xb5, 0xa8, 0xa3
        ],

        GDX: [
            0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f,
            0x5c, 0x51, 0x46, 0x4b, 0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3,
            0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b, 0xbb, 0xb6, 0xa1, 0xac,
            0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
            0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14,
            0x37, 0x3a, 0x2d, 0x20, 0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e,
            0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26, 0xbd, 0xb0, 0xa7, 0xaa,
            0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
            0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9,
            0x8a, 0x87, 0x90, 0x9d, 0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25,
            0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d, 0xda, 0xd7, 0xc0, 0xcd,
            0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
            0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75,
            0x56, 0x5b, 0x4c, 0x41, 0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42,
            0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a, 0xb1, 0xbc, 0xab, 0xa6,
            0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
            0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8,
            0xeb, 0xe6, 0xf1, 0xfc, 0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44,
            0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c, 0x0c, 0x01, 0x16, 0x1b,
            0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
            0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3,
            0x80, 0x8d, 0x9a, 0x97
        ],

        GEX: [
            0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62,
            0x48, 0x46, 0x54, 0x5a, 0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca,
            0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba, 0xdb, 0xd5, 0xc7, 0xc9,
            0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
            0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59,
            0x73, 0x7d, 0x6f, 0x61, 0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87,
            0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7, 0x4d, 0x43, 0x51, 0x5f,
            0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
            0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14,
            0x3e, 0x30, 0x22, 0x2c, 0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc,
            0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc, 0x41, 0x4f, 0x5d, 0x53,
            0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
            0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3,
            0xe9, 0xe7, 0xf5, 0xfb, 0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0,
            0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0, 0x7a, 0x74, 0x66, 0x68,
            0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
            0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e,
            0xa4, 0xaa, 0xb8, 0xb6, 0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26,
            0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56, 0x37, 0x39, 0x2b, 0x25,
            0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
            0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5,
            0x9f, 0x91, 0x83, 0x8d
        ],

        core: function(word, iteration) {
            word = this.rotate(word);
            for (var i = 0; i < 4; ++i)
                word[i] = this.sbox[word[i]];
            word[0] = word[0] ^ this.Rcon[iteration];
            return word;
        },

        expandKey: function(key, size) {
            var expandedKeySize = (16 * (this.numberOfRounds(size) + 1));

            var currentSize = 0;
            var rconIteration = 1;
            var t = [];

            var expandedKey = [];
            for (var i = 0; i < expandedKeySize; i++)
                expandedKey[i] = 0;

            for (var j = 0; j < size; j++)
                expandedKey[j] = key[j];
            currentSize += size;

            while (currentSize < expandedKeySize) {

                for (var k = 0; k < 4; k++)
                    t[k] = expandedKey[(currentSize - 4) + k];

                if (currentSize % size == 0)
                    t = this.core(t, rconIteration++);

                if (size == this.keySize.SIZE_256 && ((currentSize % size) == 16))
                    for (var l = 0; l < 4; l++)
                        t[l] = this.sbox[t[l]];

                for (var m = 0; m < 4; m++) {
                    expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[m];
                    currentSize++;
                }
            }
            return expandedKey;
        },

        addRoundKey: function(state, roundKey) {
            for (var i = 0; i < 16; i++)
                state[i] ^= roundKey[i];
            return state;
        },

        createRoundKey: function(expandedKey, roundKeyPointer) {
            var roundKey = [];
            for (var i = 0; i < 4; i++)
                for (var j = 0; j < 4; j++)
                    roundKey[j * 4 + i] = expandedKey[roundKeyPointer + i * 4 + j];
            return roundKey;
        },

        subBytes: function(state, isInv) {
            for (var i = 0; i < 16; i++)
                state[i] = isInv ? this.rsbox[state[i]] : this.sbox[state[i]];
            return state;
        },

        shiftRows: function(state, isInv) {
            for (var i = 0; i < 4; i++)
                state = this.shiftRow(state, i * 4, i, isInv);
            return state;
        },

        shiftRow: function(state, statePointer, nbr, isInv) {
            for (var i = 0; i < nbr; i++) {
                if (isInv) {
                    var tmp = state[statePointer + 3];
                    for (var j = 3; j > 0; j--)
                        state[statePointer + j] = state[statePointer + j - 1];
                    state[statePointer] = tmp;
                } else {
                    var tmp = state[statePointer];
                    for (var j = 0; j < 3; j++)
                        state[statePointer + j] = state[statePointer + j + 1];
                    state[statePointer + 3] = tmp;
                }
            }
            return state;
        },

        galois_multiplication: function(a, b) {
            var p = 0;
            for (var counter = 0; counter < 8; counter++) {
                if ((b & 1) == 1)
                    p ^= a;
                if (p > 0x100) p ^= 0x100;
                var hi_bit_set = (a & 0x80);
                a <<= 1;
                if (a > 0x100) a ^= 0x100;
                if (hi_bit_set == 0x80)
                    a ^= 0x1b;
                if (a > 0x100) a ^= 0x100;
                b >>= 1;
                if (b > 0x100) b ^= 0x100;
            }
            return p;
        },

        mixColumns: function(state, isInv) {
            var column = [];
            for (var i = 0; i < 4; i++) {
                for (var j = 0; j < 4; j++)
                    column[j] = state[(j * 4) + i];
                column = this.mixColumn(column, isInv);
                for (var k = 0; k < 4; k++)
                    state[(k * 4) + i] = column[k];
            }
            return state;
        },

        mixColumn: function(column, isInv) {
            var mult = [];
            if (isInv)
                mult = [14, 9, 13, 11];
            else
                mult = [2, 1, 1, 3];
            var cpy = [];
            for (var i = 0; i < 4; i++)
                cpy[i] = column[i];

            column[0] = this.galois_multiplication(cpy[0], mult[0]) ^
                this.galois_multiplication(cpy[3], mult[1]) ^
                this.galois_multiplication(cpy[2], mult[2]) ^
                this.galois_multiplication(cpy[1], mult[3]);
            column[1] = this.galois_multiplication(cpy[1], mult[0]) ^
                this.galois_multiplication(cpy[0], mult[1]) ^
                this.galois_multiplication(cpy[3], mult[2]) ^
                this.galois_multiplication(cpy[2], mult[3]);
            column[2] = this.galois_multiplication(cpy[2], mult[0]) ^
                this.galois_multiplication(cpy[1], mult[1]) ^
                this.galois_multiplication(cpy[0], mult[2]) ^
                this.galois_multiplication(cpy[3], mult[3]);
            column[3] = this.galois_multiplication(cpy[3], mult[0]) ^
                this.galois_multiplication(cpy[2], mult[1]) ^
                this.galois_multiplication(cpy[1], mult[2]) ^
                this.galois_multiplication(cpy[0], mult[3]);
            return column;
        },

        round: function(state, roundKey) {
            state = this.subBytes(state, false);
            state = this.shiftRows(state, false);
            state = this.mixColumns(state, false);
            state = this.addRoundKey(state, roundKey);
            return state;
        },

        invRound: function(state, roundKey) {
            state = this.shiftRows(state, true);
            state = this.subBytes(state, true);
            state = this.addRoundKey(state, roundKey);
            state = this.mixColumns(state, true);
            return state;
        },

        main: function(state, expandedKey, nbrRounds) {
            state = this.addRoundKey(state, this.createRoundKey(expandedKey, 0));
            for (var i = 1; i < nbrRounds; i++)
                state = this.round(state, this.createRoundKey(expandedKey, 16 * i));
            state = this.subBytes(state, false);
            state = this.shiftRows(state, false);
            state = this.addRoundKey(state, this.createRoundKey(expandedKey, 16 * nbrRounds));
            return state;
        },

        invMain: function(state, expandedKey, nbrRounds) {
            state = this.addRoundKey(state, this.createRoundKey(expandedKey, 16 * nbrRounds));
            for (var i = nbrRounds - 1; i > 0; i--)
                state = this.invRound(state, this.createRoundKey(expandedKey, 16 * i));
            state = this.shiftRows(state, true);
            state = this.subBytes(state, true);
            state = this.addRoundKey(state, this.createRoundKey(expandedKey, 0));
            return state;
        },

        numberOfRounds: function(size) {
            var nbrRounds;
            switch (size) {
                case this.keySize.SIZE_128:
                    nbrRounds = 10;
                    break;
                case this.keySize.SIZE_192:
                    nbrRounds = 12;
                    break;
                case this.keySize.SIZE_256:
                    nbrRounds = 14;
                    break;
                default:
                    return null;
                    break;
            }
            return nbrRounds;
        },

        encrypt: function(input, key, size) {
            var output = [];
            var block = [];
            var nbrRounds = this.numberOfRounds(size);
            for (var i = 0; i < 4; i++)
                for (var j = 0; j < 4; j++)
                    block[(i + (j * 4))] = input[(i * 4) + j];

            var expandedKey = this.expandKey(key, size);
            block = this.main(block, expandedKey, nbrRounds);
            for (var k = 0; k < 4; k++)
                for (var l = 0; l < 4; l++)
                    output[(k * 4) + l] = block[(k + (l * 4))];
            return output;
        },

        decrypt: function(input, key, size) {
            var output = [];
            var block = [];
            var nbrRounds = this.numberOfRounds(size);
            for (var i = 0; i < 4; i++)
                for (var j = 0; j < 4; j++)
                    block[(i + (j * 4))] = input[(i * 4) + j];
            var expandedKey = this.expandKey(key, size);
            block = this.invMain(block, expandedKey, nbrRounds);
            for (var k = 0; k < 4; k++)
                for (var l = 0; l < 4; l++)
                    output[(k * 4) + l] = block[(k + (l * 4))];
            return output;
        }
    },

    modeOfOperation: {
        OFB: 0,
        CFB: 1,
        CBC: 2
    },

    getBlock: function(bytesIn, start, end, mode) {
        if (end - start > 16)
            end = start + 16;

        return bytesIn.slice(start, end);
    },

    encrypt: function(bytesIn, mode, key, iv) {
        var size = key.length;
        if (iv.length % 16) {
            throw 'iv length must be 128 bits.';
        }
        var byteArray = [];
        var input = [];
        var output = [];
        var ciphertext = [];
        var cipherOut = [];
        var firstRound = true;
        if (mode == this.modeOfOperation.CBC)
            this.padBytesIn(bytesIn);
        if (bytesIn !== null) {
            for (var j = 0; j < Math.ceil(bytesIn.length / 16); j++) {
                var start = j * 16;
                var end = j * 16 + 16;
                if (j * 16 + 16 > bytesIn.length)
                    end = bytesIn.length;
                byteArray = this.getBlock(bytesIn, start, end, mode);
                if (mode == this.modeOfOperation.CFB) {
                    if (firstRound) {
                        output = this.aes.encrypt(iv, key, size);
                        firstRound = false;
                    } else
                        output = this.aes.encrypt(input, key, size);
                    for (var i = 0; i < 16; i++)
                        ciphertext[i] = byteArray[i] ^ output[i];
                    for (var k = 0; k < end - start; k++)
                        cipherOut.push(ciphertext[k]);
                    input = ciphertext;
                } else if (mode == this.modeOfOperation.OFB) {
                    if (firstRound) {
                        output = this.aes.encrypt(iv, key, size);
                        firstRound = false;
                    } else
                        output = this.aes.encrypt(input, key, size);
                    for (var i = 0; i < 16; i++)
                        ciphertext[i] = byteArray[i] ^ output[i];
                    for (var k = 0; k < end - start; k++)
                        cipherOut.push(ciphertext[k]);
                    input = output;
                } else if (mode == this.modeOfOperation.CBC) {
                    for (var i = 0; i < 16; i++)
                        input[i] = byteArray[i] ^ ((firstRound) ? iv[i] : ciphertext[i]);
                    firstRound = false;
                    ciphertext = this.aes.encrypt(input, key, size);
                    for (var k = 0; k < 16; k++)
                        cipherOut.push(ciphertext[k]);
                }
            }
        }
        return cipherOut;
    },

    decrypt: function(cipherIn, mode, key, iv) {
        var size = key.length;
        if (iv.length % 16) {
            throw 'iv length must be 128 bits.';
        }
        var ciphertext = [];
        var input = [];
        var output = [];
        var byteArray = [];
        var bytesOut = [];
        var firstRound = true;
        if (cipherIn !== null) {
            for (var j = 0; j < Math.ceil(cipherIn.length / 16); j++) {
                var start = j * 16;
                var end = j * 16 + 16;
                if (j * 16 + 16 > cipherIn.length)
                    end = cipherIn.length;
                ciphertext = this.getBlock(cipherIn, start, end, mode);
                if (mode == this.modeOfOperation.CFB) {
                    if (firstRound) {
                        output = this.aes.encrypt(iv, key, size);
                        firstRound = false;
                    } else
                        output = this.aes.encrypt(input, key, size);
                    for (i = 0; i < 16; i++)
                        byteArray[i] = output[i] ^ ciphertext[i];
                    for (var k = 0; k < end - start; k++)
                        bytesOut.push(byteArray[k]);
                    input = ciphertext;
                } else if (mode == this.modeOfOperation.OFB) {
                    if (firstRound) {
                        output = this.aes.encrypt(iv, key, size);
                        firstRound = false;
                    } else
                        output = this.aes.encrypt(input, key, size);
                    for (let i = 0; i < 16; i++)
                        byteArray[i] = output[i] ^ ciphertext[i];
                    for (var k = 0; k < end - start; k++)
                        bytesOut.push(byteArray[k]);
                    input = output;
                } else if (mode == this.modeOfOperation.CBC) {
                    output = this.aes.decrypt(ciphertext, key, size);
                    for (i = 0; i < 16; i++)
                        byteArray[i] = ((firstRound) ? iv[i] : input[i]) ^ output[i];
                    firstRound = false;
                    for (var k = 0; k < end - start; k++)
                        bytesOut.push(byteArray[k]);
                    input = ciphertext;
                }
            }
            if (mode == this.modeOfOperation.CBC)
                this.unpadBytesOut(bytesOut);
        }
        return bytesOut;
    },
    padBytesIn: function(data) {
        var len = data.length;
        var padByte = 16 - (len % 16);
        for (var i = 0; i < padByte; i++) {
            data.push(padByte);
        }
    },
    unpadBytesOut: function(data) {
        var padCount = 0;
        var padByte = -1;
        var blockSize = 16;
        for (var i = data.length - 1; i >= data.length - 1 - blockSize; i--) {
            if (data[i] <= blockSize) {
                if (padByte == -1)
                    padByte = data[i];
                if (data[i] != padByte) {
                    padCount = 0;
                    break;
                }
                padCount++;
            } else
                break;
            if (padCount == padByte)
                break;
        }
        if (padCount > 0)
            data.splice(data.length - padCount, padCount);
    }

};

function getRandomInt(max) {
    return Math.floor(Math.random() * max);
}

function getSCRTcertificate(callBack, dir) {
    let xht = new XMLHttpRequest();
    xht.open('GET', dir + '/cert.php', true);
    xht.send();
    xht.onload = function() {
	    let ai = xht.response.split('\n', 5)
        let mscd = md5(ai[1] + ai[0]);
	
		let iv = [getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9)
            ];
	
		let secret = BigInt(getRandomInt(9999));
	    let mix = BigInt(BigInt(BigInt(ai[4]) ** secret) % BigInt(ai[3]));
	    let shdkey = BigInt(BigInt(BigInt(ai[2]) ** secret) % BigInt(ai[3]));

        let key = md5(shdkey).substring(0, 16);
	
        let xht2 = new XMLHttpRequest();
        xht2.open('GET', dir + '/cert.php?info=' + mscd + '&1=' + mix + '&2=' + ai[4] + '&3=' + ai[3] + '&4=' + 
				  JSON.stringify(iv), true);
        xht2.send();
        xht2.onload = function() {
            if (xht2.response != 'false') {
			    let arrbytes = JSON.parse(xht2.response);
				let date = slowAES.decrypt(arrbytes, slowAES.modeOfOperation.OFB, key, iv);
			    let cert = '';
			    for(let i = 0; i < date.length; i++) cert += String.fromCharCode(date[i]);
                callBack(cert.split('\n', 10));
			}
            else
                callBack([]);
        }
    }
}

function getSCRTroot(callBack, dir) {
    let xht = new XMLHttpRequest();
    xht.open('GET', dir + '/cert.php', true);
    xht.send();
    xht.onload = function() {
	    let ai = xht.response.split('\n', 5)
        let mscd = md5(ai[1] + ai[0]);
	
		let iv = [getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9)
            ];
	
		let secret = BigInt(getRandomInt(9999));
	    let mix = BigInt(BigInt(BigInt(ai[4]) ** secret) % BigInt(ai[3]));
	    let shdkey = BigInt(BigInt(BigInt(ai[2]) ** secret) % BigInt(ai[3]));

        let key = md5(shdkey).substring(0, 16);
	
        let xht2 = new XMLHttpRequest();
        xht2.open('GET', dir + '/cert.php?info=' + mscd + '&1=' + mix + '&2=' + ai[4] + '&3=' + ai[3] + '&4=' + 
				  JSON.stringify(iv), true);
        xht2.send();
        xht2.onload = function() {
            if (xht2.response != 'false') {
			    let arrbytes = JSON.parse(xht2.response);
				let date = slowAES.decrypt(arrbytes, slowAES.modeOfOperation.OFB, key, iv);
			    let cert = '';
			    for(let i = 0; i < date.length; i++) cert += String.fromCharCode(date[i]);
                callBack(cert.split('\n', 10)[5]);
			}
            else
                callBack(false);
        }
    }
}

function getSCRTprime(callBack, dir) {
    let xht = new XMLHttpRequest();
    xht.open('GET', dir + '/cert.php', true);
    xht.send();
    xht.onload = function() {
	    let ai = xht.response.split('\n', 5)
        let mscd = md5(ai[1] + ai[0]);
	
		let iv = [getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9)
            ];
	
		let secret = BigInt(getRandomInt(9999));
	    let mix = BigInt(BigInt(BigInt(ai[4]) ** secret) % BigInt(ai[3]));
	    let shdkey = BigInt(BigInt(BigInt(ai[2]) ** secret) % BigInt(ai[3]));

        let key = md5(shdkey).substring(0, 16);
	
        let xht2 = new XMLHttpRequest();
        xht2.open('GET', dir + '/cert.php?info=' + mscd + '&1=' + mix + '&2=' + ai[4] + '&3=' + ai[3] + '&4=' + 
				  JSON.stringify(iv), true);
        xht2.send();
        xht2.onload = function() {
            if (xht2.response != 'false') {
			    let arrbytes = JSON.parse(xht2.response);
				let date = slowAES.decrypt(arrbytes, slowAES.modeOfOperation.OFB, key, iv);
			    let cert = '';
			    for(let i = 0; i < date.length; i++) cert += String.fromCharCode(date[i]);
                callBack(cert.split('\n', 10)[4]);
			}
            else
                callBack(false);
        }
    }
}

function checkSCRTcertificate(nums, scrtCenter, callBack) {
    if (nums.length == 10) {
        let htrq = new XMLHttpRequest();
        htrq.open('GET', scrtCenter + '/api/api.php', true);
        htrq.send();

        htrq.onload = function() {

            let numr = htrq.response.split('\n', 3);

            let nprime = numr[0];
            let nroot = numr[1];
            let nmix = numr[2];

            let iv = [getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9)
            ];

            let now = new Date();
            let secret = BigInt(getRandomInt(9999));
            let mix = BigInt(BigInt(BigInt(nroot) ** secret) % BigInt(nprime));

            let shdkey = BigInt(BigInt(BigInt(nmix) ** secret) % BigInt(nprime));

            let key = md5(shdkey).substring(0, 16);

            let strByteArray1 = [];
            let product_id = nums[0].trim();
            let lproduct_id = product_id.length;
            for (let i = 0; i < product_id.length; i++) strByteArray1.push(product_id.charCodeAt(i));
            product_id = slowAES.encrypt(strByteArray1, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray2 = [];
            let certificate_id = nums[1].trim();
            let lcertificate_id = certificate_id.length;
            for (let i = 0; i < certificate_id.length; i++) strByteArray2.push(certificate_id.charCodeAt(i));
            certificate_id = slowAES.encrypt(strByteArray2, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray3 = [];
            let date = nums[2].trim();
            let ldate = date.length;
            for (let i = 0; i < date.length; i++) strByteArray3.push(date.charCodeAt(i));
            date = slowAES.encrypt(strByteArray3, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray4 = [];
            let date_trm = nums[3].trim();
            let ldate_trm = date_trm.length;
            for (let i = 0; i < date_trm.length; i++) strByteArray4.push(date_trm.charCodeAt(i));
            date_trm = slowAES.encrypt(strByteArray4, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray5 = [];
            let c_root = nums[4].trim();
            let lc_root = c_root.length;
            for (let i = 0; i < c_root.length; i++) strByteArray5.push(c_root.charCodeAt(i));
            c_root = slowAES.encrypt(strByteArray5, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray6 = [];
            let c_prime = nums[5].trim();
            let lc_prime = c_prime.length;
            for (let i = 0; i < c_prime.length; i++) strByteArray6.push(c_prime.charCodeAt(i));
            c_prime = slowAES.encrypt(strByteArray6, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray7 = [];
            let hes1 = nums[6].trim();
            let lhes1 = hes1.length;
            for (let i = 0; i < hes1.length; i++) strByteArray7.push(hes1.charCodeAt(i));
            hes1 = slowAES.encrypt(strByteArray7, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray8 = [];
            let hes2 = nums[7].trim();
            let lhes2 = hes2.length;
            for (let i = 0; i < hes2.length; i++) strByteArray8.push(hes2.charCodeAt(i));
            hes2 = slowAES.encrypt(strByteArray8, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray9 = [];
            let hes3 = nums[8].trim();
            let lhes3 = hes3.length;
            for (let i = 0; i < hes3.length; i++) strByteArray9.push(hes3.charCodeAt(i));
            hes3 = slowAES.encrypt(strByteArray9, slowAES.modeOfOperation.OFB, key, iv);

            let strByteArray10 = [];
            let hes4 = nums[9].trim();
            let lhes4 = hes4.length;
            for (let i = 0; i < hes4.length; i++) strByteArray10.push(hes4.charCodeAt(i));
            hes4 = slowAES.encrypt(strByteArray10, slowAES.modeOfOperation.OFB, key, iv);

            let req = scrtCenter + '/api/certificate.php?1=' + JSON.stringify(product_id) +
                '&2=' + JSON.stringify(certificate_id) + '&3=' + JSON.stringify(date) + '&4=' +
                JSON.stringify(date_trm) + '&5=' + JSON.stringify(c_root) + '&6=' +
                JSON.stringify(c_prime) + '&7=' + JSON.stringify(hes1) + '&8=' + JSON.stringify(hes2) +
                '&9=' + JSON.stringify(hes3) + '&10=' + JSON.stringify(hes4) + '&11=' + JSON.stringify(lproduct_id) +
                '&12=' + JSON.stringify(lcertificate_id) + '&13=' + JSON.stringify(ldate) + '&14=' +
                JSON.stringify(ldate_trm) + '&15=' + JSON.stringify(lc_root) + '&16=' +
                JSON.stringify(lc_prime) + '&17=' + JSON.stringify(lhes1) + '&18=' + JSON.stringify(lhes2) +
                '&19=' + JSON.stringify(lhes3) + '&20=' + JSON.stringify(lhes4) + '&21=' +
                mix + '&22=' + nprime + '&23=' + JSON.stringify(iv);

            let htrq2 = new XMLHttpRequest();
            htrq2.open('GET', req, true);
            htrq2.send();
            htrq2.onload = function() {
			    let tstr = htrq2.response.trim();
                if (tstr == 'true') callBack(true);
                else callBack(false);
            }
        }
    } else {
        callBack(false);
    }
}