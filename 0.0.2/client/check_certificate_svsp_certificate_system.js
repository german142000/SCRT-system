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

class JSBI extends Array {
    constructor(length, sign) {
        super(length);
        this.sign = sign;
        Object.setPrototypeOf(this, JSBI.prototype);
        if (length > JSBI.__kMaxLength) {
            throw new RangeError('Maximum BigInt size exceeded');
        }
    }
    static BigInt(arg) {
        if (typeof arg === 'number') {
            if (arg === 0)
                return JSBI.__zero();
            if (JSBI.__isOneDigitInt(arg)) {
                if (arg < 0) {
                    return JSBI.__oneDigit(-arg, true);
                }
                return JSBI.__oneDigit(arg, false);
            }
            if (!Number.isFinite(arg) || Math.floor(arg) !== arg) {
                throw new RangeError('The number ' + arg + ' cannot be converted to ' +
                    'BigInt because it is not an integer');
            }
            return JSBI.__fromDouble(arg);
        }
        else if (typeof arg === 'string') {
            const result = JSBI.__fromString(arg);
            if (result === null) {
                throw new SyntaxError('Cannot convert ' + arg + ' to a BigInt');
            }
            return result;
        }
        else if (typeof arg === 'boolean') {
            if (arg === true) {
                return JSBI.__oneDigit(1, false);
            }
            return JSBI.__zero();
        }
        else if (typeof arg === 'object') {
            if (arg.constructor === JSBI)
                return arg;
            const primitive = JSBI.__toPrimitive(arg);
            return JSBI.BigInt(primitive);
        }
        throw new TypeError('Cannot convert ' + arg + ' to a BigInt');
    }
    toDebugString() {
        const result = ['BigInt['];
        for (const digit of this) {
            result.push((digit ? (digit >>> 0).toString(16) : digit) + ', ');
        }
        result.push(']');
        return result.join('');
    }
    toString(radix = 10) {
        if (radix < 2 || radix > 36) {
            throw new RangeError('toString() radix argument must be between 2 and 36');
        }
        if (this.length === 0)
            return '0';
        if ((radix & (radix - 1)) === 0) {
            return JSBI.__toStringBasePowerOfTwo(this, radix);
        }
        return JSBI.__toStringGeneric(this, radix, false);
    }
    valueOf() {
        throw new Error('Convert JSBI instances to native numbers using `toNumber`.');
    }
    static toNumber(x) {
        const xLength = x.length;
        if (xLength === 0)
            return 0;
        if (xLength === 1) {
            const value = x.__unsignedDigit(0);
            return x.sign ? -value : value;
        }
        const xMsd = x.__digit(xLength - 1);
        const msdLeadingZeros = JSBI.__clz30(xMsd);
        const xBitLength = xLength * 30 - msdLeadingZeros;
        if (xBitLength > 1024)
            return x.sign ? -Infinity : Infinity;
        let exponent = xBitLength - 1;
        let currentDigit = xMsd;
        let digitIndex = xLength - 1;
        const shift = msdLeadingZeros + 3;
        let mantissaHigh = (shift === 32) ? 0 : currentDigit << shift;
        mantissaHigh >>>= 12;
        const mantissaHighBitsUnset = shift - 12;
        let mantissaLow = (shift >= 12) ? 0 : (currentDigit << (20 + shift));
        let mantissaLowBitsUnset = 20 + shift;
        if (mantissaHighBitsUnset > 0 && digitIndex > 0) {
            digitIndex--;
            currentDigit = x.__digit(digitIndex);
            mantissaHigh |= (currentDigit >>> (30 - mantissaHighBitsUnset));
            mantissaLow = currentDigit << mantissaHighBitsUnset + 2;
            mantissaLowBitsUnset = mantissaHighBitsUnset + 2;
        }
        while (mantissaLowBitsUnset > 0 && digitIndex > 0) {
            digitIndex--;
            currentDigit = x.__digit(digitIndex);
            if (mantissaLowBitsUnset >= 30) {
                mantissaLow |= (currentDigit << (mantissaLowBitsUnset - 30));
            }
            else {
                mantissaLow |= (currentDigit >>> (30 - mantissaLowBitsUnset));
            }
            mantissaLowBitsUnset -= 30;
        }
        const rounding = JSBI.__decideRounding(x, mantissaLowBitsUnset, digitIndex, currentDigit);
        if (rounding === 1 || (rounding === 0 && (mantissaLow & 1) === 1)) {
            mantissaLow = (mantissaLow + 1) >>> 0;
            if (mantissaLow === 0) {
                mantissaHigh++;
                if ((mantissaHigh >>> 20) !== 0) {
                    mantissaHigh = 0;
                    exponent++;
                    if (exponent > 1023) {
                        return x.sign ? -Infinity : Infinity;
                    }
                }
            }
        }
        const signBit = x.sign ? (1 << 31) : 0;
        exponent = (exponent + 0x3FF) << 20;
        JSBI.__kBitConversionInts[1] = signBit | exponent | mantissaHigh;
        JSBI.__kBitConversionInts[0] = mantissaLow;
        return JSBI.__kBitConversionDouble[0];
    }
    static unaryMinus(x) {
        if (x.length === 0)
            return x;
        const result = x.__copy();
        result.sign = !x.sign;
        return result;
    }
    static bitwiseNot(x) {
        if (x.sign) {
            return JSBI.__absoluteSubOne(x).__trim();
        }
        return JSBI.__absoluteAddOne(x, true);
    }
    static exponentiate(x, y) {
        if (y.sign) {
            throw new RangeError('Exponent must be positive');
        }
        if (y.length === 0) {
            return JSBI.__oneDigit(1, false);
        }
        if (x.length === 0)
            return x;
        if (x.length === 1 && x.__digit(0) === 1) {
            if (x.sign && (y.__digit(0) & 1) === 0) {
                return JSBI.unaryMinus(x);
            }
            return x;
        }
        if (y.length > 1)
            throw new RangeError('BigInt too big');
        let expValue = y.__unsignedDigit(0);
        if (expValue === 1)
            return x;
        if (expValue >= JSBI.__kMaxLengthBits) {
            throw new RangeError('BigInt too big');
        }
        if (x.length === 1 && x.__digit(0) === 2) {
            const neededDigits = 1 + ((expValue / 30) | 0);
            const sign = x.sign && ((expValue & 1) !== 0);
            const result = new JSBI(neededDigits, sign);
            result.__initializeDigits();
            const msd = 1 << (expValue % 30);
            result.__setDigit(neededDigits - 1, msd);
            return result;
        }
        let result = null;
        let runningSquare = x;
        if ((expValue & 1) !== 0)
            result = x;
        expValue >>= 1;
        for (; expValue !== 0; expValue >>= 1) {
            runningSquare = JSBI.multiply(runningSquare, runningSquare);
            if ((expValue & 1) !== 0) {
                if (result === null) {
                    result = runningSquare;
                }
                else {
                    result = JSBI.multiply(result, runningSquare);
                }
            }
        }
        return result;
    }
    static multiply(x, y) {
        if (x.length === 0)
            return x;
        if (y.length === 0)
            return y;
        let resultLength = x.length + y.length;
        if (x.__clzmsd() + y.__clzmsd() >= 30) {
            resultLength--;
        }
        const result = new JSBI(resultLength, x.sign !== y.sign);
        result.__initializeDigits();
        for (let i = 0; i < x.length; i++) {
            JSBI.__multiplyAccumulate(y, x.__digit(i), result, i);
        }
        return result.__trim();
    }
    static divide(x, y) {
        if (y.length === 0)
            throw new RangeError('Division by zero');
        if (JSBI.__absoluteCompare(x, y) < 0)
            return JSBI.__zero();
        const resultSign = x.sign !== y.sign;
        const divisor = y.__unsignedDigit(0);
        let quotient;
        if (y.length === 1 && divisor <= 0x7FFF) {
            if (divisor === 1) {
                return resultSign === x.sign ? x : JSBI.unaryMinus(x);
            }
            quotient = JSBI.__absoluteDivSmall(x, divisor, null);
        }
        else {
            quotient = JSBI.__absoluteDivLarge(x, y, true, false);
        }
        quotient.sign = resultSign;
        return quotient.__trim();
    }
    static remainder(x, y) {
        if (y.length === 0)
            throw new RangeError('Division by zero');
        if (JSBI.__absoluteCompare(x, y) < 0)
            return x;
        const divisor = y.__unsignedDigit(0);
        if (y.length === 1 && divisor <= 0x7FFF) {
            if (divisor === 1)
                return JSBI.__zero();
            const remainderDigit = JSBI.__absoluteModSmall(x, divisor);
            if (remainderDigit === 0)
                return JSBI.__zero();
            return JSBI.__oneDigit(remainderDigit, x.sign);
        }
        const remainder = JSBI.__absoluteDivLarge(x, y, false, true);
        remainder.sign = x.sign;
        return remainder.__trim();
    }
    static add(x, y) {
        const sign = x.sign;
        if (sign === y.sign) {
            return JSBI.__absoluteAdd(x, y, sign);
        }
        if (JSBI.__absoluteCompare(x, y) >= 0) {
            return JSBI.__absoluteSub(x, y, sign);
        }
        return JSBI.__absoluteSub(y, x, !sign);
    }
    static subtract(x, y) {
        const sign = x.sign;
        if (sign !== y.sign) {
            return JSBI.__absoluteAdd(x, y, sign);
        }
        if (JSBI.__absoluteCompare(x, y) >= 0) {
            return JSBI.__absoluteSub(x, y, sign);
        }
        return JSBI.__absoluteSub(y, x, !sign);
    }
    static leftShift(x, y) {
        if (y.length === 0 || x.length === 0)
            return x;
        if (y.sign)
            return JSBI.__rightShiftByAbsolute(x, y);
        return JSBI.__leftShiftByAbsolute(x, y);
    }
    static signedRightShift(x, y) {
        if (y.length === 0 || x.length === 0)
            return x;
        if (y.sign)
            return JSBI.__leftShiftByAbsolute(x, y);
        return JSBI.__rightShiftByAbsolute(x, y);
    }
    static unsignedRightShift() {
        throw new TypeError('BigInts have no unsigned right shift; use >> instead');
    }
    static lessThan(x, y) {
        return JSBI.__compareToBigInt(x, y) < 0;
    }
    static lessThanOrEqual(x, y) {
        return JSBI.__compareToBigInt(x, y) <= 0;
    }
    static greaterThan(x, y) {
        return JSBI.__compareToBigInt(x, y) > 0;
    }
    static greaterThanOrEqual(x, y) {
        return JSBI.__compareToBigInt(x, y) >= 0;
    }
    static equal(x, y) {
        if (x.sign !== y.sign)
            return false;
        if (x.length !== y.length)
            return false;
        for (let i = 0; i < x.length; i++) {
            if (x.__digit(i) !== y.__digit(i))
                return false;
        }
        return true;
    }
    static notEqual(x, y) {
        return !JSBI.equal(x, y);
    }
    static bitwiseAnd(x, y) {
        if (!x.sign && !y.sign) {
            return JSBI.__absoluteAnd(x, y).__trim();
        }
        else if (x.sign && y.sign) {
            const resultLength = Math.max(x.length, y.length) + 1;
            let result = JSBI.__absoluteSubOne(x, resultLength);
            const y1 = JSBI.__absoluteSubOne(y);
            result = JSBI.__absoluteOr(result, y1, result);
            return JSBI.__absoluteAddOne(result, true, result).__trim();
        }
        if (x.sign) {
            [x, y] = [y, x];
        }
        return JSBI.__absoluteAndNot(x, JSBI.__absoluteSubOne(y)).__trim();
    }
    static bitwiseXor(x, y) {
        if (!x.sign && !y.sign) {
            return JSBI.__absoluteXor(x, y).__trim();
        }
        else if (x.sign && y.sign) {
            const resultLength = Math.max(x.length, y.length);
            const result = JSBI.__absoluteSubOne(x, resultLength);
            const y1 = JSBI.__absoluteSubOne(y);
            return JSBI.__absoluteXor(result, y1, result).__trim();
        }
        const resultLength = Math.max(x.length, y.length) + 1;
        if (x.sign) {
            [x, y] = [y, x];
        }
        let result = JSBI.__absoluteSubOne(y, resultLength);
        result = JSBI.__absoluteXor(result, x, result);
        return JSBI.__absoluteAddOne(result, true, result).__trim();
    }
    static bitwiseOr(x, y) {
        const resultLength = Math.max(x.length, y.length);
        if (!x.sign && !y.sign) {
            return JSBI.__absoluteOr(x, y).__trim();
        }
        else if (x.sign && y.sign) {
            let result = JSBI.__absoluteSubOne(x, resultLength);
            const y1 = JSBI.__absoluteSubOne(y);
            result = JSBI.__absoluteAnd(result, y1, result);
            return JSBI.__absoluteAddOne(result, true, result).__trim();
        }
        if (x.sign) {
            [x, y] = [y, x];
        }
        let result = JSBI.__absoluteSubOne(y, resultLength);
        result = JSBI.__absoluteAndNot(result, x, result);
        return JSBI.__absoluteAddOne(result, true, result).__trim();
    }
    static asIntN(n, x) {
        if (x.length === 0)
            return x;
        n = Math.floor(n);
        if (n < 0) {
            throw new RangeError('Invalid value: not (convertible to) a safe integer');
        }
        if (n === 0)
            return JSBI.__zero();
        if (n >= JSBI.__kMaxLengthBits)
            return x;
        const neededLength = ((n + 29) / 30) | 0;
        if (x.length < neededLength)
            return x;
        const topDigit = x.__unsignedDigit(neededLength - 1);
        const compareDigit = 1 << ((n - 1) % 30);
        if (x.length === neededLength && topDigit < compareDigit)
            return x;
        const hasBit = (topDigit & compareDigit) === compareDigit;
        if (!hasBit)
            return JSBI.__truncateToNBits(n, x);
        if (!x.sign)
            return JSBI.__truncateAndSubFromPowerOfTwo(n, x, true);
        if ((topDigit & (compareDigit - 1)) === 0) {
            for (let i = neededLength - 2; i >= 0; i--) {
                if (x.__digit(i) !== 0) {
                    return JSBI.__truncateAndSubFromPowerOfTwo(n, x, false);
                }
            }
            if (x.length === neededLength && topDigit === compareDigit)
                return x;
            return JSBI.__truncateToNBits(n, x);
        }
        return JSBI.__truncateAndSubFromPowerOfTwo(n, x, false);
    }
    static asUintN(n, x) {
        if (x.length === 0)
            return x;
        n = Math.floor(n);
        if (n < 0) {
            throw new RangeError('Invalid value: not (convertible to) a safe integer');
        }
        if (n === 0)
            return JSBI.__zero();
        if (x.sign) {
            if (n > JSBI.__kMaxLengthBits) {
                throw new RangeError('BigInt too big');
            }
            return JSBI.__truncateAndSubFromPowerOfTwo(n, x, false);
        }
        if (n >= JSBI.__kMaxLengthBits)
            return x;
        const neededLength = ((n + 29) / 30) | 0;
        if (x.length < neededLength)
            return x;
        const bitsInTopDigit = n % 30;
        if (x.length == neededLength) {
            if (bitsInTopDigit === 0)
                return x;
            const topDigit = x.__digit(neededLength - 1);
            if ((topDigit >>> bitsInTopDigit) === 0)
                return x;
        }
        return JSBI.__truncateToNBits(n, x);
    }
    static ADD(x, y) {
        x = JSBI.__toPrimitive(x);
        y = JSBI.__toPrimitive(y);
        if (typeof x === 'string') {
            if (typeof y !== 'string')
                y = y.toString();
            return x + y;
        }
        if (typeof y === 'string') {
            return x.toString() + y;
        }
        x = JSBI.__toNumeric(x);
        y = JSBI.__toNumeric(y);
        if (JSBI.__isBigInt(x) && JSBI.__isBigInt(y)) {
            return JSBI.add(x, y);
        }
        if (typeof x === 'number' && typeof y === 'number') {
            return x + y;
        }
        throw new TypeError('Cannot mix BigInt and other types, use explicit conversions');
    }
    static LT(x, y) {
        return JSBI.__compare(x, y, 0);
    }
    static LE(x, y) {
        return JSBI.__compare(x, y, 1);
    }
    static GT(x, y) {
        return JSBI.__compare(x, y, 2);
    }
    static GE(x, y) {
        return JSBI.__compare(x, y, 3);
    }
    static EQ(x, y) {
        while (true) {
            if (JSBI.__isBigInt(x)) {
                if (JSBI.__isBigInt(y))
                    return JSBI.equal(x, y);
                return JSBI.EQ(y, x);
            }
            else if (typeof x === 'number') {
                if (JSBI.__isBigInt(y))
                    return JSBI.__equalToNumber(y, x);
                if (typeof y !== 'object')
                    return x == y;
                y = JSBI.__toPrimitive(y);
            }
            else if (typeof x === 'string') {
                if (JSBI.__isBigInt(y)) {
                    x = JSBI.__fromString(x);
                    if (x === null)
                        return false;
                    return JSBI.equal(x, y);
                }
                if (typeof y !== 'object')
                    return x == y;
                y = JSBI.__toPrimitive(y);
            }
            else if (typeof x === 'boolean') {
                if (JSBI.__isBigInt(y))
                    return JSBI.__equalToNumber(y, +x);
                if (typeof y !== 'object')
                    return x == y;
                y = JSBI.__toPrimitive(y);
            }
            else if (typeof x === 'symbol') {
                if (JSBI.__isBigInt(y))
                    return false;
                if (typeof y !== 'object')
                    return x == y;
                y = JSBI.__toPrimitive(y);
            }
            else if (typeof x === 'object') {
                if (typeof y === 'object' && y.constructor !== JSBI)
                    return x == y;
                x = JSBI.__toPrimitive(x);
            }
            else {
                return x == y;
            }
        }
    }
    static NE(x, y) {
        return !JSBI.EQ(x, y);
    }
    static DataViewGetBigInt64(dataview, byteOffset, littleEndian = false) {
        return JSBI.asIntN(64, JSBI.DataViewGetBigUint64(dataview, byteOffset, littleEndian));
    }
    static DataViewGetBigUint64(dataview, byteOffset, littleEndian = false) {
        const [h, l] = littleEndian ? [4, 0] : [0, 4];
        const high = dataview.getUint32(byteOffset + h, littleEndian);
        const low = dataview.getUint32(byteOffset + l, littleEndian);
        const result = new JSBI(3, false);
        result.__setDigit(0, low & 0x3FFFFFFF);
        result.__setDigit(1, ((high & 0xFFFFFFF) << 2) | (low >>> 30));
        result.__setDigit(2, high >>> 28);
        return result.__trim();
    }
    static DataViewSetBigInt64(dataview, byteOffset, value, littleEndian = false) {
        JSBI.DataViewSetBigUint64(dataview, byteOffset, value, littleEndian);
    }
    static DataViewSetBigUint64(dataview, byteOffset, value, littleEndian = false) {
        value = JSBI.asUintN(64, value);
        let high = 0;
        let low = 0;
        if (value.length > 0) {
            low = value.__digit(0);
            if (value.length > 1) {
                const d1 = value.__digit(1);
                low = low | d1 << 30;
                high = d1 >>> 2;
                if (value.length > 2) {
                    high = high | (value.__digit(2) << 28);
                }
            }
        }
        const [h, l] = littleEndian ? [4, 0] : [0, 4];
        dataview.setUint32(byteOffset + h, high, littleEndian);
        dataview.setUint32(byteOffset + l, low, littleEndian);
    }
    static __zero() {
        return new JSBI(0, false);
    }
    static __oneDigit(value, sign) {
        const result = new JSBI(1, sign);
        result.__setDigit(0, value);
        return result;
    }
    __copy() {
        const result = new JSBI(this.length, this.sign);
        for (let i = 0; i < this.length; i++) {
            result[i] = this[i];
        }
        return result;
    }
    __trim() {
        let newLength = this.length;
        let last = this[newLength - 1];
        while (last === 0) {
            newLength--;
            last = this[newLength - 1];
            this.pop();
        }
        if (newLength === 0)
            this.sign = false;
        return this;
    }
    __initializeDigits() {
        for (let i = 0; i < this.length; i++) {
            this[i] = 0;
        }
    }
    static __decideRounding(x, mantissaBitsUnset, digitIndex, currentDigit) {
        if (mantissaBitsUnset > 0)
            return -1;
        let topUnconsumedBit;
        if (mantissaBitsUnset < 0) {
            topUnconsumedBit = -mantissaBitsUnset - 1;
        }
        else {
            if (digitIndex === 0)
                return -1;
            digitIndex--;
            currentDigit = x.__digit(digitIndex);
            topUnconsumedBit = 29;
        }
        let mask = 1 << topUnconsumedBit;
        if ((currentDigit & mask) === 0)
            return -1;
        mask -= 1;
        if ((currentDigit & mask) !== 0)
            return 1;
        while (digitIndex > 0) {
            digitIndex--;
            if (x.__digit(digitIndex) !== 0)
                return 1;
        }
        return 0;
    }
    static __fromDouble(value) {
        const sign = value < 0;
        JSBI.__kBitConversionDouble[0] = value;
        const rawExponent = (JSBI.__kBitConversionInts[1] >>> 20) & 0x7FF;
        const exponent = rawExponent - 0x3FF;
        const digits = ((exponent / 30) | 0) + 1;
        const result = new JSBI(digits, sign);
        const kHiddenBit = 0x00100000;
        let mantissaHigh = (JSBI.__kBitConversionInts[1] & 0xFFFFF) | kHiddenBit;
        let mantissaLow = JSBI.__kBitConversionInts[0];
        const kMantissaHighTopBit = 20;
        const msdTopBit = exponent % 30;
        let remainingMantissaBits = 0;
        let digit;
        if (msdTopBit < kMantissaHighTopBit) {
            const shift = kMantissaHighTopBit - msdTopBit;
            remainingMantissaBits = shift + 32;
            digit = mantissaHigh >>> shift;
            mantissaHigh = (mantissaHigh << (32 - shift)) | (mantissaLow >>> shift);
            mantissaLow = mantissaLow << (32 - shift);
        }
        else if (msdTopBit === kMantissaHighTopBit) {
            remainingMantissaBits = 32;
            digit = mantissaHigh;
            mantissaHigh = mantissaLow;
            mantissaLow = 0;
        }
        else {
            const shift = msdTopBit - kMantissaHighTopBit;
            remainingMantissaBits = 32 - shift;
            digit = (mantissaHigh << shift) | (mantissaLow >>> (32 - shift));
            mantissaHigh = mantissaLow << shift;
            mantissaLow = 0;
        }
        result.__setDigit(digits - 1, digit);
        for (let digitIndex = digits - 2; digitIndex >= 0; digitIndex--) {
            if (remainingMantissaBits > 0) {
                remainingMantissaBits -= 30;
                digit = mantissaHigh >>> 2;
                mantissaHigh = (mantissaHigh << 30) | (mantissaLow >>> 2);
                mantissaLow = (mantissaLow << 30);
            }
            else {
                digit = 0;
            }
            result.__setDigit(digitIndex, digit);
        }
        return result.__trim();
    }
    static __isWhitespace(c) {
        if (c <= 0x0D && c >= 0x09)
            return true;
        if (c <= 0x9F)
            return c === 0x20;
        if (c <= 0x01FFFF) {
            return c === 0xA0 || c === 0x1680;
        }
        if (c <= 0x02FFFF) {
            c &= 0x01FFFF;
            return c <= 0x0A || c === 0x28 || c === 0x29 || c === 0x2F ||
                c === 0x5F || c === 0x1000;
        }
        return c === 0xFEFF;
    }
    static __fromString(string, radix = 0) {
        let sign = 0;
        let leadingZero = false;
        const length = string.length;
        let cursor = 0;
        if (cursor === length)
            return JSBI.__zero();
        let current = string.charCodeAt(cursor);
        while (JSBI.__isWhitespace(current)) {
            if (++cursor === length)
                return JSBI.__zero();
            current = string.charCodeAt(cursor);
        }
        if (current === 0x2B) {
            if (++cursor === length)
                return null;
            current = string.charCodeAt(cursor);
            sign = 1;
        }
        else if (current === 0x2D) {
            if (++cursor === length)
                return null;
            current = string.charCodeAt(cursor);
            sign = -1;
        }
        if (radix === 0) {
            radix = 10;
            if (current === 0x30) {
                if (++cursor === length)
                    return JSBI.__zero();
                current = string.charCodeAt(cursor);
                if (current === 0x58 || current === 0x78) {
                    radix = 16;
                    if (++cursor === length)
                        return null;
                    current = string.charCodeAt(cursor);
                }
                else if (current === 0x4F || current === 0x6F) {
                    radix = 8;
                    if (++cursor === length)
                        return null;
                    current = string.charCodeAt(cursor);
                }
                else if (current === 0x42 || current === 0x62) { // 'B' or 'b'
                    radix = 2;
                    if (++cursor === length)
                        return null;
                    current = string.charCodeAt(cursor);
                }
                else {
                    leadingZero = true;
                }
            }
        }
        else if (radix === 16) {
            if (current === 0x30) {
                if (++cursor === length)
                    return JSBI.__zero();
                current = string.charCodeAt(cursor);
                if (current === 0x58 || current === 0x78) {
                    if (++cursor === length)
                        return null;
                    current = string.charCodeAt(cursor);
                }
                else {
                    leadingZero = true;
                }
            }
        }
        if (sign !== 0 && radix !== 10)
            return null;
        while (current === 0x30) {
            leadingZero = true;
            if (++cursor === length)
                return JSBI.__zero();
            current = string.charCodeAt(cursor);
        }
        const chars = length - cursor;
        let bitsPerChar = JSBI.__kMaxBitsPerChar[radix];
        let roundup = JSBI.__kBitsPerCharTableMultiplier - 1;
        if (chars > (1 << 30) / bitsPerChar)
            return null;
        const bitsMin = (bitsPerChar * chars + roundup) >>> JSBI.__kBitsPerCharTableShift;
        const resultLength = ((bitsMin + 29) / 30) | 0;
        const result = new JSBI(resultLength, false);
        const limDigit = radix < 10 ? radix : 10;
        const limAlpha = radix > 10 ? radix - 10 : 0;
        if ((radix & (radix - 1)) === 0) {
            bitsPerChar >>= JSBI.__kBitsPerCharTableShift;
            const parts = [];
            const partsBits = [];
            let done = false;
            do {
                let part = 0;
                let bits = 0;
                while (true) {
                    let d;
                    if (((current - 48) >>> 0) < limDigit) {
                        d = current - 48;
                    }
                    else if ((((current | 32) - 97) >>> 0) < limAlpha) {
                        d = (current | 32) - 87;
                    }
                    else {
                        done = true;
                        break;
                    }
                    bits += bitsPerChar;
                    part = (part << bitsPerChar) | d;
                    if (++cursor === length) {
                        done = true;
                        break;
                    }
                    current = string.charCodeAt(cursor);
                    if (bits + bitsPerChar > 30)
                        break;
                }
                parts.push(part);
                partsBits.push(bits);
            } while (!done);
            JSBI.__fillFromParts(result, parts, partsBits);
        }
        else {
            result.__initializeDigits();
            let done = false;
            let charsSoFar = 0;
            do {
                let part = 0;
                let multiplier = 1;
                while (true) {
                    let d;
                    if (((current - 48) >>> 0) < limDigit) {
                        d = current - 48;
                    }
                    else if ((((current | 32) - 97) >>> 0) < limAlpha) {
                        d = (current | 32) - 87;
                    }
                    else {
                        done = true;
                        break;
                    }
                    const m = multiplier * radix;
                    if (m > 0x3FFFFFFF)
                        break;
                    multiplier = m;
                    part = part * radix + d;
                    charsSoFar++;
                    if (++cursor === length) {
                        done = true;
                        break;
                    }
                    current = string.charCodeAt(cursor);
                }
                roundup = JSBI.__kBitsPerCharTableMultiplier * 30 - 1;
                const digitsSoFar = (((bitsPerChar * charsSoFar + roundup) >>>
                    JSBI.__kBitsPerCharTableShift) / 30) | 0;
                result.__inplaceMultiplyAdd(multiplier, part, digitsSoFar);
            } while (!done);
        }
        if (cursor !== length) {
            if (!JSBI.__isWhitespace(current))
                return null;
            for (cursor++; cursor < length; cursor++) {
                current = string.charCodeAt(cursor);
                if (!JSBI.__isWhitespace(current))
                    return null;
            }
        }
        result.sign = (sign === -1);
        return result.__trim();
    }
    static __fillFromParts(result, parts, partsBits) {
        let digitIndex = 0;
        let digit = 0;
        let bitsInDigit = 0;
        for (let i = parts.length - 1; i >= 0; i--) {
            const part = parts[i];
            const partBits = partsBits[i];
            digit |= (part << bitsInDigit);
            bitsInDigit += partBits;
            if (bitsInDigit === 30) {
                result.__setDigit(digitIndex++, digit);
                bitsInDigit = 0;
                digit = 0;
            }
            else if (bitsInDigit > 30) {
                result.__setDigit(digitIndex++, digit & 0x3FFFFFFF);
                bitsInDigit -= 30;
                digit = part >>> (partBits - bitsInDigit);
            }
        }
        if (digit !== 0) {
            if (digitIndex >= result.length)
                throw new Error('implementation bug');
            result.__setDigit(digitIndex++, digit);
        }
        for (; digitIndex < result.length; digitIndex++) {
            result.__setDigit(digitIndex, 0);
        }
    }
    static __toStringBasePowerOfTwo(x, radix) {
        const length = x.length;
        let bits = radix - 1;
        bits = ((bits >>> 1) & 0x55) + (bits & 0x55);
        bits = ((bits >>> 2) & 0x33) + (bits & 0x33);
        bits = ((bits >>> 4) & 0x0F) + (bits & 0x0F);
        const bitsPerChar = bits;
        const charMask = radix - 1;
        const msd = x.__digit(length - 1);
        const msdLeadingZeros = JSBI.__clz30(msd);
        const bitLength = length * 30 - msdLeadingZeros;
        let charsRequired = ((bitLength + bitsPerChar - 1) / bitsPerChar) | 0;
        if (x.sign)
            charsRequired++;
        if (charsRequired > (1 << 28))
            throw new Error('string too long');
        const result = new Array(charsRequired);
        let pos = charsRequired - 1;
        let digit = 0;
        let availableBits = 0;
        for (let i = 0; i < length - 1; i++) {
            const newDigit = x.__digit(i);
            const current = (digit | (newDigit << availableBits)) & charMask;
            result[pos--] = JSBI.__kConversionChars[current];
            const consumedBits = bitsPerChar - availableBits;
            digit = newDigit >>> consumedBits;
            availableBits = 30 - consumedBits;
            while (availableBits >= bitsPerChar) {
                result[pos--] = JSBI.__kConversionChars[digit & charMask];
                digit >>>= bitsPerChar;
                availableBits -= bitsPerChar;
            }
        }
        const current = (digit | (msd << availableBits)) & charMask;
        result[pos--] = JSBI.__kConversionChars[current];
        digit = msd >>> (bitsPerChar - availableBits);
        while (digit !== 0) {
            result[pos--] = JSBI.__kConversionChars[digit & charMask];
            digit >>>= bitsPerChar;
        }
        if (x.sign)
            result[pos--] = '-';
        if (pos !== -1)
            throw new Error('implementation bug');
        return result.join('');
    }
    static __toStringGeneric(x, radix, isRecursiveCall) {
        const length = x.length;
        if (length === 0)
            return '';
        if (length === 1) {
            let result = x.__unsignedDigit(0).toString(radix);
            if (isRecursiveCall === false && x.sign) {
                result = '-' + result;
            }
            return result;
        }
        const bitLength = length * 30 - JSBI.__clz30(x.__digit(length - 1));
        const maxBitsPerChar = JSBI.__kMaxBitsPerChar[radix];
        const minBitsPerChar = maxBitsPerChar - 1;
        let charsRequired = bitLength * JSBI.__kBitsPerCharTableMultiplier;
        charsRequired += minBitsPerChar - 1;
        charsRequired = (charsRequired / minBitsPerChar) | 0;
        const secondHalfChars = (charsRequired + 1) >> 1;
        const conqueror = JSBI.exponentiate(JSBI.__oneDigit(radix, false), JSBI.__oneDigit(secondHalfChars, false));
        let quotient;
        let secondHalf;
        const divisor = conqueror.__unsignedDigit(0);
        if (conqueror.length === 1 && divisor <= 0x7FFF) {
            quotient = new JSBI(x.length, false);
            quotient.__initializeDigits();
            let remainder = 0;
            for (let i = x.length * 2 - 1; i >= 0; i--) {
                const input = (remainder << 15) | x.__halfDigit(i);
                quotient.__setHalfDigit(i, (input / divisor) | 0);
                remainder = (input % divisor) | 0;
            }
            secondHalf = remainder.toString(radix);
        }
        else {
            const divisionResult = JSBI.__absoluteDivLarge(x, conqueror, true, true);
            quotient = divisionResult.quotient;
            const remainder = divisionResult.remainder.__trim();
            secondHalf = JSBI.__toStringGeneric(remainder, radix, true);
        }
        quotient.__trim();
        let firstHalf = JSBI.__toStringGeneric(quotient, radix, true);
        while (secondHalf.length < secondHalfChars) {
            secondHalf = '0' + secondHalf;
        }
        if (isRecursiveCall === false && x.sign) {
            firstHalf = '-' + firstHalf;
        }
        return firstHalf + secondHalf;
    }
    static __unequalSign(leftNegative) {
        return leftNegative ? -1 : 1;
    }
    static __absoluteGreater(bothNegative) {
        return bothNegative ? -1 : 1;
    }
    static __absoluteLess(bothNegative) {
        return bothNegative ? 1 : -1;
    }
    static __compareToBigInt(x, y) {
        const xSign = x.sign;
        if (xSign !== y.sign)
            return JSBI.__unequalSign(xSign);
        const result = JSBI.__absoluteCompare(x, y);
        if (result > 0)
            return JSBI.__absoluteGreater(xSign);
        if (result < 0)
            return JSBI.__absoluteLess(xSign);
        return 0;
    }
    static __compareToNumber(x, y) {
        if (JSBI.__isOneDigitInt(y)) {
            const xSign = x.sign;
            const ySign = (y < 0);
            if (xSign !== ySign)
                return JSBI.__unequalSign(xSign);
            if (x.length === 0) {
                if (ySign)
                    throw new Error('implementation bug');
                return y === 0 ? 0 : -1;
            }
            if (x.length > 1)
                return JSBI.__absoluteGreater(xSign);
            const yAbs = Math.abs(y);
            const xDigit = x.__unsignedDigit(0);
            if (xDigit > yAbs)
                return JSBI.__absoluteGreater(xSign);
            if (xDigit < yAbs)
                return JSBI.__absoluteLess(xSign);
            return 0;
        }
        return JSBI.__compareToDouble(x, y);
    }
    static __compareToDouble(x, y) {
        if (y !== y)
            return y;
        if (y === Infinity)
            return -1;
        if (y === -Infinity)
            return 1;
        const xSign = x.sign;
        const ySign = (y < 0);
        if (xSign !== ySign)
            return JSBI.__unequalSign(xSign);
        if (y === 0) {
            throw new Error('implementation bug: should be handled elsewhere');
        }
        if (x.length === 0)
            return -1;
        JSBI.__kBitConversionDouble[0] = y;
        const rawExponent = (JSBI.__kBitConversionInts[1] >>> 20) & 0x7FF;
        if (rawExponent === 0x7FF) {
            throw new Error('implementation bug: handled elsewhere');
        }
        const exponent = rawExponent - 0x3FF;
        if (exponent < 0) {
            return JSBI.__absoluteGreater(xSign);
        }
        const xLength = x.length;
        let xMsd = x.__digit(xLength - 1);
        const msdLeadingZeros = JSBI.__clz30(xMsd);
        const xBitLength = xLength * 30 - msdLeadingZeros;
        const yBitLength = exponent + 1;
        if (xBitLength < yBitLength)
            return JSBI.__absoluteLess(xSign);
        if (xBitLength > yBitLength)
            return JSBI.__absoluteGreater(xSign);
        const kHiddenBit = 0x00100000;
        let mantissaHigh = (JSBI.__kBitConversionInts[1] & 0xFFFFF) | kHiddenBit;
        let mantissaLow = JSBI.__kBitConversionInts[0];
        const kMantissaHighTopBit = 20;
        const msdTopBit = 29 - msdLeadingZeros;
        if (msdTopBit !== (((xBitLength - 1) % 30) | 0)) {
            throw new Error('implementation bug');
        }
        let compareMantissa;
        let remainingMantissaBits = 0;
        if (msdTopBit < kMantissaHighTopBit) {
            const shift = kMantissaHighTopBit - msdTopBit;
            remainingMantissaBits = shift + 32;
            compareMantissa = mantissaHigh >>> shift;
            mantissaHigh = (mantissaHigh << (32 - shift)) | (mantissaLow >>> shift);
            mantissaLow = mantissaLow << (32 - shift);
        }
        else if (msdTopBit === kMantissaHighTopBit) {
            remainingMantissaBits = 32;
            compareMantissa = mantissaHigh;
            mantissaHigh = mantissaLow;
            mantissaLow = 0;
        }
        else {
            const shift = msdTopBit - kMantissaHighTopBit;
            remainingMantissaBits = 32 - shift;
            compareMantissa =
                (mantissaHigh << shift) | (mantissaLow >>> (32 - shift));
            mantissaHigh = mantissaLow << shift;
            mantissaLow = 0;
        }
        xMsd = xMsd >>> 0;
        compareMantissa = compareMantissa >>> 0;
        if (xMsd > compareMantissa)
            return JSBI.__absoluteGreater(xSign);
        if (xMsd < compareMantissa)
            return JSBI.__absoluteLess(xSign);
        for (let digitIndex = xLength - 2; digitIndex >= 0; digitIndex--) {
            if (remainingMantissaBits > 0) {
                remainingMantissaBits -= 30;
                compareMantissa = mantissaHigh >>> 2;
                mantissaHigh = (mantissaHigh << 30) | (mantissaLow >>> 2);
                mantissaLow = (mantissaLow << 30);
            }
            else {
                compareMantissa = 0;
            }
            const digit = x.__unsignedDigit(digitIndex);
            if (digit > compareMantissa)
                return JSBI.__absoluteGreater(xSign);
            if (digit < compareMantissa)
                return JSBI.__absoluteLess(xSign);
        }
        if (mantissaHigh !== 0 || mantissaLow !== 0) {
            if (remainingMantissaBits === 0)
                throw new Error('implementation bug');
            return JSBI.__absoluteLess(xSign);
        }
        return 0;
    }
    static __equalToNumber(x, y) {
        if (JSBI.__isOneDigitInt(y)) {
            if (y === 0)
                return x.length === 0;
            return (x.length === 1) && (x.sign === (y < 0)) &&
                (x.__unsignedDigit(0) === Math.abs(y));
        }
        return JSBI.__compareToDouble(x, y) === 0;
    }
    static __comparisonResultToBool(result, op) {
        switch (op) {
            case 0: return result < 0;
            case 1: return result <= 0;
            case 2: return result > 0;
            case 3: return result >= 0;
        }
    }
    static __compare(x, y, op) {
        x = JSBI.__toPrimitive(x);
        y = JSBI.__toPrimitive(y);
        if (typeof x === 'string' && typeof y === 'string') {
            switch (op) {
                case 0: return x < y;
                case 1: return x <= y;
                case 2: return x > y;
                case 3: return x >= y;
            }
        }
        if (JSBI.__isBigInt(x) && typeof y === 'string') {
            y = JSBI.__fromString(y);
            if (y === null)
                return false;
            return JSBI.__comparisonResultToBool(JSBI.__compareToBigInt(x, y), op);
        }
        if (typeof x === 'string' && JSBI.__isBigInt(y)) {
            x = JSBI.__fromString(x);
            if (x === null)
                return false;
            return JSBI.__comparisonResultToBool(JSBI.__compareToBigInt(x, y), op);
        }
        x = JSBI.__toNumeric(x);
        y = JSBI.__toNumeric(y);
        if (JSBI.__isBigInt(x)) {
            if (JSBI.__isBigInt(y)) {
                return JSBI.__comparisonResultToBool(JSBI.__compareToBigInt(x, y), op);
            }
            if (typeof y !== 'number')
                throw new Error('implementation bug');
            return JSBI.__comparisonResultToBool(JSBI.__compareToNumber(x, y), op);
        }
        if (typeof x !== 'number')
            throw new Error('implementation bug');
        if (JSBI.__isBigInt(y)) {
            return JSBI.__comparisonResultToBool(JSBI.__compareToNumber(y, x), (op ^ 2));
        }
        if (typeof y !== 'number')
            throw new Error('implementation bug');
        switch (op) {
            case 0: return x < y;
            case 1: return x <= y;
            case 2: return x > y;
            case 3: return x >= y;
        }
    }
    __clzmsd() {
        return JSBI.__clz30(this.__digit(this.length - 1));
    }
    static __absoluteAdd(x, y, resultSign) {
        if (x.length < y.length)
            return JSBI.__absoluteAdd(y, x, resultSign);
        if (x.length === 0)
            return x;
        if (y.length === 0)
            return x.sign === resultSign ? x : JSBI.unaryMinus(x);
        let resultLength = x.length;
        if (x.__clzmsd() === 0 || (y.length === x.length && y.__clzmsd() === 0)) {
            resultLength++;
        }
        const result = new JSBI(resultLength, resultSign);
        let carry = 0;
        let i = 0;
        for (; i < y.length; i++) {
            const r = x.__digit(i) + y.__digit(i) + carry;
            carry = r >>> 30;
            result.__setDigit(i, r & 0x3FFFFFFF);
        }
        for (; i < x.length; i++) {
            const r = x.__digit(i) + carry;
            carry = r >>> 30;
            result.__setDigit(i, r & 0x3FFFFFFF);
        }
        if (i < result.length) {
            result.__setDigit(i, carry);
        }
        return result.__trim();
    }
    static __absoluteSub(x, y, resultSign) {
        if (x.length === 0)
            return x;
        if (y.length === 0)
            return x.sign === resultSign ? x : JSBI.unaryMinus(x);
        const result = new JSBI(x.length, resultSign);
        let borrow = 0;
        let i = 0;
        for (; i < y.length; i++) {
            const r = x.__digit(i) - y.__digit(i) - borrow;
            borrow = (r >>> 30) & 1;
            result.__setDigit(i, r & 0x3FFFFFFF);
        }
        for (; i < x.length; i++) {
            const r = x.__digit(i) - borrow;
            borrow = (r >>> 30) & 1;
            result.__setDigit(i, r & 0x3FFFFFFF);
        }
        return result.__trim();
    }
    static __absoluteAddOne(x, sign, result = null) {
        const inputLength = x.length;
        if (result === null) {
            result = new JSBI(inputLength, sign);
        }
        else {
            result.sign = sign;
        }
        let carry = 1;
        for (let i = 0; i < inputLength; i++) {
            const r = x.__digit(i) + carry;
            carry = r >>> 30;
            result.__setDigit(i, r & 0x3FFFFFFF);
        }
        if (carry !== 0) {
            result.__setDigitGrow(inputLength, 1);
        }
        return result;
    }
    static __absoluteSubOne(x, resultLength) {
        const length = x.length;
        resultLength = resultLength || length;
        const result = new JSBI(resultLength, false);
        let borrow = 1;
        for (let i = 0; i < length; i++) {
            const r = x.__digit(i) - borrow;
            borrow = (r >>> 30) & 1;
            result.__setDigit(i, r & 0x3FFFFFFF);
        }
        if (borrow !== 0)
            throw new Error('implementation bug');
        for (let i = length; i < resultLength; i++) {
            result.__setDigit(i, 0);
        }
        return result;
    }
    static __absoluteAnd(x, y, result = null) {
        let xLength = x.length;
        let yLength = y.length;
        let numPairs = yLength;
        if (xLength < yLength) {
            numPairs = xLength;
            const tmp = x;
            const tmpLength = xLength;
            x = y;
            xLength = yLength;
            y = tmp;
            yLength = tmpLength;
        }
        let resultLength = numPairs;
        if (result === null) {
            result = new JSBI(resultLength, false);
        }
        else {
            resultLength = result.length;
        }
        let i = 0;
        for (; i < numPairs; i++) {
            result.__setDigit(i, x.__digit(i) & y.__digit(i));
        }
        for (; i < resultLength; i++) {
            result.__setDigit(i, 0);
        }
        return result;
    }
    static __absoluteAndNot(x, y, result = null) {
        const xLength = x.length;
        const yLength = y.length;
        let numPairs = yLength;
        if (xLength < yLength) {
            numPairs = xLength;
        }
        let resultLength = xLength;
        if (result === null) {
            result = new JSBI(resultLength, false);
        }
        else {
            resultLength = result.length;
        }
        let i = 0;
        for (; i < numPairs; i++) {
            result.__setDigit(i, x.__digit(i) & ~y.__digit(i));
        }
        for (; i < xLength; i++) {
            result.__setDigit(i, x.__digit(i));
        }
        for (; i < resultLength; i++) {
            result.__setDigit(i, 0);
        }
        return result;
    }
    static __absoluteOr(x, y, result = null) {
        let xLength = x.length;
        let yLength = y.length;
        let numPairs = yLength;
        if (xLength < yLength) {
            numPairs = xLength;
            const tmp = x;
            const tmpLength = xLength;
            x = y;
            xLength = yLength;
            y = tmp;
            yLength = tmpLength;
        }
        let resultLength = xLength;
        if (result === null) {
            result = new JSBI(resultLength, false);
        }
        else {
            resultLength = result.length;
        }
        let i = 0;
        for (; i < numPairs; i++) {
            result.__setDigit(i, x.__digit(i) | y.__digit(i));
        }
        for (; i < xLength; i++) {
            result.__setDigit(i, x.__digit(i));
        }
        for (; i < resultLength; i++) {
            result.__setDigit(i, 0);
        }
        return result;
    }
    static __absoluteXor(x, y, result = null) {
        let xLength = x.length;
        let yLength = y.length;
        let numPairs = yLength;
        if (xLength < yLength) {
            numPairs = xLength;
            const tmp = x;
            const tmpLength = xLength;
            x = y;
            xLength = yLength;
            y = tmp;
            yLength = tmpLength;
        }
        let resultLength = xLength;
        if (result === null) {
            result = new JSBI(resultLength, false);
        }
        else {
            resultLength = result.length;
        }
        let i = 0;
        for (; i < numPairs; i++) {
            result.__setDigit(i, x.__digit(i) ^ y.__digit(i));
        }
        for (; i < xLength; i++) {
            result.__setDigit(i, x.__digit(i));
        }
        for (; i < resultLength; i++) {
            result.__setDigit(i, 0);
        }
        return result;
    }
    static __absoluteCompare(x, y) {
        const diff = x.length - y.length;
        if (diff !== 0)
            return diff;
        let i = x.length - 1;
        while (i >= 0 && x.__digit(i) === y.__digit(i))
            i--;
        if (i < 0)
            return 0;
        return x.__unsignedDigit(i) > y.__unsignedDigit(i) ? 1 : -1;
    }
    static __multiplyAccumulate(multiplicand, multiplier, accumulator, accumulatorIndex) {
        if (multiplier === 0)
            return;
        const m2Low = multiplier & 0x7FFF;
        const m2High = multiplier >>> 15;
        let carry = 0;
        let high = 0;
        for (let i = 0; i < multiplicand.length; i++, accumulatorIndex++) {
            let acc = accumulator.__digit(accumulatorIndex);
            const m1 = multiplicand.__digit(i);
            const m1Low = m1 & 0x7FFF;
            const m1High = m1 >>> 15;
            const rLow = JSBI.__imul(m1Low, m2Low);
            const rMid1 = JSBI.__imul(m1Low, m2High);
            const rMid2 = JSBI.__imul(m1High, m2Low);
            const rHigh = JSBI.__imul(m1High, m2High);
            acc += high + rLow + carry;
            carry = acc >>> 30;
            acc &= 0x3FFFFFFF;
            acc += ((rMid1 & 0x7FFF) << 15) + ((rMid2 & 0x7FFF) << 15);
            carry += acc >>> 30;
            high = rHigh + (rMid1 >>> 15) + (rMid2 >>> 15);
            accumulator.__setDigit(accumulatorIndex, acc & 0x3FFFFFFF);
        }
        for (; carry !== 0 || high !== 0; accumulatorIndex++) {
            let acc = accumulator.__digit(accumulatorIndex);
            acc += carry + high;
            high = 0;
            carry = acc >>> 30;
            accumulator.__setDigit(accumulatorIndex, acc & 0x3FFFFFFF);
        }
    }
    static __internalMultiplyAdd(source, factor, summand, n, result) {
        let carry = summand;
        let high = 0;
        for (let i = 0; i < n; i++) {
            const digit = source.__digit(i);
            const rx = JSBI.__imul(digit & 0x7FFF, factor);
            const ry = JSBI.__imul(digit >>> 15, factor);
            const r = rx + ((ry & 0x7FFF) << 15) + high + carry;
            carry = r >>> 30;
            high = ry >>> 15;
            result.__setDigit(i, r & 0x3FFFFFFF);
        }
        if (result.length > n) {
            result.__setDigit(n++, carry + high);
            while (n < result.length) {
                result.__setDigit(n++, 0);
            }
        }
        else {
            if (carry + high !== 0)
                throw new Error('implementation bug');
        }
    }
    __inplaceMultiplyAdd(multiplier, summand, length) {
        if (length > this.length)
            length = this.length;
        const mLow = multiplier & 0x7FFF;
        const mHigh = multiplier >>> 15;
        let carry = 0;
        let high = summand;
        for (let i = 0; i < length; i++) {
            const d = this.__digit(i);
            const dLow = d & 0x7FFF;
            const dHigh = d >>> 15;
            const pLow = JSBI.__imul(dLow, mLow);
            const pMid1 = JSBI.__imul(dLow, mHigh);
            const pMid2 = JSBI.__imul(dHigh, mLow);
            const pHigh = JSBI.__imul(dHigh, mHigh);
            let result = high + pLow + carry;
            carry = result >>> 30;
            result &= 0x3FFFFFFF;
            result += ((pMid1 & 0x7FFF) << 15) + ((pMid2 & 0x7FFF) << 15);
            carry += result >>> 30;
            high = pHigh + (pMid1 >>> 15) + (pMid2 >>> 15);
            this.__setDigit(i, result & 0x3FFFFFFF);
        }
        if (carry !== 0 || high !== 0) {
            throw new Error('implementation bug');
        }
    }
    static __absoluteDivSmall(x, divisor, quotient = null) {
        if (quotient === null)
            quotient = new JSBI(x.length, false);
        let remainder = 0;
        for (let i = x.length * 2 - 1; i >= 0; i -= 2) {
            let input = ((remainder << 15) | x.__halfDigit(i)) >>> 0;
            const upperHalf = (input / divisor) | 0;
            remainder = (input % divisor) | 0;
            input = ((remainder << 15) | x.__halfDigit(i - 1)) >>> 0;
            const lowerHalf = (input / divisor) | 0;
            remainder = (input % divisor) | 0;
            quotient.__setDigit(i >>> 1, (upperHalf << 15) | lowerHalf);
        }
        return quotient;
    }
    static __absoluteModSmall(x, divisor) {
        let remainder = 0;
        for (let i = x.length * 2 - 1; i >= 0; i--) {
            const input = ((remainder << 15) | x.__halfDigit(i)) >>> 0;
            remainder = (input % divisor) | 0;
        }
        return remainder;
    }
    static __absoluteDivLarge(dividend, divisor, wantQuotient, wantRemainder) {
        const n = divisor.__halfDigitLength();
        const n2 = divisor.length;
        const m = dividend.__halfDigitLength() - n;
        let q = null;
        if (wantQuotient) {
            q = new JSBI((m + 2) >>> 1, false);
            q.__initializeDigits();
        }
        const qhatv = new JSBI((n + 2) >>> 1, false);
        qhatv.__initializeDigits();
        // D1.
        const shift = JSBI.__clz15(divisor.__halfDigit(n - 1));
        if (shift > 0) {
            divisor = JSBI.__specialLeftShift(divisor, shift, 0);
        }
        const u = JSBI.__specialLeftShift(dividend, shift, 1);
        // D2.
        const vn1 = divisor.__halfDigit(n - 1);
        let halfDigitBuffer = 0;
        for (let j = m; j >= 0; j--) {
            // D3.
            let qhat = 0x7FFF;
            const ujn = u.__halfDigit(j + n);
            if (ujn !== vn1) {
                const input = ((ujn << 15) | u.__halfDigit(j + n - 1)) >>> 0;
                qhat = (input / vn1) | 0;
                let rhat = (input % vn1) | 0;
                const vn2 = divisor.__halfDigit(n - 2);
                const ujn2 = u.__halfDigit(j + n - 2);
                while ((JSBI.__imul(qhat, vn2) >>> 0) > (((rhat << 16) | ujn2) >>> 0)) {
                    qhat--;
                    rhat += vn1;
                    if (rhat > 0x7FFF)
                        break;
                }
            }
            // D4.
            JSBI.__internalMultiplyAdd(divisor, qhat, 0, n2, qhatv);
            let c = u.__inplaceSub(qhatv, j, n + 1);
            if (c !== 0) {
                c = u.__inplaceAdd(divisor, j, n);
                u.__setHalfDigit(j + n, (u.__halfDigit(j + n) + c) & 0x7FFF);
                qhat--;
            }
            if (wantQuotient) {
                if (j & 1) {
                    halfDigitBuffer = qhat << 15;
                }
                else {
                    q.__setDigit(j >>> 1, halfDigitBuffer | qhat);
                }
            }
        }
        if (wantRemainder) {
            u.__inplaceRightShift(shift);
            if (wantQuotient) {
                return { quotient: q, remainder: u };
            }
            return u;
        }
        if (wantQuotient)
            return q;
        throw new Error('unreachable');
    }
    static __clz15(value) {
        return JSBI.__clz30(value) - 15;
    }
    __inplaceAdd(summand, startIndex, halfDigits) {
        let carry = 0;
        for (let i = 0; i < halfDigits; i++) {
            const sum = this.__halfDigit(startIndex + i) +
                summand.__halfDigit(i) +
                carry;
            carry = sum >>> 15;
            this.__setHalfDigit(startIndex + i, sum & 0x7FFF);
        }
        return carry;
    }
    __inplaceSub(subtrahend, startIndex, halfDigits) {
        const fullSteps = (halfDigits - 1) >>> 1;
        let borrow = 0;
        if (startIndex & 1) {
            startIndex >>= 1;
            let current = this.__digit(startIndex);
            let r0 = current & 0x7FFF;
            let i = 0;
            for (; i < fullSteps; i++) {
                const sub = subtrahend.__digit(i);
                const r15 = (current >>> 15) - (sub & 0x7FFF) - borrow;
                borrow = (r15 >>> 15) & 1;
                this.__setDigit(startIndex + i, ((r15 & 0x7FFF) << 15) | (r0 & 0x7FFF));
                current = this.__digit(startIndex + i + 1);
                r0 = (current & 0x7FFF) - (sub >>> 15) - borrow;
                borrow = (r0 >>> 15) & 1;
            }
            const sub = subtrahend.__digit(i);
            const r15 = (current >>> 15) - (sub & 0x7FFF) - borrow;
            borrow = (r15 >>> 15) & 1;
            this.__setDigit(startIndex + i, ((r15 & 0x7FFF) << 15) | (r0 & 0x7FFF));
            const subTop = sub >>> 15;
            if (startIndex + i + 1 >= this.length) {
                throw new RangeError('out of bounds');
            }
            if ((halfDigits & 1) === 0) {
                current = this.__digit(startIndex + i + 1);
                r0 = (current & 0x7FFF) - subTop - borrow;
                borrow = (r0 >>> 15) & 1;
                this.__setDigit(startIndex + subtrahend.length, (current & 0x3FFF8000) | (r0 & 0x7FFF));
            }
        }
        else {
            startIndex >>= 1;
            let i = 0;
            for (; i < subtrahend.length - 1; i++) {
                const current = this.__digit(startIndex + i);
                const sub = subtrahend.__digit(i);
                const r0 = (current & 0x7FFF) - (sub & 0x7FFF) - borrow;
                borrow = (r0 >>> 15) & 1;
                const r15 = (current >>> 15) - (sub >>> 15) - borrow;
                borrow = (r15 >>> 15) & 1;
                this.__setDigit(startIndex + i, ((r15 & 0x7FFF) << 15) | (r0 & 0x7FFF));
            }
            const current = this.__digit(startIndex + i);
            const sub = subtrahend.__digit(i);
            const r0 = (current & 0x7FFF) - (sub & 0x7FFF) - borrow;
            borrow = (r0 >>> 15) & 1;
            let r15 = 0;
            if ((halfDigits & 1) === 0) {
                r15 = (current >>> 15) - (sub >>> 15) - borrow;
                borrow = (r15 >>> 15) & 1;
            }
            this.__setDigit(startIndex + i, ((r15 & 0x7FFF) << 15) | (r0 & 0x7FFF));
        }
        return borrow;
    }
    __inplaceRightShift(shift) {
        if (shift === 0)
            return;
        let carry = this.__digit(0) >>> shift;
        const last = this.length - 1;
        for (let i = 0; i < last; i++) {
            const d = this.__digit(i + 1);
            this.__setDigit(i, ((d << (30 - shift)) & 0x3FFFFFFF) | carry);
            carry = d >>> shift;
        }
        this.__setDigit(last, carry);
    }
    static __specialLeftShift(x, shift, addDigit) {
        const n = x.length;
        const resultLength = n + addDigit;
        const result = new JSBI(resultLength, false);
        if (shift === 0) {
            for (let i = 0; i < n; i++)
                result.__setDigit(i, x.__digit(i));
            if (addDigit > 0)
                result.__setDigit(n, 0);
            return result;
        }
        let carry = 0;
        for (let i = 0; i < n; i++) {
            const d = x.__digit(i);
            result.__setDigit(i, ((d << shift) & 0x3FFFFFFF) | carry);
            carry = d >>> (30 - shift);
        }
        if (addDigit > 0) {
            result.__setDigit(n, carry);
        }
        return result;
    }
    static __leftShiftByAbsolute(x, y) {
        const shift = JSBI.__toShiftAmount(y);
        if (shift < 0)
            throw new RangeError('BigInt too big');
        const digitShift = (shift / 30) | 0;
        const bitsShift = shift % 30;
        const length = x.length;
        const grow = bitsShift !== 0 &&
            (x.__digit(length - 1) >>> (30 - bitsShift)) !== 0;
        const resultLength = length + digitShift + (grow ? 1 : 0);
        const result = new JSBI(resultLength, x.sign);
        if (bitsShift === 0) {
            let i = 0;
            for (; i < digitShift; i++)
                result.__setDigit(i, 0);
            for (; i < resultLength; i++) {
                result.__setDigit(i, x.__digit(i - digitShift));
            }
        }
        else {
            let carry = 0;
            for (let i = 0; i < digitShift; i++)
                result.__setDigit(i, 0);
            for (let i = 0; i < length; i++) {
                const d = x.__digit(i);
                result.__setDigit(i + digitShift, ((d << bitsShift) & 0x3FFFFFFF) | carry);
                carry = d >>> (30 - bitsShift);
            }
            if (grow) {
                result.__setDigit(length + digitShift, carry);
            }
            else {
                if (carry !== 0)
                    throw new Error('implementation bug');
            }
        }
        return result.__trim();
    }
    static __rightShiftByAbsolute(x, y) {
        const length = x.length;
        const sign = x.sign;
        const shift = JSBI.__toShiftAmount(y);
        if (shift < 0)
            return JSBI.__rightShiftByMaximum(sign);
        const digitShift = (shift / 30) | 0;
        const bitsShift = shift % 30;
        let resultLength = length - digitShift;
        if (resultLength <= 0)
            return JSBI.__rightShiftByMaximum(sign);
        let mustRoundDown = false;
        if (sign) {
            const mask = (1 << bitsShift) - 1;
            if ((x.__digit(digitShift) & mask) !== 0) {
                mustRoundDown = true;
            }
            else {
                for (let i = 0; i < digitShift; i++) {
                    if (x.__digit(i) !== 0) {
                        mustRoundDown = true;
                        break;
                    }
                }
            }
        }
        if (mustRoundDown && bitsShift === 0) {
            const msd = x.__digit(length - 1);
            const roundingCanOverflow = ~msd === 0;
            if (roundingCanOverflow)
                resultLength++;
        }
        let result = new JSBI(resultLength, sign);
        if (bitsShift === 0) {
            result.__setDigit(resultLength - 1, 0);
            for (let i = digitShift; i < length; i++) {
                result.__setDigit(i - digitShift, x.__digit(i));
            }
        }
        else {
            let carry = x.__digit(digitShift) >>> bitsShift;
            const last = length - digitShift - 1;
            for (let i = 0; i < last; i++) {
                const d = x.__digit(i + digitShift + 1);
                result.__setDigit(i, ((d << (30 - bitsShift)) & 0x3FFFFFFF) | carry);
                carry = d >>> bitsShift;
            }
            result.__setDigit(last, carry);
        }
        if (mustRoundDown) {
            result = JSBI.__absoluteAddOne(result, true, result);
        }
        return result.__trim();
    }
    static __rightShiftByMaximum(sign) {
        if (sign) {
            return JSBI.__oneDigit(1, true);
        }
        return JSBI.__zero();
    }
    static __toShiftAmount(x) {
        if (x.length > 1)
            return -1;
        const value = x.__unsignedDigit(0);
        if (value > JSBI.__kMaxLengthBits)
            return -1;
        return value;
    }
    static __toPrimitive(obj, hint = 'default') {
        if (typeof obj !== 'object')
            return obj;
        if (obj.constructor === JSBI)
            return obj;
        if (typeof Symbol !== 'undefined' &&
            typeof Symbol.toPrimitive === 'symbol') {
            const exoticToPrim = obj[Symbol.toPrimitive];
            if (exoticToPrim) {
                const primitive = exoticToPrim(hint);
                if (typeof primitive !== 'object')
                    return primitive;
                throw new TypeError('Cannot convert object to primitive value');
            }
        }
        const valueOf = obj.valueOf;
        if (valueOf) {
            const primitive = valueOf.call(obj);
            if (typeof primitive !== 'object')
                return primitive;
        }
        const toString = obj.toString;
        if (toString) {
            const primitive = toString.call(obj);
            if (typeof primitive !== 'object')
                return primitive;
        }
        throw new TypeError('Cannot convert object to primitive value');
    }
    static __toNumeric(value) {
        if (JSBI.__isBigInt(value))
            return value;
        return +value;
    }
    static __isBigInt(value) {
        return typeof value === 'object' && value !== null &&
            value.constructor === JSBI;
    }
    static __truncateToNBits(n, x) {
        const neededDigits = ((n + 29) / 30) | 0;
        const result = new JSBI(neededDigits, x.sign);
        const last = neededDigits - 1;
        for (let i = 0; i < last; i++) {
            result.__setDigit(i, x.__digit(i));
        }
        let msd = x.__digit(last);
        if ((n % 30) !== 0) {
            const drop = 32 - (n % 30);
            msd = (msd << drop) >>> drop;
        }
        result.__setDigit(last, msd);
        return result.__trim();
    }
    static __truncateAndSubFromPowerOfTwo(n, x, resultSign) {
        const neededDigits = ((n + 29) / 30) | 0;
        const result = new JSBI(neededDigits, resultSign);
        let i = 0;
        const last = neededDigits - 1;
        let borrow = 0;
        const limit = Math.min(last, x.length);
        for (; i < limit; i++) {
            const r = 0 - x.__digit(i) - borrow;
            borrow = (r >>> 30) & 1;
            result.__setDigit(i, r & 0x3FFFFFFF);
        }
        for (; i < last; i++) {
            result.__setDigit(i, (-borrow & 0x3FFFFFFF) | 0);
        }
        let msd = last < x.length ? x.__digit(last) : 0;
        const msdBitsConsumed = n % 30;
        let resultMsd;
        if (msdBitsConsumed === 0) {
            resultMsd = 0 - msd - borrow;
            resultMsd &= 0x3FFFFFFF;
        }
        else {
            const drop = 32 - msdBitsConsumed;
            msd = (msd << drop) >>> drop;
            const minuendMsd = 1 << (32 - drop);
            resultMsd = minuendMsd - msd - borrow;
            resultMsd &= (minuendMsd - 1);
        }
        result.__setDigit(last, resultMsd);
        return result.__trim();
    }
    __digit(i) {
        return this[i];
    }
    __unsignedDigit(i) {
        return this[i] >>> 0;
    }
    __setDigit(i, digit) {
        this[i] = digit | 0;
    }
    __setDigitGrow(i, digit) {
        this[i] = digit | 0;
    }
    __halfDigitLength() {
        const len = this.length;
        if (this.__unsignedDigit(len - 1) <= 0x7FFF)
            return len * 2 - 1;
        return len * 2;
    }
    __halfDigit(i) {
        return (this[i >>> 1] >>> ((i & 1) * 15)) & 0x7FFF;
    }
    __setHalfDigit(i, value) {
        const digitIndex = i >>> 1;
        const previous = this.__digit(digitIndex);
        const updated = (i & 1) ? (previous & 0x7FFF) | (value << 15)
            : (previous & 0x3FFF8000) | (value & 0x7FFF);
        this.__setDigit(digitIndex, updated);
    }
    static __digitPow(base, exponent) {
        let result = 1;
        while (exponent > 0) {
            if (exponent & 1)
                result *= base;
            exponent >>>= 1;
            base *= base;
        }
        return result;
    }
    static __isOneDigitInt(x) {
        return (x & 0x3FFFFFFF) === x;
    }
}
JSBI.__kMaxLength = 1 << 25;
JSBI.__kMaxLengthBits = JSBI.__kMaxLength << 5;
JSBI.__kMaxBitsPerChar = [
    0, 0, 32, 51, 64, 75, 83, 90, 96,
    102, 107, 111, 115, 119, 122, 126, 128,
    131, 134, 136, 139, 141, 143, 145, 147,
    149, 151, 153, 154, 156, 158, 159, 160,
    162, 163, 165, 166,
];
JSBI.__kBitsPerCharTableShift = 5;
JSBI.__kBitsPerCharTableMultiplier = 1 << JSBI.__kBitsPerCharTableShift;
JSBI.__kConversionChars = '0123456789abcdefghijklmnopqrstuvwxyz'.split('');
JSBI.__kBitConversionBuffer = new ArrayBuffer(8);
JSBI.__kBitConversionDouble = new Float64Array(JSBI.__kBitConversionBuffer);
JSBI.__kBitConversionInts = new Int32Array(JSBI.__kBitConversionBuffer);
JSBI.__clz30 = Math.clz32 ? function (x) {
    return Math.clz32(x) - 2;
} : function (x) {
    if (x === 0)
        return 30;
    return 29 - (Math.log(x >>> 0) / Math.LN2 | 0) | 0;
};
JSBI.__imul = Math.imul || function (a, b) {
    return (a * b) | 0;
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
	
		let secret = JSBI.BigInt(getRandomInt(9999));
	    let mix = JSBI.remainder(JSBI.exponentiate(JSBI.BigInt(ai[4]), secret), JSBI.BigInt(ai[3]));
	    let shdkey = JSBI.remainder(JSBI.exponentiate(JSBI.BigInt(ai[2]), secret), JSBI.BigInt(ai[3]));

        let key = md5(shdkey.toString()).substring(0, 16);
	
        let xht2 = new XMLHttpRequest();
        xht2.open('GET', dir + '/cert.php?info=' + mscd + '&1=' + mix.toString() + '&2=' + ai[4] + '&3=' + ai[3] + '&4=' + 
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
	
		let secret = JSBI.BigInt(getRandomInt(9999));
	    let mix = JSBI.remainder(JSBI.exponentiate(JSBI.BigInt(ai[4]), secret), JSBI.BigInt(ai[3]));
	    let shdkey = JSBI.remainder(JSBI.exponentiate(JSBI.BigInt(ai[2]), secret), JSBI.BigInt(ai[3]));

        let key = md5(shdkey.toString()).substring(0, 16);
	
        let xht2 = new XMLHttpRequest();
        xht2.open('GET', dir + '/cert.php?info=' + mscd + '&1=' + mix.toString() + '&2=' + ai[4] + '&3=' + ai[3] + '&4=' + 
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
	
		let secret = JSBI.BigInt(getRandomInt(9999));
	    let mix = JSBI.remainder(JSBI.exponentiate(JSBI.BigInt(ai[4]), secret), JSBI.BigInt(ai[3]));
	    let shdkey = JSBI.remainder(JSBI.exponentiate(JSBI.BigInt(ai[2]), secret), JSBI.BigInt(ai[3]));

        let key = md5(shdkey.toString()).substring(0, 16);
	
        let xht2 = new XMLHttpRequest();
        xht2.open('GET', dir + '/cert.php?info=' + mscd + '&1=' + mix.toString() + '&2=' + ai[4] + '&3=' + ai[3] + '&4=' + 
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

            let numr = htrq.response.split('\n', 4);

            let nprime = numr[1];
            let nroot = numr[2];
            let nmix = numr[3];
            let iv = [getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9),
                getRandomInt(9), getRandomInt(9), getRandomInt(9), getRandomInt(9)
            ];
		
            let now = new Date();
            let secret = JSBI.BigInt(getRandomInt(9999));
	    	let mix = JSBI.remainder(JSBI.exponentiate(JSBI.BigInt(nroot), secret), JSBI.BigInt(nprime));
	    	let shdkey = JSBI.remainder(JSBI.exponentiate(JSBI.BigInt(nmix), secret), JSBI.BigInt(nprime));

        	let key = md5(shdkey.toString()).substring(0, 16);

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
                mix.toString() + '&22=' + nprime + '&23=' + JSON.stringify(iv);

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
