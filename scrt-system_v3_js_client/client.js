var config = {
    scrt_system_version: "1.0.0",
    scrt_system_host_address: "https://zetrix-server.ru/scrt-system_v3_host",
    scrt_system_address: "https://zetrix-server.ru/scrt-system_v3",
    keeper: "185.185.69.85"
};

var dbits;

var canary = 0xdeadbeefcafe;
var j_lm = ((canary & 0xffffff) == 0xefcafe);

function BigInteger(a, b, c) {
    if (a != null)
        if ("number" == typeof a) this.fromNumber(a, b, c);
        else if (b == null && "string" != typeof a) this.fromString(a, 256);
    else this.fromString(a, b);
}

function nbi() {
    return new BigInteger(null);
}

function am1(i, x, w, j, c, n) {
    while (--n >= 0) {
        var v = x * this[i++] + w[j] + c;
        c = Math.floor(v / 0x4000000);
        w[j++] = v & 0x3ffffff;
    }
    return c;
}

function am2(i, x, w, j, c, n) {
    var xl = x & 0x7fff,
        xh = x >> 15;
    while (--n >= 0) {
        var l = this[i] & 0x7fff;
        var h = this[i++] >> 15;
        var m = xh * l + h * xl;
        l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
        c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
        w[j++] = l & 0x3fffffff;
    }
    return c;
}

function am3(i, x, w, j, c, n) {
    var xl = x & 0x3fff,
        xh = x >> 14;
    while (--n >= 0) {
        var l = this[i] & 0x3fff;
        var h = this[i++] >> 14;
        var m = xh * l + h * xl;
        l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
        c = (l >> 28) + (m >> 14) + xh * h;
        w[j++] = l & 0xfffffff;
    }
    return c;
}
if (j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
    BigInteger.prototype.am = am2;
    dbits = 30;
} else if (j_lm && (navigator.appName != "Netscape")) {
    BigInteger.prototype.am = am1;
    dbits = 26;
} else {
    BigInteger.prototype.am = am3;
    dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1 << dbits) - 1);
BigInteger.prototype.DV = (1 << dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;

var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr, vv;
rr = "0".charCodeAt(0);
for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) {
    return BI_RM.charAt(n);
}

function intAt(s, i) {
    var c = BI_RC[s.charCodeAt(i)];
    return (c == null) ? -1 : c;
}

function bnpCopyTo(r) {
    for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
    r.t = this.t;
    r.s = this.s;
}

function bnpFromInt(x) {
    this.t = 1;
    this.s = (x < 0) ? -1 : 0;
    if (x > 0) this[0] = x;
    else if (x < -1) this[0] = x + DV;
    else this.t = 0;
}

function nbv(i) {
    var r = nbi();
    r.fromInt(i);
    return r;
}

function bnpFromString(s, b) {
    var k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 256) k = 8;
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else {
        this.fromRadix(s, b);
        return;
    }
    this.t = 0;
    this.s = 0;
    var i = s.length,
        mi = false,
        sh = 0;
    while (--i >= 0) {
        var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
        if (x < 0) {
            if (s.charAt(i) == "-") mi = true;
            continue;
        }
        mi = false;
        if (sh == 0)
            this[this.t++] = x;
        else if (sh + k > this.DB) {
            this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
            this[this.t++] = (x >> (this.DB - sh));
        } else
            this[this.t - 1] |= x << sh;
        sh += k;
        if (sh >= this.DB) sh -= this.DB;
    }
    if (k == 8 && (s[0] & 0x80) != 0) {
        this.s = -1;
        if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
    }
    this.clamp();
    if (mi) BigInteger.ZERO.subTo(this, this);
}

function bnpClamp() {
    var c = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] == c) --this.t;
}

function bnToString(b) {
    if (this.s < 0) return "-" + this.negate().toString(b);
    var k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else return this.toRadix(b);
    var km = (1 << k) - 1,
        d, m = false,
        r = "",
        i = this.t;
    var p = this.DB - (i * this.DB) % k;
    if (i-- > 0) {
        if (p < this.DB && (d = this[i] >> p) > 0) {
            m = true;
            r = int2char(d);
        }
        while (i >= 0) {
            if (p < k) {
                d = (this[i] & ((1 << p) - 1)) << (k - p);
                d |= this[--i] >> (p += this.DB - k);
            } else {
                d = (this[i] >> (p -= k)) & km;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
            }
            if (d > 0) m = true;
            if (m) r += int2char(d);
        }
    }
    return m ? r : "0";
}

function bnNegate() {
    var r = nbi();
    BigInteger.ZERO.subTo(this, r);
    return r;
}

function bnAbs() {
    return (this.s < 0) ? this.negate() : this;
}

function bnCompareTo(a) {
    var r = this.s - a.s;
    if (r != 0) return r;
    var i = this.t;
    r = i - a.t;
    if (r != 0) return (this.s < 0) ? -r : r;
    while (--i >= 0)
        if ((r = this[i] - a[i]) != 0) return r;
    return 0;
}

function nbits(x) {
    var r = 1,
        t;
    if ((t = x >>> 16) != 0) {
        x = t;
        r += 16;
    }
    if ((t = x >> 8) != 0) {
        x = t;
        r += 8;
    }
    if ((t = x >> 4) != 0) {
        x = t;
        r += 4;
    }
    if ((t = x >> 2) != 0) {
        x = t;
        r += 2;
    }
    if ((t = x >> 1) != 0) {
        x = t;
        r += 1;
    }
    return r;
}

function bnBitLength() {
    if (this.t <= 0) return 0;
    return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
}

function bnpDLShiftTo(n, r) {
    var i;
    for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
    for (i = n - 1; i >= 0; --i) r[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
}

function bnpDRShiftTo(n, r) {
    for (var i = n; i < this.t; ++i) r[i - n] = this[i];
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
}

function bnpLShiftTo(n, r) {
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << cbs) - 1;
    var ds = Math.floor(n / this.DB),
        c = (this.s << bs) & this.DM,
        i;
    for (i = this.t - 1; i >= 0; --i) {
        r[i + ds + 1] = (this[i] >> cbs) | c;
        c = (this[i] & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i) r[i] = 0;
    r[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
}

function bnpRShiftTo(n, r) {
    r.s = this.s;
    var ds = Math.floor(n / this.DB);
    if (ds >= this.t) {
        r.t = 0;
        return;
    }
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << bs) - 1;
    r[0] = this[ds] >> bs;
    for (var i = ds + 1; i < this.t; ++i) {
        r[i - ds - 1] |= (this[i] & bm) << cbs;
        r[i - ds] = this[i] >> bs;
    }
    if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
    r.t = this.t - ds;
    r.clamp();
}

function bnpSubTo(a, r) {
    var i = 0,
        c = 0,
        m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] - a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c -= a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    } else {
        c += this.s;
        while (i < a.t) {
            c -= a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c -= a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c < -1) r[i++] = this.DV + c;
    else if (c > 0) r[i++] = c;
    r.t = i;
    r.clamp();
}

function bnpMultiplyTo(a, r) {
    var x = this.abs(),
        y = a.abs();
    var i = x.t;
    r.t = i + y.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
}

function bnpSquareTo(r) {
    var x = this.abs();
    var i = r.t = 2 * x.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
        var c = x.am(i, x[i], r, 2 * i, 0, 1);
        if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
            r[i + x.t] -= x.DV;
            r[i + x.t + 1] = 1;
        }
    }
    if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
}

function bnpDivRemTo(m, q, r) {
    var pm = m.abs();
    if (pm.t <= 0) return;
    var pt = this.abs();
    if (pt.t < pm.t) {
        if (q != null) q.fromInt(0);
        if (r != null) this.copyTo(r);
        return;
    }
    if (r == null) r = nbi();
    var y = nbi(),
        ts = this.s,
        ms = m.s;
    var nsh = this.DB - nbits(pm[pm.t - 1]);
    if (nsh > 0) {
        pm.lShiftTo(nsh, y);
        pt.lShiftTo(nsh, r);
    } else {
        pm.copyTo(y);
        pt.copyTo(r);
    }
    var ys = y.t;
    var y0 = y[ys - 1];
    if (y0 == 0) return;
    var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
    var d1 = this.FV / yt,
        d2 = (1 << this.F1) / yt,
        e = 1 << this.F2;
    var i = r.t,
        j = i - ys,
        t = (q == null) ? nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
        r[r.t++] = 1;
        r.subTo(t, r);
    }
    BigInteger.ONE.dlShiftTo(ys, t);
    t.subTo(y, y);
    while (y.t < ys) y[y.t++] = 0;
    while (--j >= 0) {

        var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
        if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
            y.dlShiftTo(j, t);
            r.subTo(t, r);
            while (r[i] < --qd) r.subTo(t, r);
        }
    }
    if (q != null) {
        r.drShiftTo(ys, q);
        if (ts != ms) BigInteger.ZERO.subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0) r.rShiftTo(nsh, r);
    if (ts < 0) BigInteger.ZERO.subTo(r, r);
}

function bnMod(a) {
    var r = nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
    return r;
}

function Classic(m) {
    this.m = m;
}

function cConvert(x) {
    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
    else return x;
}

function cRevert(x) {
    return x;
}

function cReduce(x) {
    x.divRemTo(this.m, null, x);
}

function cMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

function cSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

function bnpInvDigit() {
    if (this.t < 1) return 0;
    var x = this[0];
    if ((x & 1) == 0) return 0;
    var y = x & 3;
    y = (y * (2 - (x & 0xf) * y)) & 0xf;
    y = (y * (2 - (x & 0xff) * y)) & 0xff;
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;

    y = (y * (2 - x * y % this.DV)) % this.DV;

    return (y > 0) ? this.DV - y : -y;
}

function Montgomery(m) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 0x7fff;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
}

function montConvert(x) {
    var r = nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
    return r;
}

function montRevert(x) {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
}

function montReduce(x) {
    while (x.t <= this.mt2)
        x[x.t++] = 0;
    for (var i = 0; i < this.m.t; ++i) {

        var j = x[i] & 0x7fff;
        var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;

        j = i + this.m.t;
        x[j] += this.m.am(0, u0, x, i, 0, this.m.t);

        while (x[j] >= x.DV) {
            x[j] -= x.DV;
            x[++j]++;
        }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

function montSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

function montMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

function bnpIsEven() {
    return ((this.t > 0) ? (this[0] & 1) : this.s) == 0;
}

function bnpExp(e, z) {
    if (e > 0xffffffff || e < 1) return BigInteger.ONE;
    var r = nbi(),
        r2 = nbi(),
        g = z.convert(this),
        i = nbits(e) - 1;
    g.copyTo(r);
    while (--i >= 0) {
        z.sqrTo(r, r2);
        if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
        else {
            var t = r;
            r = r2;
            r2 = t;
        }
    }
    return z.revert(r);
}

function bnModPowInt(e, m) {
    var z;
    if (e < 256 || m.isEven()) z = new Classic(m);
    else z = new Montgomery(m);
    return this.exp(e, z);
}

BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

function Arcfour() {
    this.i = 0;
    this.j = 0;
    this.S = new Array();
}

function ARC4init(key) {
    var i, j, t;
    for (i = 0; i < 256; ++i)
        this.S[i] = i;
    j = 0;
    for (i = 0; i < 256; ++i) {
        j = (j + this.S[i] + key[i % key.length]) & 255;
        t = this.S[i];
        this.S[i] = this.S[j];
        this.S[j] = t;
    }
    this.i = 0;
    this.j = 0;
}

function ARC4next() {
    var t;
    this.i = (this.i + 1) & 255;
    this.j = (this.j + this.S[this.i]) & 255;
    t = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = t;
    return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

function prng_newstate() {
    return new Arcfour();
}

var rng_psize = 256;

var rng_state;
var rng_pool;
var rng_pptr;

function rng_seed_int(x) {
    rng_pool[rng_pptr++] ^= x & 255;
    rng_pool[rng_pptr++] ^= (x >> 8) & 255;
    rng_pool[rng_pptr++] ^= (x >> 16) & 255;
    rng_pool[rng_pptr++] ^= (x >> 24) & 255;
    if (rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

function rng_seed_time() {
    rng_seed_int(new Date().getTime());
}

if (rng_pool == null) {
    rng_pool = new Array();
    rng_pptr = 0;
    var t;
    if (window.crypto && window.crypto.getRandomValues) {

        var ua = new Uint8Array(32);
        window.crypto.getRandomValues(ua);
        for (t = 0; t < 32; ++t)
            rng_pool[rng_pptr++] = ua[t];
    }
    if (navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {

        var z = window.crypto.random(32);
        for (t = 0; t < z.length; ++t)
            rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
    }
    while (rng_pptr < rng_psize) {
        t = Math.floor(65536 * Math.random());
        rng_pool[rng_pptr++] = t >>> 8;
        rng_pool[rng_pptr++] = t & 255;
    }
    rng_pptr = 0;
    rng_seed_time();

}

function rng_get_byte() {
    if (rng_state == null) {
        rng_seed_time();
        rng_state = prng_newstate();
        rng_state.init(rng_pool);
        for (rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
            rng_pool[rng_pptr] = 0;
        rng_pptr = 0;

    }

    return rng_state.next();
}

function rng_get_bytes(ba) {
    var i;
    for (i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;

function parseBigInt(str, r) {
    return new BigInteger(str, r);
}

function linebrk(s, n) {
    var ret = "";
    var i = 0;
    while (i + n < s.length) {
        ret += s.substring(i, i + n) + "\n";
        i += n;
    }
    return ret + s.substring(i, s.length);
}

function byte2Hex(b) {
    if (b < 0x10)
        return "0" + b.toString(16);
    else
        return b.toString(16);
}

function pkcs1pad2(s, n) {
    if (n < s.length + 11) {
        alert("Message too long for RSA");
        return null;
    }
    var ba = new Array();
    var i = s.length - 1;
    while (i >= 0 && n > 0) {
        var c = s.charCodeAt(i--);
        if (c < 128) {
            ba[--n] = c;
        } else if ((c > 127) && (c < 2048)) {
            ba[--n] = (c & 63) | 128;
            ba[--n] = (c >> 6) | 192;
        } else {
            ba[--n] = (c & 63) | 128;
            ba[--n] = ((c >> 6) & 63) | 128;
            ba[--n] = (c >> 12) | 224;
        }
    }
    ba[--n] = 0;
    var rng = new SecureRandom();
    var x = new Array();
    while (n > 2) {
        x[0] = 0;
        while (x[0] == 0) rng.nextBytes(x);
        ba[--n] = x[0];
    }
    ba[--n] = 2;
    ba[--n] = 0;
    return new BigInteger(ba);
}

function RSAKey() {
    this.n = null;
    this.e = 0;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null;
}

function RSASetPublic(N, E) {
    if (N != null && E != null && N.length > 0 && E.length > 0) {
        this.n = parseBigInt(N, 16);
        this.e = parseInt(E, 16);
    } else
        alert("Invalid RSA public key");
}

function RSADoPublic(x) {
    return x.modPowInt(this.e, this.n);
}

function RSAEncrypt(text) {
    var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
    if (m == null) return null;
    var c = this.doPublic(m);
    if (c == null) return null;
    var h = c.toString(16);
    if ((h.length & 1) == 0) return h;
    else return "0" + h;
}

RSAKey.prototype.doPublic = RSADoPublic;

RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;

(function e(t, n, r) {
    function s(o, u) {
        if (!n[o]) {
            if (!t[o]) {
                var a = typeof require == "function" && require;
                if (!u && a) return a(o, !0);
                if (i) return i(o, !0);
                var f = new Error("Cannot find module '" + o + "'");
                throw f.code = "MODULE_NOT_FOUND", f
            }
            var l = n[o] = {
                exports: {}
            };
            t[o][0].call(l.exports, function(e) {
                var n = t[o][1][e];
                return s(n ? n : e)
            }, l, l.exports, e, t, n, r)
        }
        return n[o].exports
    }
    var i = typeof require == "function" && require;
    for (var o = 0; o < r.length; o++) s(r[o]);
    return s
})({
    1: [function(require, module, exports) {

        'use strict';

        var CryptoJS = require('node-cryptojs-aes').CryptoJS;

        var OpenSslFormatter = {
            stringify(params) {
                var salt = CryptoJS.enc.Hex.parse(params.salt.toString()).toString(CryptoJS.enc.Latin1);
                var ct = params.ciphertext.toString(CryptoJS.enc.Latin1);

                return CryptoJS.enc.Latin1.parse('Salted__' + salt + ct).toString(CryptoJS.enc.Base64);
            },

            parse(str) {
                var str = CryptoJS.enc.Base64.parse(str).toString(CryptoJS.enc.Latin1);
                var salted = str.substr(0, 8);

                if (salted !== 'Salted__') {
                    throw new Error('Error parsing salt');
                }

                var salt = str.substr(8, 8);
                var ct = str.substr(16);

                return CryptoJS.lib.CipherParams.create({
                    ciphertext: CryptoJS.enc.Latin1.parse(ct),
                    salt: CryptoJS.enc.Latin1.parse(salt)
                });
            }
        };

        var AES256 = {
            encrypt: function(input, passphrase) {
                return CryptoJS.AES.encrypt(input, passphrase, {
                    format: OpenSslFormatter
                }).toString();
            },

            decrypt: function(crypted, passphrase) {
                return CryptoJS.AES.decrypt(crypted, passphrase, {
                    format: OpenSslFormatter
                }).toString(CryptoJS.enc.Utf8);
            }
        };

        module.exports = AES256;
        if (window) window.AES256 = AES256;

    }, {
        "node-cryptojs-aes": 2
    }],
    2: [function(require, module, exports) {
        var CryptoJS = require('./lib/core').CryptoJS;
        require('./lib/enc-base64');
        require('./lib/md5');
        require('./lib/evpkdf');
        require('./lib/cipher-core');
        require('./lib/aes');
        var JsonFormatter = require('./lib/jsonformatter').JsonFormatter;

        exports.CryptoJS = CryptoJS;
        exports.JsonFormatter = JsonFormatter;
    }, {
        "./lib/aes": 3,
        "./lib/cipher-core": 4,
        "./lib/core": 5,
        "./lib/enc-base64": 6,
        "./lib/evpkdf": 7,
        "./lib/jsonformatter": 8,
        "./lib/md5": 9
    }],
    3: [function(require, module, exports) {
        var CryptoJS = require('./core').CryptoJS;

        (function() {

            var C = CryptoJS;
            var C_lib = C.lib;
            var BlockCipher = C_lib.BlockCipher;
            var C_algo = C.algo;

            var SBOX = [];
            var INV_SBOX = [];
            var SUB_MIX_0 = [];
            var SUB_MIX_1 = [];
            var SUB_MIX_2 = [];
            var SUB_MIX_3 = [];
            var INV_SUB_MIX_0 = [];
            var INV_SUB_MIX_1 = [];
            var INV_SUB_MIX_2 = [];
            var INV_SUB_MIX_3 = [];

            (function() {

                var d = [];
                for (var i = 0; i < 256; i++) {
                    if (i < 128) {
                        d[i] = i << 1;
                    } else {
                        d[i] = (i << 1) ^ 0x11b;
                    }
                }

                var x = 0;
                var xi = 0;
                for (var i = 0; i < 256; i++) {

                    var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
                    sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
                    SBOX[x] = sx;
                    INV_SBOX[sx] = x;

                    var x2 = d[x];
                    var x4 = d[x2];
                    var x8 = d[x4];

                    var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
                    SUB_MIX_0[x] = (t << 24) | (t >>> 8);
                    SUB_MIX_1[x] = (t << 16) | (t >>> 16);
                    SUB_MIX_2[x] = (t << 8) | (t >>> 24);
                    SUB_MIX_3[x] = t;

                    var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
                    INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
                    INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
                    INV_SUB_MIX_2[sx] = (t << 8) | (t >>> 24);
                    INV_SUB_MIX_3[sx] = t;

                    if (!x) {
                        x = xi = 1;
                    } else {
                        x = x2 ^ d[d[d[x8 ^ x2]]];
                        xi ^= d[d[xi]];
                    }
                }
            }());

            var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

            var AES = C_algo.AES = BlockCipher.extend({
                _doReset: function() {

                    var key = this._key;
                    var keyWords = key.words;
                    var keySize = key.sigBytes / 4;

                    var nRounds = this._nRounds = keySize + 6

                    var ksRows = (nRounds + 1) * 4;

                    var keySchedule = this._keySchedule = [];
                    for (var ksRow = 0; ksRow < ksRows; ksRow++) {
                        if (ksRow < keySize) {
                            keySchedule[ksRow] = keyWords[ksRow];
                        } else {
                            var t = keySchedule[ksRow - 1];

                            if (!(ksRow % keySize)) {

                                t = (t << 8) | (t >>> 24);

                                t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

                                t ^= RCON[(ksRow / keySize) | 0] << 24;
                            } else if (keySize > 6 && ksRow % keySize == 4) {

                                t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
                            }

                            keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
                        }
                    }

                    var invKeySchedule = this._invKeySchedule = [];
                    for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
                        var ksRow = ksRows - invKsRow;

                        if (invKsRow % 4) {
                            var t = keySchedule[ksRow];
                        } else {
                            var t = keySchedule[ksRow - 4];
                        }

                        if (invKsRow < 4 || ksRow <= 4) {
                            invKeySchedule[invKsRow] = t;
                        } else {
                            invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
                                INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
                        }
                    }
                },

                encryptBlock: function(M, offset) {
                    this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
                },

                decryptBlock: function(M, offset) {

                    var t = M[offset + 1];
                    M[offset + 1] = M[offset + 3];
                    M[offset + 3] = t;

                    this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

                    var t = M[offset + 1];
                    M[offset + 1] = M[offset + 3];
                    M[offset + 3] = t;
                },

                _doCryptBlock: function(M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {

                    var nRounds = this._nRounds;

                    var s0 = M[offset] ^ keySchedule[0];
                    var s1 = M[offset + 1] ^ keySchedule[1];
                    var s2 = M[offset + 2] ^ keySchedule[2];
                    var s3 = M[offset + 3] ^ keySchedule[3];

                    var ksRow = 4;

                    for (var round = 1; round < nRounds; round++) {

                        var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
                        var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
                        var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
                        var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

                        s0 = t0;
                        s1 = t1;
                        s2 = t2;
                        s3 = t3;
                    }

                    var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
                    var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
                    var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
                    var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

                    M[offset] = t0;
                    M[offset + 1] = t1;
                    M[offset + 2] = t2;
                    M[offset + 3] = t3;
                },

                keySize: 256 / 32
            });

            C.AES = BlockCipher._createHelper(AES);
        }());

    }, {
        "./core": 5
    }],
    4: [function(require, module, exports) {
        var CryptoJS = require('./core').CryptoJS;

        CryptoJS.lib.Cipher || (function(undefined) {

            var C = CryptoJS;
            var C_lib = C.lib;
            var Base = C_lib.Base;
            var WordArray = C_lib.WordArray;
            var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
            var C_enc = C.enc;
            var Utf8 = C_enc.Utf8;
            var Base64 = C_enc.Base64;
            var C_algo = C.algo;
            var EvpKDF = C_algo.EvpKDF;

            var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({

                cfg: Base.extend(),

                createEncryptor: function(key, cfg) {
                    return this.create(this._ENC_XFORM_MODE, key, cfg);
                },

                createDecryptor: function(key, cfg) {
                    return this.create(this._DEC_XFORM_MODE, key, cfg);
                },

                init: function(xformMode, key, cfg) {

                    this.cfg = this.cfg.extend(cfg);

                    this._xformMode = xformMode;
                    this._key = key;

                    this.reset();
                },

                reset: function() {

                    BufferedBlockAlgorithm.reset.call(this);

                    this._doReset();
                },

                process: function(dataUpdate) {

                    this._append(dataUpdate);

                    return this._process();
                },

                finalize: function(dataUpdate) {

                    if (dataUpdate) {
                        this._append(dataUpdate);
                    }

                    var finalProcessedData = this._doFinalize();

                    return finalProcessedData;
                },

                keySize: 128 / 32,

                ivSize: 128 / 32,

                _ENC_XFORM_MODE: 1,

                _DEC_XFORM_MODE: 2,

                _createHelper: (function() {
                    function selectCipherStrategy(key) {
                        if (typeof key == 'string') {
                            return PasswordBasedCipher;
                        } else {
                            return SerializableCipher;
                        }
                    }

                    return function(cipher) {
                        return {
                            encrypt: function(message, key, cfg) {
                                return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
                            },

                            decrypt: function(ciphertext, key, cfg) {
                                return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
                            }
                        };
                    };
                }())
            });

            var StreamCipher = C_lib.StreamCipher = Cipher.extend({
                _doFinalize: function() {

                    var finalProcessedBlocks = this._process(!!'flush');

                    return finalProcessedBlocks;
                },

                blockSize: 1
            });

            var C_mode = C.mode = {};

            var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({

                createEncryptor: function(cipher, iv) {
                    return this.Encryptor.create(cipher, iv);
                },

                createDecryptor: function(cipher, iv) {
                    return this.Decryptor.create(cipher, iv);
                },

                init: function(cipher, iv) {
                    this._cipher = cipher;
                    this._iv = iv;
                }
            });

            var CBC = C_mode.CBC = (function() {

                var CBC = BlockCipherMode.extend();

                CBC.Encryptor = CBC.extend({

                    processBlock: function(words, offset) {

                        var cipher = this._cipher;
                        var blockSize = cipher.blockSize;

                        xorBlock.call(this, words, offset, blockSize);
                        cipher.encryptBlock(words, offset);

                        this._prevBlock = words.slice(offset, offset + blockSize);
                    }
                });

                CBC.Decryptor = CBC.extend({

                    processBlock: function(words, offset) {

                        var cipher = this._cipher;
                        var blockSize = cipher.blockSize;

                        var thisBlock = words.slice(offset, offset + blockSize);

                        cipher.decryptBlock(words, offset);
                        xorBlock.call(this, words, offset, blockSize);

                        this._prevBlock = thisBlock;
                    }
                });

                function xorBlock(words, offset, blockSize) {

                    var iv = this._iv;

                    if (iv) {
                        var block = iv;

                        this._iv = undefined;
                    } else {
                        var block = this._prevBlock;
                    }

                    for (var i = 0; i < blockSize; i++) {
                        words[offset + i] ^= block[i];
                    }
                }

                return CBC;
            }());

            var C_pad = C.pad = {};

            var Pkcs7 = C_pad.Pkcs7 = {

                pad: function(data, blockSize) {

                    var blockSizeBytes = blockSize * 4;

                    var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

                    var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

                    var paddingWords = [];
                    for (var i = 0; i < nPaddingBytes; i += 4) {
                        paddingWords.push(paddingWord);
                    }
                    var padding = WordArray.create(paddingWords, nPaddingBytes);

                    data.concat(padding);
                },

                unpad: function(data) {

                    var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

                    data.sigBytes -= nPaddingBytes;
                }
            };

            var BlockCipher = C_lib.BlockCipher = Cipher.extend({

                cfg: Cipher.cfg.extend({
                    mode: CBC,
                    padding: Pkcs7
                }),

                reset: function() {

                    Cipher.reset.call(this);

                    var cfg = this.cfg;
                    var iv = cfg.iv;
                    var mode = cfg.mode;

                    if (this._xformMode == this._ENC_XFORM_MODE) {
                        var modeCreator = mode.createEncryptor;
                    } else {
                        var modeCreator = mode.createDecryptor;

                        this._minBufferSize = 1;
                    }
                    this._mode = modeCreator.call(mode, this, iv && iv.words);
                },

                _doProcessBlock: function(words, offset) {
                    this._mode.processBlock(words, offset);
                },

                _doFinalize: function() {

                    var padding = this.cfg.padding;

                    if (this._xformMode == this._ENC_XFORM_MODE) {

                        padding.pad(this._data, this.blockSize);

                        var finalProcessedBlocks = this._process(!!'flush');
                    } else {

                        var finalProcessedBlocks = this._process(!!'flush');

                        padding.unpad(finalProcessedBlocks);
                    }

                    return finalProcessedBlocks;
                },

                blockSize: 128 / 32
            });

            var CipherParams = C_lib.CipherParams = Base.extend({

                init: function(cipherParams) {
                    this.mixIn(cipherParams);
                },

                toString: function(formatter) {
                    return (formatter || this.formatter).stringify(this);
                }
            });

            var C_format = C.format = {};

            var OpenSSLFormatter = C_format.OpenSSL = {

                stringify: function(cipherParams) {

                    var ciphertext = cipherParams.ciphertext;
                    var salt = cipherParams.salt;

                    if (salt) {
                        var wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
                    } else {
                        var wordArray = ciphertext;
                    }

                    return wordArray.toString(Base64);
                },

                parse: function(openSSLStr) {

                    var ciphertext = Base64.parse(openSSLStr);

                    var ciphertextWords = ciphertext.words;

                    if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {

                        var salt = WordArray.create(ciphertextWords.slice(2, 4));

                        ciphertextWords.splice(0, 4);
                        ciphertext.sigBytes -= 16;
                    }

                    return CipherParams.create({
                        ciphertext: ciphertext,
                        salt: salt
                    });
                }
            };

            var SerializableCipher = C_lib.SerializableCipher = Base.extend({

                cfg: Base.extend({
                    format: OpenSSLFormatter
                }),

                encrypt: function(cipher, message, key, cfg) {

                    cfg = this.cfg.extend(cfg);

                    var encryptor = cipher.createEncryptor(key, cfg);
                    var ciphertext = encryptor.finalize(message);

                    var cipherCfg = encryptor.cfg;

                    return CipherParams.create({
                        ciphertext: ciphertext,
                        key: key,
                        iv: cipherCfg.iv,
                        algorithm: cipher,
                        mode: cipherCfg.mode,
                        padding: cipherCfg.padding,
                        blockSize: cipher.blockSize,
                        formatter: cfg.format
                    });
                },

                decrypt: function(cipher, ciphertext, key, cfg) {

                    cfg = this.cfg.extend(cfg);

                    ciphertext = this._parse(ciphertext, cfg.format);

                    var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

                    return plaintext;
                },

                _parse: function(ciphertext, format) {
                    if (typeof ciphertext == 'string') {
                        return format.parse(ciphertext, this);
                    } else {
                        return ciphertext;
                    }
                }
            });

            var C_kdf = C.kdf = {};

            var OpenSSLKdf = C_kdf.OpenSSL = {

                execute: function(password, keySize, ivSize, salt) {

                    if (!salt) {
                        salt = WordArray.random(64 / 8);
                    }

                    var key = EvpKDF.create({
                        keySize: keySize + ivSize
                    }).compute(password, salt);

                    var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
                    key.sigBytes = keySize * 4;

                    return CipherParams.create({
                        key: key,
                        iv: iv,
                        salt: salt
                    });
                }
            };

            var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({

                cfg: SerializableCipher.cfg.extend({
                    kdf: OpenSSLKdf
                }),

                encrypt: function(cipher, message, password, cfg) {

                    cfg = this.cfg.extend(cfg);

                    var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

                    cfg.iv = derivedParams.iv;

                    var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

                    ciphertext.mixIn(derivedParams);

                    return ciphertext;
                },

                decrypt: function(cipher, ciphertext, password, cfg) {

                    cfg = this.cfg.extend(cfg);

                    ciphertext = this._parse(ciphertext, cfg.format);

                    var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

                    cfg.iv = derivedParams.iv;

                    var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

                    return plaintext;
                }
            });
        }());

    }, {
        "./core": 5
    }],
    5: [function(require, module, exports) {

        var CryptoJS = CryptoJS || (function(Math, undefined) {

            var C = {};

            var C_lib = C.lib = {};

            var Base = C_lib.Base = (function() {
                function F() {}

                return {

                    extend: function(overrides) {

                        F.prototype = this;
                        var subtype = new F();

                        if (overrides) {
                            subtype.mixIn(overrides);
                        }

                        if (!subtype.hasOwnProperty('init')) {
                            subtype.init = function() {
                                subtype.$super.init.apply(this, arguments);
                            };
                        }

                        subtype.init.prototype = subtype;

                        subtype.$super = this;

                        return subtype;
                    },

                    create: function() {
                        var instance = this.extend();
                        instance.init.apply(instance, arguments);

                        return instance;
                    },

                    init: function() {},

                    mixIn: function(properties) {
                        for (var propertyName in properties) {
                            if (properties.hasOwnProperty(propertyName)) {
                                this[propertyName] = properties[propertyName];
                            }
                        }

                        if (properties.hasOwnProperty('toString')) {
                            this.toString = properties.toString;
                        }
                    },

                    clone: function() {
                        return this.init.prototype.extend(this);
                    }
                };
            }());

            var WordArray = C_lib.WordArray = Base.extend({

                init: function(words, sigBytes) {
                    words = this.words = words || [];

                    if (sigBytes != undefined) {
                        this.sigBytes = sigBytes;
                    } else {
                        this.sigBytes = words.length * 4;
                    }
                },

                toString: function(encoder) {
                    return (encoder || Hex).stringify(this);
                },

                concat: function(wordArray) {

                    var thisWords = this.words;
                    var thatWords = wordArray.words;
                    var thisSigBytes = this.sigBytes;
                    var thatSigBytes = wordArray.sigBytes;

                    this.clamp();

                    if (thisSigBytes % 4) {

                        for (var i = 0; i < thatSigBytes; i++) {
                            var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                            thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
                        }
                    } else if (thatWords.length > 0xffff) {

                        for (var i = 0; i < thatSigBytes; i += 4) {
                            thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
                        }
                    } else {

                        thisWords.push.apply(thisWords, thatWords);
                    }
                    this.sigBytes += thatSigBytes;

                    return this;
                },

                clamp: function() {

                    var words = this.words;
                    var sigBytes = this.sigBytes;

                    words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
                    words.length = Math.ceil(sigBytes / 4);
                },

                clone: function() {
                    var clone = Base.clone.call(this);
                    clone.words = this.words.slice(0);

                    return clone;
                },

                random: function(nBytes) {
                    var words = [];
                    for (var i = 0; i < nBytes; i += 4) {
                        words.push((Math.random() * 0x100000000) | 0);
                    }

                    return new WordArray.init(words, nBytes);
                }
            });

            var C_enc = C.enc = {};

            var Hex = C_enc.Hex = {

                stringify: function(wordArray) {

                    var words = wordArray.words;
                    var sigBytes = wordArray.sigBytes;

                    var hexChars = [];
                    for (var i = 0; i < sigBytes; i++) {
                        var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                        hexChars.push((bite >>> 4).toString(16));
                        hexChars.push((bite & 0x0f).toString(16));
                    }

                    return hexChars.join('');
                },

                parse: function(hexStr) {

                    var hexStrLength = hexStr.length;

                    var words = [];
                    for (var i = 0; i < hexStrLength; i += 2) {
                        words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
                    }

                    return new WordArray.init(words, hexStrLength / 2);
                }
            };

            var Latin1 = C_enc.Latin1 = {

                stringify: function(wordArray) {

                    var words = wordArray.words;
                    var sigBytes = wordArray.sigBytes;

                    var latin1Chars = [];
                    for (var i = 0; i < sigBytes; i++) {
                        var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                        latin1Chars.push(String.fromCharCode(bite));
                    }

                    return latin1Chars.join('');
                },

                parse: function(latin1Str) {

                    var latin1StrLength = latin1Str.length;

                    var words = [];
                    for (var i = 0; i < latin1StrLength; i++) {
                        words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
                    }

                    return new WordArray.init(words, latin1StrLength);
                }
            };

            var Utf8 = C_enc.Utf8 = {

                stringify: function(wordArray) {
                    try {
                        return decodeURIComponent(escape(Latin1.stringify(wordArray)));
                    } catch (e) {
                        throw new Error('Malformed UTF-8 data');
                    }
                },

                parse: function(utf8Str) {
                    return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
                }
            };

            var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({

                reset: function() {

                    this._data = new WordArray.init();
                    this._nDataBytes = 0;
                },

                _append: function(data) {

                    if (typeof data == 'string') {
                        data = Utf8.parse(data);
                    }

                    this._data.concat(data);
                    this._nDataBytes += data.sigBytes;
                },

                _process: function(doFlush) {

                    var data = this._data;
                    var dataWords = data.words;
                    var dataSigBytes = data.sigBytes;
                    var blockSize = this.blockSize;
                    var blockSizeBytes = blockSize * 4;

                    var nBlocksReady = dataSigBytes / blockSizeBytes;
                    if (doFlush) {

                        nBlocksReady = Math.ceil(nBlocksReady);
                    } else {

                        nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
                    }

                    var nWordsReady = nBlocksReady * blockSize;

                    var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

                    if (nWordsReady) {
                        for (var offset = 0; offset < nWordsReady; offset += blockSize) {

                            this._doProcessBlock(dataWords, offset);
                        }

                        var processedWords = dataWords.splice(0, nWordsReady);
                        data.sigBytes -= nBytesReady;
                    }

                    return new WordArray.init(processedWords, nBytesReady);
                },

                clone: function() {
                    var clone = Base.clone.call(this);
                    clone._data = this._data.clone();

                    return clone;
                },

                _minBufferSize: 0
            });

            var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({

                cfg: Base.extend(),

                init: function(cfg) {

                    this.cfg = this.cfg.extend(cfg);

                    this.reset();
                },

                reset: function() {

                    BufferedBlockAlgorithm.reset.call(this);

                    this._doReset();
                },

                update: function(messageUpdate) {

                    this._append(messageUpdate);

                    this._process();

                    return this;
                },

                finalize: function(messageUpdate) {

                    if (messageUpdate) {
                        this._append(messageUpdate);
                    }

                    var hash = this._doFinalize();

                    return hash;
                },

                blockSize: 512 / 32,

                _createHelper: function(hasher) {
                    return function(message, cfg) {
                        return new hasher.init(cfg).finalize(message);
                    };
                },

                _createHmacHelper: function(hasher) {
                    return function(message, key) {
                        return new C_algo.HMAC.init(hasher, key).finalize(message);
                    };
                }
            });

            var C_algo = C.algo = {};

            return C;
        }(Math));

        exports.CryptoJS = CryptoJS;

    }, {}],
    6: [function(require, module, exports) {
        var CryptoJS = require('./core').CryptoJS;

        (function() {

            var C = CryptoJS;
            var C_lib = C.lib;
            var WordArray = C_lib.WordArray;
            var C_enc = C.enc;

            var Base64 = C_enc.Base64 = {

                stringify: function(wordArray) {

                    var words = wordArray.words;
                    var sigBytes = wordArray.sigBytes;
                    var map = this._map;

                    wordArray.clamp();

                    var base64Chars = [];
                    for (var i = 0; i < sigBytes; i += 3) {
                        var byte1 = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
                        var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
                        var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

                        var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

                        for (var j = 0;
                            (j < 4) && (i + j * 0.75 < sigBytes); j++) {
                            base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
                        }
                    }

                    var paddingChar = map.charAt(64);
                    if (paddingChar) {
                        while (base64Chars.length % 4) {
                            base64Chars.push(paddingChar);
                        }
                    }

                    return base64Chars.join('');
                },

                parse: function(base64Str) {

                    var base64StrLength = base64Str.length;
                    var map = this._map;

                    var paddingChar = map.charAt(64);
                    if (paddingChar) {
                        var paddingIndex = base64Str.indexOf(paddingChar);
                        if (paddingIndex != -1) {
                            base64StrLength = paddingIndex;
                        }
                    }

                    var words = [];
                    var nBytes = 0;
                    for (var i = 0; i < base64StrLength; i++) {
                        if (i % 4) {
                            var bits1 = map.indexOf(base64Str.charAt(i - 1)) << ((i % 4) * 2);
                            var bits2 = map.indexOf(base64Str.charAt(i)) >>> (6 - (i % 4) * 2);
                            words[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
                            nBytes++;
                        }
                    }

                    return WordArray.create(words, nBytes);
                },

                _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
            };
        }());

    }, {
        "./core": 5
    }],
    7: [function(require, module, exports) {
        var CryptoJS = require('./core').CryptoJS;

        (function() {

            var C = CryptoJS;
            var C_lib = C.lib;
            var Base = C_lib.Base;
            var WordArray = C_lib.WordArray;
            var C_algo = C.algo;
            var MD5 = C_algo.MD5;

            var EvpKDF = C_algo.EvpKDF = Base.extend({

                cfg: Base.extend({
                    keySize: 128 / 32,
                    hasher: MD5,
                    iterations: 1
                }),

                init: function(cfg) {
                    this.cfg = this.cfg.extend(cfg);
                },

                compute: function(password, salt) {

                    var cfg = this.cfg;

                    var hasher = cfg.hasher.create();

                    var derivedKey = WordArray.create();

                    var derivedKeyWords = derivedKey.words;
                    var keySize = cfg.keySize;
                    var iterations = cfg.iterations;

                    while (derivedKeyWords.length < keySize) {
                        if (block) {
                            hasher.update(block);
                        }
                        var block = hasher.update(password).finalize(salt);
                        hasher.reset();

                        for (var i = 1; i < iterations; i++) {
                            block = hasher.finalize(block);
                            hasher.reset();
                        }

                        derivedKey.concat(block);
                    }
                    derivedKey.sigBytes = keySize * 4;

                    return derivedKey;
                }
            });

            C.EvpKDF = function(password, salt, cfg) {
                return EvpKDF.create(cfg).compute(password, salt);
            };
        }());

    }, {
        "./core": 5
    }],
    8: [function(require, module, exports) {
        var CryptoJS = require('./core').CryptoJS;

        var JsonFormatter = {
            stringify: function(cipherParams) {

                var jsonObj = {
                    ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64)
                };

                if (cipherParams.iv) {
                    jsonObj.iv = cipherParams.iv.toString();
                }

                if (cipherParams.salt) {
                    jsonObj.s = cipherParams.salt.toString();
                }

                return JSON.stringify(jsonObj)
            },

            parse: function(jsonStr) {

                var jsonObj = JSON.parse(jsonStr);

                var cipherParams = CryptoJS.lib.CipherParams.create({
                    ciphertext: CryptoJS.enc.Base64.parse(jsonObj.ct)
                });

                if (jsonObj.iv) {
                    cipherParams.iv = CryptoJS.enc.Hex.parse(jsonObj.iv);
                }

                if (jsonObj.s) {
                    cipherParams.salt = CryptoJS.enc.Hex.parse(jsonObj.s);
                }

                return cipherParams;
            }
        };

        exports.JsonFormatter = JsonFormatter;
    }, {
        "./core": 5
    }],
    9: [function(require, module, exports) {
        var CryptoJS = require('./core').CryptoJS;

        (function(Math) {

            var C = CryptoJS;
            var C_lib = C.lib;
            var WordArray = C_lib.WordArray;
            var Hasher = C_lib.Hasher;
            var C_algo = C.algo;

            var T = [];

            (function() {
                for (var i = 0; i < 64; i++) {
                    T[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
                }
            }());

            var MD5 = C_algo.MD5 = Hasher.extend({
                _doReset: function() {
                    this._hash = new WordArray.init([
                        0x67452301, 0xefcdab89,
                        0x98badcfe, 0x10325476
                    ]);
                },

                _doProcessBlock: function(M, offset) {

                    for (var i = 0; i < 16; i++) {

                        var offset_i = offset + i;
                        var M_offset_i = M[offset_i];

                        M[offset_i] = (
                            (((M_offset_i << 8) | (M_offset_i >>> 24)) & 0x00ff00ff) |
                            (((M_offset_i << 24) | (M_offset_i >>> 8)) & 0xff00ff00)
                        );
                    }

                    var H = this._hash.words;

                    var M_offset_0 = M[offset + 0];
                    var M_offset_1 = M[offset + 1];
                    var M_offset_2 = M[offset + 2];
                    var M_offset_3 = M[offset + 3];
                    var M_offset_4 = M[offset + 4];
                    var M_offset_5 = M[offset + 5];
                    var M_offset_6 = M[offset + 6];
                    var M_offset_7 = M[offset + 7];
                    var M_offset_8 = M[offset + 8];
                    var M_offset_9 = M[offset + 9];
                    var M_offset_10 = M[offset + 10];
                    var M_offset_11 = M[offset + 11];
                    var M_offset_12 = M[offset + 12];
                    var M_offset_13 = M[offset + 13];
                    var M_offset_14 = M[offset + 14];
                    var M_offset_15 = M[offset + 15];

                    var a = H[0];
                    var b = H[1];
                    var c = H[2];
                    var d = H[3];

                    a = FF(a, b, c, d, M_offset_0, 7, T[0]);
                    d = FF(d, a, b, c, M_offset_1, 12, T[1]);
                    c = FF(c, d, a, b, M_offset_2, 17, T[2]);
                    b = FF(b, c, d, a, M_offset_3, 22, T[3]);
                    a = FF(a, b, c, d, M_offset_4, 7, T[4]);
                    d = FF(d, a, b, c, M_offset_5, 12, T[5]);
                    c = FF(c, d, a, b, M_offset_6, 17, T[6]);
                    b = FF(b, c, d, a, M_offset_7, 22, T[7]);
                    a = FF(a, b, c, d, M_offset_8, 7, T[8]);
                    d = FF(d, a, b, c, M_offset_9, 12, T[9]);
                    c = FF(c, d, a, b, M_offset_10, 17, T[10]);
                    b = FF(b, c, d, a, M_offset_11, 22, T[11]);
                    a = FF(a, b, c, d, M_offset_12, 7, T[12]);
                    d = FF(d, a, b, c, M_offset_13, 12, T[13]);
                    c = FF(c, d, a, b, M_offset_14, 17, T[14]);
                    b = FF(b, c, d, a, M_offset_15, 22, T[15]);

                    a = GG(a, b, c, d, M_offset_1, 5, T[16]);
                    d = GG(d, a, b, c, M_offset_6, 9, T[17]);
                    c = GG(c, d, a, b, M_offset_11, 14, T[18]);
                    b = GG(b, c, d, a, M_offset_0, 20, T[19]);
                    a = GG(a, b, c, d, M_offset_5, 5, T[20]);
                    d = GG(d, a, b, c, M_offset_10, 9, T[21]);
                    c = GG(c, d, a, b, M_offset_15, 14, T[22]);
                    b = GG(b, c, d, a, M_offset_4, 20, T[23]);
                    a = GG(a, b, c, d, M_offset_9, 5, T[24]);
                    d = GG(d, a, b, c, M_offset_14, 9, T[25]);
                    c = GG(c, d, a, b, M_offset_3, 14, T[26]);
                    b = GG(b, c, d, a, M_offset_8, 20, T[27]);
                    a = GG(a, b, c, d, M_offset_13, 5, T[28]);
                    d = GG(d, a, b, c, M_offset_2, 9, T[29]);
                    c = GG(c, d, a, b, M_offset_7, 14, T[30]);
                    b = GG(b, c, d, a, M_offset_12, 20, T[31]);

                    a = HH(a, b, c, d, M_offset_5, 4, T[32]);
                    d = HH(d, a, b, c, M_offset_8, 11, T[33]);
                    c = HH(c, d, a, b, M_offset_11, 16, T[34]);
                    b = HH(b, c, d, a, M_offset_14, 23, T[35]);
                    a = HH(a, b, c, d, M_offset_1, 4, T[36]);
                    d = HH(d, a, b, c, M_offset_4, 11, T[37]);
                    c = HH(c, d, a, b, M_offset_7, 16, T[38]);
                    b = HH(b, c, d, a, M_offset_10, 23, T[39]);
                    a = HH(a, b, c, d, M_offset_13, 4, T[40]);
                    d = HH(d, a, b, c, M_offset_0, 11, T[41]);
                    c = HH(c, d, a, b, M_offset_3, 16, T[42]);
                    b = HH(b, c, d, a, M_offset_6, 23, T[43]);
                    a = HH(a, b, c, d, M_offset_9, 4, T[44]);
                    d = HH(d, a, b, c, M_offset_12, 11, T[45]);
                    c = HH(c, d, a, b, M_offset_15, 16, T[46]);
                    b = HH(b, c, d, a, M_offset_2, 23, T[47]);

                    a = II(a, b, c, d, M_offset_0, 6, T[48]);
                    d = II(d, a, b, c, M_offset_7, 10, T[49]);
                    c = II(c, d, a, b, M_offset_14, 15, T[50]);
                    b = II(b, c, d, a, M_offset_5, 21, T[51]);
                    a = II(a, b, c, d, M_offset_12, 6, T[52]);
                    d = II(d, a, b, c, M_offset_3, 10, T[53]);
                    c = II(c, d, a, b, M_offset_10, 15, T[54]);
                    b = II(b, c, d, a, M_offset_1, 21, T[55]);
                    a = II(a, b, c, d, M_offset_8, 6, T[56]);
                    d = II(d, a, b, c, M_offset_15, 10, T[57]);
                    c = II(c, d, a, b, M_offset_6, 15, T[58]);
                    b = II(b, c, d, a, M_offset_13, 21, T[59]);
                    a = II(a, b, c, d, M_offset_4, 6, T[60]);
                    d = II(d, a, b, c, M_offset_11, 10, T[61]);
                    c = II(c, d, a, b, M_offset_2, 15, T[62]);
                    b = II(b, c, d, a, M_offset_9, 21, T[63]);

                    H[0] = (H[0] + a) | 0;
                    H[1] = (H[1] + b) | 0;
                    H[2] = (H[2] + c) | 0;
                    H[3] = (H[3] + d) | 0;
                },

                _doFinalize: function() {

                    var data = this._data;
                    var dataWords = data.words;

                    var nBitsTotal = this._nDataBytes * 8;
                    var nBitsLeft = data.sigBytes * 8;

                    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);

                    var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
                    var nBitsTotalL = nBitsTotal;
                    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
                        (((nBitsTotalH << 8) | (nBitsTotalH >>> 24)) & 0x00ff00ff) |
                        (((nBitsTotalH << 24) | (nBitsTotalH >>> 8)) & 0xff00ff00)
                    );
                    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
                        (((nBitsTotalL << 8) | (nBitsTotalL >>> 24)) & 0x00ff00ff) |
                        (((nBitsTotalL << 24) | (nBitsTotalL >>> 8)) & 0xff00ff00)
                    );

                    data.sigBytes = (dataWords.length + 1) * 4;

                    this._process();

                    var hash = this._hash;
                    var H = hash.words;

                    for (var i = 0; i < 4; i++) {

                        var H_i = H[i];

                        H[i] = (((H_i << 8) | (H_i >>> 24)) & 0x00ff00ff) |
                            (((H_i << 24) | (H_i >>> 8)) & 0xff00ff00);
                    }

                    return hash;
                },

                clone: function() {
                    var clone = Hasher.clone.call(this);
                    clone._hash = this._hash.clone();

                    return clone;
                }
            });

            function FF(a, b, c, d, x, s, t) {
                var n = a + ((b & c) | (~b & d)) + x + t;
                return ((n << s) | (n >>> (32 - s))) + b;
            }

            function GG(a, b, c, d, x, s, t) {
                var n = a + ((b & d) | (c & ~d)) + x + t;
                return ((n << s) | (n >>> (32 - s))) + b;
            }

            function HH(a, b, c, d, x, s, t) {
                var n = a + (b ^ c ^ d) + x + t;
                return ((n << s) | (n >>> (32 - s))) + b;
            }

            function II(a, b, c, d, x, s, t) {
                var n = a + (c ^ (b | ~d)) + x + t;
                return ((n << s) | (n >>> (32 - s))) + b;
            }

            C.MD5 = Hasher._createHelper(MD5);

            C.HmacMD5 = Hasher._createHmacHelper(MD5);
        }(Math));

    }, {
        "./core": 5
    }]
}, {}, [1]);

var Base64 = {
    base64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    encode: function($input) {
        if (!$input) {
            return false;
        }
        var $output = "";
        var $chr1, $chr2, $chr3;
        var $enc1, $enc2, $enc3, $enc4;
        var $i = 0;
        do {
            $chr1 = $input.charCodeAt($i++);
            $chr2 = $input.charCodeAt($i++);
            $chr3 = $input.charCodeAt($i++);
            $enc1 = $chr1 >> 2;
            $enc2 = (($chr1 & 3) << 4) | ($chr2 >> 4);
            $enc3 = (($chr2 & 15) << 2) | ($chr3 >> 6);
            $enc4 = $chr3 & 63;
            if (isNaN($chr2)) $enc3 = $enc4 = 64;
            else if (isNaN($chr3)) $enc4 = 64;
            $output += this.base64.charAt($enc1) + this.base64.charAt($enc2) + this.base64.charAt($enc3) + this.base64.charAt($enc4);
        } while ($i < $input.length);
        return $output;
    },
    decode: function($input) {
        if (!$input) return false;
        $input = $input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
        var $output = "";
        var $enc1, $enc2, $enc3, $enc4;
        var $i = 0;
        do {
            $enc1 = this.base64.indexOf($input.charAt($i++));
            $enc2 = this.base64.indexOf($input.charAt($i++));
            $enc3 = this.base64.indexOf($input.charAt($i++));
            $enc4 = this.base64.indexOf($input.charAt($i++));
            $output += String.fromCharCode(($enc1 << 2) | ($enc2 >> 4));
            if ($enc3 != 64) $output += String.fromCharCode((($enc2 & 15) << 4) | ($enc3 >> 2));
            if ($enc4 != 64) $output += String.fromCharCode((($enc3 & 3) << 6) | $enc4);
        } while ($i < $input.length);
        return $output;
    }
};

function getRandomNumber(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function base64ToHex(base64) {
    var binaryString = atob(base64);
    var hexString = '';
    for (var i = 0; i < binaryString.length; i++) {
        var hex = binaryString.charCodeAt(i).toString(16);
        hexString += (hex.length === 2 ? hex : '0' + hex);
    }
    return hexString;
}

function handshake() {
    if (sessionStorage.getItem("scrt-session") == undefined || sessionStorage.getItem("scrt-aes") == undefined ||
	    sessionStorage.getItem("scrt-session") == "undefined" || sessionStorage.getItem("scrt-aes") == "undefined") {
        sessionStorage.setItem("scrt-session", undefined);
        sessionStorage.setItem("scrt-aes", undefined);
        let xhr = new XMLHttpRequest();
        xhr.open('GET', config.scrt_system_host_address + "/getKeyId.php", false);
        xhr.send();
        var data = JSON.parse(xhr.response);
        if (data.scrt_version != config.scrt_system_version) {
            var error = "Incompatible versions of the SCRT-system client and server. Client: ";
            error += config.scrt_system_version + ". Server: " + data.scrt_version + ".";
            console.error(error);
            return false;
        }
        var keyId = data.keyId;
        xhr.open('GET', config.scrt_system_address + "/getVersion.php", false);
        xhr.send();
        data = xhr.response;
        if (data != config.scrt_system_version) {
            var error = "Incompatible versions of the SCRT-system client and certificate server. Client: ";
            error += config.scrt_system_version + ". Server: " + data + ".";
            console.error(error);
            return false;
        }
        xhr.open('GET', config.scrt_system_address + "/getJWKpublicKey.php?id=" + keyId + "&keeper=" + config.keeper, false);
        xhr.send();
        var rsaKey = JSON.parse(xhr.response);
        var key_128 = [getRandomNumber(0, 255), getRandomNumber(0, 255), getRandomNumber(0, 255), getRandomNumber(0, 255),
            getRandomNumber(0, 255), getRandomNumber(0, 255), getRandomNumber(0, 255), getRandomNumber(0, 255),
            getRandomNumber(0, 255), getRandomNumber(0, 255), getRandomNumber(0, 255), getRandomNumber(0, 255),
            getRandomNumber(0, 255), getRandomNumber(0, 255), getRandomNumber(0, 255), getRandomNumber(0, 255)
        ];
        var aesKey = "";
        for (const elm of key_128) {
            aesKey += String(elm);
        }
        aesKey = Base64.encode(aesKey);
        var RSAPublicKey = new RSAKey();
        RSAPublicKey.setPublic(base64ToHex(rsaKey.n), base64ToHex(rsaKey.e));
        var encAES = RSAPublicKey.encrypt(aesKey);
        xhr.open('GET', config.scrt_system_host_address + "/handshake.php?data=" + encAES + "&sym=" + aesKey.length, false);
        xhr.send();
        var session = xhr.response;
        var verificationNumber = getRandomNumber(0, 999999);
        var encVN = AES256.encrypt(String(verificationNumber), aesKey);
        xhr.open('GET', config.scrt_system_host_address + "/verification.php?data=" + encodeURIComponent(encVN) + "&session=" + session, false);
        xhr.send();
        if (xhr.response != String(verificationNumber)) {
            console.error("server don't trust");
            return false;
        } else {
            sessionStorage.setItem("scrt-session", session);
            sessionStorage.setItem("scrt-aes", aesKey);
            return true;
        }
    }
}

function packData(data) {
    if (typeof data != "string" || sessionStorage.getItem("scrt-session") == undefined || sessionStorage.getItem("scrt-aes") == undefined) return false;
    var encData = AES256.encrypt(data, sessionStorage.getItem("scrt-aes"));
    var pack = {
        session: sessionStorage.getItem("scrt-session"),
        data: encData
    };
    return JSON.stringify(pack);
}

function unpackData(data) {
    if (typeof data != "string" || sessionStorage.getItem("scrt-session") == undefined || sessionStorage.getItem("scrt-aes") == undefined) return false;
    var pack = JSON.parse(data);
    var decData = AES256.decrypt(pack.data, sessionStorage.getItem("scrt-aes"));
    return decData;
}

function sendData(url, data) {
    let xhr = new XMLHttpRequest();
    xhr.open('GET', url + "?data=" + encodeURIComponent(packData(data)), false);
    xhr.send();
    return unpackData(xhr.response);
}