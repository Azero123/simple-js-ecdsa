var sha256_K = [
  1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
  1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
  264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
  113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
  1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
  430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
  1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998
];

function sha256_S(X, n) {
  return (X >>> n) | (X << (32 - n));
}

function sha256_Sigma0256(x) {
  return (sha256_S(x, 2) ^ sha256_S(x, 13) ^ sha256_S(x, 22));
}

function sha256_Sigma1256(x) {
  return (sha256_S(x, 6) ^ sha256_S(x, 11) ^ sha256_S(x, 25));
}

function sha256_Gamma0256(x) {
  return (sha256_S(x, 7) ^ sha256_S(x, 18) ^ (x >>> 3));
}

function sha256_Gamma1256(x) {
  return (sha256_S(x, 17) ^ sha256_S(x, 19) ^ (x >>> 10));
}


function binb(m, l) {
  var HASH = [1779033703, -1150833019, 1013904242, -1521486534,
    1359893119, -1694144372, 528734635, 1541459225
  ];
  var W = new Array(64);
  var a, b, c, d, e, f, g, h;
  var i, j, T1, T2;

  /* append padding */
  m[l >> 5] |= 0x80 << (24 - l % 32);
  m[((l + 64 >> 9) << 4) + 15] = l;

  for (i = 0; i < m.length; i += 16) {
    a = HASH[0];
    b = HASH[1];
    c = HASH[2];
    d = HASH[3];
    e = HASH[4];
    f = HASH[5];
    g = HASH[6];
    h = HASH[7];

    for (j = 0; j < 64; j += 1) {
      if (j < 16) {
        W[j] = m[j + i];
      } else {
        W[j] = safe_add(safe_add(safe_add(sha256_Gamma1256(W[j - 2]), W[j - 7]),
          sha256_Gamma0256(W[j - 15])), W[j - 16]);
      }

      T1 = safe_add(h + sha256_Sigma1256(e) + ((e & f) ^ ((~e) & g)) + sha256_K[j], W[j]);
      T2 = sha256_Sigma0256(a) + ((a & b) ^ (a & c) ^ (b & c));
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    HASH[0] = a + HASH[0];
    HASH[1] = b + HASH[1];
    HASH[2] = c + HASH[2];
    HASH[3] = d + HASH[3];
    HASH[4] = e + HASH[4];
    HASH[5] = f + HASH[5];
    HASH[6] = g + HASH[6];
    HASH[7] = h + HASH[7];
  }
  return HASH;
}


function utf8Encode(str) {
  var x, y, output = '',
    i = -1,
    l;

  if (str && str.length) {
    l = str.length;
    while ((i += 1) < l) {
      /* Decode utf-16 surrogate pairs */
      x = str.charCodeAt(i);
      y = i + 1 < l ? str.charCodeAt(i + 1) : 0;
      if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF) {
        x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
        i += 1;
      }
      /* Encode output as utf-8 */
      if (x <= 0x7F) {
        output += String.fromCharCode(x);
      } else if (x <= 0x7FF) {
        output += String.fromCharCode(0xC0 | ((x >>> 6) & 0x1F),
          0x80 | (x & 0x3F));
      } else if (x <= 0xFFFF) {
        output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
          0x80 | ((x >>> 6) & 0x3F),
          0x80 | (x & 0x3F));
      } else if (x <= 0x1FFFFF) {
        output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
          0x80 | ((x >>> 12) & 0x3F),
          0x80 | ((x >>> 6) & 0x3F),
          0x80 | (x & 0x3F));
      }
    }
  }
  return output;
}

/**
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */

function safe_add(x, y) {
  var lsw = (x & 0xFFFF) + (y & 0xFFFF),
    msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/**
 * Convert an array of big-endian words to a string
 */

function binb2rstr(input) {
  var i, l = input.length * 32,
    output = '';
  for (i = 0; i < l; i += 8) {
    output += String.fromCharCode((input[i >> 5] >>> (24 - i % 32)) & 0xFF);
  }
  return output;
}


/**
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */

function rstr2binb(input) {
  var i, l = input.length * 8,
    output = Array(input.length >> 2),
    lo = output.length;
  for (i = 0; i < lo; i += 1) {
    output[i] = 0;
  }
  for (i = 0; i < l; i += 8) {
    output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
  }
  return output;
}

/*
	 * Convert a raw string to a hex string
	 */
	function rstr2hex(input)
	{
	  try { hexcase } catch(e) { hexcase=false; }
	  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
	  var output = "";
	  var x;
	  for(var i = 0; i < input.length; i++)
	  {
		x = input.charCodeAt(i);
		output += hex_tab.charAt((x >>> 4) & 0x0F)
			   +  hex_tab.charAt( x        & 0x0F);
	  }
	  return output;
	}


module.exports = (data) => {
  if (typeof data !== 'string') throw 'must be a string!'
  
  return rstr2hex(binb2rstr(binb(rstr2binb(data), data.length * 8)));
}
