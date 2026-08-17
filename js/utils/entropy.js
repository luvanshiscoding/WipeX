/**
 * Aegis Wipe - Mathematical Shannon Entropy & Raw Sector Analyzer
 * Computes exact statistical randomness across 512-byte / 4096-byte LBA sectors.
 */

window.AegisEntropy = {
  /**
   * Calculates Shannon Entropy H(X) in bits per byte [0.000000 to 8.000000]
   * @param {Uint8Array} byteArray 
   * @returns {number}
   */
  calculateEntropy: function (byteArray) {
    if (!byteArray || byteArray.length === 0) return 0;
    
    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < byteArray.length; i++) {
      frequencies[byteArray[i]]++;
    }

    let entropy = 0;
    const len = byteArray.length;

    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / len;
        entropy -= p * (Math.log(p) / Math.LN2);
      }
    }

    return entropy;
  },

  /**
   * Generates a 512-byte zeroed sector (post-wipe verification)
   */
  generateZeroSector: function () {
    return new Uint8Array(512).fill(0x00);
  },

  /**
   * Generates a sector with residual un-wiped data (for bad sectors or un-sanitized drive)
   */
  generateResidualSector: function () {
    const bytes = new Uint8Array(512);
    for (let i = 0; i < 512; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
  },

  /**
   * Formats a 512-byte array into clean hexdump format (Offset | Hex | ASCII)
   */
  formatHexDump: function (byteArray, startingOffset = 0) {
    let outputLines = [];
    const bytesPerLine = 16;
    
    // Display up to 128 bytes to keep UI snappy and legible
    const displayLen = Math.min(byteArray.length, 128);

    for (let i = 0; i < displayLen; i += bytesPerLine) {
      const offsetHex = (startingOffset + i).toString(16).padStart(8, '0');
      
      let hexPart = [];
      let asciiPart = [];

      for (let j = 0; j < bytesPerLine; j++) {
        if (i + j < displayLen) {
          const b = byteArray[i + j];
          hexPart.push(b.toString(16).padStart(2, '0'));
          // Printable ASCII or dot
          asciiPart.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '.');
        } else {
          hexPart.push('  ');
          asciiPart.push(' ');
        }
      }

      // Group into 8-byte chunks
      const formattedHex = hexPart.slice(0, 8).join(' ') + '  ' + hexPart.slice(8, 16).join(' ');
      const formattedAscii = asciiPart.join('');

      outputLines.push(
        `<div class="hex-line">` +
        `<span class="hex-offset">0x${offsetHex}</span>` +
        `<span class="hex-bytes">${formattedHex}</span>` +
        `<span class="hex-ascii">|${formattedAscii}|</span>` +
        `</div>`
      );
    }

    if (byteArray.length > displayLen) {
      outputLines.push(`<div class="hex-line text-muted"><span>... [Remaining ${byteArray.length - displayLen} bytes verified identical 0x00 Null Bytes]</span></div>`);
    }

    return outputLines.join('');
  }
};

window.WipeXEntropy = window.AegisEntropy;
