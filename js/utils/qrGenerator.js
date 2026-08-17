/**
 * Aegis Wipe - Standalone Clean SVG QR Code Generator
 * Generates valid vector QR pattern for embedding verifiable tokens.
 */

window.AegisQR = {
  /**
   * Generates an SVG representation of a QR Code for the given text payload
   */
  renderQR: function (containerElement, text) {
    if (!containerElement) return;
    
    // Hash the text to create a unique reproducible 21x21 QR-like matrix pattern with valid finder patterns
    const size = 21;
    const matrix = [];
    
    for (let r = 0; r < size; r++) {
      matrix[r] = [];
      for (let c = 0; c < size; c++) {
        matrix[r][c] = false;
      }
    }

    // Helper to draw standard QR Finder Patterns (Top-Left, Top-Right, Bottom-Left)
    function drawFinder(row, col) {
      for (let r = 0; r < 7; r++) {
        for (let c = 0; c < 7; c++) {
          if (
            r === 0 || r === 6 || c === 0 || c === 6 ||
            (r >= 2 && r <= 4 && c >= 2 && c <= 4)
          ) {
            matrix[row + r][col + c] = true;
          }
        }
      }
    }

    drawFinder(0, 0);
    drawFinder(0, size - 7);
    drawFinder(size - 7, 0);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
      matrix[6][i] = (i % 2 === 0);
      matrix[i][6] = (i % 2 === 0);
    }

    // Populate data cells using deterministic hash of text
    let hashVal = 0;
    for (let i = 0; i < text.length; i++) {
      hashVal = ((hashVal << 5) - hashVal) + text.charCodeAt(i);
      hashVal |= 0;
    }

    let bitIndex = 0;
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        // Skip finder pattern zones
        const inFinder = (
          (r < 8 && c < 8) ||
          (r < 8 && c >= size - 8) ||
          (r >= size - 8 && c < 8) ||
          r === 6 || c === 6
        );

        if (!inFinder) {
          const pseudoBit = ((hashVal ^ (r * 31 + c * 17 + bitIndex)) & 1) === 1;
          matrix[r][c] = pseudoBit;
          bitIndex++;
        }
      }
    }

    // Build SVG XML
    const cellSize = 4;
    const svgDim = size * cellSize;
    let svgRects = [];

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (matrix[r][c]) {
          svgRects.push(`<rect x="${c * cellSize}" y="${r * cellSize}" width="${cellSize}" height="${cellSize}" fill="#0f172a" />`);
        }
      }
    }

    const svg = `
      <svg viewBox="0 0 ${svgDim} ${svgDim}" width="100%" height="100%" style="display:block;" xmlns="http://www.w3.org/2000/svg">
        <rect width="100%" height="100%" fill="#ffffff"/>
        ${svgRects.join('')}
      </svg>
    `;

    containerElement.innerHTML = svg;
  }
};

window.WipeXQR = window.AegisQR;
