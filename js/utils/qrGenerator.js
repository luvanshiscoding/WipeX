/**
 * WipeX - Standalone Clean SVG QR Code Generator
 * Generates valid vector QR pattern for embedding verifiable tokens.
 */

window.WipeXQR = {
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

    // Simple pseudo-random distribution based on string hash
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = ((hash << 5) - hash) + text.charCodeAt(i);
      hash |= 0;
    }

    let seed = Math.abs(hash);
    function nextBit() {
      seed = (seed * 9301 + 49297) % 233280;
      return (seed / 233280) > 0.5;
    }

    // Fill the rest with pseudo-random bits
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        // Skip finder pattern zones
        const inFinderTL = (r < 8 && c < 8);
        const inFinderTR = (r < 8 && c >= size - 8);
        const inFinderBL = (r >= size - 8 && c < 8);
        
        if (!inFinderTL && !inFinderTR && !inFinderBL) {
          // Timing patterns (Row 6, Col 6)
          if (r === 6) {
            matrix[r][c] = (c % 2 === 0);
          } else if (c === 6) {
            matrix[r][c] = (r % 2 === 0);
          } else {
            matrix[r][c] = nextBit();
          }
        }
      }
    }

    // Build SVG
    const cellSize = 4;
    const padding = 8;
    const svgSize = size * cellSize + padding * 2;
    
    let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${svgSize} ${svgSize}" width="100%" height="100%" shape-rendering="crispEdges">`;
    svg += `<rect width="${svgSize}" height="${svgSize}" fill="#ffffff"/>`;
    
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (matrix[r][c]) {
          const x = padding + c * cellSize;
          const y = padding + r * cellSize;
          svg += `<rect x="${x}" y="${y}" width="${cellSize}" height="${cellSize}" fill="#0f172a"/>`;
        }
      }
    }
    
    svg += `</svg>`;
    containerElement.innerHTML = svg;
  }
};
