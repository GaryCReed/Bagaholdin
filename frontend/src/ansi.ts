// Maps standard ANSI color codes to hex values (One Dark palette, dark-terminal friendly)
const ANSI_COLORS: Record<number, string> = {
  30: '#4a4a4a', 31: '#e06c75', 32: '#98c379', 33: '#e5c07b',
  34: '#61afef', 35: '#c678dd', 36: '#56b6c2', 37: '#abb2bf',
  90: '#7f848e', 91: '#ff7b85', 92: '#b8e8a2', 93: '#ffd080',
  94: '#7dc4ff', 95: '#da8fff', 96: '#6ec5cc', 97: '#ffffff',
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Converts a string containing ANSI escape codes to an HTML string with
 * <span style="..."> tags. The input text is HTML-escaped before processing,
 * so only our own span tags are injected — no XSS risk from msfconsole output.
 */
export function ansiToHtml(text: string): string {
  const escaped = escapeHtml(text);
  let result = '';
  let currentColor: string | null = null;
  let isBold = false;
  let isOpen = false;

  const closeSpan = () => {
    if (isOpen) {
      result += '</span>';
      isOpen = false;
    }
  };

  const openSpan = () => {
    if (currentColor !== null || isBold) {
      const styles: string[] = [];
      if (currentColor) styles.push(`color:${currentColor}`);
      if (isBold) styles.push('font-weight:bold');
      result += `<span style="${styles.join(';')}">`;
      isOpen = true;
    }
  };

  // Split on ANSI CSI sequences of the form ESC [ ... m
  const parts = escaped.split(/(\x1b\[\d+(?:;\d+)*m)/);

  for (const part of parts) {
    const match = part.match(/^\x1b\[(\d+(?:;\d+)*)m$/);
    if (match) {
      closeSpan();
      const codes = match[1].split(';').map(Number);
      for (const code of codes) {
        if (code === 0) {
          currentColor = null;
          isBold = false;
        } else if (code === 1) {
          isBold = true;
        } else if (code === 22) {
          isBold = false;
        } else if (ANSI_COLORS[code] !== undefined) {
          currentColor = ANSI_COLORS[code];
        }
        // Unknown codes (underline, blink, 256-color, etc.) are silently ignored
      }
      openSpan();
    } else if (part) {
      result += part;
    }
  }

  closeSpan();
  return result;
}
