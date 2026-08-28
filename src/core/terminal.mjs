const useColor = process.stdout.isTTY && !process.env.NO_COLOR;

const ansi = (code) => (value) => (useColor ? `\x1b[${code}m${value}\x1b[0m` : String(value));

export const bold = ansi('1');
export const dim = ansi('2');
export const red = ansi('31');
export const green = ansi('32');
export const yellow = ansi('33');
export const magenta = ansi('35');
export const cyan = ansi('36');
export const gray = ansi('90');

export const SEV_COLOR = { CRITICAL: red, HIGH: red, MEDIUM: yellow, LOW: cyan, INFO: gray };

export const VERDICT_COLOR = { FAIL: red, REVIEW: yellow, PASS: green };
