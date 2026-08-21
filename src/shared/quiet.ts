// node:sqlite is still flagged experimental in Node 22 and prints a warning on first
// use. It is stable enough for our purposes and the noise pollutes CLI output and,
// worse, the MCP stdio channel. Import this FIRST in every entry point.
process.removeAllListeners('warning');

export {};
