#!/usr/bin/env node
import { dim, red } from './src/core/terminal.mjs';
import { main } from './src/cli/main.mjs';

function reportFatal(cause) {
  const error = cause instanceof Error ? cause : new Error(String(cause));
  console.error(red(`✗ ${error.message}`));
  if (process.env.SHOMRA_DEBUG) console.error(dim(error.stack ?? ''));
  process.exit(1);
}

process.on('unhandledRejection', reportFatal);

main().catch(reportFatal);
