// Attacker CLI entrypoint. The interactive runtime lives in cli-runtime.js
// so this module remains a small executable boundary.
import { pathToFileURL } from 'node:url';
import { main } from './cli-runtime.js';

export { main } from './cli-runtime.js';
export {
  createSingleFlight,
  formatLiveNotification,
  inputBlockGeometry,
  pendingDirectTasks,
  sanitizeRegistryText,
} from './text.js';

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`fatal: ${err.message}`);
    process.exit(1);
  });
}
