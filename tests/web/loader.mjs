/* Подменяет модули Firebase из CDN локальными заглушками для тестов в Node. */
import { pathToFileURL } from "node:url";
import { resolve as resolvePath } from "node:path";

const STUB = pathToFileURL(resolvePath("tests/web/stub-firebase.mjs")).href;
const PREFIX = "https://www.gstatic.com/firebasejs/";

export async function resolve(specifier, context, next) {
  if (specifier.startsWith(PREFIX)) {
    return { url: STUB, shortCircuit: true };
  }
  return next(specifier, context);
}
