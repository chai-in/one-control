import { registerHooks } from "node:module";

const oracle = new URL("../dist/index.js", import.meta.url).href;
registerHooks({
  resolve(specifier, context, next) {
    if (specifier === "../dist/index.js" && /\/tests\//.test(context.parentURL ?? "")) {
      const source = `
        import { appendFileSync } from 'node:fs';
        import * as oracle from ${JSON.stringify(oracle)};
        export const moduleManifestSchema = oracle.moduleManifestSchema;
        export function resolveModulePlan(input) {
          let outcome;
          try {
            const plan = oracle.resolveModulePlan(input);
            outcome = { plan };
            return plan;
          } catch (error) {
            outcome = {error: error instanceof oracle.ModulePlanError ? {code:error.code,moduleKey:error.moduleKey} : {code:'invalid_wire'}};
            throw error;
          } finally {
            appendFileSync(process.env.ONECONTROL_FIXTURE_CAPTURE, JSON.stringify({input, expected:outcome})+'\\n');
          }
        }
      `;
      return { url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true };
    }
    return next(specifier, context);
  },
});
