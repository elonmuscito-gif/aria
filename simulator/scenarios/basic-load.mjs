import { honestAgent } from "../agents/honest.mjs";
import { spamAgent } from "../agents/spam.mjs";
import { invalidAgent } from "../agents/invalid.mjs";
import { analyzeResults } from "../metrics/analyzer.mjs";

export async function runScenario(baseUrl) {
  const results = [];

  console.log("⚡ Ejecutando escenario básico...\n");

  results.push(await honestAgent(baseUrl));
  results.push(await spamAgent(baseUrl));
  results.push(await invalidAgent(baseUrl));

  const summary = analyzeResults(results);

  return { results, summary };
}