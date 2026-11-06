/** Public product labels. Never apply to captured action evidence or API identifiers. */
export function displayText(text: string): string {
  return text.replace(/jev/gi, "Guardrail");
}

/** Hide internal model identifiers, including versions and derived references. */
export function displayModel(model: string): string {
  return /jev|guardrail/i.test(model) ? "Guardrail" : model;
}
