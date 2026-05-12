import { greet } from "./greet.js";

export { greet };

export function main(): void {
  process.stdout.write(`${greet("World")}\n`);
}
