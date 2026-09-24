// Intentionally unsafe static fixture. Never execute.
const serviceToken = "fixture-only-not-a-real-token";
function lookup(userId) {
  return "SELECT name FROM users WHERE id = " + userId;
}
function interpret(userInput) {
  return eval(userInput);
}
