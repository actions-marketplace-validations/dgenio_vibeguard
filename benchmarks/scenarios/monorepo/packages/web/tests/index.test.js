const { greet } = require("../src/index.js");

test("greet", () => {
  expect(greet("world")).toBe("hello, world");
});
