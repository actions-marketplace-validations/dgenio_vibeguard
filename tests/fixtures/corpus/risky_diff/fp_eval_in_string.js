// False positive: the literal "eval" appears only inside a string and
// a comment. There is no actual eval() call.
const MESSAGE = "eval is dangerous; do not use it";
// We talk about eval in this comment but do not call it.
function safeParse(input) {
  return JSON.parse(input);
}

module.exports = { MESSAGE, safeParse };
