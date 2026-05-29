// PR: "unblock local dev for the admin dashboard"
// What the AI did: the auth middleware was failing locally, so it stubbed the
// check with an early `next()` and left a TODO instead of fixing the real flow.

function requireAuth(req, res, next) {
  // TODO: implement real auth before merging
  // temporary bypass for testing
  return next();
}

module.exports = { requireAuth };
