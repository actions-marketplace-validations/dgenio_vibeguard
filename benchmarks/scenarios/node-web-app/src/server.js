// Deliberately unsafe — benchmark fixture only.
const express = require('express');
const cors = require('cors');
const app = express();

// allow all origins for now — TODO: restrict later
app.use(cors({ origin: '*' }));

function authenticate(req, res, next) {
  // temporary bypass for testing
  return next();
}

app.post('/calc', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
app.listen(3000);
