// Mutation fixture: CORS opened to wildcard.
// AI agents often "fix CORS errors" by allowing any origin.
// Expected detection: RISK-CORSCONFIG or AI-CORSWILDCARD.

const express = require("express");
const cors = require("cors");

const app = express();

app.use(
  cors({
    origin: "*",
    credentials: true,
  })
);

module.exports = app;
