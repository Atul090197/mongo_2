const express = require("express");
const web_user = require("./web_routes/users");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());

var bodyParser = require("body-parser");
app.use(bodyParser.json());

// in latest body-parser use like below.
app.use(bodyParser.urlencoded({ extended: false }));

//app.use(express.static("public"))

require('./utils/database');

// Uncomment the line below if you have an 'uploads' directory
app.use(express.static(path.join(__dirname, "public")));

app.use("/web", web_user);


app.get("/", (req, res) => {
  res.send({ success: "0", message: "Hello World" });
});

app.get("/", (req, res) => {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "*",
    "http://localhost:4000",
    {
      reconnect: true,
    }
  );

  res.header("Access-Control-Allow-Credentials", true);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,PUT,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Accept, X-Custom-Header,Authorization"
  );

  res.setHeader("Content-Type", "text/plain");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  } else {
    return res.send({ success: "0", message: "Hello World" });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Node app is running on port ${PORT}`);
});

module.exports = app;
