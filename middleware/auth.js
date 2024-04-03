const jwt = require("jsonwebtoken");
const { fetchUserById } = require("../web_models/users");

const auth = async (req, res, next) => {
  try {
    const bearerHeader = req.headers["authorization"];

    if (typeof bearerHeader !== undefined) {
      const bearer = bearerHeader.split(" ");
      const token = bearer[1];

      const verifyUser = jwt.verify(token, "SecretKey");
      const userdata = verifyUser.data.id;
      console.log(verifyUser, "user verify");

      const user = await fetchUserById({ id: verifyUser.data.id });

      req.user = verifyUser.data.id;
      if (user !== null) {
        next();
      } else {
        return res.json({
          success:false,
          status: 200,
          message: "Access Forbidden",
        });
      }
    } else {
      return res.json({
        message: "Token Not Provided",
        status: 400,
        success: "0",
      });
    }
  } catch (err) {
    console.log(err);
    return res.json({
      message: "Access forbidden",
      status: 400,
      success: false,
    });
  }
};

module.exports = auth;
