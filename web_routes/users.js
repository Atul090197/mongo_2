const express = require("express");
const web_userController = require("../web_controller/user_Controller");
const auth = require("../middleware/auth");
const upload = require("../middleware/ProfileImages.JS");
const router = express.Router();


router.post("/signUp", web_userController.signUp);

router.post("/login_buyer", web_userController.login_buyer);


router.post("/editProfile", auth, upload.single("file"), web_userController.editProfile);

module.exports = router;
