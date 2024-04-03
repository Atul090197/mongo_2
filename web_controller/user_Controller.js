const Joi = require("joi");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const hbs = require("nodemailer-express-handlebars");
const path = require("path");
const localStorage = require("localStorage");
var base64url = require("base64url");
var crypto = require("crypto");
const moment = require("moment");
const fs = require("fs");
const axios = require("axios");
require("moment-timezone");
const config = require("../config");
const userModel = require('../web_models/users')

const {
  registerUser,
  phone_no_check,
  get_all_users, updateUserbyPass_1,
  Delete_otp,
  delete_User, updateUserbyPass,
  updateUserBy_ActToken,
  fetchUserByToken,
  username_Check,
  updatePassword,
  updatePassword_1,
  fetchUserByEmail,
  updateUser,
  updateToken,
  phone_Check, register_seller,
  fetchUserByActToken,
  updateUserByActToken,
  fetchUserById,
  insert_Links, fetchsellerByEmail,
  fetchUserBy_Id, updateUser_1,
  verify_otp, update_guest_cart, update_guest_whislist,
  updateUserById,
  verify_status,
  fetchUserByIdtoken,
} = require("../web_models/users");
const { Console } = require("console");

const baseurl = config.base_url;

function generateRandomString(length) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

const saltRounds = 10;

const complexityOptions = {
  min: 8,
  max: 250,
  lowerCase: 1,
  upperCase: 1,
  numeric: 1,
  symbol: 1,
};

function generateToken() {
  var length = 6,
    charset =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&",
    retVal = "";
  for (var i = 0, n = charset.length; i < length; ++i) {
    retVal += charset.charAt(Math.floor(Math.random() * n));
  }
  return retVal;
}

// Usage example

var transporter = nodemailer.createTransport({
  // service: 'gmail',
  host: "smtp.gmail.com",
  port: 587,
  // secure: true,
  auth: {
    user: "testing26614@gmail.com",
    pass: "ibxakoguozdwqtav",
  },
});

const handlebarOptions = {
  viewEngine: {
    partialsDir: path.resolve(__dirname + "/view/"),
    defaultLayout: false,
  },
  viewPath: path.resolve(__dirname + "/view/"),
};

transporter.use("compile", hbs(handlebarOptions));

exports.signUp = async (req, res) => {
  try {
    const { fname, email, phone, lname, password, } = req.body;
    const act_token = generateRandomString(8);
    const schema = Joi.alternatives(
      Joi.object({
        fname: [Joi.string().empty().required()],
        lname: [Joi.string().empty().required()],
        phone: [Joi.number().empty().required()],
        email: [
          Joi.string()
            .min(5)
            .max(255)
            .email({ tlds: { allow: false } })
            .lowercase()
            .required(),
        ],
        // password: passwordComplexity(complexityOptions),
        password: Joi.string().min(6).max(15).required().messages({
          "any.required": "{{#label}} is required!!",
          "string.empty": "can't be empty!!",
          "string.min": "minimum 6 value required",
          "string.max": "maximum 15 values allowed",
        })
      })
    );
    const result = schema.validate(req.body);
    if (result.error) {
      const message = result.error.details.map((i) => i.message).join(",");
      return res.json({
        message: result.error.details[0].message,
        error: message,
        missingParams: result.error.details[0].message,
        status: 400,
        success: false,
      });
    } else {
      const data = await userModel.findOne({email});
      if (data!= null) {
        return res.json({
          success: false,
          message: "Already have account, Please Login",
          status: 400,
        });
      } else {

        let mailOptions = {
          from: "testing26614@gmail.com",
          to: email,
          subject: "Activate Account",
          template: "signupemail",
          context: {
            href_url: baseurl + `/web/verifyUser/` + `${act_token}`,
            // image_logo: baseurl + `/image/logo.png`,
            msg: `Please click below link to activate your account.`
          },
        };
        transporter.sendMail(mailOptions, async function (error, info) {
          if (error) {
            return res.json({
              success: false,
              status: 400,
              message: "Mail Not delivered",
            });
          } else {

            const hash = await bcrypt.hash(password, saltRounds);
            const user = {
              fname: fname,
              lname: lname,
              email: email,
              password: hash,
              show_password: password,
              phone: phone,
              show_password: password,
            };
            const create_user = await userModel.create(user);
            console.log(">>>>>>>>", create_user)
            return res.json({
              success: true,
              message:
                "Please verify your account with the email we have sent an OTP to your email address  " +
                `${email}`,
              status: 200,
            });
          }
        });

      }
    }
  } catch (error) {
    console.log(error);
    return res.json({
      success: false,
      message: "Internal server error",
      status: 500,
      error: error,
    });
  }
};

exports.login_buyer = async (req, res) => {
  try {
    const { email, password } = req.body;
    const token = generateToken();
    const schema = Joi.alternatives(
      Joi.object({
        email: [Joi.string().empty().required()],
        password: Joi.string().min(6).max(15).required().messages({
          "any.required": "{{#label}} is required!!",
          "string.empty": "can't be empty!!",
          "string.min": "minimum 6 value required",
          "string.max": "maximum 15 values allowed",
        }),
      })
    );
    const result = schema.validate({ email, password });

    if (result.error) {
      const message = result.error.details.map((i) => i.message).join(",");
      return res.json({
        message: result.error.details[0].message,
        error: message,
        missingParams: result.error.details[0].message,
        status: 400,
        success: false,
      });
    } else {
      const data = await userModel.findOne({email});
      // console.log("data", data[0].id);
      if (data !== null) {
          if (email === data[0].email) {
            const match = bcrypt.compareSync(password, data[0]?.password);
            // console.log(">>>>>>>>>", match);
            if (match) {
              const toke = jwt.sign(
                {
                  data: {
                    id: data[0].id,
                  },
                },
                "SecretKey",
                // { expiresIn: "1d" }
              );
              // console.log(toke);
              bcrypt.genSalt(saltRounds, async function (err, salt) {
                bcrypt.hash(token, salt, async function (err, hash) {
                  if (err) throw err;
                  // const results = await updateToken(hash, email);

                  return res.json({
                    status: 200,
                    success: true,
                    message: "Login successful!",
                    token: toke,
                    user_id: data[0].id,
                    user_info: data[0],
                  });
                });
              });
            } else {
              return res.json({
                success: false,
                message: "Invalid password.",
                status: 400,
              });
            }
          } else {
            return res.json({
              message: "Account not found. Please check your details",
              status: 400,
              success: false,
            });
          }
        
      } else {
        return res.json({
          success: false,
          message: "Account not found. Please check your details.",
          status: 400,
        });
      }
    }
  } catch (error) {
    console.log(error);
    return res.json({
      success: false,
      message: "An internal server error occurred. Please try again later.",
      status: 500,
      error: error,
    });
  }
};

exports.myProfile = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    console.log("authHeader>>>>>>>", authHeader);
    const token_1 = authHeader;
    const token = token_1.replace("Bearer ", "");

    console.log(">>>>>>>>>>>", token);

    const decoded = jwt.decode(token);
    const user_id = decoded.data.id;

    const data = await fetchUserBy_Id(user_id);

    console.log(">>>>>>>>", data)
    if (data.length != 0) {
      await Promise.all(
        data.map(async (item) => {
          if (item.profile_image != 0) {
            // item.profile_image = baseurl + "/profile/" + item.profile_image;
            item.profile_image =
              baseurl + "/ProfileImages/" + item.profile_image;
          } else {
            item.profile_image = ""
          }
        })
      );

      return res.json({
        status: 200,
        success: true,
        message: "User Found Successfull",
        user_info: data,
      });
    } else {
      return res.json({
        status: 400,
        success: false,
        message: "User Not Found",
      });
    }
  } catch (error) {
    console.log(error);
    return res.json({
      success: false,
      message: "Internal server error",
      status: 500,
      error: error,
    });
  }
};

exports.editProfile = async (req, res) => {
  try {
    const { buyer_name, phone_number, user_name, license_state, license_number } = req.body;

    const schema = Joi.alternatives(
      Joi.object({
        buyer_name: [Joi.string().empty().required()],
        user_name: [Joi.string().empty().required()],
        license_state: [Joi.string().empty().required()],
        license_number: [Joi.string().empty().required()],
        user_name: [Joi.string().empty().required()],
        phone_number: [Joi.number().empty().required()],
      })
    );
    const result = schema.validate(req.body);
    if (result.error) {
      const message = result.error.details.map((i) => i.message).join(",");
      return res.json({
        message: result.error.details[0].message,
        error: message,
        missingParams: result.error.details[0].message,
        status: 200,
        success: true,
      });
    } else {
      const authHeader = req.headers.authorization;

      // console.log("authHeader>>>>>>>", authHeader)
      const token_1 = authHeader;
      const token = token_1.replace("Bearer ", "");

      // console.log(">>>>>>>>>>>", token);

      const decoded = jwt.decode(token);
      const user_id = decoded.data.id;

      // console.log(">>>>>>>", user_id);
      let filename = "";
      if (req.file) {
        const file = req.file;
        filename = file.filename;
      }

      console.log(">>>>>>>>>", filename)


      const userInfo = await fetchUserBy_Id(user_id);
      // console.log("userInfo>>>>>>>>>>", userInfo);
      if (userInfo.length !== 0) {
        const usernmae_check = await username_Check(user_name, user_id);
        if (usernmae_check != 0) {
          return res.json({
            success: false,
            message:
              "Usernmae is already taken. Please use a different username.",
            status: 400,
          });
        }
        let user = {
          profile_image: filename ? filename : userInfo[0].profile_image,
          user_name: user_name ? user_name : userInfo[0].user_name,
          buyer_name: buyer_name ? buyer_name : userInfo[0].buyer_name,
          phone_number: phone_number ? phone_number : userInfo[0].phone_number,
          license_state: license_state ? license_state : userInfo[0].license_state,
          license_number: license_number ? license_number : userInfo[0].license_number,
        };
        console.log(">>>>>>>>>>>>", user)
        const result = await updateUserById(user, user_id);
        if (result.affectedRows) {

          const userInfo = await fetchUserBy_Id(user_id);

          return res.json({
            message: "update user successfully",
            status: 200,
            success: true,
            userInfo: userInfo,
          });
        } else {
          return res.json({
            message: "update user failed ",
            status: 200,
            success: false,
          });
        }


      } else {
        return res.json({
          messgae: "data not found",
          status: 200,
          success: false,
        });
      }
    }
  } catch (err) {
    console.log(err);
    return res.json({
      success: false,
      message: "Internal server error",
      error: err,
      status: 500,
    });
  }
};







