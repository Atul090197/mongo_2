const multer = require("multer");
const { DATE } = require("sequelize");
const { v4 } = require("uuid");
const docFilter = (req, file, cb) => {
  if (
    file.mimetype === "application/pdf" ||
    file.mimetype === "image/png" ||
    file.mimetype === "image/jpg" ||
    file.mimetype === "image/jpeg"
  ) {
    cb(null, true);
  } else {
    cb("Please upload only selected formats", false);
  }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/ProfileImages/");
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${v4()}-${file.originalname}`);
  },
});


const uploadFile = multer({ storage, fileFilter: docFilter });
module.exports = uploadFile;
