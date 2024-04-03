const mongoose = require("mongoose");


mongoose
  .connect(
    "mongodb://localhost:27017/atul",
    {
      useNewUrlParser: true,
    }
  )
  .then(() => console.log("MongoDb is Connected"))
  .catch((err) => console.log(err));


