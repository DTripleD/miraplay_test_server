import app from "./app.js";
import mongoose from "mongoose";
import dotenv from "dotenv";

mongoose.set("strictQuery", true);

dotenv.config();

const { DB_HOST } = process.env;

mongoose
  .connect(DB_HOST)
  .then(() =>
    app.listen(8000, () => {
      console.log("Database connection successful");
    })
  )
  .catch((error) => {
    console.log(error.message);
    process.exit(1);
  });

// BNItsVNEUkATtKCX
