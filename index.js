import express from "express";
import bodyParser from "body-parser";
import env from "dotenv";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRound = 10;
env.config();


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const db = new pg.Client({
  host: "localhost",
  user: "postgres",
  database: "secrets",
  password: "SubinFasliya@123",
  port: 5432,
})

db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1",
      [email]);

    if (checkResult.rows.length > 0) {
      res.send("Already user exist.Try loggin in");
    } else {

      bcrypt.hash(password, saltRound, async (err, hash) => {
        if (err) {
          console.log("Password hashing error", err);
        } else {
          const result = await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",
            [email, hash]);

          console.log(result);
          res.render("secrets.ejs");
        }
      });
    }

  } catch (error) {
    console.log(error);
  }

});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const logginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length > 0) {

      const user = result.rows[0];
      const storedHashPassword = user.password;

      bcrypt.compare(logginPassword, storedHashPassword, (err, result) => {
        if (err) {
          console.log("Error comparing Password", err);
        } else {
          if (result) {
            res.render("secrets.ejs")
          } else {
            res.send("Invalid Password")
          }
        }
      })

    } else {
      res.send("User Not Found.If you not Register! Please register and try again")
    }
  } catch (error) {
    console.log(error);
  }

});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
