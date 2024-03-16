import express from "express";
import bodyParser from "body-parser";
import env from "dotenv";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";


const app = express();
const port = 3000;
const saltRound = 10;
env.config();


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.PASSPORT_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
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

app.get("/secrets", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/")
  }
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  })
})

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
          const result = await db.query("INSERT INTO users (email,password) VALUES ($1,$2) RETURNING * ",
            [email, hash]);

          const user = result.rows[0];
          console.log(user);
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/secrets");
          });

        }
      });
    }

  } catch (error) {
    console.log(error);
  }

});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

// 

passport.use(new Strategy(async function verify(username, password, cb) {
  console.log(username);
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);

    if (result.rows.length > 0) {

      const user = result.rows[0];
      const storedHashPassword = user.password;

      bcrypt.compare(password, storedHashPassword, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            return cb(null, user);
          } else {
            return cb(null, false);
          }
        }
      })

    } else {
      return cb("User not found");
    }
  }
  catch (error) {
    console.log(error);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
