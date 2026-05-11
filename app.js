require("dotenv").config();

// Express
const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;

// EJS
app.set("view engine", "ejs");

// Encryption
const bcrypt = require("bcrypt");
const saltRounds = 12;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static("public"));

const node_session_secret = process.env.NODE_SESSION_SECRET;
const oneHour = 60 * 60 * 1000;

// MongoDB Connection
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_users_database = process.env.MONGODB_USER_DATABASE;
const mongodb_sessions_database = process.env.MONGODB_SESSION_DATABASE;

// session
const session = require("express-session");
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

// Creates an instance of MongoClient to manage the connection to the database
const MongoClient = require("mongodb").MongoClient;

// Rebuilds the connection string (MongoDB users database)
const usersDbURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_users_database}`;

// Creates an object that can make requests to the database
let database = new MongoClient(usersDbURI, {});

// Rebuilds the connection string (MongoDB sessions database)
const sessionsDbURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_sessions_database}`;

// Creates a session storage adapter, enabling Express to save sessions in MongoDB instead of memory
const MongoStore = require("connect-mongo").default;
let sessionStore = MongoStore.create({
  mongoUrl: sessionsDbURI,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: sessionStore,
    saveUninitialized: false,
    resave: true,
  }),
);

app.use((req, res, next) => {
  res.locals.authenticated = req.session.authenticated || false;
  next();
});

// Gets the users collection from MongoDB
const userCollection = database.db(mongodb_users_database).collection("users");

const Joi = require("joi");

// Home Page
app.get("/", (req, res) => {
  res.render("home", {
    authenticated: req.session.authenticated,
    username: req.session.username,
    titleName: "Home Page",
  });
});

// Sign Up Page
app.get("/signup", (req, res) => {
  res.render("signup", {
    titleName: "Sign Up Page",
  });
  
});

app.post("/signup", async (req, res) => {
  let username = req.body.username;
  let email = req.body.email;
  let password = req.body.password;
  let hashedPassword;

  // Validates and prevents injection attacks
  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, email, password });

  if (validationResult.error != null) {
    res.render("error", {titleName: "Sign Up Error", errorMessage: validationResult.error.message, redirectLink: "/signup", redirectMessage:"Try again"} );
    return;
  }

  hashedPassword = bcrypt.hashSync(password, saltRounds);

  // Prevent multiple users with the same user name
  let existingUser = await userCollection.findOne({ email: email });
  if (existingUser) {
    res.render("error", {titleName: "Sign Up Error", errorMessage: `The email: ${email} is already taken`, redirectLink: "/signup", redirectMessage:"Try again"} );
    return;
  }

  // Adds the user to the MongoDB users collection
  userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
    admin: true,
  });

  req.session.authenticated = true;
  req.session.username = username;
  req.session.email = email;
  req.session.cookie.maxAge = oneHour;
  req.session.admin = true;

  req.session.save((err) => {
    if (err) console.error("Session save error:", err);
    else console.log("Session saved, ID:", req.session.id);
    res.redirect("/members");
  });
});

// Login Page
app.get("/login", (req, res) => {
  res.render("login", {titleName: "Log In Page"});
});

app.post("/login", async (req, res) => {
  let email = req.body.email;
  let password = req.body.password;

  // Validates and prevents injection attacks
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });

  if (validationResult.error != null) {
    res.redirect("/login");
    return;
  }

  const match = await userCollection
    .find({ email: email })
    .project({ email: 1, username: 1, password: 1, _id: 1, admin: 1 })
    .toArray();

  if (match.length != 1) {
    res.render("error", {titleName: "Login Error", errorMessage: "Invalid email, user does not exist!", redirectLink: "/login", redirectMessage:"Try again"} );
    return;
  }

  if (await bcrypt.compare(password, match[0].password)) {
    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = match[0].username;
    req.session.cookie.maxAge = oneHour;
    req.session.admin = match[0].admin;
    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        res.render("error", { titleName: "Login Error", errorMessage: "Session save error!", redirectLink: "/login", redirectMessage: "Try again" });
        return;
      }
      res.redirect("/members");
    });
  } else {
    res.render("error", {titleName: "Login Error", errorMessage: "Incorrect Password!", redirectLink: "/login", redirectMessage:"Try again"} );
    return;
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
  res.redirect("/");
  return;
  }
  
  res.render("members", {
    username: req.session.username,
    titleName: "Members Only Page",
  });
});

app.get("/admin", async (req, res) => {
  //TODO replace face with req.session.authorized?
  if (!req.session.authenticated) {
  res.redirect("/login");
  return;
  }

  // const userCollection = database.db(mongodb_users_database).collection("users");
  
  if (!req.session.admin) {
    res.status(403);
    res.render("error", {titleName: "Admin Error", errorMessage: "You are not authorized to view this page", redirectLink: "/", redirectMessage: "Return to Home Page"} );
    return;
  }

  const users = await userCollection.find().toArray();
  res.render("admin", {
    titleName: "Admin",
    users: users,
  });
});


app.post("/promote", async(req, res) => {
  if (!req.session.authenticated || !req.session.admin){
    res.render("error", {titleName: "Admin Error", errorMessage: "You are not authorized to view this page", redirectLink: "/", redirectMessage: "Return to Home Page"} );
    return;
  }

  console.log("User: ", req.body.email);
  await userCollection.updateOne(
    { email: req.body.email},
    {$set: {admin: true}}
  );
  res.redirect("/admin");
});

app.post("/demote", async(req, res) => {
  if (!req.session.authenticated || !req.session.admin){
    res.render("error", {titleName: "Admin Error", errorMessage: "You are not authorized to view this page", redirectLink: "/", redirectMessage: "Return to Home Page"} );
    return;
  }

  await userCollection.updateOne(
    { email: req.body.email},
    {$set: {admin: false}}
  );

  if (req.body.email === req.session.email){
    req.session.admin = false;
    req.session.save((err) => {
      if (err) console.error("Session save error:", err);
      res.redirect("/admin");
    });
  }
  
  res.redirect("/admin");
});

app.use((req, res) => {
  res.status(404);
  res.render("pageNotFound", {titleName: "Page Not Found - 404"});
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
