require("dotenv").config();

// Express
const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;

// Encryption
const bcrypt = require("bcrypt");
const saltRounds = 12;

app.use(express.urlencoded({extended: false}));
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
const usersDbURI  = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_users_database}`;

// Creates an object that can make requests to the database
let database = new MongoClient(usersDbURI , {});

// Rebuilds the connection string (MongoDB sessions database)
const sessionsDbURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_sessions_database}`;

// Creates a session storage adapter, enabling Express to save sessions in MongoDB instead of memory
const MongoStore = require("connect-mongo").default;
let sessionStore = MongoStore.create({
  mongoUrl: sessionsDbURI,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({
  secret: node_session_secret,
  store: sessionStore,
  saveUninitialized: false,
  resave: true
}));

// Gets the users collection from MongoDB
const userCollection = database.db(mongodb_users_database).collection("users")

const Joi = require("joi");

// Home Page
app.get("/", (req, res) => {
  let homeHTML;
  
  if(!req.session.authenticated){
    homeHTML =
    `<form action="signup" method="get">
        <button>Sign up</button>
      </form>
    `
    homeHTML += 
      `<form action="login" method="get">
        <button>Log in</button>
      </form>
    `
  }
  else{
    homeHTML = 
    `
    Hello, ${req.session.username}!
    <form action="members" method="get">
        <button>Members Area</button>
      </form>
    `
    homeHTML += 
      `<form action="logout" method="get">
        <button>Logout</button>
      </form>
    `
  }

  res.send(homeHTML);
});

// Sign Up Page
app.get("/signup", (req, res) => {
    let signupHTML = 
    `
    Create User
    <form action="signup" method="post">
      <input name="username" type="text" placeholder="username">
      <input name="email" type="email" placeholder="email">
      <input name="password" type="password" placeholder="password">
      <button>Submit</button>
    </form>
    `;
  res.send(signupHTML);
});

app.post("/signup", async (req, res) =>{
  let username = req.body.username;
  let email = req.body.email;
  let password = req.body.password;
  let hashedPassword; 

    // Validates and prevents injection attacks
  const schema = Joi.object({
      username: Joi.string().alphanum().max(20).required(),
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required()
    });
  
  const validationResult = schema.validate({username, email, password});

  if (validationResult.error != null){
    let errorMessage = `${validationResult.error.message} <br><br>
      <a href="/signup">Try again</a>
    `
    res.send(errorMessage);
    return;
  }

  hashedPassword = bcrypt.hashSync(password, saltRounds);

  // Prevent multiple users with the same user name
  let existingUser = await userCollection.findOne({email: email});
  if (existingUser){
    let errorMessage = `The email: ${email} is already taken<br><br>
      <a href="/signup">Try again</a>
    `
    res.send(errorMessage);
    return;
  }

  // Adds the user to the MongoDB users collection
  userCollection.insertOne({username: username, email: email, password: hashedPassword})

  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = oneHour; 

  req.session.save((err) => {
    if (err) console.error("Session save error:", err);
    else console.log("Session saved, ID:", req.session.id);
    res.redirect("/members");
  });
});

// Login Page
app.get("/login", (req, res) => {
  let loginHTML = 
    `
    Log In
    <form action="login" method="post">
      <input name="email" type="email" placeholder="email">
      <input name="password" type="password" placeholder="password">
      <button>Submit</button>
    </form>
    `;
  res.send(loginHTML);
});

app.post("/login", async(req, res) => {
let email = req.body.email;
let password = req.body.password;


// Validates and prevents injection attacks
const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required()
  });

const validationResult = schema.validate({email, password});

if (validationResult.error != null){
  res.redirect("/login");
  return;
}

const match = await userCollection.find({email:email}).project({email: 1, username: 1, password: 1, _id:1}).toArray();

if (match.length != 1){
  
  let errorMessage = `Invalid email, user does not exist! <br><br>
      <a href="/login">Try again</a>
    `
  res.send(errorMessage);
  return;
}

if (await bcrypt.compare(password, match[0].password)){
  req.session.authenticated = true;
  req.session.email = email;
  req.session.username = match[0].username;
  req.session.cookie.maxAge = oneHour; 
  res.redirect("members");
}
else{
  let errorMessage = `Incorrect Password! <br><br>
    <a href="/login">Try again</a>
  `
  res.send(errorMessage);
  return;
}
});

app.get("/logout", (req, res) =>{
  req.session.destroy();
  res.redirect("/");
});

app.get("/members", (req, res) => {
  let randNum = Math.floor(Math.random() * 3);
  let randImg;

  switch(randNum){
    case 0:{
      randImg = "<img src='1.png' style='width:250px;'>"
      break;
    }
    case 1:{
      randImg = "<img src='2.png' style='width:250px;'>"
      break;
    }
    case 2:{
      randImg = "<img src='3.png' style='width:250px;'>"
      break;
    }
  }

  if(req.session.authenticated){
    let memberHTML = `<h1>Hello, ${req.session.username}</h1>
      ${randImg} <br><br>
      <form action="logout" method="get">
        <button>Logout</button>
      </form>
    `
    res.send(memberHTML);
  }
  else{
    res.redirect("/");
  }
});

app.use((req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});