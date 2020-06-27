//jshint esversion:6
require("dotenv").config()
const express = require("express");
const app = express();
const bodyParser = require("body-parser")
const ejs = require("ejs")
const saltRounds = 10;
const session = require("express-session")
const LocalStrategy = require("passport-local").Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const passport = require("passport")
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
var findOrCreate = require("mongoose-findorcreate")


app.use(bodyParser.urlencoded({ extended: true }))
app.set("view engine", "ejs");
app.use(express.static("public"))
app.use(session({
  secret: "this is our secret",
  resave: false,
  saveUninitialized: false,

}))
app.use(passport.initialize());
app.use(passport.session());

const mongoose = require("mongoose");


mongoose.connect("mongodb://localhost/userDB", {useNewUrlParser: true ,useUnifiedTopology: true});
mongoose.set("useNewUrlParser", true);
mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId : String,
    facebookId : String,
    secret : String

});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",

  } ,
  (accessToken, refreshToken, profile, cb) =>{
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });



app.get("/" , (req,res)=>{
  res.render("home")
})
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

  app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
      res.redirect("/secrets");
    });

app.get("/secrets" ,(req ,res)=>{
  User.find({"secret" : {$ne : null}} , (err , foundUser)=>{
    if (err) {
      console.log(err)
    }
    if(foundUser){
      res.render("secrets" , {usersSecrets : foundUser})
    }
  })
  }
)

app.route("/register")

.get ((req,res)=>{
  res.render("register")
})

.post((req,res)=> {

  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register")
     }
     else {
       passport.authenticate("local")(req,res,()=>{
         res.redirect("/secrets")
         console.log("registered")
       })
     }

  });

});


app.get("/login", (req,res)=>{
  res.render("login")
})



app.post("/login" ,(req , res)=>{
  const user = new User({
    username : req.body.username,
    password : req.body.password
  });
  req.login(user, function(err) {
  if (err) {
    console.log(err)
  }
  else {
    passport.authenticate("local")(req,res,()=>{
      res.redirect("/secrets");
      console.log("login successfully")
    })
  }
});

})

app.get("/submit" , (req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else {
    res.redirect("/login")
    console.log("not authenticated")
  }
})

app.post("/submit" , (req,res)=>{

  const submittedSecret = req.body.secret
  User.findById(req.user.id , (err,foundedUser)=>{
    if (err){
      console.log(err)
    }
    if (foundedUser){
      foundedUser.secret = submittedSecret;
      foundedUser.save(()=>{
        res.redirect("/secrets")
      })
    }
  })
})

app.get("/logout", (req,res)=>{
  req.logout();
  res.redirect("/");
})



app.listen(3000 , ()=>console.log("Secret app listening on 3000"))
