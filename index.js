const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt=require('bcrypt');

mongoose
  .connect("mongodb://127.0.0.1:27017", {
    dbName: "backend",
  })
  .then((c) => console.log("connected"))
  .catch((e) => console.log(e));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const user = mongoose.model("User", userSchema);

const app = express();

app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.set("view engine", "ejs");

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});


app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const decoded = jwt.verify(token, "amulsharma");

    req.user = await user.findById(decoded._id);
    next();
  } else {
    res.redirect("/login");
  }
};
app.get("/", isAuthenticated, (req, res) => {
    console.log(req.user);
    res.render("logout.ejs", { name: req.user.name });
  });
  

app.post("/register", async (req, res) => {
  let existingUser = await user.findOne({ email: req.body.email });

  if (existingUser) {
    return res.redirect("/login");
  }
  const hashedPassword= await bcrypt.hash(req.body.password,10);

  const newUser = await user.create({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  });

  const token = jwt.sign({ _id: newUser.id }, "amulsharma");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60000),
  });
  res.redirect("/");
});

app.post("/login",async(req,res)=>{
    let existUser = await user.findOne({ email: req.body.email });

    if(!existUser) return res.redirect('/register');

    const isMatch=await bcrypt.compare(req.body.password,existUser.password);

    if(!isMatch){
        return res.render('login.ejs', {message :"incorrect password"})
    }

    const token = jwt.sign({ _id: existUser.id }, "amulsharma");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60000),
  });
  res.redirect("/");

})

app.listen(5000, () => {
  console.log("server running");
});
