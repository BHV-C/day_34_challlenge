const express = require('express');
const app = express();
const port = 3001; // You can change this to your desired port number
const session = require('express-session');
const cookieParser = require('cookie-parser');

const csurf = require("csrf");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt"); // Library for password hashing
const { body, validationResult, cookie } = require("express-validator");
const rateLimit = require("express-rate-limit");
const xss = require("xss");

let isAuthenticated = false;
// let sessionId = session.userId;

const saltRounds = 10; 

// Dummy user data (replace this with your actual user database)
const users = [
    { id: 1, username: 'user1', passwordHash: bcrypt.hashSync('password1', saltRounds) ,role: 'user' },  
    { id: 2, username: 'user2', passwordHash: bcrypt.hashSync('password2', saltRounds) ,role: 'user'  },
    { id: 3, username: 'admin', passwordHash: 'admin',role: 'admin'  },
    { id: 4, username: 'alice', passwordHash: bcrypt.hashSync('admin123', saltRounds) ,role: 'user'  }
];

// this is to validate and sanitize login inputs
const loginValidator = [
    body("username", "Username cannot be empty").not().isEmpty(),
    body("password", "The minimum password length is 6 characters").isLength({
      min: 6,   
    }),
  ];

// this is for Rate Limiter in login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // Limit to 3 login attempts per IP within the window
  });

// Define a strong secret key for sessions (consider using an environment variable)
const secretKey =
  "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTY5NTY0NzAxOCwiaWF0IjoxNjk1NjQ3MDE4fQ.SMr1eGjU5OJW2Hxa0pzZHLi2a-y-njx2CteH5e0qL5c";


// function isAuthenticated(req, res, next) {
//     if (req.cookies.sessionId) {
//       // If a session identifier exists in the cookie, consider the user authenticated
//       return next();
//     } else {
//       // If there's no session identifier, redirect the user to the login page or handle it as needed
//       return res.redirect('/login'); // Redirect to the login page
//     }
// }

// Use the express-session middleware
// app.use(session({
    //     secret: 'your-secret-key', // Replace with your secret key for session encryption
    //     resave: false,
    //     saveUninitialized: true
    //   }));
    // Middleware
try {
app.use(
    session({
        secret: secretKey,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: false, //this make me debug for hours and it is simple
        },
    })
);
// app.use(express.urlencoded({ extended: true })); // Middleware to parse form data
const formParser = bodyParser.urlencoded({ extended: false });
app.use(cookieParser()); // Use cookie-parser middleware    

const csrfProtect = csurf({ cookie: true });
app.use(function (err, req, res, next) {
  if (err.code !== "EBADCSRFTOKEN") return next(err);

  // handle CSRF token errors here
  res.status(403);
  res.send("form tampered with");
});
app.use(express.json());

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    res.send('welcome to basic server'); // Renders the 'registration.ejs' template
});
        
        
// Render the registration form
app.get('/register', (req, res) => {
  res.render('registration', { error: "" });
});

// Handle registration logic (e.g., storing users in an array)
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    // Pass the error message to the template
    return res.render("register", { error: "Username already exists" });
  }
  // Hash the password
  const passwordHash = bcrypt.hashSync(password, saltRounds);

  
  // Create a new user object and add it to the array
  const newUser = {
    id: users.length + 1,
    username,
    passwordHash,
    role: "user", // You can set the role as needed
  };

  users.push(newUser);

  users.push({ id: users.length + 1, username, password });
  res.redirect('/login');
});

// Render the login form
app.get('/login', (req, res) => {
  res.render('login');
});
// app.get("/login", csrfProtect, (req, res) => {
//     const errors = []; // Create an empty errors array
//     res.render("login", { csrfToken: req.csrfToken(), errors }); // Pass the errors array to the template
//   });


// Handle login authentication
app.post('/login', async (req, res) => { // async
  const { username, password } = req.body;

  // Check if the provided username and password match any registered user
  const user = users.find((user) => user.username === username);

  if (user && await bcrypt.compare(password, user.passwordHash)) { // && await bcrypt.compare(passwordd, user.passwordHash)
    // Create a session and store the user's unique identifier (in this case, user id)
    req.session.userId = user.id;
    sessionId = req.session.userId;

    
    
    // Set the session identifier as a cookie
    res.cookie('sessionId', sessionId);
    res.send('Login successful'); // Replace with your authentication logic
  } else {
    res.send(`username is ${username} and the given password is ${password}`); 
    // res.send('Login failed. Invalid credentials.'); // Replace with your error handling logic
  }
});

// app.post(
//     "/login",
//     formParser,
//     csrfProtect,
//     loginLimiter,
//     loginValidator,
//     (req, res) => {
//       try {
//         const { username, password } = req.body;
//         const errors = validationResult(req);
//         if (!errors.isEmpty()) {
//           return res.render("login", {
//             csrfToken: req.csrfToken(),
//             errors: "Invalid username or password",
//             errors: errors.array(), // Pass the errors array to the template
//           });
//         }
//         const sanitizedData = {
//           name: xss(username),
//           password: xss(password),
//         };
  
//         // Validate and authenticate the user securely
//         const user = users.find((u) => u.username === sanitizedData.name);
//         if (
//           user &&
//           bcrypt.compareSync(sanitizedData.password, user.passwordHash)
//         ) {
//           if (username === sanitizedData.name || password === user.passwordHash) {
//             req.session.isAuthenticated = true;
//             isAuthenticated = true;
//             req.session.username = username; // Set the username in the session
//             res.send('Login successful');
//             res.redirect("/protected");
//           } else {
//             res.redirect("/");
//           }
//         } else {
//           // Redirect to '/' if the username or password is incorrect
//           res.send('Login successful');
//           res.render("login", { csrfToken: req.csrfToken(), errors: "Invalid username or password" });
//           res.redirect("/login");
//         }
//       } catch (errors) {
//         console.error("Error during login:", errors);
//         res.redirect("/");
//       }
//     }
// );


// Middleware to check if the user is authenticated

// Protected route that can only be accessed by authenticated users
app.get('/protected', (req, res) => {
    if(!isAuthenticated){
        res.send('This is a protected route.'); 
    } else {
        res.render("protected");
    }
});

const escapeHtml = (unsafe) => {
    return unsafe.replace(/[&<"']/g, (match) => {
      switch (match) {
        case "&":
          return "&amp;";
        case "<":
          return "&lt;";
        case ">":
          return "&gt;";
        case '"':
          return "&quot;";
        case "'":
          return "&#39;";
      }
    });
};

app.get("/home", (req, res) => { // , csrfProtect
    if (isAuthenticated) {
        const username = req.session.username; // Retrieve the username from the session
        res.render("home", { username, escapeHtml, csrfToken: req.csrfToken() });
        document.alert("redirected");
    } else {
        res.send("you ve been redirected to the login page from home page");
        res.redirect("/login");
    }
});
  

app.get("/logout", function (req, res, next) {
    if (req.session) {
      // delete session object
      req.session.destroy(function (err) {
        if (err) {
          return next(err);
        } else {
          return res.redirect("/login");
        }
      });
    }
  });
}catch (err) {
    console.error(err);
};
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
