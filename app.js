const path = require("path");
const crypto = require("crypto");

const express = require("express");
const mongoose = require("mongoose");

// hash pass strongly
const bcrypt = require("bcrypt");
// handle csrf
const jwt = require("jsonwebtoken");
const cors = require("cors");
// handle xss
const { body, validationResult } = require("express-validator");
const helmet = require("helmet");
// logger
const winston = require("winston");
const morgan = require("morgan");
// structurized error object creator
const createError = require("http-errors");
// performance metrics dashboard
const expressStatusMonitor = require("express-status-monitor");
// api rate limit
const expressRateLimit = require("express-rate-limit");

const {
  SESClient,
  SendEmailCommand,
  VerifyEmailIdentityCommand,
} = require("@aws-sdk/client-ses");

require("dotenv").config();

var indexRouter = require("./routes/index");
var usersRouter = require("./routes/users");

const {
  WS_SECRET: awsSecret,
  WS_REGION: awsRegion,
  WS_ACCESS_Id: awsId,
  TOKEN_SECRET: secret,
  DATABASE_STRING,
  SOURCE: source,
  NODE_ENV,
} = process.env;

const app = express();

// set env
app.set("env", NODE_ENV || "development");

// mount routes
app.use("/", indexRouter);
app.use("/users", usersRouter);

// parser incoming json and urlencoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// handle csrf
app.use(
  cors({
    origin: [
      "https://social.d2b65wp3mxn1jy.amplifyapp.com/",
      "https://main.d2b65wp3mxn1jy.amplifyapp.com/",
      "http://localhost:3000",
      "http://localhost:3001",
    ],
    methods: ["PUT", "DELETE", "GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("base64");
  next();
});

const cspConfig = (req, res) => {
  return {
    directives: {
      defaultSrc: [`'self'`],
      scriptSrc: [
        `'self'`,
        "https://cdnjs.cloudflare.com",
        NODE_ENV === "development"
          ? `'unsafe-inline'`
          : `'nonce-${res.locals.nonce}'`,
      ],
      styleSrc: [
        `'self'`,
        "https://cdnjs.cloudflare.com",
        NODE_ENV === "development"
          ? `'unsafe-inline'`
          : `'nonce-${res.locals.nonce}'`,
      ],
      imgSrc: [`'self'`, "data:"],
      fontSrc: [`'self'`],
      connectSrc: [
        `'self'`,
        "http://localhost:3000",
        "http://localhost:3001",
        "https://social.d2b65wp3mxn1jy.amplifyapp.com/",
        "https://main.d2b65wp3mxn1jy.amplifyapp.com/",
      ],
      baseUri: [`'self'`],
      mediaSrc: [`'self'`],
      frameSrc: [`'self'`],
      objectSrc: [`'none'`],
      frameAncestors: [`'none'`],
      formAction: [`'self'`],
      reportUri: ["/report-csp-violation"],
      upgradeInsecureRequests: [],
    },
    reportOnly: false,
    browserSniff: false,
    disableAndroid: false,
  };
};

app.use((req, res, next) => {
  const config = cspConfig(req, res);
  if (NODE_ENV === "production") {
    delete config.directives.upgradeInsecureRequests;
    config.reportOnly = true;
  }
  helmet.contentSecurityPolicy(config)(req, res, next);
});

const cspJsonParser = express.json({
  type: "application/csp-report",
  limit: "1mb",
});

const validateCspReport = [
  body("csp-report").isObject(),
  body("csp-report.document-url").isURL().escape(),
  body("csp-report.violated-directive").isString().escape(),
  body("csp-report.effective-directive").isString().escape(),
  body("csp-report.blocked-uri").isString().escape(),
  body("csp-report.original-policy").isString().escape(),
];

const cspLogger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  level: "info",
  transports: [
    new winston.transports.File({
      filename: "csp-report.log",
      level: "info",
    }),
  ],
});

if (NODE_ENV !== "production") {
  cspLogger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

// Middleware to handle CSP violation reports
app.post(
  "/report-csp-violation",
  cspJsonParser,
  validateCspReport,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
    }

    const report = req.body["csp-report"];

    cspLogger.warn("CSP violation", {
      "document-uri": report["document-uri"],
      "violated-directive": report["violated-directive"],
      "original-policy": report["original-policy"],
      "blocked-uri": report["blocked-uri"] || "N/A",
      userAgent: req.get("User-Agent"),
      ip: req.ip,
    });

    cspLogger.info("CSP Violation: ", report);
    console.log("CSP Violation: ", report);

    res.status(204).end();
  }
);

// Example endpoint that could trigger a CSP violation
app.get("/vio", (req, res) => {
  const scriptEl = `<script nonce='${res.locals.nonce}'>alert("Hello, world!")</script>`;
  res.send(`
    <html>
      <head>
        <title>CSP Example</title>
      </head>
      <body>
        <p>Listen</p>
        <audio unsafe-inline src="https://github.com/farhan7reza7/farhan7reza7-3/blob/main/audio.mp3">Listener</audio>
        <h1>o, w...!</h1>
        ${scriptEl}
      </body>
    </html>
  `);
});

// limit api rate
const limiter = expressRateLimit({
  windowMs: 45 * 1000 * 60,
  max: 200,
  message: "Too many requests from this IP, please try again later.",
  headers: true,
});
// limit api rate globally
app.use(limiter);

// centralized logging and monitoring
// config winston
const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  level: "info",
  transports: [
    new winston.transports.File({
      filename: "error.log",
      level: "error",
    }),
    new winston.transports.File({
      filename: "combined.log",
      level: "info",
    }),
  ],
});

if (NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

logger.stream = {
  write: function (message) {
    // Use the 'info' log level so the output will be picked up by both transports (file and console)
    logger.info(message.trim());
  },
};

// set morgan to use winston logging system
app.use(morgan("combined", { stream: logger.stream }));

// app metrics monitoring
app.use(expressStatusMonitor());

mongoose.connect(DATABASE_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const sesClient = new SESClient({
  region: awsRegion,
  credentials: {
    accessKeyId: awsId,
    secretAccessKey: awsSecret,
  },
});

const messageCreator = (text, email) => {
  const messageData = {
    Destination: {
      ToAddresses: [email],
    },
    Message: {
      Body: {
        Text: {
          Data: text,
          Charset: "UTF-8",
        },
      },
      Subject: {
        Data: "Account verification",
        Charset: "UTF-8",
      },
    },
    Source: source,
  };
  return messageData;
};

const UserSchema = new mongoose.Schema({
  username: { type: String, required: false },
  password: { type: String, required: false },
  email: { type: String, required: true, unique: true },
  tasks: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Task",
    },
  ],
});

const User = mongoose.model("User", UserSchema);

const Task = mongoose.model("Task", {
  content: String,
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
});

async function deleter() {
  await User.deleteMany();
  const data = await User.find();
  console.log("users: ", data);
}

const generateToken = (payload, config = {}) => {
  return jwt.sign(payload, secret, config);
};

const verifyToken = (token) => {
  jwt.verify(token, secret, (err, decode) => {
    if (err) {
      return false;
    } else {
      return decode;
    }
  });
};

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    res.status(401).json({ message: "not autheticated user" });
  }
  const token = authHeader.split(" ")[1];
  if (token) {
    const verified = verifyToken(token);
    if (verified === false) {
      res.status(403).json({
        message: "authentication failed",
      });
    } else {
      req.user = verified;
      next();
    }
  } else {
    res.status(401).json({ message: "not autheticated user" });
  }
};

app.get("/current", async (req, res, next) => {
  try {
    const { email, id } = req.query;
    const user = await User.findOne({
      email: email,
    });
    const token = generateToken({ id });
    if (user) {
      const userId = user._id;
      console.log("user in run");
      res.status(200).json({ valid: true, userId, token });
    } else {
      const newUser = new User({ email });
      const userId = newUser._id;
      await newUser.save();
      console.log("user up run");
      res.json({ valid: true, userId, token });
    }
    console.log("user not in and up work");
  } catch (error) {
    console.log("user error block  run");
    //res.json({ valid: false, mess: "issue" });
    next(error);
  }
});

app.post(
  "/login",
  [body("username").isString().escape(), body("password").isString().escape()],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ erros: errors.array() });
    }

    const details = req.body;
    try {
      const user = await User.findOne({
        username: details.username,
      });
      if (user && (await bcrypt.compare(details.password, user.password))) {
        const token = generateToken(
          { userId: user._id },
          {
            expiresIn: "1m",
          }
        );

        const verificationLink = `http://localhost:3000/api/verify-mfa?token=${token}&userId=${user._id}`;

        const messageData = messageCreator(
          `Please click this link to log in to your account ${verificationLink}`,
          (email = user.email)
        );

        const command = new SendEmailCommand(messageData);
        sesClient
          .send(command)
          .then(() => {
            res.status(200).json({
              valid: true,
              userId: user._id,
              token,
              message: "Please check the mfa link in your email",
            });
          })
          .catch((error) => {
            res.status(500).json({ message: error.message });
          });
      } else {
        res.json({ valid: false, message: "Please fill correct details" });
      }
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/register",

  [
    body("username").isString().escape(),
    body("password").isString().escape(),
    body("email").isEmail().normalizeEmail(),
  ],

  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ erros: errors.array() });
    }
    const details = req.body;
    try {
      const user = await User.findOne({ username: details.username });
      if (!user) {
        const hashedPass = await bcrypt.hash(details.password, 10);

        const token = generateToken(
          { username: details.username },
          {
            expiresIn: 30,
          }
        );

        const otp = token.slice(-6);
        const messageData = messageCreator(
          `Use otp below\n\notp: ${otp}`,
          (email = details.email)
        );

        const command = new SendEmailCommand(messageData);

        sesClient
          .send(command)
          .then(() => {
            res.status(200).json({
              valid: true,
              username: details.username,
              email: details.email,
              password: hashedPass,
              token,
              message: "Please check the otp in your linked email",
            });
          })
          .catch((error) => {
            res.status(500).json({ message: error.message });
          });
      } else {
        res.json({
          valid: false,
          message: "Username already exists, please choose another username",
        });
      }
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/forget",
  [
    body("email").isEmail().normalizeEmail(),
    body("username").isString().escape(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
    }

    const { email, username } = req.body;

    try {
      const user = await User.findOne({ username: username, email: email });
      if (user) {
        const token = generateToken(
          { userId: user._id },
          {
            expiresIn: "1m",
          }
        );

        const verificationLink = `http://localhost:3000/api/verify-email?token=${token}&userId=${user._id}`;
        const messageData = messageCreator(
          `Please click this link to reset your password ${verificationLink}`,
          email
        );

        const command = new SendEmailCommand(messageData);
        sesClient
          .send(command)
          .then(() => {
            res.status(200).json({
              valid: true,
              userId: user._id,
              token,
              message: "Please click the verification link in your email",
            });
          })
          .catch((error) => {
            res
              .status(500)
              .json({ message: error.message + " error in sending request" });
          });
      } else {
        res.json({
          valid: false,
          message: "Please fill correct details",
        });
      }
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/verify-email",
  [body("email").isEmail().normalizeEmail()],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
      await sesClient
        .send(new VerifyEmailIdentityCommand({ EmailAddress: email }))
        .then(() => {
          res.json({
            message: "Please check the verification link in your email",
          });
        })
        .catch((error) => {
          res.json({
            message: "Please fill correct email: " + error.message,
          });
        });
    } catch (error) {
      res.json({
        message: "Please fill correct email: " + error.message,
      });
    }
  }
);

app.get("/verify-mfa", async (req, res, next) => {
  try {
    const { token, userId } = req.query;
    const verified = verifyToken(token);
    if (verified === false) {
      res.redirect(`http://localhost:3000/timeout`);
    } else {
      const tokenz = generateToken({ userId });
      res.redirect(`http://localhost:3000?token=${tokenz}&userId=${userId}`);
    }
  } catch (error) {
    next(error);
  }
});

app.get("/verify-user", async (req, res, next) => {
  try {
    const { token, userId } = req.query;
    const verified = verifyToken(token);
    if (verified === false) {
      res.json({ valid: false });
    } else {
      const user = await User.findById(userId);
      if (user) {
        const tokenz = generateToken({ userId });
        res.json({ valid: true, token: tokenz });
      } else {
        res.json({ valid: false });
      }
    }
  } catch (error) {
    next(error);
  }
});

app.post(
  "/verify-mfa",
  [
    body("username").isString().escape(),
    body("password").isString().escape(),
    body("email").isEmail().normalizeEmail(),
    body("token").isString().escape(),
    body("otp").isString().escape(),
  ],

  authenticate,
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
    }

    const { token, username, password, email, otp } = req.body;
    try {
      const verified = verifyToken(token);
      if (verified === false) {
        res.json({
          valid: false,
          message:
            otp === token.slice(-6)
              ? "otp expired, please generate new otp"
              : "please enter correct otp",
        });
      } else {
        if (otp === token.slice(-6)) {
          const newUser = new User({
            username: username,
            email: email,
            password: password,
          });
          await newUser.save();
          const tokenz = generateToken({ userId: newUser._id });
          res.json({
            valid: true,
            token: tokenz,
            user: newUser.username,
            userId: newUser._id,
            message: "otp verified successfully",
          });
        } else {
          res.json({ valid: false, message: "please fill correct otp" });
        }
      }
    } catch (error) {
      next(error);
    }
  }
);

app.get("/verify-email", async (req, res, next) => {
  const { token, userId } = req.query;
  const verified = verifyToken(token);
  if (verified === false) {
    res.redirect(`http://localhost:3000/timeout`);
  } else {
    res.redirect(`http://localhost:3000/reset?token=${token}&userId=${userId}`);
  }
});

app.post(
  "/reset",
  [body("userId").isString().escape(), body("password").isString().escape()],
  authenticate,
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
    }
    const { password, userId } = req.body;
    try {
      const user = await User.findById(userId);
      if (user) {
        const hashedPass = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate(userId, {
          password: hashedPass,
        });
        res.json({ valid: true, message: "password reset successfully" });
      } else {
        res.json({
          valid: false,
          message: "Please use verification link to reset password",
        });
      }
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/task",
  authenticate,
  [body("content").isString().escape(), body("userId").isString().escape()],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
    }
    const { content, userId } = req.body;

    try {
      const user = await User.findById(userId);
      if (!user) {
        res.status(404).json({ message: "user not found" });
      }
      const task = await Task({ content, user: user._id });
      await task.save();
      user.tasks.push(task._id);
      await user.save();
      res.json({ message: "added successfully" });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/tasks", authenticate, async (req, res, next) => {
  try {
    const { userId } = req.query;
    const user = await User.findById(userId).populate("tasks");
    if (!user) {
      res.status(404).json({ message: "user not found" });
    } else {
      res.status(200).json({ tasks: user.tasks });
    }
  } catch (error) {
    console.error("\n\n\n\ntry not work in tasks: ", error.message, "\n\n\n\n");
    next(error);
  }
});

// create 404 error object
app.use(function (req, res, next) {
  next(createError(404, "Not Found 404!"));
});

// error handler
app.use((err, req, res, next) => {
  logger.error({
    message: err.message,
    stack: err.stack,
    request: {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body,
    },
  });

  const statusCode = err.statusCode || 500;

  const response = {
    status: "error",
    statusCode,
    message: statusCode === 500 ? "Server internal error" : err.message,
  };

  if (req.app.get("env") === "development") {
    response.stack = err.stack;
    response.request = {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body,
    };
  }

  res.status(statusCode).json(response);
});

module.exports = app;
