
export const esmFolders = [
  'src/config',
  'src/controllers',
  'src/models',
  'src/routes',
  'src/middlewares',
  'src/services',
  'src/utils',
  'src/validations',
  'src/constants',
  'docs',
  'logs',
  'public',
  'uploads',
  'tests',
];

export const esmFiles = {
  'package.json': `{
  "name": "rest-api",
  "version": "1.0.0",
  "type": "module",
  "main": "index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest --coverage",
    "lint": "eslint .",
    "format": "prettier --write .",
    "docs": "apidoc -i routes/ -o docs/"
  },
  "dependencies": {
    "express": "^4.18.2",
    "dotenv": "^16.3.1",
    "mongoose": "^8.0.3",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0",
    "winston": "^3.11.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "express-rate-limit": "^6.7.0",
    "express-validator": "^7.0.1",
    "swagger-ui-express": "^5.0.0",
    "yamljs": "^0.3.0",
    "prom-client": "^15.1.3"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.56.0",
    "prettier": "^3.1.1",
    "apidoc": "^0.53.1"
  }
}`,
  '.gitignore': `node_modules
.env
*.log
.DS_Store
coverage
uploads/*
!uploads/.gitkeep
`,
  '.env': `# App Configuration
PORT=5000
NODE_ENV=development

# Database Configuration
DB_URI=mongodb://localhost:27017/restapi
DB_TEST_URI=mongodb://localhost:27017/restapi_test

# JWT Configuration
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRE=30d
JWT_COOKIE_EXPIRE=30

# Rate Limiting
RATE_LIMIT_WINDOW_MS=15*60*1000 # 15 minutes
RATE_LIMIT_MAX=100

# Email Configuration (TODO: Configure for production)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_EMAIL=your_email@example.com
SMTP_PASSWORD=your_email_password
FROM_EMAIL=noreply@example.com
FROM_NAME=REST API
`,
  '.env.example': `# App Configuration
PORT=5000
NODE_ENV=development

# Database Configuration
DB_URI=mongodb://localhost:27017/restapi
DB_TEST_URI=mongodb://localhost:27017/restapi_test

# JWT Configuration
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRE=30d
JWT_COOKIE_EXPIRE=30

# Rate Limiting
RATE_LIMIT_WINDOW_MS=15*60*1000 # 15 minutes
RATE_LIMIT_MAX=100

# Email Configuration (TODO: Configure for production)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_EMAIL=your_email@example.com
SMTP_PASSWORD=your_email_password
FROM_EMAIL=noreply@example.com
FROM_NAME=REST API
`,
  '.eslintrc.json': `{
  "extends": ["eslint:recommended"],
  "env": {
    "node": true,
    "es2021": true
  },
  "parserOptions": {
    "ecmaVersion": "latest",
    "sourceType": "module"
  },
  "rules": {
    "indent": ["error", 2],
    "linebreak-style": ["error", "unix"],
    "quotes": ["error", "single"],
    "semi": ["error", "always"]
  }
}`,
  '.prettierrc': `{
  "semi": true,
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "trailingComma": "es5"
}`,
  'src/index.js': `import express from 'express';
import cors from 'cors';
import config from './config/index.js';
import helmet from 'helmet';
import path from 'path';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';
import logger from './utils/logger.js';
import db from './config/database.js'; 
import { errorResponse } from './utils/responseHandler.js';

// Create Express app
const app = express();

// Database connection
db();

// Middlewares
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Rate limiting
const limiter = rateLimit({
  windowMs: process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000, // 15 minutes
  max: process.env.RATE_LIMIT_MAX || 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Static files
app.use('/public', express.static(path.join(__dirname, '../public')));

// Swagger documentation
const swaggerDocument = YAML.load(path.join(__dirname, '../docs/swagger.yaml'));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Routes
import routes from './routes/index.js';
app.use('/api', routes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Resource not found' });
});

// Error handler
app.use((err, req, res) => {
  logger.error(\`Error: \${err.message}\`, config.env === 'development' ? err : undefined);
  errorResponse(res, err);
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  logger.info(\`Server running in \${config.env} mode on port \${PORT}\`);
});

export default app; // for testing`,
  'src/config/index.js': `import dotenv from 'dotenv';

dotenv.config();

export default {
  env: process.env.NODE_ENV,
  port: process.env.PORT,
  mongoose: {
    url: process.env.DB_URI + (process.env.NODE_ENV === 'test' ? '_test' : ''),
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    },
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRE,
    cookieExpires: process.env.JWT_COOKIE_EXPIRE,
  },
  rateLimit: {
    windowMs: process.env.RATE_LIMIT_WINDOW_MS,
    max: process.env.RATE_LIMIT_MAX,
  },
  email: {
    smtp: {
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD,
      },
    },
    from: process.env.FROM_EMAIL,
    fromName: process.env.FROM_NAME,
  },
};`,
  'src/config/database.js': `import mongoose from 'mongoose';
import config from './index.js';
import logger from '../utils/logger.js';

// TODO: Configure database connection pooling
// TODO: Add database transaction support
// TODO: Implement database migration system

const connectDB = async () => {
  try {
    await mongoose.connect(config.mongoose.url, config.mongoose.options);
    logger.info('Connected to MongoDB');
  } catch (err) {
    logger.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

export default connectDB;`,
  'src/utils/logger.js': `import winston from 'winston';
import path from 'path';
import config from '../config/index.js';
  
// TODO: Configure logging levels based on environment
// TODO: Implement log rotation for production
// TODO: Add error tracking service integration (Sentry, etc.)
  
const transports = [];
  
if (config.env === 'production') {
  transports.push(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
    new winston.transports.File({
      filename: path.join(__dirname, '../../logs/error.log'),
      level: 'error',
    }),
    new winston.transports.File({
      filename: path.join(__dirname, '../../logs/combined.log'),
    })
  );
} else {
  transports.push(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    })
  );
}
  
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports,
});
  
export default logger;
`,
  'src/utils/apiError.js': `export default class ApiError extends Error {
  constructor(statusCode, message, isOperational = true, stack = '') {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}`,
  'src/utils/responseHandler.js': `import logger from './logger.js';
import config from '../config/index.js';

/**
 * Success response handler
 * @param {Object} res - Express response object
 * @param {*} data - Response data
 * @param {number} [statusCode=200] - HTTP status code
 * @param {string} [message='Success'] - Response message
 */
export const successResponse = (res, data, statusCode = 200, message = 'Success') => {
  logger.info(\`Response: \${message}\`, config.env === 'development' ? data : undefined);
  res.status(statusCode).json({
    success: true,
    message,
    data,
  });
};

/**
 * Error response handler
 * @param {Object} res - Express response object
 * @param {Error} error - Error object
 */
export const errorResponse = (res, error) => {
  const statusCode = error.statusCode || 500;
  const message = error.message || 'Internal Server Error';
  res.status(statusCode).json({
    success: false,
    message,
    error: config.env === 'development' ? error.stack : undefined,
  });
};`,
  'src/middlewares/auth.js': `import jwt from 'jsonwebtoken';
import ApiError from '../utils/apiError.js';
import config from '../config/index.js';

// TODO: Implement role-based access control (RBAC)
// TODO: Add token blacklisting for logout functionality
// TODO: Implement refresh token mechanism

const auth = () => {
  return async (req, res, next) => {
    try {
      // 1) Get token from header or cookies
      let token;
      if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
      ) {
        token = req.headers.authorization.split(' ')[1];
      } else if (req.cookies?.token) {
        token = req.cookies.token;
      }

      if (!token) {
        throw new ApiError(401, 'Please authenticate to access this resource');
      }

      // 2) Verify token
      const decoded = jwt.verify(token, config.jwt.secret);

      // 3) Attach user to request object
      req.user = decoded;

      next();
    } catch (err) {
      next(err);
    }
  };
};

export default auth;`,
  'src/middlewares/error.js': `import ApiError from '../utils/apiError.js';
import logger from '../utils/logger.js';
import config from '../config/index.js';

// TODO: Add more specific error handling for different error types
// TODO: Implement error tracking integration

export const errorConverter = (err, req, res, next) => {
  let error = err;
  if (!(error instanceof ApiError)) {
    const statusCode = error.statusCode || 500;
    const message = error.message || 'Internal Server Error';
    error = new ApiError(statusCode, message, false, err.stack);
  }
  next(error);
};

export const errorHandler = (err, req, res, next) => {
  const { statusCode, message } = err;
  
  logger.error(\`Error \${statusCode}: \${message}\`);
  
  res.locals.errorMessage = message;

  res.status(statusCode).json({
    success: false,
    message,
    ...(config.env === 'development' && { stack: err.stack }),
  });
};`,
  'src/middlewares/validate.js': `import { validationResult } from 'express-validator';

// TODO: Add more validation rules as needed
// TODO: Implement custom validation messages

const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map((validation) => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    const extractedErrors = [];
    errors.array().map((err) => extractedErrors.push({ [err.param]: err.msg }));

    return res.status(422).json({
      success: false,
      errors: extractedErrors,
    });
  };
};

export default validate;`,
  'src/routes/index.js': `import express from 'express';
const router = express.Router();
  
// Mount your routes
import userRoutes from './user.routes.js';
import healthRoutes from './health.routes.js';
import metricsRoutes from './metrics.routes.js';
import docsRoutes from './docs.routes.js';
import authRoutes from './auth.routes.js';

router.use('/users', userRoutes); 
router.use('/health', healthRoutes);
router.use('/metrics', metricsRoutes);
router.use('/docs', docsRoutes);
router.use('/auth', authRoutes);
  
export default router;`,
  'src/routes/health.routes.js': `import express from 'express';
import mongoose from 'mongoose';
const router = express.Router();

router.get('/', async (req, res) => {
  const healthcheck = {
    uptime: process.uptime(),
    message: 'OK',
    timestamp: Date.now(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  };
  res.status(200).json(healthcheck);
});

export default router;`,
  'src/routes/metrics.routes.js': `import client from 'prom-client';
import express from 'express';
const router = express.Router();

client.collectDefaultMetrics();

router.get('/', async (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.end(await client.register.metrics());
});

export default router;`,
  'src/routes/auth.routes.js': `import express from 'express';
import authController from '../controllers/auth.controller.js';
import validate from '../middlewares/validate.js';
import authValidation from '../validations/auth.validation.js';

const router = express.Router();

// TODO: Add rate limiting for auth routes
// TODO: Implement password reset routes

router.post(
  '/register',
  validate(authValidation.register),
  authController.register
);
router.post('/login', validate(authValidation.login), authController.login);
router.post('/logout', authController.logout);
router.post(
  '/refresh-token',
  validate(authValidation.refreshToken),
  authController.refreshToken
);

export default router;`,
  'src/routes/user.routes.js': `import express from 'express';
import auth from '../middlewares/auth.js';
import userController from '../controllers/user.controller.js';
import validate from '../middlewares/validate.js';
import userValidation from '../validations/user.validation.js';

const router = express.Router();

// TODO: Add more user-related routes as needed
// TODO: Implement user profile picture upload

router.use(auth());

router
  .route('/')
  .get(userController.getUsers)
  .post(validate(userValidation.createUser), userController.createUser);

router
  .route('/:userId')
  .get(validate(userValidation.getUser), userController.getUser)
  .patch(validate(userValidation.updateUser), userController.updateUser)
  .delete(validate(userValidation.deleteUser), userController.deleteUser);

export default router;`,
  'src/routes/docs.routes.js': `import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// TODO: Add API documentation authentication in production
// TODO: Implement versioned documentation

router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../../docs/index.html'));
});

export default router;`,
  'src/controllers/auth.controller.js': `import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import ApiError from '../utils/apiError.js';
import { successResponse, errorResponse } from '../utils/responseHandler.js';
import config from '../config/index.js';
import logger from '../utils/logger.js';
import User from '../models/user.model.js';

// TODO: Implement email verification
// TODO: Add password reset functionality
// TODO: Implement 2FA (Two-Factor Authentication)

const register = async (req, res, next) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ApiError(400, 'Email already in use');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || 'user',
    });

    // Generate JWT token
    const token = generateToken(user);

    successResponse(res, { user, token }, 201, 'User registered successfully');
  } catch (err) {
    logger.error(\`Register error: \${err.message}\`);
    errorResponse(res, err);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      throw new ApiError(401, 'Invalid credentials');
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new ApiError(401, 'Invalid credentials');
    }

    // Generate JWT token
    const token = generateToken(user);

    // Set cookie
    res.cookie('token', token, {
      expires: new Date(
        Date.now() + config.jwt.cookieExpires * 24 * 60 * 60 * 1000
      ),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });

    successResponse(res, { user, token }, 200, 'Login successful');
  } catch (err) {
    logger.error(\`Login error: \${err.message}\`);
    errorResponse(res, err);
  }
};

const logout = (req, res, next) => {
  try {
    res.cookie('token', 'none', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    });

    successResponse(res, null, 200, 'User logged out successfully');
  } catch (err) {
    logger.error(\`Logout error: \${err.message}\`);
    errorResponse(res, err);
  }
};

const refreshToken = async (req, res, next) => {
  try {
    // TODO: Implement refresh token logic
    throw new ApiError(501, 'Refresh token functionality not implemented yet');
  } catch (err) {
    logger.error(\`Refresh token error: \${err.message}\`);
    errorResponse(res, err);
  }
};

const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      role: user.role,
    },
    config.jwt.secret,
    {
      expiresIn: config.jwt.expiresIn,
    }
  );
};

export default {
  register,
  login,
  logout,
  refreshToken,
};`,
  'src/controllers/user.controller.js': `import ApiError from '../utils/apiError.js';
import { successResponse, errorResponse } from '../utils/responseHandler.js';
import User from '../models/user.model.js';
import logger from '../utils/logger.js';

// TODO: Implement user profile picture upload
// TODO: Add user activity tracking
// TODO: Implement user search and filtering

const getUsers = async (req, res, next) => {
  try {
    // Pagination
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const skip = (page - 1) * limit;

    // Query
    const users = await User.find()
      .skip(skip)
      .limit(limit)
      .select('-password');

    const count = await User.countDocuments();

    successResponse(res, {
      users,
      pagination: {
        total: count,
        pages: Math.ceil(count / limit),
        currentPage: page,
      },
    });
  } catch (err) {
    logger.error(\`Get users error: \${err.message}\`);
    errorResponse(res, err);
  }
};

const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId).select('-password');
    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    successResponse(res, user);
  } catch (err) {
    logger.error(\`Get user error: \${err.message}\`);
    errorResponse(res, err);
  }
};

const createUser = async (req, res, next) => {
  try {
    const user = await User.create(req.body);
    successResponse(res, user, 201, 'User created successfully');
  } catch (err) {
    logger.error(\`Create user error: \${err.message}\`);
    errorResponse(res, err);
  }
};

const updateUser = async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.userId, req.body, {
      new: true,
      runValidators: true,
    }).select('-password');

    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    successResponse(res, user, 200, 'User updated successfully');
  } catch (err) {
    logger.error(\`Update user error: \${err.message}\`);
    errorResponse(res, err);
  }
};

const deleteUser = async (req, res, next) => {
  try {
    const user = await User.findByIdAndDelete(req.params.userId);
    if (!user) {
      throw new ApiError(404, 'User not found');
    }

    successResponse(res, null, 200, 'User deleted successfully');
  } catch (err) {
    logger.error(\`Delete user error: \${err.message}\`);
    errorResponse(res, err);
  }
};

export default {
  getUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
};`,
  'src/models/user.model.js': `import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import validator from 'validator';

// TODO: Add more user fields as needed
// TODO: Implement user soft delete
// TODO: Add user activity tracking

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please provide your name'],
      trim: true,
      maxlength: [50, 'Name cannot be more than 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Please provide your email'],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please provide a valid email'],
    },
    password: {
      type: String,
      required: [true, 'Please provide a password'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastLogin: {
      type: Date,
    },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform: function (doc, ret) {
        delete ret.password;
        delete ret.__v;
        return ret;
      },
    },
    toObject: {
      virtuals: true,
      transform: function (doc, ret) {
        delete ret.password;
        delete ret.__v;
        return ret;
      },
    },
  }
);

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model('User', userSchema);

export default User;`,
  'src/services/email.service.js': `import nodemailer from 'nodemailer';
import config from '../config/index.js';
import logger from '../utils/logger.js';

// TODO: Implement email templates
// TODO: Add email queue for production
// TODO: Implement email retry logic

const transporter = nodemailer.createTransport({
  host: config.email.smtp.host,
  port: config.email.smtp.port,
  auth: {
    user: config.email.smtp.auth.user,
    pass: config.email.smtp.auth.pass,
  },
});

if (process.env.NODE_ENV !== 'production') {
  transporter.verify((error) => {
    if (error) {
      logger.error('Error with email configuration:', error);
    } else {
      logger.info('Email server is ready to take our messages');
    }
  });
}

const sendEmail = async (to, subject, text) => {
  try {
    const mailOptions = {
      from: \`"\${config.email.fromName}" <\${config.email.from}>\`,
      to,
      subject,
      text,
      // html: TODO: Add HTML template
    };

    await transporter.sendMail(mailOptions);
  } catch (err) {
    logger.error('Email sending error:', err);
    throw err;
  }
};

const sendVerificationEmail = async (user, verificationToken) => {
  try {
    const verificationUrl = \`\${process.env.FRONTEND_URL}/verify-email?token=\${verificationToken}\`;
    const subject = 'Email Verification';
    const text = \`Hi \${user.name},\\n\\nPlease verify your email by clicking on the following link: \${verificationUrl}\\n\\nIf you did not create an account, please ignore this email.\\n\`;

    await sendEmail(user.email, subject, text);
  } catch (err) {
    logger.error('Verification email error:', err);
    throw err;
  }
};

export default {
  sendEmail,
  sendVerificationEmail,
};`,
  'src/validations/auth.validation.js': `import { body } from 'express-validator';

// TODO: Add more validation rules as needed
// TODO: Implement custom validation messages

const register = [
  body('name')
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ max: 50 })
    .withMessage('Name cannot be more than 50 characters'),
  body('email')
    .notEmpty()
    .withMessage('Email is required')
    .isEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters'),
  body('role')
    .optional()
    .isIn(['user', 'admin'])
    .withMessage('Role must be either user or admin'),
];

const login = [
  body('email')
    .notEmpty()
    .withMessage('Email is required')
    .isEmail()
    .withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required'),
];

const refreshToken = [
  body('refreshToken').notEmpty().withMessage('Refresh token is required'),
];

export default {
  register,
  login,
  refreshToken,
};`,
  'src/validations/user.validation.js': `import { body, param } from 'express-validator';

// TODO: Add more validation rules as needed
// TODO: Implement custom validation messages

const createUser = [
  body('name')
    .notEmpty()
    .withMessage('Name is required')
    .isLength({ max: 50 })
    .withMessage('Name cannot be more than 50 characters'),
  body('email')
    .notEmpty()
    .withMessage('Email is required')
    .isEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters'),
  body('role')
    .optional()
    .isIn(['user', 'admin'])
    .withMessage('Role must be either user or admin'),
];

const getUser = [
  param('userId').isMongoId().withMessage('Invalid user ID format'),
];

const updateUser = [
  param('userId').isMongoId().withMessage('Invalid user ID format'),
  body('name')
    .optional()
    .isLength({ max: 50 })
    .withMessage('Name cannot be more than 50 characters'),
  body('email').optional().isEmail().withMessage('Please provide a valid email'),
  body('role')
    .optional()
    .isIn(['user', 'admin'])
    .withMessage('Role must be either user or admin'),
];

const deleteUser = [
  param('userId').isMongoId().withMessage('Invalid user ID format'),
];

export default {
  createUser,
  getUser,
  updateUser,
  deleteUser,
};`,
  'src/constants/httpStatusCodes.js': `export default {
  // Success
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,

  // Client errors
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  VALIDATION_ERROR: 422,

  // Server errors
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
};`,
  'src/constants/errorMessages.js': `export default {
  // Authentication errors
  INVALID_CREDENTIALS: 'Invalid credentials',
  UNAUTHORIZED_ACCESS: 'Unauthorized access',
  INVALID_TOKEN: 'Invalid token',
  TOKEN_EXPIRED: 'Token expired',
  EMAIL_IN_USE: 'Email already in use',

  // User errors
  USER_NOT_FOUND: 'User not found',
  USER_DELETED: 'User deleted',
  USER_INACTIVE: 'User account is inactive',

  // Validation errors
  VALIDATION_ERROR: 'Validation error',
  INVALID_EMAIL: 'Invalid email',
  INVALID_PASSWORD: 'Invalid password',
  INVALID_ID: 'Invalid ID format',

  // Server errors
  INTERNAL_ERROR: 'Internal server error',
  NOT_IMPLEMENTED: 'Not implemented',
  DATABASE_ERROR: 'Database error',

  // Success messages
  LOGIN_SUCCESS: 'Login successful',
  LOGOUT_SUCCESS: 'Logout successful',
  REGISTER_SUCCESS: 'Registration successful',
  UPDATE_SUCCESS: 'Update successful',
  DELETE_SUCCESS: 'Delete successful',
};`,
  'tests/auth.test.js': `import request from 'supertest';
import app from '../src/index.js';
import mongoose from 'mongoose';
import User from '../src/models/user.model.js';
import { MongoMemoryServer } from 'mongodb-memory-server';

let mongoServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

afterEach(async () => {
  await User.deleteMany();
});

describe('Auth API', () => {
  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password: 'password123',
        });

      expect(res.statusCode).toEqual(201);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('message', 'User registered successfully');
      expect(res.body.data).toHaveProperty('user');
      expect(res.body.data).toHaveProperty('token');
    });

    it('should not register with duplicate email', async () => {
      await User.create({
        name: 'Existing User',
        email: 'test@example.com',
        password: 'password123',
      });

      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password: 'password123',
        });

      expect(res.statusCode).toEqual(400);
      expect(res.body).toHaveProperty('success', false);
      expect(res.body).toHaveProperty('message', 'Email already in use');
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      await User.create({
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123',
      });
    });

    it('should login with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('message', 'Login successful');
      expect(res.body.data).toHaveProperty('user');
      expect(res.body.data).toHaveProperty('token');
    });

    it('should not login with invalid password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword',
        });

      expect(res.statusCode).toEqual(401);
      expect(res.body).toHaveProperty('success', false);
      expect(res.body).toHaveProperty('message', 'Invalid credentials');
    });
  });
});`,
  'tests/user.test.js': `import request from 'supertest';
import app from '../src/index.js';
import mongoose from 'mongoose';
import User from '../src/models/user.model.js';
import { MongoMemoryServer } from 'mongodb-memory-server';
import jwt from 'jsonwebtoken';
import config from '../src/config/index.js';

let mongoServer;
let authToken;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);

  // Create a test user and generate token
  const user = await User.create({
    name: 'Admin User',
    email: 'admin@example.com',
    password: 'password123',
    role: 'admin',
  });

  authToken = jwt.sign(
    { id: user._id, role: user.role },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

afterEach(async () => {
  await User.deleteMany({ email: { $ne: 'admin@example.com' } });
});

describe('User API', () => {
  describe('GET /api/users', () => {
    it('should get all users', async () => {
      await User.create([
        {
          name: 'User 1',
          email: 'user1@example.com',
          password: 'password123',
        },
        {
          name: 'User 2',
          email: 'user2@example.com',
          password: 'password123',
        },
      ]);

      const res = await request(app)
        .get('/api/users')
        .set('Authorization', \`Bearer \${authToken}\`);

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body.data).toHaveProperty('users');
      expect(res.body.data.users.length).toBe(3); // Including admin user
      expect(res.body.data).toHaveProperty('pagination');
    });
  });

  describe('POST /api/users', () => {
    it('should create a new user', async () => {
      const res = await request(app)
        .post('/api/users')
        .set('Authorization', \`Bearer \${authToken}\`)
        .send({
          name: 'New User',
          email: 'newuser@example.com',
          password: 'password123',
        });

      expect(res.statusCode).toEqual(201);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('message', 'User created successfully');
      expect(res.body.data).toHaveProperty('name', 'New User');
      expect(res.body.data).toHaveProperty('email', 'newuser@example.com');
    });
  });
});`,
  'docs/swagger.yaml': `openapi: 3.0.0
info:
  title: REST API Documentation
  version: 1.0.0
  description: Documentation for the REST API
servers:
  - url: http://localhost:5000/api
    description: Development server
tags:
  - name: Auth
    description: Authentication operations
  - name: Users
    description: User management operations
paths:
  /auth/register:
    post:
      tags: [Auth]
      summary: Register a new user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - name
                - email
                - password
              properties:
                name:
                  type: string
                  example: John Doe
                email:
                  type: string
                  format: email
                  example: john@example.com
                password:
                  type: string
                  format: password
                  example: password123
                role:
                  type: string
                  enum: [user, admin]
                  default: user
      responses:
        '201':
          description: User registered successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  message:
                    type: string
                    example: User registered successfully
                  data:
                    type: object
                    properties:
                      user:
                        $ref: '#/components/schemas/User'
                      token:
                        type: string
                        example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        '400':
          description: Bad request (validation errors)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /auth/login:
    post:
      tags: [Auth]
      summary: Authenticate user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - email
                - password
              properties:
                email:
                  type: string
                  format: email
                  example: john@example.com
                password:
                  type: string
                  format: password
                  example: password123
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  message:
                    type: string
                    example: Login successful
                  data:
                    type: object
                    properties:
                      user:
                        $ref: '#/components/schemas/User'
                      token:
                        type: string
                        example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        '401':
          description: Invalid credentials
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /auth/logout:
    post:
      tags: [Auth]
      summary: Logout user
      security:
        - bearerAuth: []
      responses:
        '200':
          description: Logout successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  message:
                    type: string
                    example: Logout successful
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /auth/refresh-token:
    post:
      tags: [Auth]
      summary: Refresh access token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - refreshToken
              properties:
                refreshToken:
                  type: string
                  example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
      responses:
        '200':
          description: Token refreshed
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  data:
                    type: object
                    properties:
                      token:
                        type: string
                        example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        '401':
          description: Invalid refresh token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /users:
    get:
      tags: [Users]
      summary: Get all users
      security:
        - bearerAuth: []
      parameters:
        - in: query
          name: page
          schema:
            type: integer
            default: 1
          description: Page number
        - in: query
          name: limit
          schema:
            type: integer
            default: 10
          description: Items per page
        - in: query
          name: role
          schema:
            type: string
            enum: [user, admin]
          description: Filter by role
      responses:
        '200':
          description: List of users
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  data:
                    type: object
                    properties:
                      users:
                        type: array
                        items:
                          $ref: '#/components/schemas/User'
                      pagination:
                        type: object
                        properties:
                          total:
                            type: integer
                            example: 1
                          pages:
                            type: integer
                            example: 1
                          currentPage:
                            type: integer
                            example: 1
        '403':
          description: Forbidden (admin access required)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

    post:
      tags: [Users]
      summary: Create new user (admin only)
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUserInput'
      responses:
        '201':
          description: User created
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  message:
                    type: string
                    example: User created successfully
                  data:
                    $ref: '#/components/schemas/User'
        '400':
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /users/{userId}:
    get:
      tags: [Users]
      summary: Get user by ID
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: userId
          required: true
          schema:
            type: string
          description: User ID
      responses:
        '200':
          description: User details
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  data:
                    $ref: '#/components/schemas/User'
        '404':
          description: User not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

    patch:
      tags: [Users]
      summary: Update user
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: userId
          required: true
          schema:
            type: string
          description: User ID
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateUserInput'
      responses:
        '200':
          description: User updated
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  message:
                    type: string
                    example: User updated successfully
                  data:
                    $ref: '#/components/schemas/User'
        '403':
          description: Forbidden (users can only update their own profile)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

    delete:
      tags: [Users]
      summary: Delete user (admin only)
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: userId
          required: true
          schema:
            type: string
          description: User ID
      responses:
        '200':
          description: User deleted
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                    example: true
                  message:
                    type: string
                    example: User deleted successfully
        '403':
          description: Forbidden (admin access required)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    User:
      type: object
      properties:
        id:
          type: string
          example: 5f8d0d55b54764421b7156c3
        name:
          type: string
          example: John Doe
        email:
          type: string
          format: email
          example: john@example.com
        role:
          type: string
          enum: [user, admin]
          example: user
        isActive:
          type: boolean
          example: true
        createdAt:
          type: string
          format: date-time
        updatedAt:
          type: string
          format: date-time

    CreateUserInput:
      type: object
      required:
        - name
        - email
        - password
      properties:
        name:
          type: string
          example: Jane Doe
        email:
          type: string
          format: email
          example: jane@example.com
        password:
          type: string
          format: password
          example: password123
        role:
          type: string
          enum: [user, admin]
          default: user

    UpdateUserInput:
      type: object
      properties:
        name:
          type: string
          example: Updated Name
        email:
          type: string
          format: email
          example: updated@example.com
        role:
          type: string
          enum: [user, admin]
        isActive:
          type: boolean

    ErrorResponse:
      type: object
      properties:
        success:
          type: boolean
          example: false
        message:
          type: string
          example: Error message
        errors:
          type: array
          items:
            type: object
            properties:
              field:
                type: string
                example: email
              message:
                type: string
                example: must be a valid email`,
  'logs/.gitkeep': '',
  'logs/error.log': 'Make env as production to get log errors here',
  'logs/info.log': 'Make env as production to get log info here',
  'uploads/.gitkeep': '',
  'public/.gitkeep': '',
  'README.md': `# REST API Project

## Project Structure

\`\`\`
project-root/
|──  src/
|     ├── config/               # Configuration files
|     ├── controllers/          # Route controllers
|     ├── models/               # Database models
|     ├── routes/               # Route definitions
|     ├── middlewares/          # Custom express middlewares
|     ├── services/             # Business logic services
|     ├── utils/                # Utility classes and functions
|     ├── validations/          # Request validation schemas
|     ├── constants/            # Constants definitions
|     ├── tests/                # Test cases
|     ├── docs/                 # Documentation files
|     ├── logs/                 # Log files
|     ├── public/               # Public assets
|     └── uploads/              # File uploads
|──  tests/               # Test files
|──  docs/                # API documentation files
|──  logs/                # Log files
|──  public/              # Public assets
|──  uploads/             # File uploads
|──  .env.example         # Example environment variables
├──  .env                 # Environment variables
├──  .gitignore           # Git ignore file
├──  .eslintrc.js         # ESLint configuration
├──  .prettierrc          # Prettier configuration
\`\`\`

## Environment Variables

## Getting Started

### Prerequisites
- Node.js (v16 or higher)
- MongoDB
- npm (comes with Node.js)

### Installation
1. Clone the repository
2. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`
3. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   \`\`\`
4. Start the development server:
   \`\`\`bash
   npm run dev
   \`\`\`

## Available Scripts
- \`npm start\`: Start production server
- \`npm run dev\`: Start development server with nodemon
- \`npm test\`: Run tests
- \`npm run lint\`: Run ESLint
- \`npm run format\`: Format code with Prettier
- \`npm run docs\`: Generate API documentation

## API Documentation
After starting the server, API documentation will be available at \`/api-docs\`

## Deployment
TODO: Add deployment instructions

## Contributing
TODO: Add contribution guidelines

## License
TODO: Add license information
`,
};
