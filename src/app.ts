import cors from 'cors';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import path from 'path';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

import { morganErrorHandler, morganSuccessHandler } from './config/morgan';
import { Constants } from './const/constants';
import { SSMService } from './service/ssm.service';
import ApiError from './utils/ApiError';
import routes from './routes';
const secret = SSMService?.secret;
const app = express();
app.use(express.json());
app.use(
  cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  }),
);
app.get('/', (req, res) => res.send('healthy'));
app.use(morganSuccessHandler);
app.use(morganErrorHandler);
app.use(
  session({
    secret: secret.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
      maxAge: Constants.Session.EXPIRE_TIME,
    },
  }),
);
app.use(Constants.config.PrefixPath, routes);

// Use Helmet!
app.use(helmet());
const swaggerOptions = {
  definition: {
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    openapi: '3.0.0',
    info: {
      title: 'Authentication',
      version: '1.0.0',
      description: 'Authentication project apis',
    },
    servers: [
      {
        name: 'local',
        url: `http://localhost:${secret?.APP_PORT}`,
        description: 'local server',
      },
      {
        name: 'dev',
        url: `https://92f1-103-83-252-2.ngrok-free.app`,
        description: 'dev server',
      },
    ],
  },
  apis: [path.join(__dirname, './routes/*.{ts,js}')], // Specify the path to your TypeScript file(s) with API annotations
};
// Initialize Swagger-jsdocs
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// send back a 404 error for any unknown api request
app.use((_req, _res, next) => {
  next(
    new ApiError(Constants.Http.NOT_FOUND, Constants.ErrorMessage.NOT_FOUND),
  );
});
module.exports = app;
