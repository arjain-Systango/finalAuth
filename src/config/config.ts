import 'dotenv/config';
export default {
  APP_PORT: process.env.APP_PORT || 3000,
  APP_ENV: process.env.APP_ENV || 'development',
  APP_NAME: process.env.APP_NAME || 'authentication',
  AWS_ACCESS_DENIED_EXCEPTION:
    process.env.AWS_ACCESS_DENIED_EXCEPTION || 'AccessDeniedException',
};
