export interface SSMRequiredKeys {
  APP_PORT: number;
  DB_HOST: string;
  DB_PORT: number;
  DB_DIALECT: string;
  DB_USER: string;
  DB_PASSWORD: string;
  DB_NAME: string;
  JWT_SECRET: string;
  JWT_EXPIRE: string;
  TRIGGER_EMAIL_URL: string;
  PARAMETER_STORE_AWS_ACCESS_KEY_ID: string;
  PARAMETER_STORE_AWS_SECRET_ACCESS_KEY: string;
  SESSION_SECRET: string;
  REFRESH_TOKEN_SECRET: string;
  REFRESH_TOKEN_EXPIRE: string;
  FRONT_END_HOST_URL: string;
}
