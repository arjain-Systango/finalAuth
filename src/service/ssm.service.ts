// / eslint-disable @typescript-eslint/no-non-null-asserted-optional-chain /
import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';

import config from '../config/config';
import { SSMRequiredKeys } from '../interfaces/ssm.interface';
const client = new SecretsManagerClient({
  region: process.env.AWS_REGION || 'ap-south-1',
});

export class SSMService {
  public static secret: any;

  static async getSecretManagerValue() {
    let response;

    if (!this.secret) {
      try {
        response = await client
          .send(
            new GetSecretValueCommand({
              SecretId: `${config.APP_NAME}/${config.APP_ENV}`,
              VersionStage: 'AWSCURRENT',
            }),
          )
          .catch((error) => {
            const json = JSON.stringify(error);
            if (JSON.parse(json).name != config.AWS_ACCESS_DENIED_EXCEPTION) {
              // throw error;
            }
          });
        const secret = response
          ? JSON.parse(response.SecretString as string)
          : {};
        const requiredSecretKey: SSMRequiredKeys = {
          APP_PORT: null,
          DB_HOST: null,
          DB_PORT: null,
          DB_DIALECT: null,
          DB_USER: null,
          DB_PASSWORD: null,
          DB_NAME: null,
          JWT_SECRET: null,
          JWT_EXPIRE: null,
          TRIGGER_EMAIL_URL: null,
          PARAMETER_STORE_AWS_ACCESS_KEY_ID: null,
          PARAMETER_STORE_AWS_SECRET_ACCESS_KEY: null,
          SESSION_SECRET: null,
          REFRESH_TOKEN_SECRET: null,
          REFRESH_TOKEN_EXPIRE: null,
          FRONT_END_HOST_URL: null,
        };
        this.secret = secret;

        for (const key in requiredSecretKey) {
          this.secret[key] = process.env[key] ? process.env[key] : secret[key];
        }
        return this.secret;
      } catch (error) {
        throw error;
      }
    }
    return this.secret;
  }
}
