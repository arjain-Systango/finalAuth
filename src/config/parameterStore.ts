import * as AWS from '@aws-sdk/client-ssm';

import config from '../config/config';
import { ParameterRequiredKeysInterface } from '../interfaces/parameterRequiredKeys.interface';
import { SSMService } from '../service/ssm.service';

class ParameterStoreConfig {
  static parameterStoreValue: any;
  private static secret = SSMService.secret;
  private static client = new AWS.SSM({
    region: process.env.AWS_REGION,
    credentials: {
      accessKeyId: this.secret.PARAMETER_STORE_AWS_ACCESS_KEY_ID,
      secretAccessKey: this.secret.PARAMETER_STORE_AWS_SECRET_ACCESS_KEY,
    },
  });

  public static async getParameterStoreValue() {
    try {
      const requiredKeys: ParameterRequiredKeysInterface = {
        JWT_SYSTEM_ROLE: null,
        JWT_USER_ROLE: null,
      };

      this.parameterStoreValue = requiredKeys;
      const keysArray = Object.keys(requiredKeys);

      for (let index = 0; index < keysArray.length; index++) {
        const element = keysArray[index];
        const options = {
          Name: `/${config.APP_ENV}/${config.APP_NAME}/${element}`,
          WithDecryption: false,
        };
        const data = (await this.client
          .getParameter(options)
          .catch((error: any) => {
            const json = JSON.stringify(error);
            if (JSON.parse(json).name != config.AWS_ACCESS_DENIED_EXCEPTION) {
              // throw error;
            }
          })) as AWS.GetParameterCommandOutput;

        this.parameterStoreValue[element] = process.env[element]
          ? process.env[element]
          : data?.Parameter?.Value;
      }
    } catch (error) {
      throw error;
    }
  }
}

export = ParameterStoreConfig;
