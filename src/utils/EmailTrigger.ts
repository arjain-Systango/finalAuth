import axios from 'axios';
import jwt from 'jsonwebtoken';

import logger from '../config/logger';
import ParameterStoreConfig from '../config/parameterStore';
import { Constants } from '../const/constants';
import { SSMService } from '../service/ssm.service';

export interface EmailTriggerPayload {
  receivers: string[];
  templateName: string;
  subject: string;
  details: any;
}

export class EmailTrigger {
  async triggerEmail(emailPayload: EmailTriggerPayload) {
    try {
      const secret = SSMService.secret;
      const parameterSecret = ParameterStoreConfig.parameterStoreValue;
      const token = await this.createJWT(parameterSecret?.JWT_SYSTEM_ROLE);
      await axios.post(secret.TRIGGER_EMAIL_URL, emailPayload, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
    } catch (error) {
      logger.error(`Error in EmailTrigger triggerEmail : ${error}`);
      throw {
        message: Constants.ErrorMessage.ERROR_IN_EMAIL_TRIGGER,
      };
    }
  }
  async createJWT(role: string) {
    const secret = SSMService.secret;
    return jwt.sign(
      {
        role: role,
      },
      secret?.JWT_SECRET,
      {
        expiresIn: secret?.JWT_EXPIRE,
      },
    );
  }
}

const emailTrigger: EmailTrigger = new EmailTrigger();
export default emailTrigger;
