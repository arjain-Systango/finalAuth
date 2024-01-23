import { Constants } from '../const/constants';
import emailTrigger from './EmailTrigger';

export async function sendOtp(otp: number, email: string) {
  const otpArray = otp.toString().split('');

  const emailPayload = {
    receivers: [email],
    subject: Constants.EmailSubject.EMAIL_VERIFICATION,
    details: {
      otp1: otpArray[0],
      otp2: otpArray[1],
      otp3: otpArray[2],
      otp4: otpArray[3],
    },
    templateName: Constants.EmailTemplateName.EMAIL_VERIFICATION,
  };

  await emailTrigger.triggerEmail(emailPayload);
}
