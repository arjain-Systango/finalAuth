export class Constants {
  static config = {
    PrefixPath: '/',
  };
  static Http = {
    OK: 200,
    CREATED: 201,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    GONE: 410,
    INTERNAL_SERVER_ERROR: 500,
    CONFLICT: 409,
    UNPROCESSABLE: 422,
    TOO_MANY_REQUESTS: 429,
  };

  static SuccessMessage = {
    LOGIN_SUCCESS: 'login successful',
    REGISTER_SUCCESS: 'registration successful',
    FACEBOOK_AUTHENTICATION_SUCCESS: 'Facebook authentication successful',
    GOOGLE_AUTHENTICATION_SUCCESS: 'Google authentication successful',
    APPLE_AUTHENTICATION_SUCCESS: 'Apple authentication successful',
    LINKEDIN_AUTHENTICATION_SUCCESS: 'Linkedin authentication successful',
    GITHUB_AUTHENTICATION_SUCCESS: 'Github authentication successful',
    TWITTER_AUTHENTICATION_SUCCESS: 'Twitter authentication successful',
    REDDIT_AUTHENTICATION_SUCCESS: 'Reddit authentication successful',
    YAHOO_AUTHENTICATION_SUCCESS: 'Yahoo authentication successful',
    AMAZON_AUTHENTICATION_SUCCESS: 'Amazon authentication successful',
    DISCORD_AUTHENTICATION_SUCCESS: 'Discord authentication successful',
    GITLAB_AUTHENTICATION_SUCCESS: 'Gitlab authentication successful',
    MICROSOFT_AUTHENTICATION_SUCCESS: 'Microsoft authentication successful',
    OTP_VERIFICATION_SUCCESS: 'Otp verification successful',
    OTP_SENT_SUCCESSFULLY: 'Otp sent  successfully',
    RESET_PASSWORD_MAIL_SENT_SUCCESSFULLY:
      'Reset password email sent successfully',
    TWO_FA_ENABLED_SUCCESS: '2FA Enabled Successfully',
    TWO_FA_DISABLED_SUCCESS: '2FA Disabled Successfully',
    TWO_FA_Verification_SUCCESS: '2FA verification Successful',
    UPDATED_SUCCESSFULLY: 'Updated successfully',
    USER_DATA_FETCHED_SUCCESSFULLY: 'User Data Fetched Successfully',
    USER_DELETED_SUCCESSFULLY: 'User Deleted Successfully',
    GENERATED_SUCCESSFULLY: 'Generated Successfully',
  };
  static ErrorMessage = {
    INTERNAL_SERVER_ERROR: 'Internal Service Error',
    USER_ALREADY_EXIST: 'Already Exist',
    USER_NOT_FOUND: 'Invalid email or password',
    NOT_FOUND: 'Not Found',
    BAD_REQUEST: 'Bad Request',
    TOO_MANY_REQUEST: 'Too Many Request',
    UNAUTHORIZED: 'Unauthorized',
    USER_NOT_ACTIVE: 'User is inactive',
    APPLE_LOGIN_ERROR: 'JsonWebTokenError',
    INVALID_OTP: 'Invalid Otp',
    INVALID_CODE: 'Invalid code',
    INVALID_EMAIL: 'Invalid Email',
    INVALID_MOBILE: 'Invalid Mobile Number',
    INVALID_BACKUP_CODE: 'Invalid Backup Code',
    INVALID_TYPE: 'Invalid Type',
    INVALID_PASSWORD_TOKEN:
      'The password reset token you are trying to use has expired or is no longer valid.',
    EMAIL_ALREADY_VERIFIED: 'Email Already Verified',
    MOBILE_ALREADY_VERIFIED: 'Mobile Already Verified',
    TWO_FA_NOT_ENABLED: '2FA Not Enabled',
    RESEND_VERIFICATION_CODE_LIMIT_REACHED:
      'Max limit 3 to send verification code reached please try after 1 hour',
    INVALID_TOKEN: 'Invalid token',
    INVALID_USER: 'Invalid user',
    OLD_PASSWORD_NOT_MATCH: 'Old password does not match',
    SAME_PASSWORD: "New password can't be same as old password",
    FAILED_TO_CHANGE_PASSWORD: 'Failed To Change Password',
    DATA_NOT_FOUND: 'Data not found',
    EITHER_EMAIL_OR_MOBILE_CAN_VERIFY:
      'Either email or mobile can be verified at once',
    EITHER_EMAIL_OR_MOBILE_ALLOWED: 'Either email or mobile is allowed',
    EMAIL_OR_MOBILE_REQUIRED: 'Either email or mobile is required',
    ERROR_IN_EMAIL_TRIGGER: 'Error in Trigger Email',
  };
  static UserRole = {
    ADMIN: 'admin',
    USER: 'user',
  };

  static AuthType = {
    FACEBOOK: 'facebook',
    GOOGLE: 'google',
    EMAIL: 'email',
    APPLE: 'apple',
    LINKEDIN: 'linkedin',
    GITHUB: 'github',
    TWITTER: 'twitter',
    REDDIT: 'reddit',
    YAHOO: 'yahoo',
    AMAZON: 'amazon',
    GITLAB: 'gitlab',
    DISCORD: 'discord',
    MICROSOFT: 'microsoft',
  };
  static SaltRounds = 10;

  static userLookupUrl = {
    Facebook: 'https://graph.facebook.com/me',
    Google: 'https://www.googleapis.com/oauth2/v2/userinfo',
    Linkedin: 'https://api.linkedin.com/v2/userinfo',
    Github: 'https://api.github.com/user',
    Twitter: 'https://api.twitter.com/2/users/me',
    Reddit: 'https://oauth.reddit.com/api/v1/me',
    Yahoo: 'https://api.login.yahoo.com/openid/v1/userinfo',
    Amazon: 'https://api.amazon.com/user/profile',
    Gitlab: 'https://gitlab.com/oauth/userinfo',
    Discord: 'https://discordapp.com/api/users/@me',
    Microsoft: 'https://graph.microsoft.com/v1.0/me',
  };

  static EmailSubject = {
    EMAIL_VERIFICATION: 'Email Verification',
    RESET_PASSWORD: 'reset_password',
  };
  static EmailTemplateName = {
    EMAIL_VERIFICATION: 'verification_email',
    RESET_PASSWORD: 'reset_password',
  };
  static RESEND_OTP = {
    MAX_LIMIT: 3,
    DURATION: 1,
    DURATION_TIME_UNIT: 'hour',
  };
  static otpType = {
    EMAIL_VERIFICATION: 'email_verification',
    FORGOT_PASSWORD: 'forgot_password',
    SMS_VERIFICATION: 'sms_verification',
  };
  static Pagination = {
    DEFAULT_PAGE: 1,
    DEFAULT_LIMIT: 10,
    DEFAULT_OFFSET: 0,
  };
  static Session = {
    EXPIRE_TIME: 60000,
  };
}
