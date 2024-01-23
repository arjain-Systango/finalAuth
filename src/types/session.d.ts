import 'express-session';
declare module 'express-session' {
  interface SessionData {
    isTwoFactorVerified: boolean;
    userEmail: string;
  }
}
