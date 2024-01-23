import qrcode from 'qrcode';
import speakeasy from 'speakeasy';

class TwoFAHandler {
  async generateQr(id: number) {
    const secret = speakeasy.generateSecret({ length: 20 }).base32;
    const link = `otpauth://totp/${id}?secret=${secret}&issuer=Systango`;
    return {
      code: await qrcode.toDataURL(link, { type: 'image/png' }),
      secret,
    };
  }

  verify2FACode(secret: string, token: string) {
    return speakeasy.totp.verify({ secret, encoding: 'base32', token });
  }
}

const twoFAHandler: TwoFAHandler = new TwoFAHandler();
export default twoFAHandler;
