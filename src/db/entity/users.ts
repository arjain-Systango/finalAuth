import bcrypt from 'bcrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';
import {
  BeforeInsert,
  Column,
  DeleteDateColumn,
  Entity,
  JoinColumn,
  OneToMany,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';

import { Constants } from '../../const/constants';
import { SSMService } from '../../service/ssm.service';
import { TwoFactorAuthenticators } from './twoFactorAuthenticators';
import { UserOtps } from './userOtps';
const secret = SSMService.secret;

export interface IUserData {
  id?: number;
  email: string;
  mobile?: string;
  firstName?: string;
  lastName?: string;
  password?: string;
  authType?: string;
  role?: string;
  isActive?: boolean;
  isEmailVerified?: boolean;
  isMobileVerified?: boolean;
  otp?: number;
  deletedAt?: Date;
  isTwoFactorVerified?: boolean;
}

export interface IJwtData {
  id: number;
  role?: string;
  isActive?: boolean;
  firstName?: string;
  lastName?: string;
  email: string;
  mobile?: string;
  authType?: string;
  isEmailVerified?: boolean;
  isMobileVerified?: boolean;
}
export interface IGetUserListQueryParams {
  page: number;
  limit: number;
}

export interface IUserUpdateData {
  firstName?: string;
  lastName?: string;
  mobile?: string;
}

@Entity('users')
export class Users {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', unique: true, nullable: false })
  email: string;

  @Column({ type: 'varchar', unique: true, nullable: true })
  mobile: string;

  @Column({ type: 'varchar', nullable: true })
  firstName: string;

  @Column({ type: 'varchar', nullable: true })
  lastName: string;

  @Column({
    type: 'enum',
    enum: [Constants.UserRole.ADMIN, Constants.UserRole.USER],
    default: 'user',
  })
  role: string;

  @Column({ type: 'varchar', nullable: true })
  password: string;

  @Column({ type: 'varchar', nullable: true })
  passwordToken: string;

  @Column({ type: 'int', default: 0, nullable: false })
  retryCount: number;

  @Column({
    type: 'enum',
    enum: [
      Constants.AuthType.APPLE,
      Constants.AuthType.EMAIL,
      Constants.AuthType.GOOGLE,
      Constants.AuthType.FACEBOOK,
      Constants.AuthType.LINKEDIN,
      Constants.AuthType.GITHUB,
      Constants.AuthType.TWITTER,
      Constants.AuthType.REDDIT,
      Constants.AuthType.YAHOO,
      Constants.AuthType.AMAZON,
      Constants.AuthType.GITLAB,
      Constants.AuthType.DISCORD,
      Constants.AuthType.MICROSOFT,
    ],
  })
  authType: string;

  @Column({ type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'boolean', default: true })
  isEmailVerified: boolean;

  @Column({ type: 'boolean', default: true })
  isMobileVerified: boolean;

  @DeleteDateColumn({ type: 'date', nullable: true })
  deletedAt: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP(6)' })
  createdAt: Date;

  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  updatedAt: Date;

  @OneToMany(() => UserOtps, (userOtps) => userOtps.users)
  @JoinColumn({ name: 'id' })
  userOtps: UserOtps[];

  @OneToOne(
    () => TwoFactorAuthenticators,
    (twoFactorAuthenticators) => twoFactorAuthenticators.users,
  )
  @JoinColumn({ name: 'id' })
  twoFactorAuthenticators: TwoFactorAuthenticators;

  @BeforeInsert()
  // used to handle password for seeder and register
  hashPassword(password?: string): void | string {
    if (!password) {
      if (!this.password) {
        return;
      }
      password = this.password;
    }
    const saltRounds = Constants.SaltRounds;
    const hashedPassword = bcrypt.hashSync(password, saltRounds);
    if (this.password) {
      this.password = hashedPassword;
      // return;
    }
    return hashedPassword;
  }
  async verifyPassword(userPassword: string): Promise<boolean> {
    if (!this.password) {
      return false;
    }
    return await bcrypt.compare(userPassword, this.password);
  }
  async toAuthJSON() {
    const {
      email,
      role,
      authType,
      id,
      mobile,
      firstName,
      lastName,
      isActive,
      isEmailVerified,
      isMobileVerified,
    } = this;
    const data = {
      id,
      email,
      role,
      mobile,
      authType,
      isActive,
      firstName,
      lastName,
      isEmailVerified,
      isMobileVerified,
      token: await this.generateJWT(),
      refreshToken: await this.createRefreshToken(),
      timeToLive: 0,
    };
    const jwtData = jwt.verify(data.token, secret?.JWT_SECRET);
    const { exp } = jwtData as JwtPayload;
    data.timeToLive = exp;
    if (!firstName) {
      delete data.firstName;
    }
    if (!lastName) {
      delete data.lastName;
    }
    if (!mobile) {
      delete data.mobile;
      delete data.isMobileVerified;
    }
    return data;
  }
  async generateJWT(optJwtData?: IJwtData) {
    const {
      id,
      email,
      mobile,
      role,
      firstName,
      lastName,
      authType,
      isActive,
      isEmailVerified,
      isMobileVerified,
    } = this;
    let jwtData: IJwtData = {
      id,
      email,
      role,
      authType,
      isActive,
      isEmailVerified,
    };
    if (firstName) {
      jwtData.firstName = firstName;
    }
    if (lastName) {
      jwtData.lastName = lastName;
    }
    if (mobile) {
      jwtData.mobile = mobile;
      jwtData.isMobileVerified = isMobileVerified;
    }
    if (optJwtData) {
      jwtData = optJwtData;
    }
    return jwt.sign(jwtData, secret?.JWT_SECRET, {
      expiresIn: secret?.JWT_EXPIRE,
    });
  }
  async createRefreshToken() {
    return jwt.sign(
      {
        id: this.id,
      },
      secret?.REFRESH_TOKEN_SECRET,

      {
        expiresIn: secret?.REFRESH_TOKEN_EXPIRE,
      },
    );
  }
}
