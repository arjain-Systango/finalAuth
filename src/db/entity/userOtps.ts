import {
  Column,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  Unique,
} from 'typeorm';

import { Constants } from '../../const/constants';
import { Users } from './users';
@Entity('userOtps')
@Unique(['userId', 'type'])
export class UserOtps {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'int', nullable: false })
  userId: number;

  @Column({ type: 'int', nullable: false })
  otp: number;

  @Column({ type: 'int', default: 0, nullable: false })
  retryCount: number;

  @Column({
    type: 'enum',
    enum: [
      Constants.otpType.EMAIL_VERIFICATION,
      Constants.otpType.FORGOT_PASSWORD,
      Constants.otpType.SMS_VERIFICATION,
    ],
  })
  type: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP(6)' })
  createdAt: Date;

  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  updatedAt: Date;

  @ManyToOne(() => Users, (users) => users.userOtps)
  @JoinColumn({ name: 'userId' })
  users: Users;
}
