import { Column, Entity, JoinColumn, OneToOne, PrimaryColumn } from 'typeorm';

import { Users } from './users';

@Entity('twoFactorAuthenticators')
export class TwoFactorAuthenticators {
  @PrimaryColumn({ type: 'int', nullable: false })
  userId: number;

  @Column({ type: 'varchar', unique: true, nullable: false })
  secret: string;

  @Column({ type: 'varchar', unique: true, nullable: false })
  qrCode: string;

  @Column({ type: 'varchar', unique: true, nullable: false })
  backupCode: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP(6)' })
  createdAt: Date;

  @Column({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  updatedAt: Date;

  @OneToOne(() => Users, (users) => users.twoFactorAuthenticators)
  @JoinColumn({ name: 'userId' })
  users: Users;
}
