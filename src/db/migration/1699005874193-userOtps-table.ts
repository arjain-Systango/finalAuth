import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
  TableUnique,
} from 'typeorm';

import { Constants } from '../../const/constants';

export class UserOtpsTable1699005874193 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'userOtps',
        columns: [
          {
            name: 'id',
            type: 'int',
            isGenerated: true,
            isPrimary: true,
          },
          {
            name: 'userId',
            type: 'int',
            isNullable: false,
          },
          {
            name: 'otp',
            type: 'int',
            isUnique: true,
            isNullable: false,
          },
          {
            name: 'retryCount',
            type: 'int',
            isNullable: false,
            default: 0,
          },
          {
            name: 'type',
            type: 'enum',
            enum: [
              Constants.otpType.EMAIL_VERIFICATION,
              Constants.otpType.FORGOT_PASSWORD,
              Constants.otpType.SMS_VERIFICATION,
            ],
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'now()',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'now()',
          },
        ],
      }),
    );

    await queryRunner.createForeignKey(
      'userOtps',
      new TableForeignKey({
        columnNames: ['userId'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
      }),
    );

    await queryRunner.createUniqueConstraint(
      'userOtps',
      new TableUnique({
        columnNames: ['userId', 'type'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('userOtps');
  }
}
