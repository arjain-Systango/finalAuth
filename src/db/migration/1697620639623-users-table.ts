import { MigrationInterface, QueryRunner, Table } from 'typeorm';

import { Constants } from '../../const/constants';

export class UsersTable1697620639623 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'users',
        columns: [
          {
            name: 'id',
            type: 'int',
            isGenerated: true,
            isPrimary: true,
          },
          {
            name: 'email',
            type: 'varchar',
            isUnique: true,
            isNullable: false,
          },
          {
            name: 'mobile',
            type: 'varchar',
            isUnique: true,
            isNullable: true,
          },
          {
            name: 'firstName',
            type: 'varchar',
            isNullable: true,
          },
          {
            name: 'lastName',
            type: 'varchar',
            isNullable: true,
          },
          {
            name: 'role',
            type: 'enum',
            enum: ['user', 'admin'],
            default: "'user'",
          },
          {
            name: 'authType',
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
          },
          {
            name: 'password',
            type: 'varchar',
            isNullable: true,
          },
          {
            name: 'passwordToken',
            type: 'varchar',
            isNullable: true,
          },
          {
            name: 'retryCount',
            type: 'int',
            isNullable: false,
            default: 0,
          },
          {
            name: 'isEmailVerified',
            type: 'boolean',
            isNullable: false,
            default: true,
          },
          {
            name: 'isMobileVerified',
            type: 'boolean',
            isNullable: false,
            default: false,
          },
          {
            name: 'isActive',
            type: 'boolean',
            isNullable: false,
            default: true,
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
          {
            name: 'deletedAt',
            type: 'date',
            isNullable: true,
          },
        ],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('users');
  }
}
