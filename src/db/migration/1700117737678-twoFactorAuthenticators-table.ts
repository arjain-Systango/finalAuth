import {
  MigrationInterface,
  QueryRunner,
  Table,
  TableForeignKey,
} from 'typeorm';

export class TwoFactorAuthenticatorsTable1700117737678
  implements MigrationInterface
{
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'twoFactorAuthenticators',
        columns: [
          {
            name: 'userId',
            type: 'int',
            isPrimary: true,
          },
          {
            name: 'secret',
            type: 'varchar',
            isUnique: true,
            isNullable: false,
          },
          {
            name: 'qrCode',
            type: 'varchar',
            isUnique: true,
            isNullable: false,
          },
          {
            name: 'backupCode',
            type: 'varchar',
            isUnique: true,
            isNullable: false,
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
      'twoFactorAuthenticators',
      new TableForeignKey({
        columnNames: ['userId'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('twoFactorAuthenticators');
  }
}
