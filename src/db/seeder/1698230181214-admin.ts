import { DataSource } from 'typeorm';
import { Seeder } from 'typeorm-extension';

import { Constants } from '../../const/constants';
import { Users } from '../entity/users';

export default class UserSeeder implements Seeder {
  public async run(dataSource: DataSource): Promise<void> {
    const repository = dataSource.getRepository(Users);
    await repository.insert([
      {
        firstName: 'admin',
        lastName: 'admin',
        role: Constants.UserRole.ADMIN,
        email: 'admin@example.com',
        password: new Users().hashPassword('admin@123D') as string,
        authType: Constants.AuthType.EMAIL,
        isEmailVerified: true,
        isMobileVerified: true,
      },
    ]);
  }
}
