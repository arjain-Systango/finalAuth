import config from './config/config';
import logger from './config/logger';
import { DatabaseInitialization } from './db/dbConnection';
import { SSMService } from './service/ssm.service';
const PORT = config.APP_PORT;
(async function () {
  await SSMService.getSecretManagerValue();
  await DatabaseInitialization.dbCreateConnection();
  await require('./config/parameterStore').getParameterStoreValue();
  require('./app').listen(PORT, () => {
    logger.info(`listening on : http://localhost:${PORT}`);
    logger.info(`Swagger : http://localhost:${PORT}/api-docs`);
  });
})();
