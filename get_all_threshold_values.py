#!/usr/bin/env python3
import configparser
import sys
import traceback
import time
import logging
import os

SPLUNK_HOME = os.environ['SPLUNK_HOME']
APPNAME = os.path.basename(os.path.dirname(os.getcwd()))
sys.path.append(os.path.join(SPLUNK_HOME, 'etc', 'apps', APPNAME, 'bin', 'lib'))
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

import common.utils as utils

CONF_FILE_NAME = 'anomaly_threshold_tracker.conf'
CONST_DRIFT_SUFFIX = 'drift'


@Configuration()
class GetAllThreshold(GeneratingCommand):
    config = None
    r = None
    run_id = ''
    log = None

    db_connection = None  # Type of DB engine. At the moment, only Redis is supported.
    db_host = None
    db_port = None
    db_engine_type = None
    db_is_cluster = False
    db_user = 'default'
    db_enc_pswd = None
    db_enc_key = None

    # Number of commands to be passed to the DB engine in each pipeline.
    max_process_chunk_size = Option(default=25000, require=False, validate=validators.Integer(0))

    key = Option(require=True)

    def setup_logging(self):
        try:
            extra = {'run_id': self.run_id}
            logger = logging.getLogger("a")
            file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk', APPNAME + ".log"), mode='a',
                maxBytes=25000000, backupCount=2)
            formatter = logging.Formatter("%(asctime)s, run_id=%(run_id)s, "
                                          "filename=%(filename)s, method=%(funcName)s, lineno=%(lineno)d,"
                                          "level=%(levelname)s, pid=%(process)d, thread=%(thread)d, "
                                          "msg=\"%(message)s\"")

            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.setLevel(logging.DEBUG)
            logger = logging.LoggerAdapter(logger, extra)
            return logger
        except Exception:
            raise Exception("Exception occurred while initializing logger instance")

    def get_config_value(self, stanza, key):
        try:
            return self.config[stanza][key]
        except Exception as Ex:
            self.log.error('Exception occurred while retrieving value from conf. Exiting..  exception=' + str(Ex))
            raise

    def load_config(self):
        """
        Loads the config file as specified in (CONF_FILE_NAME) and reads the key config values to be used
        in the implementation. Reads the configurations from 'default' and 'local' directory (preference for 'local'
        config over 'default' configs.
        :return: None
        """
        try:
            self.config = configparser.ConfigParser()
            self.config.read(['../default/' + CONF_FILE_NAME, '../local/' + CONF_FILE_NAME])

            self.db_is_cluster = self.get_config_value('db', 'is_cluster')
            self.db_engine_type = self.get_config_value('db', 'engine_type')
            self.db_host = self.get_config_value('db', 'host')
            self.db_port = self.get_config_value('db', 'port')
            self.db_user = self.get_config_value('db', 'username')
            self.db_enc_pswd = self.get_config_value('db', 'encrypted_password')
            self.db_enc_key = self.get_config_value('db', 'encryption_key')

        except Exception as e:
            self.log.error(msg="Exception occurred while loading config file. Exiting.. exception=" + str(e))
            raise

    def generate(self):

        try:
            overall_time_start = time.time()

            # Generates a new run id for every invocation
            if not self.run_id:
                self.run_id = self.metadata.searchinfo.sid

            # initializes the logger instance
            self.log = self.setup_logging()

            # loads the config from CONF_FILE if not loaded already
            if not self.config:
                self.log.info('Loading the configurations..')
                self.load_config()

            # creates a redis instance
            if not self.r:
                try:
                    self.r = utils.connect_db(self.db_engine_type, self.db_is_cluster, self.db_host, self.db_port,
                                              self.db_user, self.db_enc_pswd, self.db_enc_key)
                    try:
                        response = self.r.ping()
                        if response:
                            self.log.info('Created %s Connection with db_host=%s, db_port=%s', self.db_engine_type,
                                          self.db_host, self.db_port)
                    except Exception as ex:
                        self.log.error('Unable to create connection for %s, db_host=%s, db_port=%s, exception=%s',
                                       self.db_engine_type, self.db_host, self.db_port, str(ex))
                        raise
                except Exception as ex:
                    self.log.error(
                        'Exception occurred while creating DB connection - db_engine_type=%s, db_host=%s, '
                        'db_port=%s, exception=%s', self.db_engine_type, self.db_host, self.db_port, str(ex))
                    raise

            all_hash_values = self.r.hgetall(self.key)
            self.log.info('Retreiving all values for key=' + self.key)

            if all_hash_values:
                dict_hash_values = dict(all_hash_values)

                for key in dict_hash_values.keys():
                    record = {}
                    if CONST_DRIFT_SUFFIX not in key:
                        value = dict_hash_values[key]
                        if value:
                            value_split = value.split('|')
                            if len(value_split) == 4:
                                record['actual_mean'], record['actual_stdev'], record['actual_count'], \
                                record['actual_update_time'] = value_split
                                record['time_period'] = key
                            drift_key = key + ':' + CONST_DRIFT_SUFFIX
                            drift_value = dict_hash_values.get(drift_key, None)
                            if drift_value:
                                drift_value_split = drift_value.split('|')
                                if len(drift_value_split) == 5:
                                    record['drift_mean'], record['drift_stdev'], record['drift_time'],\
                                    record['drift_update_time'], record['drift_counter'] = drift_value_split

                        yield record

            overall_time_end = time.time()

            self.log.info(f'Completed processing the records. time_taken={overall_time_end - overall_time_start} secs')
        except Exception as ex:
            self.log.error('Exception occurred while getting all values, exception=%s' + str(ex))

        finally:
            logging.shutdown()


dispatch(GetAllThreshold, sys.argv, sys.stdin, sys.stdout, __name__)
