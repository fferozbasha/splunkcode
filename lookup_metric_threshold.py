#!/usr/bin/env python3
import configparser
import sys
from math import sqrt
import traceback
import time
import logging
import os

SPLUNK_HOME = os.environ['SPLUNK_HOME']
APPNAME = os.path.basename(os.path.dirname(os.getcwd()))
sys.path.append(os.path.join(SPLUNK_HOME, 'etc', 'apps', APPNAME, 'bin', 'lib'))

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import common.utils as utils

CONF_FILE_NAME = 'anomaly_threshold_tracker.conf'
CONST_DRIFT_SUFFIX = 'drift'


@Configuration()
class LookupMetricThreshold(StreamingCommand):
    config = None
    r = None
    db_pipeline = None
    db_pipeline_counter = 0
    existing_values_dict = {}
    run_id = None
    log = None
    input_keys_list = None

    # Number of commands to be passed to the DB engine in each pipeline.
    max_process_chunk_size = Option(default=25000, require=False, validate=validators.Integer(0))

    db_connection = None  # Type of DB engine. At the moment, only Redis is supported.
    db_host = None
    db_port = None
    db_engine_type = None
    db_is_cluster = False
    db_user = 'default'
    db_enc_pswd = None
    db_enc_key = None

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
        except Exception as ex:
            self.log.error('Exception occurred while retrieving value from conf, stanza=%s, key=%s. Exiting.. '
                           'exception=%s', stanza, key, str(ex))
            sys.exit(-1)

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

    def get_existing_values(self, input_value):
        """
        Retrieves the key / hash key from the input record and creates a hmget command and updates the redis pipeline
        :param input_value:
        :return: None. Updates the existing redis pipeline.
        """
        try:
            key = input_value.get('key', 'default')
            time_period = input_value.get('time_period', 'default')
            hash_keys_list = [time_period, time_period + ':' + CONST_DRIFT_SUFFIX]
            self.db_pipeline.hmget(key, hash_keys_list)
        except Exception as ex:
            self.log.error('Exception occurred while trying to fetch existing values, exception=%s', str(ex))
            raise

    @staticmethod
    def return_record(existing_value, record):

        try:
            if existing_value:
                existing_value_threshold_split = existing_value[0].split('|') if existing_value[0] else None
                existing_value_drift_split = existing_value[1].split('|') if existing_value[1] else None
                if existing_value_threshold_split:
                    record['actual_mean'], record['actual_stdev'], record['actual_count'], \
                        record['actual_update_time'] = existing_value_threshold_split
                if existing_value_drift_split:
                    record['drift_mean'], record['drift_stdev'], record['drift_time'], \
                        record['drift_update_time'], record['drift_counter'] = existing_value_drift_split
                return record
            else:
                return record
        except Exception as ex:
            self.log.error('Exception occurred while creating return values exception=%s,', str(ex))

    def stream(self, records):

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
                self.log.error('Exception occurred while creating DB connection - db_engine_type=%s, db_host=%s, '
                               'db_port=%s, exception=%s', self.db_engine_type, self.db_host, self.db_port, str(ex))
                raise

        # the incoming records is a generator object. converting the same as list for further processing
        # based on the value configured in .conf file, sets the max number of entries to be processed
        # in each chunk
        chunk_size = self.max_process_chunk_size

        records = list(records)

        try:
            chunk_list = utils.split_chunks(records, chunk_size)
        except Exception as ex:
            self.log.error('Exception occurred while creating chunk list. exception=%s', str(ex))
            raise

        self.log.info(f'Created chunks to process the records in batch. TotalRecords={len(records)}, '
                      f'TotalChunks={len(chunk_list)}, MaxChunkSize={self.max_process_chunk_size}')

        try:
            for chunk in chunk_list:
                chunk_idx = time.time() * 1000000
                self.db_pipeline = self.r.pipeline(transaction=False)

                ts_load_get_existing_values_pipeline = time.time()
                list(map(self.get_existing_values, chunk))
                te_load_get_existing_values_pipeline = time.time()
                self.log.info(f'Process Chunk, chunk_idx={chunk_idx}, chunk_size={len(chunk)}, '
                              f'activity=LoadGetExistingValuesPipeline,'
                              f'time_taken='
                              f'{te_load_get_existing_values_pipeline - ts_load_get_existing_values_pipeline} secs')

                ts_exec_get_existing_values_pipeline = time.time()
                existing_values = self.db_pipeline.execute()
                te_exec_get_existing_values_pipeline = time.time()

                self.log.info(f'Process Chunk, chunk_idx={chunk_idx}, chunk_size={len(chunk)},'
                              f'activity=ExecuteGetExistingValuesPipeline,'
                              f'time_taken='
                              f'{te_exec_get_existing_values_pipeline - ts_exec_get_existing_values_pipeline} secs')

                yield from map(self.return_record, iter(existing_values), iter(chunk))

        except Exception as ex:
            self.log.error('Exception occurred while looping the chunks, exception=%s', str(ex))
            traceback.print_exc()

        finally:
            self.db_pipeline.close()
            overall_time_end = time.time()
            self.log.info(f'Completed processing the records. time_taken={overall_time_end - overall_time_start} secs')
            logging.shutdown()


dispatch(LookupMetricThreshold, sys.argv, sys.stdin, sys.stdout, __name__)
