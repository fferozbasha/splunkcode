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

VARIABLE_MEAN = 'mean'
VARIABLE_STDEV = 'stdev'
VARIABLE_COUNT = 'count'
VARIABLE_TIME = '_time'

CONST_DRIFT_SUFFIX = 'drift'
MAX_DECIMAL_ROUNDING = 4


@Configuration()
class UpdateThresholdValues(StreamingCommand):
    config = None
    r = None  # holds the db connection
    db_pipeline = None  # pipeline instance of the db connection
    existing_values_dict = {}  # dict to hold the existing values from DB for the current keys in loop
    run_id = ''  # uniqu run_id for every execution
    log = None  # logger instance
    overall_time_start = None
    overall_time_end = None

    # Multiplier to be used when checking if the new mean is in range of existing mean or not.
    # Reducing this much, will make the algorithm to be more sensitive and thereby, if the new value is even little bit
    # out of range of existing ones, then the threshold values will get reset with the new ones (after passing the
    # max_allowed_drift_period_counter periods )
    # if value for this is -1, then the comparison will be ignored.
    mean_comparison_stdev_multiplier = Option(default=6, require=False, validate=validators.Integer(0))

    # Max number of time periods allowed for a drift before starting to consider the same as new-normal.
    # During this period, the drift values will just be tracked, but the anomaly comparison will be based on
    # actual values
    max_allowed_drift_period_counter = Option(default=3, require=False, validate=validators.Integer(0))

    # When the number of data points of historical values is more than 3 times the count of new data,
    # then from that point on-wards, the count value of historical data is completely ignored and instead this
    # weightage * new total count is considered as the historical count of data points.
    historical_mean_weightage = Option(default=4, require=False, validate=validators.Integer(0))

    # Number of commands to be passed to the DB engine in each pipeline.
    max_process_chunk_size = Option(default=25000, require=False, validate=validators.Integer(0))

    db_connection = None  # Type of DB engine. At the moment, only Redis/KeyDB is supported.
    db_host = None
    db_port = None
    db_engine_type = None
    db_is_cluster = 0
    db_user = 'default'
    db_enc_pswd = None
    db_enc_key = None

    # log counters used in process which will be logged as part of execution summary
    # <upd|ins|del _ current|drift _ reason>
    ctr_updated_current_cumulative = 0  # Current mean updated with new mean
    ctr_deleted_drift_one_off = 0  # Deleted the drift entries as the latest mean is back in range of actual mean.
    ctr_inserted_drift_new = 0  # Inserted new drift values as they are quite out of range of actual mean values.
    ctr_updated_drift_as_current = 0  # drift values persisted for the wait period and hence setting drift as actual mean.
    ctr_updated_drift_cumulative = 0  # new mean is in range of drift mean, hence updating drift with cumulative value.
    ctr_updated_drift_new_drift = 0  # new mean is not in range of existing drift too, so resetting drift with new value.
    ctr_skipped_time_previous = 0  # new mean has come with time period older than existing values, hence ignored.
    ctr_inserted_current_new_entry = 0  # new entry found for the metric.
    ctr_skipped_key_invalid = 0  # invalid / no key value received. hence ignoring the metric and not updating anything.
    ctr_delete_drift_new_drift_found = 0  # deleting current drift as the new value is not in range of existing drift too.

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
        except Exception as ex:
            raise Exception("Exception occurred while initializing logger instance, %s", str(ex))

    def reset_log_counters(self):
        self.ctr_updated_current_cumulative = 0
        self.ctr_deleted_drift_one_off = 0
        self.ctr_inserted_drift_new = 0
        self.ctr_updated_drift_as_current = 0
        self.ctr_updated_drift_cumulative = 0
        self.ctr_updated_drift_new_drift = 0
        self.ctr_skipped_time_previous = 0
        self.ctr_inserted_current_new_entry = 0
        self.ctr_skipped_key_invalid = 0
        self.ctr_delete_drift_new_drift_found = 0

    def get_config_value(self, stanza, key):
        try:
            return self.config[stanza][key]
        except Exception as ex:
            self.log.error('Exception occurred while retrieving value from conf for stanza=%s, key=%s, '
                           'Exiting..  exception=%s', stanza, key, str(ex))
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

            # DB Connection parameters
            self.db_is_cluster = self.get_config_value('db', 'is_cluster')
            self.db_engine_type = self.get_config_value('db', 'engine_type')
            self.db_host = self.get_config_value('db', 'host')
            self.db_port = self.get_config_value('db', 'port')
            self.db_user = self.get_config_value('db', 'username')
            self.db_enc_pswd = self.get_config_value('db', 'encrypted_password')
            self.db_enc_key = self.get_config_value('db', 'encryption_key')

        except Exception as ex:
            self.log.error("Exception occurred while loading config file. Exiting.., exception=%s", str(ex))
            raise

    def create_hashmap_entry(self, time_period=None, is_drift=False, mean=None, stdev=None, count=None,
                             update_time=None, counter=None):
        """
        Creates a hash value based on the values provided.
        For actual values, hash value is created as - mean|stdev|update_time
        For drift values, hash value is created as - drift_mean|drift_stdev|drift_time|drift_counter
        The mean and standard deviations are rounded off to max digits as set in variable MAX_DECIMAL_ROUNDING
        This is to make sure that we do not end up having very huge decimal values and end up reaching the hash value
        limit of 64 bytes (redis config - hash-max-ziplist-value).
        :param time_period: prefix based on day & hour
        :param is_drift: boolean flag, if drift, the counter as well will be appended
        :param mean: value as received in the argument
        :param stdev: value as received in the argument
        :param count: value as received in teh argument
        :param update_time: epoch timestamp (rounded off to seconds)
        :param counter: drift counter, used only when is_drift flag is true
        :return: dict object {hash_key, hash_value}
        """

        hashmap_entry = {}
        try:
            if update_time:
                if not is_drift:
                    hashmap_entry[time_period] = str(round(mean, MAX_DECIMAL_ROUNDING)) + '|' + \
                                                str(round(stdev, MAX_DECIMAL_ROUNDING)) + '|' \
                                                + str(round(count)) + '|' + str(round(update_time))
                else:
                    hashmap_entry[time_period + ':' + CONST_DRIFT_SUFFIX] = \
                        str(round(mean, MAX_DECIMAL_ROUNDING)) + '|'\
                        + str(round(stdev, MAX_DECIMAL_ROUNDING))\
                        + '|' + str(round(count)) + '|' \
                        + str(round(update_time)) \
                        + '|' + str(round(counter))
                return hashmap_entry
            return None
        except Exception as ex:
            self.log.error('Exception occurred while creating hashmap entry for time_period=%s, is_drift=%s, '
                           'mean=%s, stdev=%s, count=%s, update_time=%s, counter=%s, exception=%s',
                           time_period, is_drift, mean, stdev, count, update_time, counter, str(ex))
            return None

    def calculate_cumulative_values(self, new_mean, new_stdev, new_count, existing_mean, existing_stdev,
                                    existing_count):
        """
        Calculates cumulative value.
        :param new_mean: Mean as in the incoming event
        :param new_stdev: Standard deviation as in the incoming event
        :param new_count: Count of data points as in the incoming event
        :param existing_mean: Mean retrieved from Redis for the same key / hash entry
        :param existing_count: Existing count of data points
        :param existing_stdev: Standard deviation retrieved from Redis for the same key / hash entry
        :return: tuple of updated mean and standard deviation (mean, stdev)
        """

        try:
            # if the existing count has gone higher than the weighted count, then the count is brought down as per
            # weightage * new count, so that the historical values does not subside the impact of new mean.
            # else if the existing count is less, then the same will be considered as-is for calculation.
            if existing_count > (self.historical_mean_weightage * new_count):
                weighted_existing_count = self.historical_mean_weightage * new_count
            else:
                weighted_existing_count = existing_count

            calc_total_count = weighted_existing_count + new_count
            calc_total_mean = ((weighted_existing_count * existing_mean) + (new_count * new_mean)) / calc_total_count
            existing_d = existing_mean - calc_total_mean
            new_d = new_mean - calc_total_mean

            calc_total_stdev = sqrt(
                (weighted_existing_count * ((existing_stdev ** 2) + (existing_d * existing_d)) +
                 new_count * ((new_stdev ** 2) + (new_d * new_d))) / (
                        weighted_existing_count + new_count))

            return calc_total_mean, calc_total_stdev, calc_total_count

        except Exception as ex:
            self.log.error('Exception occurred while calculating cumulative values for new_mean=%s, new_stdev=%s, '
                           'new_count=%s, existing_mean=%s, existing_stdev=%s, existing_count%s, exception=%s',
                           new_mean, new_stdev, new_count, existing_mean, existing_stdev, existing_count, str(ex))
            # Returning with existing values as-is if unable to calculate cumulative values
            return existing_mean, existing_stdev, existing_count

    def check_if_values_are_in_same_range(self, new_mean, existing_mean, existing_stdev):
        """
        Checks the new mean is in range of existing mean and stdev. The upper/lower bounds are calculated
        using the configured threshold multiplier.
        :param new_mean: Mean value as sent in the incoming event
        :param existing_mean: Mean retrieved for the same key / hash key from Redis
        :param existing_stdev: Stdev retrieved for the same key / hash key from Redis
        :return: Boolean. True if in range, False if not.
        """

        try:

            if self.mean_comparison_stdev_multiplier == 0:
                # Ignore the comparison and returns True without comparing the new and existing mean values
                return True

            limits = self.mean_comparison_stdev_multiplier * existing_stdev
            upper_limit = existing_mean + limits
            lower_limit = existing_mean - limits

            return True if lower_limit <= new_mean <= upper_limit else False

        except Exception as ex:
            self.log.error('Exception occurred while checking if values are in range, new_mean=%s,'
                           'existing_mean=%s, existing_stdev=%s, exception=%s',
                           new_mean, existing_mean, existing_stdev, str(ex))
            # Not raising exception and returning as False during exception, as it is better to ignore calculating
            # cumulative value when we are not sure if the new value is in range of not.
            # Rather create the new entry as drift.
            return False

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
            self.log.error('Exception occurred while trying to fetch existing values, input_value=%s, exception=%s',
                           input_value, str(ex))
            raise

    def calculate_update_threshold_values(self, input_value):
        """
        Compares the current metric values against the existing values and identifies the updated value.
        On a high level, if the new metric value is completely off the existing value, then creates drift metrics
        After a while, if the drift behavior continues, then the drift value is considered as new normal.
        :param input_value: the metric to be processed
        :return: None. Redis pipeline is updated with commands (hmset, hdel)
        """
        try:

            key = input_value.get('key', 'default')
            time_period = input_value.get('time_period', 'default')

            # retrieve the values from the incoming record
            new_mean = float(input_value.get(VARIABLE_MEAN, 0))
            new_stdev = float(input_value.get(VARIABLE_STDEV, 0))
            new_count = float(input_value.get(VARIABLE_COUNT, 0))
            new_time = float(input_value.get(VARIABLE_TIME, 0))

            # local variables to hold the existing db values based on the key
            existing_mean = 0
            existing_stdev = 0
            existing_count = 0
            existing_time = 0
            existing_drift_mean = 0
            existing_drift_stdev = 0
            existing_drift_time = 0
            existing_drift_count = 0
            existing_drift_counter = 0

            # from the dict of list of existing values (for all input keys), retrieve the
            # values for the current key / hash key in loop.
            existing_values_list = self.existing_values_dict.get(key + '_' + time_period)

            # ideally the existing_values_list should be as
            # ['mean|stdev|count|time', 'drift_mean|drift_stdev|drift_count|drift_time|drift_counter']
            # but if no existing values are found, then they are returned as None
            # or if only actual values are returned and no drift values, then they come as ['mean|stdev|time', None]
            # so in case of None, creating an array of [None, None]
            if not existing_values_list:
                existing_values_list = [None, None]

            for idx, existing_values in enumerate(existing_values_list):
                if idx == 0:  # handling the original values
                    if existing_values:
                        existing_values_array = existing_values.split('|')
                        if len(existing_values_array) == 4:
                            existing_mean = float(existing_values_array[0]) if existing_values_array[0] else 0
                            existing_stdev = float(existing_values_array[1]) if existing_values_array[1] else 0
                            existing_count = float(existing_values_array[2]) if existing_values_array[2] else 0
                            existing_time = float(existing_values_array[3]) if existing_values_array[3] else 0
                else:  # handling the drift values
                    if existing_values:
                        existing_drift_values_array = existing_values.split('|')
                        if len(existing_drift_values_array) == 5:
                            existing_drift_mean = float(existing_drift_values_array[0]) \
                                if existing_drift_values_array[0] else 0
                            existing_drift_stdev = float(existing_drift_values_array[1]) \
                                if existing_drift_values_array[1] else 0
                            existing_drift_count = float(existing_drift_values_array[2]) \
                                if existing_drift_values_array[2] else 0
                            existing_drift_time = float(existing_drift_values_array[3]) \
                                if existing_drift_values_array[3] else 0
                            existing_drift_counter = float(existing_drift_values_array[4]) \
                                if existing_drift_values_array[4] else 0

            if key != 'default' and time_period != 'default':

                if existing_time > 0:

                    # if the latest metric time is older than the existing ones, then the new metric will be ignored.
                    if (new_time > existing_time) and (new_time > existing_drift_time):

                        # Checks if the new mean is in range of existing mean / existing stdev
                        if self.check_if_values_are_in_same_range(new_mean, existing_mean, existing_stdev):

                            updated_mean, updated_stdev, updated_count = self.calculate_cumulative_values(new_mean,
                                                                                                          new_stdev,
                                                                                                          new_count,
                                                                                                          existing_mean,
                                                                                                          existing_stdev,
                                                                                                          existing_count)

                            # creates a new entry to be added to the hash map
                            mapping = self.create_hashmap_entry(time_period=time_period, is_drift=False,
                                                                mean=updated_mean, stdev=updated_stdev,
                                                                count=updated_count, update_time=new_time)

                            if mapping:
                                self.ctr_updated_current_cumulative += 1
                                self.db_pipeline.hset(name=key, mapping=mapping)
                            else:
                                self.log.error('Something wrong, hashmap not created for key=%s and time_period=%s',
                                               key, time_period)

                            if existing_drift_counter > 0:
                                # Since the latest value is in line with the existing values, drift values seems
                                # to be one-off. Hence deleting them.
                                self.ctr_deleted_drift_one_off += 1
                                self.db_pipeline.hdel(key, time_period + ':' + CONST_DRIFT_SUFFIX)

                        elif existing_drift_counter == 0:
                            # The new values are NOT in range with existing values and no earlier
                            # drift values found. Hence setting current values as drift values
                            mapping = self.create_hashmap_entry(time_period=time_period, is_drift=True,
                                                                mean=new_mean, stdev=new_stdev, count=new_count,
                                                                update_time=new_time, counter=1)
                            if mapping:
                                self.ctr_inserted_drift_new += 1
                                self.db_pipeline.hset(name=key, mapping=mapping)
                            else:
                                self.log.error('Something wrong, hashmap not created for key=%s and time_period=%s',
                                               key, time_period)

                        elif existing_drift_counter > 0:
                            # The new values are NOT in range with existing values and already drift values are present
                            if self.check_if_values_are_in_same_range(new_mean, existing_drift_mean,
                                                                      existing_drift_stdev):

                                # The new values are in range with existing drift values and hence
                                # cumulative drift values will be calculated
                                updated_mean, updated_stdev, updated_count = \
                                    self.calculate_cumulative_values(new_mean, new_stdev, new_count,
                                                                     existing_drift_mean, existing_drift_stdev,
                                                                     existing_drift_count)

                                updated_counter = existing_drift_counter + 1

                                if updated_counter >= self.max_allowed_drift_period_counter:
                                    # Seems like the drift counter has exceeded limit. So will rather
                                    # set the values as actual rather than drift values. The drift values are going to
                                    # be the new normal now.

                                    mapping = self.create_hashmap_entry(time_period=time_period, is_drift=False,
                                                                        mean=updated_mean, stdev=updated_stdev,
                                                                        count=updated_count, update_time=new_time)

                                    if mapping:
                                        self.db_pipeline.hset(name=key, mapping=mapping)
                                        self.ctr_updated_drift_as_current += 1
                                        self.db_pipeline.hdel(key, time_period + ':' + CONST_DRIFT_SUFFIX)
                                    else:
                                        self.log.error(
                                            'Something wrong, hashmap not created for key=%s and time_period=%s',
                                            key, time_period)
                                else:
                                    # Updating the existing drift values with updated values. Incrementing the counter
                                    # Still the drift counter has not exceeded the limit set. So, will continue to
                                    # consider the drift values as anomaly
                                    mapping = self.create_hashmap_entry(time_period=time_period, is_drift=True,
                                                                        mean=updated_mean, stdev=updated_stdev,
                                                                        update_time=new_time, count=updated_count,
                                                                        counter=updated_counter)
                                    if mapping:
                                        self.db_pipeline.hset(name=key, mapping=mapping)
                                        self.ctr_updated_drift_cumulative += 1
                                    else:
                                        self.log.error(
                                            'Something wrong, hashmap not created for key=%s and time_period=%s',
                                            key, time_period)

                            else:
                                # The existing drift values are not in range with the new values which
                                # also seem to be drifted. Hence deleting old ones and setting new drift values

                                mapping = self.create_hashmap_entry(time_period=time_period, is_drift=True,
                                                                    mean=new_mean, stdev=new_stdev,
                                                                    count=new_count, update_time=new_time, counter=1)
                                if mapping:
                                    self.ctr_updated_drift_new_drift += 1
                                    self.db_pipeline.hset(name=key, mapping=mapping)
                                else:
                                    self.log.error('Something wrong, hashmap not created for key=%s and time_period=%s',
                                                   key, time_period)
                    else:
                        # Skipping the latest values as they seem to be out-dated compared to existing values'
                        self.ctr_skipped_time_previous += 1

                else:
                    # No existing values found. Hence setting the incoming new values in the db as-is
                    # self.log.info('No existing values. Hence setting with new values as-is')
                    mapping = self.create_hashmap_entry(time_period=time_period, is_drift=False,
                                                        mean=new_mean, stdev=new_stdev, count=new_count,
                                                        update_time=new_time)
                    if mapping:
                        self.ctr_inserted_current_new_entry += 1
                        self.db_pipeline.hset(name=key, mapping=mapping)
                    else:
                        self.log.error('Something wrong, hashmap not created for key=%s and time_period=%s',
                                       key, time_period)

            else:
                # Key / HashKeyPrefix is not sent in the search results. Hence ignoring to process this request
                self.ctr_skipped_key_invalid += 1

        except Exception as ex:
            self.log.error('Exception occurred while calculating threshold values for %s, exception=%s',
                           input_value, str(ex))
            raise

    def stream(self, records):

        if not self.overall_time_start:
            self.overall_time_start = time.time()

        # Generates a new run id for every invocation
        if not self.run_id:
            self.run_id = self.metadata.searchinfo.sid

        # initializes the logger instance
        self.log = self.setup_logging()

        # loads the config from CONF_FILE if not loaded already
        if not self.config:
            self.log.info('Loading the configurations..')
            self.load_config()

        self.log.info('password is :')
        self.log.info(self.decrypt_password(self.db_enc_pswd, self.db_enc_key))

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
        records = list(records)

        # based on the value configured in .conf file, sets the max number of entries to be processed
        # in each chunk
        chunk_size = self.max_process_chunk_size

        # splits the input records in to multiple chunks based on chunk size
        # ex: input records = [1,2,3,...10] & chunk size = 2
        # chunk_list = [[1,2], [3,4], .. ,[9,10]]

        try:
            chunk_list = utils.split_chunks(records, chunk_size)
        except Exception as ex:
            self.log.error('Exception occurred while creating chunk list... %s', str(ex))
            raise Exception("Exception occurred while creating chunk list")

        self.log.info(f'Created chunks to process the records in batch. TotalRecords={len(records)}, '
                      f'TotalChunks={len(chunk_list)}, MaxChunkSize={self.max_process_chunk_size}')

        try:
            for chunk in chunk_list:
                chunk_idx = time.time() * 1000000

                # for each loop, resets the counters to 0.
                # counter will be used to identify the number of different scenarios processed in each loop
                self.reset_log_counters()
                chunk_process_time_start = time.time()
                self.db_pipeline = self.r.pipeline(transaction=False)

                # invokes the get_existing_values method which generates a pipeline
                # with hmget commands retrieving the actual and drift values if any for the keys in the
                # incoming records
                self.existing_values_dict = {}
                time_start_get_pipeline_load = time.time()
                list(map(self.get_existing_values, chunk))
                time_end_get_pipeline_load = time.time()
                self.log.info(f'Process Chunk, chunk_idx={chunk_idx}, chunk_size={len(chunk)}, '
                              f'activity=LoadGetExistingValuesPipeline, '
                              f'time_taken={time_end_get_pipeline_load - time_start_get_pipeline_load} secs')

                # the pipeline for get_existing_values is executed
                # the values will be returned as [(25|1.3|44|1689889782, 5|0.8|23|168977879), (), (), ..]
                # or as [(None, None), ...] if any of the key does not have existing values
                time_start_get_pipeline_values = time.time()
                existing_values = self.db_pipeline.execute()
                time_end_get_pipeline_values = time.time()
                self.log.info(f'Process Chunk, chunk_idx={chunk_idx}, chunk_size={len(chunk)},'
                              f' activity=ExecuteGetExistingValuesPipeline,'
                              f'time_taken={time_end_get_pipeline_values - time_start_get_pipeline_values} secs')

                # the key and the time prefix is made in to a list.
                # the values will be as
                # ['domain1:device1:inf1:metric1_mon:09', 'domain2:device2:inf2:metric1_tue:10' ..]
                time_start_retrieve_input_records_keys = time.time()
                input_keys_list = [x['key'] + '_' + x['time_period'] for x in chunk]
                time_end_retrieve_input_records_keys = time.time()
                self.log.info(f'Process Chunk, chunk_idx={chunk_idx}, chunk_size={len(chunk)}, '
                              f'activity=RetrieveAllKeysFromInputRecord,'
                              f'time_taken='
                              f'{time_end_retrieve_input_records_keys - time_start_retrieve_input_records_keys} secs')

                # the existing values list and as well the input keys list will be zipped together as a dict.
                # the values will be
                # {'domain1:device1:inf1:metric1_mon:09': [25|1.3|44|1689889782, 5|0.8|23|168977879], ..}
                time_start_zip_input_keys_existing_values = time.time()
                self.existing_values_dict = dict(zip(input_keys_list, existing_values))
                time_end_zip_input_keys_existing_values = time.time()
                self.log.info(f'Process Chunk, chunk_idx={chunk_idx}, chunk_size={len(chunk)},'
                              f'activity=ZipInputKeysExistingValues,'
                              f'time_taken='
                              f'{time_end_zip_input_keys_existing_values - time_start_zip_input_keys_existing_values}'
                              f' secs')

                self.db_pipeline = self.r.pipeline(transaction=False)

                # for each entry in the chunk, the updated threshold values will be calculated
                # the update pipeline will be populated with the hmset or hdel commands as required.
                ts_calc_upd_threshold_values = time.time()
                list(map(self.calculate_update_threshold_values, iter(chunk)))
                te_calc_upd_threshold_values = time.time()
                self.log.info(f'Process Chunk, chunk_idx={chunk_idx}, chunk_size={len(chunk)},'
                              f'activity=CalculateUpdateThresholdValues,'
                              f'time_taken={te_calc_upd_threshold_values - ts_calc_upd_threshold_values} secs')

                # at last, all the updates for the chunk will be executed together in one-go.
                time_start_execute_update_pipeline = time.time()
                self.db_pipeline.execute()
                time_end_execute_update_pipeline = time.time()
                self.log.info(f'Process Chunk, chunk_idx={chunk_idx}, chunk_size={len(chunk)}, '
                              f'activity=ExecuteUpdatePipeline, time_taken='
                              f'{time_end_execute_update_pipeline - time_start_execute_update_pipeline} secs')
                chunk_process_time_end = time.time()

                self.log.info(f'Process Chunk, run_id={self.run_id}, chunk_idx={chunk_idx}, chunk_size={len(chunk)},'
                              f'chunk_process_time={chunk_process_time_end - chunk_process_time_start}, '
                              f'ctr_updated_current_cumulative={self.ctr_updated_current_cumulative}, '
                              f'ctr_deleted_drift_one_off={self.ctr_deleted_drift_one_off}, '
                              f'ctr_inserted_drift_new={self.ctr_inserted_drift_new}, '
                              f'ctr_updated_drift_as_current={self.ctr_updated_drift_as_current}, '
                              f'ctr_updated_drift_cumulative={self.ctr_updated_current_cumulative}, '
                              f'ctr_updated_drift_new_drift={self.ctr_updated_drift_new_drift}, '
                              f'ctr_skipped_key_invalid={self.ctr_skipped_key_invalid}, '
                              f'ctr_skipped_time_previous={self.ctr_skipped_time_previous}, '
                              f'ctr_inserted_current_new_entry={self.ctr_inserted_current_new_entry}')

                yield {'run_id': self.run_id, 'chunk_idx': chunk_idx, 'chunk_size': len(chunk),
                       'chunk_process_time': chunk_process_time_end - chunk_process_time_start,
                       'ctr_updated_current_cumulative': self.ctr_updated_current_cumulative,
                       'ctr_deleted_drift_one_off': self.ctr_deleted_drift_one_off,
                       'ctr_inserted_drift_new': self.ctr_inserted_drift_new,
                       'ctr_updated_drift_as_current': self.ctr_updated_drift_as_current,
                       'ctr_updated_drift_cumulative': self.ctr_updated_drift_cumulative,
                       'ctr_updated_drift_new_drift': self.ctr_updated_drift_new_drift,
                       'ctr_skipped_key_invalid': self.ctr_skipped_key_invalid,
                       'ctr_skipped_time_previous': self.ctr_skipped_time_previous,
                       'ctr_inserted_current_new_entry': self.ctr_inserted_current_new_entry}

        except Exception as ex:
            self.log.error('Exception occurred while looping the chunks, exception=%s', str(ex))
            raise Exception("Exception occurred while looping the chunks, exception=%s")

        finally:
            self.db_pipeline.close()

            self.overall_time_end = time.time()

            self.log.info(f'Completed processing the records. '
                          f'time_taken={self.overall_time_end - self.overall_time_start} seconds')

            logging.shutdown()


dispatch(UpdateThresholdValues, sys.argv, sys.stdin, sys.stdout, __name__)
