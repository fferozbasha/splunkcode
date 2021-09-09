import random
import keydb
import subprocess
import os

__VALID_DB_ENGINES = ('redis', 'keydb')
SPLUNK_HOME = os.environ['SPLUNK_HOME']


def decrypt_password(encoded_text, key):
    """
    Password encrypted using command as
    echo 'password | ./splunk cmd openssl aes-256-cbc -a -salt -k 'secretkey'
    :param encoded_text: Encrypted password string
    :param key: Encoded secret key
    :return: Plain text password
    """
    try:
        command = "echo '%s' " \
              "| %s/bin/splunk cmd openssl aes-256-cbc -a -d -salt -k '%s'" % \
              (encoded_text, SPLUNK_HOME, key)
        p = subprocess.Popen(command,
                             shell=True,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        password = p.communicate()[0].decode()
        password = password.lstrip()
        password = password.rstrip()
        return password
    except Exception:
        raise


def connect_db(db_engine_type=None, db_is_cluster=None, db_host=None, db_port=None, db_username='default',
               db_encrypted_password=None, db_password_key=None):
    db_engine_connection = None
    db_password = None

    if db_encrypted_password and db_password_key:
        try:
            db_password = decrypt_password(db_encrypted_password, db_password_key)
        except Exception as ex:
            raise

    try:
        if db_engine_type not in __VALID_DB_ENGINES:
            raise Exception('Invalid DB engine. Not supported. db_engine=%s', db_engine_type)

        if db_engine_type == 'redis':
            if db_is_cluster == '1':
                from rediscluster import RedisCluster
                startup_nodes_list = []
                cluster_nodes_list = db_host.split(',')
                for node in cluster_nodes_list:
                    temp = dict()
                    temp['host'] = node.split(':')[0]
                    temp['port'] = node.split(':')[1]
                    startup_nodes_list.append(temp)
                db_engine_connection = RedisCluster(startup_nodes=startup_nodes_list, username=db_username,
                                                    password=db_password, decode_responses=True)
                return db_engine_connection
            else:
                import redis
                db_engine_connection = redis.StrictRedis(host=db_host, port=db_port, username=db_username,
                                                         password=db_password, decode_responses=True)
                return db_engine_connection
        elif db_engine_type == 'keydb':
            try:
                if db_is_cluster == '0':
                    db_engine_connection = keydb.StrictRedis(host=db_host, port=db_port, username=db_username,
                                                             password=db_password, decode_responses=True)
                    return db_engine_connection
                else:
                    raise Exception("KeyDB Cluster configuration is not yet supported")
            except Exception as ex:
                log.error('Exception occurred while creating db connection ' + str(ex))

        return db_engine_connection

    except Exception as e:
        raise Exception(str(e))


def split_chunks(records, chunk_size):
    try:
        chunk_list = []
        if len(records) > chunk_size:
            chunk_list = [records[i * chunk_size:(i + 1) * chunk_size] for i in
                          range((len(records) + chunk_size - 1) // chunk_size)]

            # For the residual value in the last chunk, if the value is just around 10% of
            # the configured chunk size, then that will be appended to the previous chunk
            # so that a loop with very less entries is avoided and rather processed together with the
            # earlier loop.
            if len(chunk_list[len(chunk_list) - 1]) < (0.1 * chunk_size):
                chunk_list[len(chunk_list) - 2] = chunk_list[len(chunk_list) - 2] + chunk_list[len(chunk_list) - 1]
                del chunk_list[-1]

        else:
            chunk_list.append(records)

        return chunk_list
    except Exception as ex:
        raise Exception('Exception occurred while creating chunks.. %s, ', str(ex))
