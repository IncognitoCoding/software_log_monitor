#!interpreter

"""
This program is designed to search through software logs to determine if an issue is present. The issue is logged into a tracker file, and an email is sent.
The tracker file is used, so previously discovered issues are skipped because they were sent in a previous notification email. Eventually, software like Sonarr, Radarr, etc. 
will clear log files because the size and previously discovered issues will be gone.

Each discovered issue will be logged and emailed separately. This is by design to make sure each issue gets individual focus when emailed.
"""

# Built-in/Generic Imports
import os
import pathlib
import sys
import traceback
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
from traceback import print_exc
import glob
from urllib.parse import urlparse
import threading
from threading import Thread
from threading import Event
import time
import socket

# Libraries
from functools import partial

# Own modules
from ictoolkit.directors.log_director import create_logger
from ictoolkit.directors.file_director import file_exist_check
from ictoolkit.directors.file_director import search_file
from ictoolkit.directors.file_director import search_multiple_files
from ictoolkit.directors.email_director import send_email
from ictoolkit.directors.yaml_director import read_yaml_config, yaml_value_validation
from ictoolkit.directors.subprocess_director import start_subprocess
from ictoolkit.directors.thread_director import start_function_thread
from companion.decryptor.http_info_decryptor import start_decryptor_site
from ictoolkit.directors.dict_director import remove_duplicate_dict_values_in_list

__author__ = 'IncognitoCoding'
__copyright__ = 'Copyright 2021, software_log_monitor'
__credits__ = ['IncognitoCoding', 'Monoloch']
__license__ = 'GPL'
__version__ = '0.2'
__maintainer__ = 'IncognitoCoding'
__status__ = 'Development'


def software_log_info_check(info_tracking_file_path, monitored_software_file_path, monitored_software_name, monitored_software_search_info, root_logger, tracker_logger):
    """This function is used to check if the searched info exist in the software log. Uses logs, software name, and info information to determine the file matches the search info.

    Args:
        info_tracking_file_path (str): log tracking file path
        monitored_software_file_path (str): monitoring software log file path
        monitored_software_name (str): monitoring software name
        monitored_software_search_info (str): monitoring software log search info
        root_logger (logger): main root loggger
        tracker_logger (logger): tracker logger used for keeping track of discovered searched info

    Returns:
        list or None: a list of discovered search values that have not been previously matched. Each discovered value is per element. No discovered values will return None
    """

    # Creates list variable to be used for returning multiple found tracker files (ex. Rotation Backups).
    unreported_issue_tracker_info = []

    root_logger.debug('Using the software file, software name, and issued string to determine the log file issues')
    root_logger.debug(f'Begining to search for info in log file. Searching software \"{monitored_software_name}\" for search info \"{monitored_software_search_info}\"')
    
    # Calls function to search for info in the software log file.
    # Calling Example: search_file(<log file>, <search string>, <configured logger>)
    # Return Example: <list with info> or <none>
    found_software_search_entries = search_file(monitored_software_file_path, monitored_software_search_info, root_logger)
    
    # Sets count on matched info entries. Each discovered entry will be one per line.
    count_mached_info = len(found_software_search_entries)

    # Checks if search found the info in the log file.
    if found_software_search_entries != "None": 
        
        # Sets the basename variable for logging output only.
        basename_info_tracking_path = os.path.basename(info_tracking_file_path)

        root_logger.info(f'Searching info \"{monitored_software_search_info}\" found {count_mached_info} matches in {monitored_software_name}\'s log file \"{basename_info_tracking_path}\"')
        root_logger.debug('Looping through each discovered match entry and comparing against the info tracker logs.')

        # Loops through each found info entry. Found info entries will be validated against the tracker log. If it does not exist, the info entry will be added to a list.
        for index, info in enumerate(found_software_search_entries):
            
            # Sets the found_entry value to a variable. This is done to decrease the code complexity.
            found_info = info.get('found_entry')

            root_logger.debug(f'Looping through matched info {index + 1} of {count_mached_info}')
            root_logger.info(f'Checking the info tracker file \"{basename_info_tracking_path}\" to find previously discovered info \"{found_info}\"')
            
            # Gets all tracker log files, including backups.
            info_tracking_file_paths = glob.glob(f'{info_tracking_file_path}*')
            
            # Calls function to search if the found entry info has already been found and added into the tracker log(s).
            # Calling Example: search_file(<list list of files>, <search string>, <configured logger>)
            # Return Example: [{'search_entry': '|Error|', 'found_entry': 'the entry found'}, {'search_entry': '|Warning|', 'found_entry': 'the entry found'}]
            found_tracker_file_entries = search_multiple_files(info_tracking_file_paths, found_info, root_logger)

            # Checks if no return data is found in the tracker log(s). This is used to determine if the info entry has been previously discovered and needs skipped.
            if found_tracker_file_entries == None: 
                # Validates entry does not already exist in the tracker file(s) before writting.
                if found_info not in unreported_issue_tracker_info:
                    # Adds the previous discovered issue that was not found in the tracker file to the list for processing.
                    # Returns dictionary entry and not just the second element.
                    unreported_issue_tracker_info.append(info)

        # Checks if the list has any entries. Found entries will be returned in list format, and no entries will return none because the notification has already been sent.
        if not unreported_issue_tracker_info: 
            return None
        else:
            return unreported_issue_tracker_info

    else:
        root_logger.info('No matching info found. No action is required')


def merge_software_monitored_settings(config_yaml_read):
    """
    This function is part of the yaml import. The function takes the users software name, software path, and software log search strings and merges them into a multidemensional list.
    This function is required to allow monitored software entries in the yaml configuration file. The yaml configuration file allows dynamic software entries. This allows the user to 
    add software without updating the script. This function will create an list with the required monitored software settings. Calling the function will pull the monitored software 
    settings and merge the user-selected software log path and software log search string.

    Args:
        config_yaml_read (yaml): read in YAML configuration

    Raises:
        ValueError: The YAML software entry section is missing the required keys. Please verify you have set all required keys and try again
        ValueError: No value has been entered for '{key}' nested key 'info_search' in the YAML file
        ValueError: Incorrect '{key}' nested key 'info_search' YAML value. <class 'str' or class 'list'> is required
    Returns:
        list: A list of individual software monitored settings. Each line represents an individual software. The list is returned with individual list elements. Each list element 
              will contain the software name, software URL log path, and "software log search info. 
              Return Example: [['Sonarr', '\\\\mypath\\sonarr sample.log', ['|Error|', 'Warning'], None, None], ['Radarr', '\\\\mypath\\radarr sample.log', '|Error|', None, None]]
    """

    # Assigns the software path and software search string to create a multidimensional list.
    # Placement Example: [name, url_log_path, info_search, post_processing_args, post_processing_info_search]
    # Return Example: ['Sonarr', '\\\\mypath\\sonarr sample.log', ['|Error|', 'Warning'], None, None]
    software_monitored_settings = []

    # Finds all software monitoring entries in the YAML configuration and loops through each one to pull the configuration settings.
    for key, monitored_software in config_yaml_read.get('software').items():
        
        try:

            # Gets software configuration settings from the yaml configuration.
            name = monitored_software.get('name')
            url_log_path = monitored_software.get('url_log_path')
            info_search = monitored_software.get('info_search')
            email_subject_line = monitored_software.get('email_subject_line')
            post_processing_args = monitored_software.get('post_processing_args')
            post_processing_info_search = monitored_software.get('post_processing_info_search')
            post_processing_email_subject_line = monitored_software.get('post_processing_email_subject_line')

        except Exception as err:
            raise ValueError(f'The YAML software entry section is missing the required keys. Please verify you have set all required keys and try again, Originating error on line {format(sys.exc_info()[-1].tb_lineno)} in <{__name__}>')

        # Validates the YAML value.
        # Email subject and Post-processing values are not required because these are optional settings.
        yaml_value_validation(f'{key} nested key \'name\'', name, str)
        yaml_value_validation(f'{key} nested key \'url_log_path\'', url_log_path, str)
        # Local YAML value validation because multiple types (str or list) are possible.
        if not info_search:
            raise ValueError(f'No value has been entered for \'{key}\' nested key \'info_search\' in the YAML file, Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
        if not isinstance(info_search, list) and not isinstance(info_search, str):
            raise ValueError(f'Incorrect \'{key}\' nested key \'info_search\' YAML value. <class \'str\' or class \'list\'> is required, Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
        
        # Takes the software path and software search string and creates a single multidimensional list entry.
        software_monitored_settings.append([name, url_log_path, info_search, email_subject_line, post_processing_args, post_processing_info_search, post_processing_email_subject_line])

    return software_monitored_settings


def populate_startup_variables():
    """
    This function populates all hard-coded and yaml-configuration variables into a dictionary that is pulled into the main function.
    YAML entry validation checks are performed within this function. No manual configurations are setup within the program. All user 
    settings are completed in the "software_log_monitor.yaml" configuration file.
    
    Raises:
        ValueError: The 'general' key is missing from the YAML file
        ValueError: The 'software' key is missing from the YAML file
        ValueError: The 'email' key is missing from the YAML file
        ValueError: The 'companion_programs' key is missing from the YAML file
        ValueError: The 'logging' key is missing from the YAML file
        ValueError: NameError
        ValueError: KeyError
        ValueError: General Error
        
    Returns:
        dict: A dictionary of all startup variables required for the program to run. These startup variables consist of pre-configured and YAML configuration.
    """

    # Initialized an empty dictionary for running variables.
    startup_variables = {}
    # Initialized an empty dictionary for email variables.
    email_settings = {}

    # This is required to start the program. The YAML file is read to set the required variables.
    # No file output or formatted console logging is completed in these variable population sections. Basic print statements will prompt an error.
    # Each configuration section is unique. To make the read easier, each sections will be comment blocked using ############.
    try:

        ##############################################################################
        # Gets the config from the YAML file.
        returned_yaml_read_config = read_yaml_config('software_log_monitor.yaml')

        # Validates required root keys exist in the YAML configuration.
        if not 'general' in returned_yaml_read_config:
            raise ValueError(f'The \'general\' key is missing from the YAML file, Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
        if not 'software' in returned_yaml_read_config:
            raise ValueError(f'The \'software\' key is missing from the YAML file, Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
        if not 'email' in returned_yaml_read_config:
            raise ValueError(f'The \'email\' key is missing from the YAML file, Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
        if not 'companion_programs' in returned_yaml_read_config:
            raise ValueError(f'The \'companion_programs\' key is missing from the YAML file, Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')
        if not 'logging' in returned_yaml_read_config:
            raise ValueError(f'The \'logging\' key is missing from the YAML file, Originating error on line {traceback.extract_stack()[-1].lineno} in <{__name__}>')

        # Sets the yaml read configuration to the dictionary.
        startup_variables['imported_yaml_read_config'] = returned_yaml_read_config
        ##############################################################################

        ##############################################################################
        # Gets the programs root directory.
        preset_root_directory = os.path.dirname(os.path.realpath(__file__))

        # Sets the program save path to the script directory.
        save_log_path = os.path.abspath(f'{preset_root_directory}/logs')
        
        # Checks if the save_log_path exists and if not it will be created.
        # This is required because the logs do not save to the root directory.
        if not os.path.exists(save_log_path):
            os.makedirs(save_log_path)

        # Sets the savePath to the startup_variable dictionary.
        startup_variables['save_log_path'] = save_log_path
        ##############################################################################

        ##############################################################################
        # Gets the monitoring software sleep settings.
        #
        # Time is in seconds.
        monitor_sleep = returned_yaml_read_config.get('general', {}).get('monitor_sleep')

        # Validates the YAML value.
        yaml_value_validation('monitor_sleep', monitor_sleep, int)
        
        # Sets the sleep time in seconds to the startup_variable dictionary
        startup_variables['monitor_sleep'] = monitor_sleep
        ##############################################################################

        ##############################################################################
        # Gets the option to enable or not enable email alerts.
        email_alerts = returned_yaml_read_config.get('general', {}).get('email_alerts')

        # Validates the YAML value.
        yaml_value_validation('email_alerts', email_alerts, bool)

        # Sets the sleep time in seconds to the startup_variable dictionary
        startup_variables['email_alerts'] = email_alerts
        ##############################################################################

        ##############################################################################
        # Gets the option to enable or not enable program error email alerts.
        #
        alert_program_errors = returned_yaml_read_config.get('general', {}).get('alert_program_errors')

        # Validates the YAML value.
        yaml_value_validation('alert_program_errors', alert_program_errors, bool)

        # Sets the sleep time in seconds to the startup_variable dictionary
        startup_variables['alert_program_errors'] = alert_program_errors
        ##############################################################################

        ##############################################################################
        # Gets the max log size.
        #
        # Calling function to set the max log size in bytes.
        # Default 1000000 Byltes (1 Megabyte)
        max_log_file_size = returned_yaml_read_config.get('logging', {}).get('max_log_file_size')

        # Validates the YAML value.
        yaml_value_validation('max_log_file_size', max_log_file_size, int)
        ##############################################################################

        ##############################################################################
        # Gets/Sets the root logger.
        #
        # Sets the name of the logger.
        logger_name = __name__
        # Set the name of the log file.
        log_name = 'software_log_monitor.log'
        # Sets the file log level.
        file_log_level = returned_yaml_read_config.get('logging', {}).get('file_log_level')
        # Sets the console log level.
        console_log_level = returned_yaml_read_config.get('logging', {}).get('console_log_level')
        # Sets the log format based on a number option or manual.
        logging_format_option = returned_yaml_read_config.get('logging', {}).get('logging_format_option')
        # Sets handler option.
        logging_handler_option = returned_yaml_read_config.get('logging', {}).get('logging_handler_option')
        # Sets the backup count.
        logging_backup_log_count = returned_yaml_read_config.get('logging', {}).get('logging_backup_log_count')
        # Sets the rollover option.
        rollover = returned_yaml_read_config.get('logging', {}).get('rollover')

        # Validates the YAML value.
        yaml_value_validation('file_log_level', file_log_level, str)
        yaml_value_validation('console_log_level', console_log_level, str)
        yaml_value_validation('logging_handler_option', logging_handler_option, int)
        yaml_value_validation('logging_backup_log_count', logging_backup_log_count, int)
        yaml_value_validation('rollover', rollover, bool)

        # Sets LoggingFormatOption entry type based on input.
        # Checks if user entered a custom format or selected a pre-configured option.
        if '%' in f'{logging_format_option}':
            # Removes single quotes from logging format if they exist.
            logging_format_option = logging_format_option.replace("'", "")
        else:

            # Validates the YAML value.
            yaml_value_validation('logging_format_option', logging_format_option, int)

            # Converts string to int because the user selected a pre-configured option.
            logging_format_option = int(logging_format_option)
            
        # Calls function to setup logging and create the root logger.
        root_logger = create_logger(save_log_path, logger_name, log_name, max_log_file_size, file_log_level, console_log_level, logging_backup_log_count, logging_format_option, logging_handler_option, rollover)
        
        # Sets the tracker_logger to the startup_variable dictionary.
        startup_variables['root_logger'] = root_logger
        ##############################################################################

        ##############################################################################
        # Gets/Sets the tracker logger.
        #
        # This is used for tracking matched search info. The logger will only be used to log the discovered search info and rotate files.
        #
        # NOTE: Some of these settings are hard-coded. No yaml configuration input.
        #
        # Sets the name of the logger.
        logger_name = 'Tracker'
        # Set the name of the log file.
        tracker_log_name = 'software_matched_log_tracker.log'
        # Sets the file log level.
        file_log_level = 'DEBUG'
        # Sets the console log level.
        console_log_level = 'INFO'
        # Sets the log format based on a number option or manual.
        logging_format_option = 2
        # Sets handler option.
        logging_handler_option = 2
        # Sets rollover
        rollover = False

        # Calls function to setup logging and create the tracker logger.
        tracker_logger = create_logger(save_log_path, logger_name, tracker_log_name, max_log_file_size, file_log_level, console_log_level, logging_backup_log_count, logging_format_option, logging_handler_option, rollover)

        # Sets the trackerLoggerName to the startup_variable dictionary.
        startup_variables['tracker_log_name'] = tracker_log_name

        # Sets the tracker_logger to the startup_variable dictionary.
        startup_variables['preset_trackerLogger'] = tracker_logger
        ##############################################################################

        ##############################################################################
        # Sets email values.
        smtp = returned_yaml_read_config.get('email', {}).get('smtp')
        authentication_required = returned_yaml_read_config.get('email', {}).get('authentication_required')
        use_tls = returned_yaml_read_config.get('email', {}).get('use_tls')
        username = returned_yaml_read_config.get('email', {}).get('username')
        password = returned_yaml_read_config.get('email', {}).get('password')
        from_email = returned_yaml_read_config.get('email', {}).get('from_email')
        to_email = returned_yaml_read_config.get('email', {}).get('to_email')
        send_message_encrypted = returned_yaml_read_config.get('email', {}).get('send_message_encrypted')
        message_encryption_password = returned_yaml_read_config.get('email', {}).get('message_encryption_password')
        # Gets the random "salt".
        # yaml bytes entry being passed is not allowing it to be recognized as bytes.
        # Seems the only way to fix the issue is to strip the bytes section and re-encode.
        # Strips the bytes section off the input.
        # Removes first 2 characters.
        unconverted_encrypted_info = returned_yaml_read_config.get('email', {}).get('message_encryption_random_salt')[2:]

        # Validates the YAML value.
        yaml_value_validation('smtp', smtp, str)
        yaml_value_validation('authentication_required', authentication_required, bool)
        yaml_value_validation('use_tls', use_tls, bool)
        yaml_value_validation('username', username, str)
        yaml_value_validation('password', password, str)
        yaml_value_validation('from_email', from_email, str)
        yaml_value_validation('to_email', to_email, str)
        yaml_value_validation('send_message_encrypted', send_message_encrypted, bool)
        yaml_value_validation('message_encryption_password', message_encryption_password, str)
        yaml_value_validation('unconverted_encrypted_info', unconverted_encrypted_info, str)

        # Adds the email_settings into a dictionary.
        email_settings['smtp'] = smtp
        email_settings['authentication_required'] = authentication_required
        email_settings['use_tls'] = use_tls
        email_settings['username'] = username
        email_settings['password'] = password
        email_settings['from_email'] = from_email
        email_settings['to_email'] = to_email
        email_settings['send_message_encrypted'] = send_message_encrypted
        email_settings['message_encryption_password'] = message_encryption_password
        
        # Removes last character.
        unconverted_encrypted_info = unconverted_encrypted_info[:-1]
        # Re-encodes the salt and sets value to the email_settings dictionary.
        # Adds the random "salt" to the email_settings into a dictionary.
        email_settings['message_encryption_random_salt'] = unconverted_encrypted_info.encode()

        # Sets email dictionary settings to the startup_variable dictionary.
        startup_variables['email_settings'] = email_settings
        ##############################################################################

        ##############################################################################
        # Gets the monitoring software settings by calling the function and merging the user-selected software log path and software log search string.
        # Return Example: [['Sonarr', '\\\\mypath\\sonarr sample.log', ['|Error|', 'Warning'], None, None], ['Radarr', '\\\\mypath\\radarr sample.log', '|Error|', None, None]]
        monitored_software_settings = merge_software_monitored_settings(returned_yaml_read_config)
        ##############################################################################

        ##############################################################################
        # Sets the monitored software settings to the startup_variable dictionary
        startup_variables['monitored_software_settings'] = monitored_software_settings
        ##############################################################################

        ##############################################################################
        # Gets the users option on enabling the web companion.
        decryptor_web_companion_option = returned_yaml_read_config.get('companion_programs', {}).get('decryptor_web_companion_option')

        # Validates the YAML value.
        yaml_value_validation('decryptor_web_companion_option', decryptor_web_companion_option, bool)

        # Sets decriptor web compaion option to the startup_variable dictionary.
        startup_variables['decryptor_web_companion_option'] = decryptor_web_companion_option
        ##############################################################################

        # Returns the dictionary with all the startup variables.
        return (startup_variables)

    except NameError as err:
        print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|NameError: {err}, Error on line {format(sys.exc_info()[-1].tb_lineno)} in <{__name__}>')

    except KeyError as err:
        print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|KeyError: {err}, Error on line {format(sys.exc_info()[-1].tb_lineno)} in <{__name__}>')
        
    except Exception as err:
        print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|{err}, Error on line {format(sys.exc_info()[-1].tb_lineno)} in <{__name__}>')
        quit()


def main():
    """This function is main program function that controls all the sub-function calls. A loop set to allow this program to run all time and process based on a sleep variable."""

    # Calls function to pull in the startup variables.
    startup_variables = populate_startup_variables()

    # Sets top-level main variables based on the dictionary of presets.
    # Note: Using [] will give KeyError and using get() will return None.
    save_log_path = startup_variables.get('save_log_path')
    email_alerts = startup_variables.get('email_alerts')
    alert_program_errors = startup_variables.get('alert_program_errors')
    tracker_log_name = startup_variables.get('tracker_log_name')
    root_logger = startup_variables.get('root_logger')
    tracker_logger = startup_variables.get('preset_trackerLogger')
    monitored_software_settings = startup_variables.get('monitored_software_settings')
    email_settings = startup_variables.get('email_settings')
    monitor_sleep = startup_variables.get('monitor_sleep')
    decryptor_web_companion_option = startup_variables.get('decryptor_web_companion_option')

    root_logger.info('######################################################################')
    root_logger.info('                     Software Log Monitor Check                       ')
    root_logger.info('######################################################################')

    # Checks if the user enabled the start_decryptor_site companion program program.
    if decryptor_web_companion_option == True:

        # Checks if the start_decryptor_site companion program program is not running for initial startup.
        if 'companion_decryptor_thread' not in str(threading.enumerate()):

            root_logger.info('Starting the start_decryptor_site companion program')

            # Gets message encryption settings from the yaml configuration to pass to the companion decryptor.
            message_encryption_password = email_settings.get('message_encryption_password')
            message_encryption_random_salt = email_settings.get('message_encryption_random_salt')

            # This calls the start_function_thread function and passes the companion start_decryptor_site function and arguments to the start_function_thread.
            # You have to use functools for this to work correctly. Adding the function without functools will cause the function to start before being passed to the start_function_thread.
            start_function_thread(partial(start_decryptor_site, message_encryption_password, message_encryption_random_salt, False), 'companion_decryptor_thread', False)

            # Sleeps 5 seconds to allow startup.
            time.sleep(5)

            # Gets the hosts IP address for message output.
            host_ip = socket.gethostbyname(socket.gethostname()) 

            # Validates the start_decryptor_site companion program started.
            if 'companion_decryptor_thread' in str(threading.enumerate()):
                root_logger.info(f'start_decryptor_site companion program has started. You may access the webpage via http://127.0.0.1:5000/ or http://{host_ip}:5000/')
            else:
                root_logger.error('Failed to start the start_decryptor_site companion program. The program will continue, but additional troubleshooting will be required to utilize the decryption companion\'s web interface')

    elif decryptor_web_companion_option == False:

        # Checks if the start_decryptor_site companion program is running. This can happen when the yaml is modified when the program is running.
        if 'companion_decryptor_thread' in str(threading.enumerate()):
            root_logger.warning('The user has chosen to turn off the start_decryptor_site companion program. Please restart the program for this change to take effect')
        else:
            root_logger.debug('The user has chosen not to use the start_decryptor_site companion programm')
            

    root_logger.debug('Starting the main program function')
    root_logger.info(f'{monitor_sleep} seconds until next log check')

    # Sleeps for the amount of seconds set in the YAML file.
    time.sleep(monitor_sleep)

    # Setting the hard-coded info tracker log path.
    path_software_matched_log_tracker = os.path.abspath(f'{save_log_path}/{tracker_log_name}')

    # Loops through each monitored software settings entry.
    for software_settings in monitored_software_settings:

        # Sets easier to read variables from list.
        # Entry Example1: ['MySoftware', 'software sample log.txt', '|Error|', 'Error Detected in MySoftware', 'python', '\\mypath\\software.py', 'Software.py Ran Successful']
        # Entry Example2: ['Sonarr', '\\\\mypath\\sonarr sample.log', ['|Error|', 'Warning'], None, None, None, None]
        name_monitoring_software = software_settings[0]
        file_monitoring_software = os.path.abspath(software_settings[1])
        monitored_software_search_info = software_settings[2]
        email_subject_line = software_settings[3]
        post_processing_args = software_settings[4]
        post_processing_info_search = software_settings[5]
        post_processing_email_subject_line = software_settings[6]

        # Sets the basename for cleaner logging output.
        basename_monitoring_software = os.path.basename(file_monitoring_software)

        root_logger.debug(f'Processing software \"{name_monitoring_software}\" with the file name \"{basename_monitoring_software}\" and searching for info \"{monitored_software_search_info}\"')

        try:

            # Verifies monitoring software log file exists.
            # Calling Example: file_exist_check(<monitoring software log file path>, <software name>, <configured logger>)
            file_exist_check(file_monitoring_software, name_monitoring_software, root_logger)

            # Calls function to check if the searched info exist in the software log.
            # Calling Example: software_log_info_check(<info tracking log file path>, <monitoring software log file path>, <software name>, <info to search>)
            matched_software_info = software_log_info_check(path_software_matched_log_tracker, file_monitoring_software, name_monitoring_software, monitored_software_search_info, root_logger, tracker_logger)

            # Validates the return value is not equal to "None". None = nothing was found.
            if matched_software_info != None:
                
                 # Custom log level that has been created for alerts. (39 = ALERT)
                root_logger.log(39,'The info is newly discovered')

                # Sets count on total entries found
                total_info_entries = len(matched_software_info)

                root_logger.debug('Starting to loop through matched info')

                # Loops through matched software info. If info exists in the list, an email will be sent.
                for index, info in enumerate(matched_software_info):

                    # Sets the searched_entry value to a variable. This is done to decrease the code complexity.
                    searched_entry = info.get('search_entry')
                    # Sets the found_entry value to a variable. This is done to decrease the code complexity.
                    matched_info = info.get('found_entry')

                    # Custom log level that has been created for alerts. (39 = ALERT)
                    root_logger.log(39,f'Writing output to tracker log. Entry {index + 1} of {total_info_entries}')

                    # Writes returned software info status.
                    tracker_logger.info(matched_info)

                    # Checks if email notifications are enabled
                    if email_alerts:

                        # Custom log level that has been created for alerts. (39 = ALERT)
                        root_logger.log(39,f'Sending email. Entry {index + 1} of {total_info_entries}')

                        # Sets the default email subject line if one did not get provided in the YAML.
                        if email_subject_line == None:
                            email_subject_line = f'Software Log Discovery Event for {name_monitoring_software}. Search Entry = ({searched_entry})'

                        # Calls function to send the email.
                        # Calling Example: send_email(<Dictionary: email settings>, <Subject>, <Issue Message To Send>, <configured logger>)
                        send_email(email_settings, email_subject_line, matched_info, root_logger)  
                    
                    else:
                        
                        # Custom log level that has been created for alerts. (39 = ALERT)
                        root_logger.info('Email alerting is disabled. The found log event is not be sent')
                
                ############################################################
                ########################Post-Processing#####################
                ############################################################
                # Checks if any post-processing arguments are not being used.
                if post_processing_args:

                    # Custom log level that has been created for alerts. (39 = ALERT)
                    root_logger.log(39,f'The info is newly discovered. Post-processing task enabled. Please wait while the process completes...')

                    # Calls function to perform post processing task.
                    post_processing_output = start_subprocess(post_processing_args)

                    # Make sure a search entry has been entered
                    if post_processing_info_search:
 
                        # Validates post-processing information is returned
                        if post_processing_output.stdout:

                            # Assigns list variable to be used in this function.
                            # Required to return multiple found strings.
                            matched_entries = []
                            
                            # Loops through all the post-processing entries.
                            for post_output_entry in post_processing_output.stdout:
                                
                                # Checks if post_processing_info_search is a str or list.
                                if isinstance(post_processing_info_search, str):
                                    
                                    # Checks if the search entry exists.
                                    if post_processing_info_search in post_output_entry:

                                        root_logger.info(f'Post-processing search value \"{post_output_entry}\" found. Adding the value to the list \"matched_entries\"')
                                        
                                        # Adds found line and search value to list.
                                        matched_entries.append({'search_entry': post_processing_info_search, 'found_entry': post_output_entry})

                                elif isinstance(post_processing_info_search, list):

                                    # Loops through each search value.
                                    for search_value in post_processing_info_search:

                                        # Checks if a value exists as each line is read.
                                        if search_value in post_output_entry:

                                            root_logger.info(f'Post-processing search value \"{search_value}\" from value list \"{post_output_entry}\" found. Adding the value to the list \"matched_entries\"')
                                            
                                            # Adds found line and search value to list.
                                            matched_entries.append({'search_entry': search_value, 'found_entry': post_output_entry})

                            # Checks if searching_value is str or list to clean up any potential duplicates
                            if isinstance(post_processing_info_search, list):
                                
                                root_logger.debug(f'A list of all found search matches is listed below: {matched_entries}')
                                root_logger.debug(f'Removing any duplicate entries that may have matched multiple times with similar search info')

                                # Removes any duplicate matched values using the 2nd entry (1st element). This can happen if a search list has a similar search word that discovers the same line.
                                # Example Return: [{'search_entry': '|Error|', 'found_entry': 'the entry found2'}]
                                matched_entries = remove_duplicate_dict_values_in_list(matched_entries, 1) 
                                
                                root_logger.debug(f'The adjusted match list with removed duplicates is listed below: {matched_entries}')

                            # Checks if email notifications are enabled
                            # Loops post-processing info. If info exists in the list, an email will be sent.
                            for index, info in enumerate(matched_entries):

                                # Sets the searched_entry value to a variable. This is done to decrease the code complexity.
                                searched_entry = info.get('search_entry')
                                # Sets the found_entry value to a variable. This is done to decrease the code complexity.
                                matched_info = info.get('found_entry')

                                # Checks if email notifications are enabled
                                if email_alerts:

                                    # Custom log level that has been created for alerts. (39 = ALERT)
                                    root_logger.log(39,f'Sending email. Entry {index + 1} of {total_info_entries}')

                                    # Sets the default email subject line if one did not get provided in the YAML.
                                    if post_processing_email_subject_line == None:
                                        post_processing_email_subject_line = f'Software Log Post-Processing Event for {name_monitoring_software}. Search Entry = ({searched_entry})'
                                        
                                    # Calls function to send the email.
                                    # Calling Example: send_email(<Dictionary: email settings>, <Subject>, <Issue Message To Send>, <configured logger>)
                                    send_email(email_settings, post_processing_email_subject_line, matched_info, root_logger)  

                                    # Custom log level that has been created for alerts. (39 = ALERT)
                                    root_logger.info('Email sent and the post-processing event ran')

                                else:
                                    
                                    # Custom log level that has been created for alerts. (39 = ALERT)
                                    root_logger.info('Email alerting is disabled. The post-processing event ran, but no event was sent')

                        else:
                            root_logger.info('The post-processing job ran. No return output was sent')

                    else:

                        root_logger.info(f'No post-processing search entry configured')

                    # Logs post-processing output by joining the lines. Without .join the info would be grouped on a few lines
                    root_logger.debug("Post-processing output message listed below: " + '\n'.join(post_processing_output.stdout))

            else:
                root_logger.info('The info was previously discovered. No action is required')

            root_logger.info(f'Finished processing log searches for {name_monitoring_software}')

        except ValueError as err:

            print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|{err}, Error on line {format(sys.exc_info()[-1].tb_lineno)} in <{__name__}>')

            ###########################################################
            # Currently the program is exiting on any discovered error. 
            ###########################################################

            # System exit print output for general setup
            print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|{err}')
            print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Info|See log for more details')
            
            root_logger.error(f'{err}')
            
            # Checking if the user chooses not to send program errors to email.
            if alert_program_errors == True and email_alerts == True:

                root_logger.error('Sending email notification')
                
                try:
                    
                    # Calls function to send the email.
                    # Calling Example: send_email(<Dictionary: email settings>, <Subject>, <Issue Message To Send>, <configured logger>)
                    send_email(email_settings, "Software Log Monitor Program Issue Occured", f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|Exception Thrown|{err}', root_logger)

                except Exception as err:
                    root_logger.error(f'{err}')

            elif alert_program_errors == False:
                root_logger.debug(f'The user chooses not to send program errors to email')
            else:
                root_logger.error('The user did not choose an option on sending program errors to email. Continuing to exit')

            root_logger.error('Exiting because of the exception error....')

            exit()


# Checks that this is the main program initiates the classes to start the functions.
if __name__ == "__main__":

    # Prints out at the start of the program.
    print('# ' + '=' * 85)
    print('Author: ' + __author__)
    print('Copyright: ' + __copyright__)
    print('Credits: ' + ', '.join(__credits__))
    print('License: ' + __license__)
    print('Version: ' + __version__)
    print('Maintainer: ' + __maintainer__)
    print('Status: ' + __status__)
    print('# ' + '=' * 85)

    # Loops to keep the main program active. 
    # The YAML configuration file will contain a sleep setting within the main function.
    while True:

        # Calls main function.
        main()
        
        # 1 second delay sleep to prevent system resource issues if the function fails and the loop runs without any pause.
        time.sleep(5)