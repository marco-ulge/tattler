#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import configparser
import json
import os
import magic
import math
import re
import sys
import time
import uuid

from collections import Counter
from db import class_OverallResults as res
from pathlib import Path
from utility import utilities as utils
from utility import results as reslib
from utility import strings as strlib

# Check for the correct version of Python
if sys.version_info[0] < 3:
    raise Exception("Python 3.6 or above is required.")


def check_variable_exclusion(variable_name, ex_variables):
    """Checks whether the variable has to be excluded.
       Excluded variables are reported by the user in the .cfg file

    Arguments:
        variable_name {string} -- the variable name
        ex_variables {list}    -- the list of excluded variables

    Returns:
        True  -- if the variable is not excluded
        False -- is the variable is the .cfg file
    """
    if variable_name in ex_variables:
        return False
    else:
        return True


def check_false_positive(variable_name, current_string, ex_results):
    """Checks whether the result is a false positive.
       False positives are reported by the user in the .cfg file (var:string)

    Arguments:
        variable_name {string}  -- the variable name
        current_string {string} -- the current string - you don't fucking say
        ex_results {list}       -- the list of excluded variables
                                   in the form of variable_name:current_string

    Returns:
        True  -- if there are no false positives
        False -- if the current combination is a false positive
    """
    var = strlib.select_words_only(variable_name)
    sst = strlib.select_words_only(current_string)
    for key in ex_results:
        if key.split(":")[0] == var and key.split(":")[1] == sst:
            return False
    return True


def shannon_entropy(data):
    """Calculates shannon entropy value

    Arguments:
        data {string} -- the string whose entropy must be calculated

    Returns:
        [float] -- value that represents the entropy value on the data {string}
    """
    p, lns = Counter(data), float(len(data))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())


def check_password_vs_blacklist(current_string, blacklist):
    """Checks a string to determine whether it is contained within a blacklist

    Arguments:
        current_string {string} -- the string to be checked against blacklist
        blacklist {list}        -- list of words defined within a given
                                   blacklist file

    Returns:
        [bool] -- whether current_string was found within the blacklist file
    """
    if (((current_string.strip()).strip('\"') in blacklist) or
       ((current_string.strip()).strip("'") in blacklist) or
       ((current_string.strip()).strip('`') in blacklist)):
        return True
    else:
        return False


def analyze_string(current_string, variable_name, current_file_name,
                   line_counter, password_blacklist, exceptions_single_string,
                   single_string_results, variable_names_rules,
                   reduced_var_names_rules, exceptions_rules, ex_variables,
                   ex_results):
    """Analyzes a single string to determine dangerous secrets

    Arguments:
        current_string {string}         -- the string to be analyzed
        variable_name {string}          -- the name of the variable
        current_file_name {string}      -- the name of the current file
        line_counter {integer}          -- line number the string is found at
        password_blacklist {list}       -- list of blacklisted strings
        exceptions_single_string {list} -- list of strings that cannot be
                                           classified with certainty
        single_string_results {list}    -- list of results for single string
        variable_names_rules {list}     -- list of compiled regular expressions
                                           used to extract the variable name
        exceptions_rules {list}         -- list of compiled regular expressions
                                           used to reduce false positives
    """

    exception_match, rule = strlib.regex_check_rules(
        current_string.rstrip(),
        exceptions_rules
    )

    if not exception_match and len(current_string.strip(' "\'\t\r\n')) > 3:
        pwd_blacklist_check = check_password_vs_blacklist(
            current_string,
            password_blacklist
        )
        current_shannon_value = shannon_entropy(current_string)

        if variable_name:
            variable_name_match, rule = strlib.regex_check_rules(
                variable_name,
                variable_names_rules
            )
            dynamic_value = strlib.process_dynamic_value(current_string)
            if variable_name_match and not dynamic_value:
                check_var_excl = check_variable_exclusion(
                    variable_name,
                    ex_variables
                )
                check_false_pos = check_false_positive(
                    variable_name,
                    current_string,
                    ex_results
                )
                if check_var_excl and check_false_pos:

                    single_string_results.append(
                        res.store_single_string_results(
                            "Single string",
                            current_file_name,
                            line_counter,
                            variable_name + current_string,
                            current_shannon_value,
                            "password/secret",
                            pwd_blacklist_check
                        )
                    )
                    return

        if pwd_blacklist_check and not variable_name:
            exceptions_single_string.append(current_string)
            return

        if current_shannon_value > 3.5 and len(current_string) > 15:
            # load here as infrequent usage of the ruleset is expected
            hashing_identifiers = strlib.prepare_rules(
                Path("../rules/hashing_rules.json"),
                True
            )
            known_hash_check, rule = strlib.regex_check_rules(
                current_string.strip('\"\'`'),
                hashing_identifiers
            )
            if known_hash_check:
                single_string_results.append(res.store_single_string_results(
                    "Single string",
                    current_file_name,
                    line_counter,
                    known_hash_check,
                    current_shannon_value,
                    "hardcoded_hash",
                    False
                ))
                return

    else:
        return


def analyze_file(file_to_analyze, whitelist_rules, blacklist_rules,
                 extensions_rules, variable_name_rules,
                 reduced_var_names_rules, exceptions_rules,
                 password_blacklist, ex_variables, ex_results,
                 single_string_check=False):
    """Process a single file and checks for whitelist, blacklist
       or single string (custom logic) matches

    Arguments:
        file_to_analyze {string}   -- the file to process
        whitelist_rules {list}     -- list of compiled regex to check
                                      the string contains non-dangerous data
        blacklist_rules {list}     -- list of compiled regex
                                      containing dangerous definitions
        extensions_rules {list}    -- list of compiled regex
                                      containing dangerous extensions
        variable_name_rules {list} -- list of compiled regex
                                      containing dangerous variable names
        exceptions_rules {list}    -- list of compiled regex
                                      containing exceptions
        password_blacklist {list}  -- list of common passwords

    Returns:
        whitelist_results {list}     -- list of strings that matched
                                        whitelist_rules
        blacklist_results {list}     -- list of strings that matched
                                        blacklist_rules
        single_string_results {list} -- list of single strings that matched
                                        one or more dangerous criteria
        read_errors {list}           -- list containing files that could not
                                        be opened due to unicode errors
        manual_review {list}         -- list of files that must be
                                        reviewed manually
        line_counter {integer}       -- number of processed line in
                                        current file
    """
    line_counter = 1
    blacklist_results = []
    properties_file_results = []
    single_string_results = []
    # note that exceptions are processed but not stored
    exceptions_single_string = []
    manual_review = []
    read_errors = []

    dangerous_file_ext, rule = strlib.regex_check_rules(
        str(file_to_analyze),
        extensions_rules
    )

    try:
        with open(file_to_analyze, "r", encoding="utf-8") as current_file:

            for line in current_file:

                white_match, rule = strlib.regex_check_rules(
                    line.rstrip(),
                    whitelist_rules
                )
                if white_match:
                    line_counter += 1
                    continue

                black_match, rule = strlib.regex_check_rules(
                    line.rstrip(),
                    blacklist_rules
                )
                if black_match:
                    blacklist_results.append(res.store_regex_results(
                        "Blacklist",
                        current_file.name,
                        line_counter,
                        line.lstrip(),
                        rule
                    ))
                    line_counter += 1
                    continue

                if dangerous_file_ext:
                    refined_line = strlib.find_variable_no_string(line)
                    if refined_line:
                        regex_check, rule = strlib.regex_check_rules(
                            refined_line,
                            reduced_var_names_rules
                        )
                        dynamic_value = strlib.process_dynamic_value(line)
                        if regex_check and not dynamic_value:
                            properties_file_results.append(
                                res.store_properties_file_results(
                                    "Config/properties file",
                                    current_file.name,
                                    line_counter,
                                    line,
                                    "password/secret"
                                )
                            )
                        continue

                if not black_match and dangerous_file_ext:
                    if current_file.name not in manual_review:
                        manual_review.append(current_file.name)

                if single_string_check:
                    strings_in_line = strlib.find_strings_in_line(line)
                    if strings_in_line:
                        refined_strings, variable_name, exceptions = strlib.refine_strings(strings_in_line)
                        exceptions_single_string.extend(exceptions)

                        for current_string in refined_strings:
                            analyze_string(
                                current_string,
                                variable_name,
                                current_file.name,
                                line_counter,
                                password_blacklist,
                                exceptions_single_string,
                                single_string_results,
                                variable_name_rules,
                                reduced_var_names_rules,
                                exceptions_rules,
                                ex_variables,
                                ex_results
                            )

                line_counter += 1

    except UnicodeDecodeError:
        read_errors.append(current_file.name)

    return blacklist_results, properties_file_results, single_string_results, \
        read_errors, manual_review, line_counter


def parse_config_file(config_file_path):
    """Reads configuration file to determine folders and variables to exclude

    Arguments:
        config_file_path {string} -- path of the .cfg file

    Returns:
        excluded_folders {list}   -- list of excluded folders
        excluded_variables {list} -- list of excluded variables
        excluded_results {list}   -- list of excluded results
    """

    config = configparser.ConfigParser()
    if utils.does_exist(config_file_path):
        config.read(config_file_path)
    else:
        raise Exception("The specified configuration file does not exist. Aborting.")

    excluded_folders = []
    for key in config["EXCLUDED FOLDERS"]:
        excluded_folders.append(config["EXCLUDED FOLDERS"][key])

    excluded_variables = []
    for key in config["EXCLUDED VARIABLES"]:
        excluded_variables.append(config["EXCLUDED VARIABLES"][key])

    excluded_results = []
    for key in config["EXCLUDED RESULTS"]:
        excluded_results.append(config["EXCLUDED RESULTS"][key])

    excluded_files = []
    for key in config["EXCLUDED FILES"]:
        excluded_files.append(config["EXCLUDED FILES"][key])

    return excluded_folders, excluded_variables, \
        excluded_results, excluded_files


def main():

    start_time = time.time()

    # TODO: support option to check for length(string) > N && shannon_entropy > M

    parser = argparse.ArgumentParser(
                        description='Checking the code for dark secrets.'
                        )
    parser.add_argument("-c",
                        "--config",
                        dest="config",
                        help="Specify .cfg file to set exclusions"
                        )
    parser.add_argument("-o",
                        "--output-file",
                        dest="output_file",
                        required=True,
                        help="Save the output to file"
                        )
    parser.add_argument("-p",
                        "--password-list",
                        dest="blacklist",
                        help="Select file for password blacklist check"
                        )
    parser.add_argument("-s",
                        "--with-strings",
                        dest="single_string_check",
                        action="store_true",
                        help="Enable checks for single strings"
                        )
    mex_args_repo = parser.add_mutually_exclusive_group(required=True)
    mex_args_repo.add_argument("--local-repo",
                               dest="local_repo",
                               help="Specify a local repository to analyse"
                               )
    mex_args_repo.add_argument("--remote-repo",
                               dest="remote_repo",
                               nargs=2,
                               help="Specify a remote repository to analyze, \
                                     followed by the local path to clone the \
                                     repository into")
    args = parser.parse_args()

    if args.blacklist:
        password_blacklist_file = args.blacklist
    else:
        password_blacklist_file = "../password_lists/default-passwords-file.txt"
    password_blacklist = strlib.file_into_list(password_blacklist_file)

    if args.output_file:
        current_uuid = uuid.uuid4().hex
        os.mkdir("results/" + current_uuid)
        output_path = Path("../results/" + current_uuid)
        output_file_name = args.output_file
        output_file = output_path / output_file_name

    manual_review_file_name = "manual_review.txt"
    manual_review_file = output_path / manual_review_file_name
    message_manual_review = "The following files did not trigger any \
                             blacklist rule, but usually contain secrets. \
                             Manual review is recommended.\n"
    reslib.write_text_header(manual_review_file, message_manual_review)

    read_errors_file_name = "read_errors.txt"
    read_errors_file = output_path / read_errors_file_name
    message_read_errors = "The following files could not be opened \
                           due to Unicode Decode error.\n"
    reslib.write_text_header(read_errors_file, message_read_errors)

    blacklist_rules = strlib.prepare_rules(
                            Path("../rules/blacklist_rules.json")
                            )
    whitelist_rules = strlib.prepare_rules(
                            Path("../rules/whitelist_rules.json")
                            )
    extensions_rules = strlib.prepare_rules(
                            Path("../rules/extensions_rules.json")
                            )
    variable_names_rules = strlib.prepare_rules(
                            Path("../rules/variable_names_rules.json")
                            )
    reduced_var_names_rules = strlib.prepare_rules(
                            Path("../rules/reduced_variable_name_rules.json")
                            )
    exceptions_rules = strlib.prepare_rules(
                            Path("../rules/exceptions_rules.json")
                            )

    if args.local_repo:
        start_folder = args.local_repo

    if args.remote_repo:
        utils.setup_remote_repository(args.remote_repo)
        start_folder = args.remote_repo[1]

    utils.does_exist(start_folder)

    ex_folders = []
    ex_variables = []
    ex_results = []
    ex_files = []
    if args.config:
        ex_folders, ex_variables, ex_results, ex_files = parse_config_file(
            args.config
            )

    total_files = 0
    total_lines = 0
    total_issues = 0

    allowed_mime = ["ASCII text", "RSA", "JSON", "CLIPPER", "UTF-8"]

    for (dirpath, dirname, filename) in os.walk(start_folder):

        if utils.is_excluded_folder(dirpath, ex_folders):
            continue

        for single_file in filename:

            if utils.is_excluded_file(single_file, ex_files):
                continue

            if not (os.path.islink(dirpath + "/" + single_file)):
                mime = magic.from_file(os.path.join(dirpath, single_file))
                # TODO: would be better to translate all to lower case
                if any(mimetype in allowed_mime for mimetype in allowed_mime):
                    print(" " * 100, end="\r")
                    print("Processing file {}".format(single_file),
                          end="\r",
                          flush=True
                          )

                    blacklist_results, properties_file_results, single_string_results, read_errors, manual_review, lines = analyze_file(
                        os.path.join(dirpath, single_file),
                        whitelist_rules,
                        blacklist_rules,
                        extensions_rules,
                        variable_names_rules,
                        reduced_var_names_rules,
                        exceptions_rules,
                        password_blacklist,
                        ex_variables,
                        ex_results,
                        args.single_string_check
                    )
                    total_files += 1
                    total_lines += lines

                    if blacklist_results or properties_file_results or single_string_results:
                        reslib.store_results_text(
                            blacklist_results,
                            properties_file_results,
                            single_string_results,
                            output_file,
                            os.path.join(dirpath, single_file)
                        )
                        total_issues += len(blacklist_results)
                        total_issues += len(single_string_results)

                    if manual_review:
                        reslib.store_exceptions_text(
                            manual_review_file,
                            manual_review,
                            message_manual_review
                            )

                    if read_errors:
                        reslib.store_exceptions_text(
                            read_errors_file,
                            read_errors,
                            message_read_errors
                            )

    end_time = time.time()
    execution_time = end_time - start_time
    reslib.write_text_footer(
                        output_file,
                        total_issues,
                        total_files,
                        execution_time
                        )
    print("\n" * 2)
    print("Results written to: " + str(output_file))


if __name__ == "__main__":
    main()
