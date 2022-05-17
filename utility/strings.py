import json
import os
import re
import sys


def extract_variable_name(line):
    """Extracts the variable name

    Arguments:
        line {string} -- raw line of code

    Returns:
        string -- the variable name
    """
    variable_name = re.search(r"[\"'`]*[A-Za-z0-9\-\_]+[\"'`]* ?[ =:+([{]", line.rstrip())
    if variable_name:
        return variable_name.group()


def file_into_list(file_to_parse):
    """Reads a file and stores passwords (text) in a list

    Arguments:
        file_to_parse {string} -- path to the file to read into list

    Returns:
        list -- list of passwords
    """
    try:
        with open(
            os.path.join(
                os.path.dirname(__file__), file_to_parse),
                "r",
                encoding="utf-8"
                ) as p_bl_file:
            lines = p_bl_file.read().splitlines()
            return lines
    except FileNotFoundError:
        sys.exit("File not found: " + p_bl_file.name + ". Aborting.")
    except IOError:
        sys.exit("Error opening file: " + p_bl_file.name + ". Aborting.")


def find_strings_in_line(line):
    """Extracts all the lines in code that contain at least one string,
       determined by either '', "" or ``

    Arguments:
        line {string} -- the line of code being analyzed

    Returns:
        list -- strings that match either one of the
                3 regular expressions defined below
    """
    found_strings = []

    full_sq_match = re.search(r"[A-Za-z0-9\-\_\"\'\`]* ?[ =:+([{] ?['].*(?<!\\)['] ?[ +=\-)\r\n\t\0.,;|&\]\}><?]?", line)
    full_bq_match = re.search(r"[A-Za-z0-9\-\_\"\'\`]* ?[ =:+([{] ?[`].*(?<!\\)[`] ?[ +=\-)\r\n\t\0.,;|&\]\}><?]?", line)
    full_dq_match = re.search(r"[A-Za-z0-9\-\_\"\'\`]* ?[ =:+([{] ?[\"].*(?<!\\)[\"] ?[ +=\-)\r\n\t\0.,;|&\]\}><?]?", line)

    if bool(full_sq_match):
        found_strings.append(full_sq_match.group())
    elif bool(full_bq_match):
        found_strings.append(full_bq_match.group())
    elif bool(full_dq_match):
        found_strings.append(full_dq_match.group())

    return found_strings


def find_variable_no_string(line):
    """Finds a line without strings, in the form of variable = value

    Arguments:
        line {string} -- the line of code being analyzed

    Returns:
        refined_line -- text that matches the above criteria
    """
    refined_line = re.search(r"[a-zA-Z0-9\.\-\_]+ ?[=:] ?[a-zA-Z0-9\.\-\_]+", line)
    if refined_line:
        return refined_line.group()


def prepare_rules(rules_file, multiline=False):
    """Reads .json file and compile the regular expressions define within

    Arguments:
        rules_file {string} -- path to the .json file
                               containing rules to compile

    Keyword Arguments:
        multiline {bool} -- whether to compile the rules using the
                            re.MULTILINE option (default: {False})

    Returns:
        list -- set of compiled rules
    """
    try:
        with open(
            os.path.join(
                os.path.dirname(__file__), rules_file),
                "r",
                encoding="utf-8"
                ) as current_file:
            rules_list = json.loads(current_file.read())
    except FileNotFoundError:
        sys.exit("File not found: " + rules_file + ". Aborting.")
    except IOError:
        sys.exit("Error opening file: " + rules_file + ". Aborting.")
    if multiline:
        for rule in rules_list:
            rules_list[rule] = re.compile(rules_list[rule], re.MULTILINE)
    else:
        for rule in rules_list:
            rules_list[rule] = re.compile(rules_list[rule])
    return rules_list


def process_dynamic_value(line):
    """ Cheks if the current line has an assignment
        in the form of variable = ${some.value}

    Arguments:
        line {string} -- the line to be checked for the dynamic assignment

    Returns:
        dynamic_value -- matched text from line.
                         If there is no match, it returns nothing

    """
    dynamic_vaue = re.search(r"['\"`]?\$[{|(] ?.* ?[}|)]['\"`]?", line.rstrip())
    if dynamic_vaue:
        return dynamic_vaue.group()


def refine_strings(strings_list):
    """Extracts only the portion of string container either within '' or ""

    Arguments:
        strings_list {list} -- a list of string determined
                               by find_strings_in_line

    Returns:
        list -- list of string refined
        list -- list of variable name (left assignment for R value)
        list -- list of exceptions
    """

    refined_strings = []
    exceptions = []
    variable_name = ""

    for index, element in enumerate(strings_list):

        base_sq_match = re.search(r"(?<=[=:]) ?['].*(?<!\\)[']", element)
        base_bq_match = re.search(r"(?<=[=:]) ?[`].*(?<!\\)[`]", element)
        base_dq_match = re.search(r"(?<=[=:]) ?[\"].*(?<!\\)[\"]", element)

        if bool(base_sq_match):
            refined_strings.append(base_sq_match.group())
        elif bool(base_bq_match):
            refined_strings.append(base_bq_match.group())
        elif bool(base_dq_match):
            refined_strings.append(base_dq_match.group())
        else:
            exceptions.append(element)

        variable_name = extract_variable_name(element)

    return refined_strings, variable_name, exceptions


def regex_check_rules(line, compiled_rules):
    """Check the given line against a set of regular expressions

    Arguments:
        line {string}         -- the line of code possibly
        compiled_rules {list} -- set of regular expressions
                                 to evaluate against line

    Returns:
        string -- the first match found evaluating compiled_rules
    """
    for rule in compiled_rules:
        match = re.search(compiled_rules[rule], line)
        if bool(match):
            return match.group(), rule
    return None, None


def select_words_only(text):
    """Extracts only word characters from a given string,
       useful to exclude single and double quotes

    Arguments:
        text {string} -- the string to extract text from

    Returns:
        word -- the matched text
    """
    word = re.search(r'[\w\-_]+', text)
    if word:
        return word.group()
