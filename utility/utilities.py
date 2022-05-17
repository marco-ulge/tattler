#!/usr/bin/env python
# -*- coding: utf-8 -*-

import git
import hashlib
import os
import re
import sys
import socket
import urllib3

from git.exc import InvalidGitRepositoryError
from pathlib import Path
from utility import strings as strlib


def check_network_connectivity():
    """Checks internet connectivity

    Arguments:
        -

    Returns:
        True or False -- True if there is internet connection, False otherwise
    """
    try:
        http = urllib3.PoolManager()
        # WARNING: might need to change github.com depending on country
        request = http.request('GET', 'https://www.github.com')
        if request.data:
            return True
    except urllib3.exceptions.NewConnectionError:
        return False


def does_exist(path):
    """Checks if the specified file or folder exists

    Arguments:
        path {string} -- the directory or file to be checked

    Returns:
        True -- if exists
        False -- if not
    """
    try:
        if not os.path.exists(path):
            raise Exception("The specified file/folder does not exist")
    except Exception as e:
        print(e)
        quit()


def is_excluded_file(filename, excluded_files):
    """ Check if the given file (filename) must be exluded

    Arguments:
        filename {string} -- name of the file to check
        excluded_files {list} -- list of files or extensions to exclude

    Returns:
        True -- if the filename contains one or more elements on excluded_files
        False -- if otherwise
    """
    for ex in excluded_files:
        if filename.endswith(ex):
            return True
    return False


def is_excluded_folder(dirpath, excluded_folders):
    """ Check if one element of excluded_folders is in the current
        dirpath to determine if the folder has to be excluded

    Arguments:
        dirpath {string} -- the current dirpath
        excluded_folders {list} -- list of folders to exclude

    Returns:
        True -- if the filename contains one or more elements on excluded_files
        False -- if otherwise
    """
    for folder in excluded_folders:
        return folder.rstrip("\\/") in dirpath


def is_folder_writable(path):
    """Checks if the folder can be written by the application

    Arguments:
        path {string} -- the location of the folder to check

    Returns:
        True if the folder is writable, false otherwise
    """
    return os.access(path, os.W_OK)


def is_git_repo(path):
    """Checks if the folder is a git repository

    Arguments:
        path {string} -- the location of the folder to check

    Returns:
        True if the folder is a git repository, false otherwise
    """
    try:
        _ = git.Repo(path).git_dir
        return True
    except InvalidGitRepositoryError:
        return False


def setup_remote_repository(remote_repo):
    """Clones a remote repository into a local folder

    Arguments:
        remote_repo {list} -- URL of remote repository,
                              local folder to clone repository into
    """

    if check_network_connectivity():
        url_validation_rule = strlib.prepare_rules(
                                        Path("rules/url_validation_rules.json")
                                        )
        url_validation, rule = strlib.regex_check_rules(
                                            remote_repo[0],
                                            url_validation_rule
                                            )
        if (url_validation):
            if (os.path.exists(remote_repo[1])):
                if is_git_repo(remote_repo[1]):
                    print("[!] The specified folder is \
                          already a Git repository.")
                if is_folder_writable(remote_repo[1]):
                    os.system("git clone {}".format(remote_repo[0]) +
                              " {}".format(remote_repo[1]))
            else:
                create_path = input("The specified path does not exist. \
                                     Do you want to create it? (Y/n): ")
                if create_path in ["y", "Y", "yes"]:
                    os.system("mkdir -p {}".format(remote_repo[1]))
                    os.system("git clone {}".format(remote_repo[0]) +
                              " {}".format(remote_repo[1]))
        else:
            sys.exit("Only .git repositories are supported.")
    else:
        sys.exit("No network connection. \
                  Check your internet connection and try again.")


def validate_fs_path(path):
    """Checks if the specified file system path is valid

    Arguments:
        path {string} -- the file system path to check

    Returns:
        True if the specified path matches the regex (is a valid path),
        False if otherwise
    """
    is_valid_path = re.search(r"(\w:)?([\\\/]{1}[a-zA-Z-_ ]*)*", path)
    return bool(is_valid_path)


def validate_url(url):
    """Checks if the specified input value is a valid URL

    Arguments:
        url {string} -- the URL to be validated

    Returns:
        True if the specified input is a valid URL, False otherwise
    """
    regex = "(http|ftp|https)?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&\\/\\/=]*)"
    regex_compiled = re.compile(regex)
    match = re.match(regex_compiled, url)
    return True if match else False
