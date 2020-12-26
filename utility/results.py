import os
import sys


def write_text_header(output_file, message):
    """Writes the file header

    Arguments:
        output_file {string} -- the file (path) to save to
        message {string}     -- the text to write as header
    """
    try:
        with open(
            os.path.join(
                os.path.dirname(__file__), output_file),
                "a+",
                encoding="utf-8"
                ) as output_file:
            output_file.write(message + "\n" * 2)

    except FileNotFoundError:
        sys.exit("File not found: " + output_file.name + ". Aborting.")
    except IOError:
        sys.exit("Error opening file: " + output_file.name + ". Aborting.")


def write_text_footer(output_file, total_issues, total_files, execution_time):
    """Writes the file footer

    Arguments:
        output_file {string} -- the file (path) to save to
        total_issues {int} -- the overall number of issues found
        total_files {int} -- the overall number of processed files
        execution_time {float} -- the overall execution time
    """
    try:
        with open(
            os.path.join(
                os.path.dirname(__file__), output_file),
                "a+",
                encoding="utf-8"
                ) as output_file:
            output_file.write("\n")
            output_file.write("Total files analyzed: " + str(total_files) + "\n")
            output_file.write("Total issues found: " + str(total_issues) + "\n")
            output_file.write("Execution Time: " + str(execution_time) + "\n")

    except FileNotFoundError:
        sys.exit("File not found: " + output_file.name + ". Aborting.")
    except IOError:
        sys.exit("Error opening file: " + output_file.name + ". Aborting.")


def store_results_text(blacklist_results, properties_file_results,
                       single_string_results, output_file, filename):
    """Stores the analysis results within a file

    Arguments:
        blacklist_results {list} -- list of string that matched blacklist_rules
        single_string_results {list} -- list of single strings determined to be dangerous
        output_file {string} -- the file (path) to save to
        filename {string} -- name of the file with secrets
    """
    try:
        with open(
            os.path.join(
                os.path.dirname(__file__), output_file),
                "a+",
                encoding="utf-8")as output_file:

            output_file.write("Results for File: " + str(filename) + "\n")

            if blacklist_results:
                output_file.write("\n" * 2)
                output_file.write("BLACKLIST RESULTS:\n")
                for result in blacklist_results:
                    output_file.write("Line number: " + str(result.line_number) + "\n")
                    output_file.write("Occurrence: " + result.occurrence)
                    output_file.write("Rule: " + result.rule)
                    output_file.write("\n" * 2)

            if properties_file_results:
                output_file.write("\n" * 2)
                output_file.write("PROPERTIES FILE RESULTS:\n")
                for result in properties_file_results:
                    output_file.write("Line number: " + str(result.line_number) + "\n")
                    output_file.write("Type: " + result.specific_string_occurrence + "\n")
                    output_file.write("Occurrence: " + result.occurrence.lstrip() + "\n")
                    output_file.write("\n" * 2)

            if single_string_results:
                output_file.write("\n" * 2)
                output_file.write("SINGLE STRING RESULTS:\n")
                for result in single_string_results:
                    output_file.write("Line number: " + str(result.line_number) + "\n")
                    output_file.write("Type: " + result.specific_string_occurrence + "\n")
                    output_file.write("Occurrence: " + result.occurrence + "\n")
                    output_file.write("Shannon Entropy: " + str(result.shannon_entropy) + "\n")
                    output_file.write("Password blacklist match: " + str(result.blacklist_match))
                    output_file.write("\n" * 2)

            output_file.write("=" * 100)
            output_file.write("\n" * 2)

    except FileNotFoundError:
        sys.exit("File not found: " + output_file.name + ". Aborting.")
    except IOError:
        sys.exit("Error opening file: " + output_file.name + ". Aborting.")


def store_exceptions_text(output_file, data, message=None):
    """Stores read errors and file to be manually reviewed

    Arguments:
        output_file {string} -- the output file to write to
        data {list}          -- list of filenames (full path)
                                that generated exceptions
        message {string}     -- message to be written in the
                                beginning of file for more context
    """
    try:
        with open(
            os.path.join(
                os.path.dirname(__file__), output_file),
                "a+",
                encoding="utf-8"
                ) as output_file:
            for elem in data:
                output_file.write("File: " + elem + "\n")
    except IOError:
        sys.exit("Error opening file: " + output_file.name + ". Aborting.")

