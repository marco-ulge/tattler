## tattler

tattler.py is a simple python tool designed to find secrets and sensitive information in source code, parsing all the files recursively from a given starting folder.

This tool has been created with two purposes in mind:
* Help uncovering sensitive information during Penetration Tests and Code Reviews
* Help determining the Security posture in relation to Secrets Management

The long term idea is to replace the heavy usage of regex in favor of ML.
___

### How to launch first scan

Launch scan from local repository:
```
tattler.py --local-repo /path/to/repo --output-file output.txt
```

Launch scan from remote repository:
```
tattler.py --remote-repo https://urltoremoterepo.git /home/local/path --output-file output.txt
```
Note that both Unix and Windows paths are supported

Results will be stored and accessible from the results/ folder

___

### Advanced options

By default, tattler will apply the rules located into rules/blacklist_rules.json.

It is possible to launch tattler.py with the option --with-strings, which enables checks on single strings. This kind of checks, will likely increase the rate of false positives. To manage the latter and exclude additional variables and/or folders, see the following section.

___

### Use the configuration file

When invoking tattler, it is possible to specify a configuration file. An example is available under the config/ folder (example.cfg)

Launch tattler.py with a config file:

```
tattler.py --config config/example.cfg --local-repo /path/to/repo --output-file output.txt
```

This file allows to exclude the following:
* Folders (and subfolders)
* Variables (eg. "username")
* Results which are known false positives

___

### Requirements
* python dependencies can be installed with:
    ```
    pip install -r requirements.txt 
    ```
* Python 3.6+ required. Not tested on previous versions (should work on Python 3+).
* *For OS X*: libmagic must be installed via:
    ```
    brew install libmagic
    ```
* Tested on Linux, Windows and OSX
