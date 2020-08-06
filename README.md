# SDF - Site Directory Fuzzer

SDF has been created to automate search task of hidden directories and files on server. It's multithreading, up to 100 threads for one url.

Simple example:

    python sdf.py -u example.com


You can use one url or file with list of urls:

    python sdf.py -u domains.txt


Also SDF can use directory as `-u` option with lots of files with urls:

    python sdf.py -u ./directory


Also you can fuzz subdomains.

Example:

    python sdf.py -u example.com -s subdomains.txt

List of fuzzing paths store in files in `./pathlist` directory.

It can be used with `-l` option:

    python sdf.py -u example.com -l ./pathlist/apiDict/api.txt

Output stored in `endpoints.txt` by default, but it can be given manualy by `-o` option:

    python sdf.py -u example.com -o out.txt

Optional change user-agent:

    python sdf.py -u example.com -ua 31337



## Installation 

To install SDF, simply use git:

    git clone https://github.com/codebyzen/SiteDirectoryFuzzer

### Thanx to:
* [Avi Lumelsky aka Avilum](https://github.com/avilum)
* [Xavi Mendez aka xmendez](https://github.com/xmendez)
* [鸭王](https://github.com/TheKingOfDuck)