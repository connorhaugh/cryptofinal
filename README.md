# CryptoFinal 2020 AIT FT System
Created by Omari Matthews, Sagar Punjabi, Stella Trout, and Connor Haugh.

Welcome to the Secure File Transfer System!

## Starting the Application
Run the following lines in two different terminal windows.

    python3 network.py -p './network/' -a 'ABCDE' --clean
    python3 sender.py -p './network/' -a A
    python3 receiver.py -p './network/' -a B

The address given in sender.py and receiver.py can be changed to whatever address is desired for the client and server, respectively, although the server address must remain the same after creation.
     

## Username/Password Pairs
The application will prompt you for your username and then your password. The following tuples are valid inputs for login information, where the first element is the username and the second the password (both case-sensitive).

- ('John', 'Smith')
- ('Raz', 'Mataz')
- ('oatmeal', 'soymilk')

## Valid Commands

- help (displays list of valid commands and usage)
- mkd DIR (makes new directory DIR within current directory) example: mkd test
- rmd DIR (removes directory DIR) example: rmd test
- gwd (prints working directory path)
- cwd DIR (changes working directory to DIR, provided it is a valid path) example: cwd test
- lst (lists contents of working directory)
- upl FILENAME (uploads the file located by FILENAME to the server) example: upl test1.txt
- dnl FILENAME (downloads the file located by FILENAME to the server) example: dnl test1.txt
- rmf FILENAME DIR (removes the file FILENAME from folder DIR) example: rmf test1.txt test1

