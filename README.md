# keychainreader

This program is a modification of Juuso Salonen's [keychaindump](https://github.com/juuso/keychaindump). The difference is, instead of looking for the master key in memory, you simply pass the keychain password to the program.

This is a simple OSX keychain reader.

## How?
Build instructions:

    $ gcc keychainreader.c -o keychainreader -lcrypto

Basic usage:

    $ ./keychainreader <path to keychain file>

    [*] Enter password (will be echoed!):

    ...
    (keychain contents)
    ...

## Who?
Keychaindump was originally written by [Juuso Salonen](http://twitter.com/juusosalonen), the guy behind [Radio Silence](http://radiosilenceapp.com) and [Private Eye](http://radiosilenceapp.com/private-eye).

Modified by [Lessandro Mariano](https://github.com/lessandro).

## License
Do whatever you wish. Please don't be evil.