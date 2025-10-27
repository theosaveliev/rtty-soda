# rtty-soda

A CLI tool for Unix-like environments to encrypt a RTTY session using NaCl.


#### Features

- Public Key encryption (Curve25519-XSalsa20-Poly1305)
- Secret Key encryption (XSalsa20-Poly1305)
- Key derivation (Argon2id-Blake2b)
- Text compression (zstd, zlib, bz2, lzma)
- Custom encodings:
  - Base26 (Latin)
  - Base31 (Cyrillic)
  - Base36 (Latin with numbers)
  - Base64 (RFC 3548)
  - Base94 (ASCII printable)
  - Binary


## Installation
#### Package manager

1. [Install uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Install rtty-soda:
   ```
   % uv tool install rtty-soda
   ```
3. Remove rtty-soda:
   ```
   % uv tool uninstall rtty-soda
   ```

#### Docker

```
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.2.3
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.2.3-tools
```


## Getting help

All commands have `[-h | --help]` option.

```
% soda
Usage: soda [OPTIONS] COMMAND [ARGS]...

Options:
  --version   Show the version and exit.
  -h, --help  Show this message and exit.

Commands:
  decrypt-password (dp)  Decrypt Message (Password).
  decrypt-public (d)     Decrypt Message (Public).
  decrypt-secret (ds)    Decrypt Message (Secret).
  encode                 Encode File.
  encrypt-password (ep)  Encrypt Message (Password).
  encrypt-public (e)     Encrypt Message (Public).
  encrypt-secret (es)    Encrypt Message (Secret).
  genkey                 Generate Private Key.
  kdf                    Key Derivation Function.
  pubkey                 Get Public Key.
```

Some commands have aliases, so `% soda encrypt-password ...` and `% soda ep ...`
are equivalent.


## Public Key encryption
#### Key generation

```
% soda genkey | tee alice | soda pubkey - | tee alice_pub
R5xUCEhvkRRwQD+iWo2hV65fIsWucUZtiFJGKy6pTyA=

% soda genkey | tee bob | soda pubkey - | tee bob_pub
woNtqALnGLzp8VBuzJ8T13E4OZRv5YZy6kXMBpV8/mI=

% soda genkey -h
Usage: soda genkey [OPTIONS]

  Generate Private Key.

  Encoding: base26 | base31 | base36 | base64 | base94 | binary

Options:
  -e, --encoding TEXT     [default: base64]
  -o, --output-file FILE  Write output to file.
  --group-len INTEGER     [default: 0]
  --line-len INTEGER      [default: 80]
  --padding INTEGER       [default: 0]
  -v, --verbose           Show verbose output.
  -h, --help              Show this message and exit.
```

#### Encryption

Alice sends the message to Bob:

```
% cat message
A telegraph key is a specialized electrical switch used by a trained operator to
transmit text messages in Morse code in a telegraphy system.
The first telegraph key was invented by Alfred Vail, an associate of Samuel Morse.
(c) Wikipedia

% soda encrypt-public alice bob_pub message --group-len 79 | tee encrypted
q+zCgyCfHdlSHrcuyM/Yfw1+ZvqNRXgY0O7gGrauPyQlsI0MdPXoVlkfyKZUtg6Jcqn47d4BGLMBITo
y3Wp9+9FvI1rolCd7JmyIxRIHHYWqxux+czh88aDdGjbDQ2pRNX68TU33PylBDw/H+VfYSZ6fyw1xdJ
005pJeEXCzpOXljvXMgAElBIFJ/vsluunrRI9Sw6WcnrCsPYFxTFRZVOvsq6U8PJwnhnaDyLW0Z28Op
dS71gNH/7xA7P1LbFwxSD0jAjDqPZdLYkPzd94=

% soda encrypt-public -h
Usage: soda encrypt-public [OPTIONS] PRIVATE_KEY_FILE PUBLIC_KEY_FILE
                           MESSAGE_FILE

  Encrypt Message (Public).

  Encoding: base26 | base31 | base36 | base64 | base94 | binary

  Compression: zstd | zlib | bz2 | lzma | raw

Options:
  --key-encoding TEXT       [default: base64]
  -e, --data-encoding TEXT  [default: base64]
  -c, --compression TEXT    [default: zstd]
  -o, --output-file FILE    Write output to file.
  --group-len INTEGER       [default: 0]
  --line-len INTEGER        [default: 80]
  --padding INTEGER         [default: 0]
  -v, --verbose             Show verbose output.
  -h, --help                Show this message and exit.
```

#### Decryption

```
% soda decrypt-public bob alice_pub encrypted 
A telegraph key is a specialized electrical switch used by a trained operator to
transmit text messages in Morse code in a telegraphy system.
The first telegraph key was invented by Alfred Vail, an associate of Samuel Morse.
(c) Wikipedia
```


## Secret Key encryption

Alice and Bob share a key for symmetric encryption:

```
% soda genkey > shared
% soda encrypt-secret shared message -o encrypted
% soda decrypt-secret shared encrypted -o message
```

Another day, they share a password:

```
% echo qwerty | soda encrypt-password - message -p interactive -o encrypted
% echo qwerty | soda decrypt-password - encrypted -p interactive -o message
```


## Key derivation

The KDF function derives the key from the password.
It accepts different profiles: interactive, moderate, and sensitive.

```
% echo qwerty | soda kdf --profile interactive -
HqbvUXflAG+no3YS9njezZ3leyr8IwERAyeNoG2l41U=

% soda kdf -h
Usage: soda kdf [OPTIONS] PASSWORD_FILE

  Key Derivation Function.

  Encoding: base26 | base31 | base36 | base64 | base94 | binary

  Profile: interactive | moderate | sensitive

Options:
  -e, --encoding TEXT     [default: base64]
  -p, --profile TEXT      [default: sensitive]
  -o, --output-file FILE  Write output to file.
  --group-len INTEGER     [default: 0]
  --line-len INTEGER      [default: 80]
  --padding INTEGER       [default: 0]
  -v, --verbose           Show verbose output.
  -h, --help              Show this message and exit.
```


## Text compression

That works as follows:
1. The plaintext is compressed with the compression lib
2. The 16-byte MAC and 24-byte nonce are added
3. The result is encoded with Base64, which adds ~25% overhead

```
% soda es shared message -c zstd -v > /dev/null
Plaintext: 239
Ciphertext: 276
Overhead: 1.155
Groups: 1
% soda es shared message -c zlib -v > /dev/null
Plaintext: 239
Ciphertext: 280
Overhead: 1.172
Groups: 1
% soda es shared message -c bz2 -v > /dev/null
Plaintext: 239
Ciphertext: 340
Overhead: 1.423
Groups: 1
% soda es shared message -c lzma -v > /dev/null
Plaintext: 239
Ciphertext: 324
Overhead: 1.356
Groups: 1
% soda es shared message -c raw -v > /dev/null
Plaintext: 239
Ciphertext: 372
Overhead: 1.556
Groups: 1
```


## Encoding

The rtty-soda supports various encodings:

```
% soda encrypt-public alice bob_pub message --data-encoding base36 --group-len 5 --verbose
9URCN ARRN8 MSE7G G9980 37D8S 568QP 16AZW TOHAI KYP5W VAK7R VZ6YO GZ38A QOIP7
60P2E GWWOG DSHDD EG2TZ 7PSZM 7FKBX 50TAD RHS2E VM063 N297Y 753BP TLUX0 9K8BD
DZF8O 7TPUG MJV4R T2C92 HU1G8 KGJCN URU1F 9COP9 EFLZO BSL2V 171DS 2HKPE JY2GY
V86IT T0HBR 9B08H M9R2V IEM7A R91IF UWQYM ZV4JN 7YU3K ILPJY E8OMA NWQC5 Q6BG7
PXM4I 9UU9E J9IRU HSZ41 RPZQG XTDC6 E5NMS B4HBQ 7QRI2 RRUYH HSHGQ 7USN
Plaintext: 239
Ciphertext: 319
Overhead: 1.335
Groups: 64
```


## Environment variables

Common options can be set in the environment variables:

```
% cat .env 
KEY_ENCODING=base26
DATA_ENCODING=base26
COMPRESSION=bz2
KDF_PROFILE=moderate
VERBOSE=1
GROUP_LEN=5
LINE_LEN=80
PADDING=1

% set -a
% source .env
```


## Alternative usage

- Password source
  ```
  % echo 'A line from a book or a poem' | soda kdf - -e base94           
  wN/K.@3Q#]Czn4kk3(negX=R|*xvvPQmk'XW$-s
  ```

- WireGuard keyer
  ```
  % echo 'A line from a book or a poem' | soda kdf - -o privkey
  % cat privkey 
  thyA4dlQgg93+rQj/evBbBymw82GTwQCh3RJ0I6GOsY=
  % soda pubkey privkey 
  ruIUMqbUtyqRVSIBLSGI7AOruE2DLWgTe9o+h7Yktkw=
  % cat privkey | wg pubkey 
  ruIUMqbUtyqRVSIBLSGI7AOruE2DLWgTe9o+h7Yktkw=
  ```


## Compatibility

During the initial development (versions prior to 1.0.0),
I can break backwards compatibility.


## Releases 

This project follows a rolling release cycle. 
Each version bump represents where I completed a full test cycle. 
When testing passes successfully, I commit and release - so every release is a verified stable point.
