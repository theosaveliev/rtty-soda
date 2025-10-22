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
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.2.0
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.2.0-tools
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
  --line-len INTEGER      [default: 0]
  --padding INTEGER       [default: 0]
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

% soda encrypt-public alice bob_pub message --line-len 80 | tee encrypted
cCipniCmJVAb2mc3JLoDo/DAun7cMunWS5bMqtKRPc/e3d2vfRm8wnqTsYjOXVOCZRj78/GqcVweBV0
mE43X7xO8B0OVyKKgqPAqnAJxwggTLPmWtKFrTwKi0utf7n6fIQuDaCths0qO6FF5rm0znc/3KYKP3D
/WbgE/IBrTOAV6P+mLUnGlzO6U/HdtDCjk1ZB45EN0Q76dDzYav+bliCrVWiAUfZUCtEQ/6B4fi9Aqn
KRDC4XSnd7nLs/ZkhL8hkM13xJ+1MBGbIvEjaY=

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
  --line-len INTEGER        [default: 0]
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

% soda decrypt-public -h
Usage: soda decrypt-public [OPTIONS] PRIVATE_KEY_FILE PUBLIC_KEY_FILE
                           MESSAGE_FILE

  Decrypt Message (Public).

  Encoding: base26 | base31 | base36 | base64 | base94 | binary

  Compression: zstd | zlib | bz2 | lzma | raw

Options:
  --key-encoding TEXT       [default: base64]
  -e, --data-encoding TEXT  [default: base64]
  -c, --compression TEXT    [default: zstd]
  -o, --output-file FILE    Write output to file.
  --padding INTEGER         [default: 0]
  -v, --verbose             Show verbose output.
  -h, --help                Show this message and exit.
```


## Secret Key encryption

Alice and Bob share a key for symmetric encryption:

```
% soda genkey > shared
% soda encrypt-secret shared message -o encrypted
% soda decrypt-secret shared encrypted -o message

% soda encrypt-secret -h
Usage: soda encrypt-secret [OPTIONS] KEY_FILE MESSAGE_FILE

  Encrypt Message (Secret).

  Encoding: base26 | base31 | base36 | base64 | base94 | binary

  Compression: zstd | zlib | bz2 | lzma | raw

Options:
  --key-encoding TEXT       [default: base64]
  -e, --data-encoding TEXT  [default: base64]
  -c, --compression TEXT    [default: zstd]
  -o, --output-file FILE    Write output to file.
  --group-len INTEGER       [default: 0]
  --line-len INTEGER        [default: 0]
  --padding INTEGER         [default: 0]
  -v, --verbose             Show verbose output.
  -h, --help                Show this message and exit.
```

Another day, they share a password:

```
% echo qwerty | soda encrypt-password - message -p interactive -o encrypted
% echo qwerty | soda decrypt-password - encrypted -p interactive -o message

% soda encrypt-password -h
Usage: soda encrypt-password [OPTIONS] PASSWORD_FILE MESSAGE_FILE

  Encrypt Message (Password).

  KDF profile: interactive | moderate | sensitive

  Encoding: base26 | base31 | base36 | base64 | base94 | binary

  Compression: zstd | zlib | bz2 | lzma | raw

Options:
  -p, --kdf-profile TEXT    [default: sensitive]
  -e, --data-encoding TEXT  [default: base64]
  -c, --compression TEXT    [default: zstd]
  -o, --output-file FILE    Write output to file.
  --group-len INTEGER       [default: 0]
  --line-len INTEGER        [default: 0]
  --padding INTEGER         [default: 0]
  -v, --verbose             Show verbose output.
  -h, --help                Show this message and exit.
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
  --line-len INTEGER      [default: 0]
  --padding INTEGER       [default: 0]
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
% soda es shared message -c zlib -v > /dev/null
Plaintext: 239
Ciphertext: 280
Overhead: 1.172
% soda es shared message -c bz2 -v > /dev/null
Plaintext: 239
Ciphertext: 340
Overhead: 1.423
% soda es shared message -c lzma -v > /dev/null
Plaintext: 239
Ciphertext: 324
Overhead: 1.356
% soda es shared message -c raw -v > /dev/null
Plaintext: 239
Ciphertext: 372
Overhead: 1.556
```


## Encoding

The rtty-soda supports various encodings:

```
% soda encrypt-public alice bob_pub message --data-encoding base36 --group-len 5 --line-len 80
9TPUZ T8OA3 PNC2Z XEH87 EPMCN NDQJJ GX0DE YW16D OJ2FC D3PCM B148K 6UZFN 9RQX7
8C83X 6O8WS MQ4CX 26C7H 35EK5 CVSIX IFSVN KPV6A TRV1F 573WI JFFGE I7N3Z Z4N6D
FSSOB DJUBK PC2YW Z6RG0 SUD2N OIYH8 WHJMN YYSKQ EBEVJ ZT0M1 DYJ7E NJ25J FMXNE
7LHUQ N5UIH SK5O7 96LWM IZ7BA R8SIV 6G55R Q50L4 PJH5Z 2JQNX JZTPK BG140 AKXOB
DKR4K POW9A HCQSQ JLSJ1 11AZY P8BM4 F3GUC SFX04 RMD0G 4V0PL RLRHN G8D8
```


## Compatibility

During the initial development (versions prior to 1.0.0),
I can break backwards compatibility.


## Releases 

This project follows a rolling release cycle. 
Each version bump represents where I completed a full test cycle. 
When testing passes successfully, I commit and release - so every release is a verified stable point.
