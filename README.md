# rtty-soda

A CLI tool for Unix-like environments to encrypt a RTTY session using NaCl.


#### Features

- Public Key encryption (Curve25519-XSalsa20-Poly1305)
- Secret Key encryption (XSalsa20-Poly1305)
- Key derivation (Argon2id-Blake2b)
- Password encryption
- Text compression (zlib, bz2, lzma)
- Custom encodings


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
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.1.6
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.1.6-tools
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
```

#### Encryption

Alice sends the message to Bob:

```
% cat message
A telegraph key is a specialized electrical switch used by a trained operator to
transmit text messages in Morse code in a telegraphy system.
The first telegraph key was invented by Alfred Vail, an associate of Samuel Morse.
(c) Wikipedia

% soda encrypt-public alice bob_pub message --output-file encrypted
Plaintext: 239
Ciphertext: 280
Overhead: 1.172

% cat encrypted
xaLTAu3qD/h7cUspHL2HP0HVASovUE84WnWBj+uHgIqNPzxVhUoObILvDlb2WBJqiXmhMHSXpdMBMSiewdXtU9m
YlNumkJ8qq+pzsBL3Lrrjdg3jdoeMkweyR9xUY2QytR91Qi9Cga5GM5tTO+rHB6yriThUp2XGEQ1Bap358AT8u/
dJ7dOzaAv2ei5LfgqtlGmetACfXqxG5SunrOqWvmxpi2QI3FqWUkOLUl00Rj/ZnISmZRsDjekKgJcknKit498cL
7AVUKQA5PxFm4ZN9Q==
```

#### Decryption

```
$ soda decrypt-public bob alice_pub encrypted

A telegraph key is a specialized electrical switch used by a trained operator to
transmit text messages in Morse code in a telegraphy system.
The first telegraph key was invented by Alfred Vail, an associate of Samuel Morse.
(c) Wikipedia

Plaintext: 239
Ciphertext: 280
Overhead: 1.172
```


## Secret Key encryption

Alice and Bob share a key for symmetric encryption:

```
% soda genkey > shared
% soda encrypt-secret shared message > encrypted
Plaintext: 239
Ciphertext: 280
Overhead: 1.172

% soda decrypt-secret shared encrypted -o message
Overwrite the output file? (message) [y/N]: y
Plaintext: 239
Ciphertext: 280
Overhead: 1.172
```

Another day, they share a password:

```
% echo qwerty | soda encrypt-password - message -p interactive > encrypted
Plaintext: 239
Ciphertext: 280
Overhead: 1.172

% echo qwerty | soda decrypt-password - encrypted -p interactive > plain
Plaintext: 239
Ciphertext: 280
Overhead: 1.172
```


## Key derivation

The KDF function derives the key from the password.
It accepts different profiles: interactive, moderate, and sensitive.

```
% echo qwerty > password
% time soda kdf password
jNLXU8/Ne5ZC8KuhDYqPUBg7xrxwv8J6yDJgCcFib9g=
real	0m7.850s
user	0m7.386s
sys	0m0.461s

% time soda kdf password --profile interactive
HqbvUXflAG+no3YS9njezZ3leyr8IwERAyeNoG2l41U=
real	0m0.295s
user	0m0.279s
sys	0m0.014s
```


## Text compression

That works as follows:
1. The plaintext is compressed with the compression lib
2. The 16-byte MAC and 24-byte nonce are added
3. The result is encoded with Base64, which adds ~25% overhead

Aside from the default zlib, there are more compression options. \
For a short message, the raw option provides smaller output.
For a long text, the bz2 showed the best results. \
Overall, encrypting a letter into 1.172 letters is a working solution.

```
% soda encrypt-public alice bob_pub message --compression zlib > /dev/null
Plaintext: 239
Ciphertext: 280
Overhead: 1.172
% soda encrypt-public alice bob_pub message --compression bz2 > /dev/null
Plaintext: 239
Ciphertext: 344
Overhead: 1.439
% soda encrypt-public alice bob_pub message --compression lzma > /dev/null
Plaintext: 239
Ciphertext: 324
Overhead: 1.356
% soda encrypt-public alice bob_pub message --compression raw > /dev/null
Plaintext: 239
Ciphertext: 372
Overhead: 1.556
```


## Encoding

The rtty-soda supports various encodings:

- Base26 (Latin)
- Base36 (Latin with numbers)
- Base64 (RFC 3548)
- Base94 (ASCII printable)
- Binary

```
% soda encrypt-public alice bob_pub message --data-encoding base36

67EG0R6HNKWJCVWF76SXDVXBUVR2L1CZ5WNZ2O1GHVM6488OGHZGIVX6GQE19V7VMSHFWOQD09GRIOOFSUXFRVG
M2UNVG9NN9X2113FA6JNQ8082WQ38YNQ5KUXHB82SD7HK4YHQDODYTA3O8WY93T6EG5ZX5JB9W1IETKC4D7TOHT
K7ZROL69IYLZVT9MCIPX7V6IX259F4RGC6PRKVNTP8HRLYZZVU4B1V5Y1HZV0AFGLEIPYECEKN7WC7ZL1YVTWJQ
458E5E9ZK4E731MCFO8USWBHJ7SM9PTK4IP5NFFB28WWS6KVWU9RBV1WL11MT

Plaintext: 239
Ciphertext: 322
Overhead: 1.347
```


## Compatibility

During the initial development (versions prior to 1.0.0),
I can break backwards compatibility.
