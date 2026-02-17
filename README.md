# rtty-soda

A PyNaCl frontend with custom encodings, compression, and key derivation.


#### Features

- Public key encryption (Curve25519-XSalsa20-Poly1305)
- Secret key encryption (XSalsa20-Poly1305)
- Key derivation (Argon2id-Blake2b)
- Text compression (brotli, zstd, zlib, bz2, lzma)
- Custom encodings:
  - Base10 (Decimal)
  - Base26 (Latin)
  - Base31 (Cyrillic)
  - Base32 (RFC 4648)
  - Base36 (Latin with numbers)
  - Base64 (RFC 4648)
  - Base94 (ASCII printable)
  - Binary


## Installation
#### Package manager

1. [Install uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Install rtty-soda:
   ```
   % uv tool install "rtty-soda[cli]"
   ```
3. Remove rtty-soda:
   ```
   % uv tool uninstall rtty-soda
   ```

#### Docker

```
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.7.0
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.7.0-tools
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
  compression            List supported compression libs.
  decrypt-password (dp)  Decrypt Message (Password).
  decrypt-public (d)     Decrypt Message (Public).
  decrypt-secret (ds)    Decrypt Message (Secret).
  encode                 Encode File.
  encodings              List supported encodings.
  encrypt-password (ep)  Encrypt Message (Password).
  encrypt-public (e)     Encrypt Message (Public).
  encrypt-secret (es)    Encrypt Message (Secret).
  genkey                 Generate Private Key.
  google-auth (ga)       Google Authenticator TOTP.
  kdf                    Key Derivation Function.
  kdf-profiles           List supported KDF profiles.
  pubkey                 Get Public Key.
```

Some commands have aliases, so `% soda encrypt-password ...` and `% soda ep ...`
are equivalent.


## Public key encryption
#### Key generation

```
% soda genkey | tee alice | soda pubkey - | tee alice_pub
ACXd5nCLbiNRimfiFzvPOiAYGVESorUM6zGBwUfMhi8=

% soda genkey | tee bob | soda pubkey - | tee bob_pub
W6UbJ/MCk6hZI2kBjfeG7hmltdk+LCT3LX/biumC2hY=

% soda genkey -h
Usage: soda genkey [OPTIONS]

  Generate Private Key.

Options:
  -s, --key-passphrase TEXT  Private Key passphrase.
  -e, --encoding ENCODING    See `soda encodings`.  [default: base64]
  -o, --output-file FILE     Write output to file.
  -g, --group-len INTEGER    [default: 0]
  --line-len INTEGER         [default: 80]
  --padding INTEGER          [default: 0]
  -v, --verbose              Show verbose output.
  -h, --help                 Show this message and exit.
```

#### Encryption

Alice sends the message to Bob:

```
% cat message
A telegraph key is a specialized electrical switch used by a trained operator to
transmit text messages in Morse code in a telegraphy system.
The first telegraph key was invented by Alfred Vail, an associate of Samuel Morse.
(c) Wikipedia

% soda encrypt-public alice bob_pub message | tee encrypted | cut -c 1-80
kj8AKqlT+IOkCgl0AvtOsLLJ8oW4//+uqj+UayCJfnvSXqUYlJ3YB7L+vV+0ySWChkKxNQpUm8EYO6PK

% soda encrypt-public -h
Usage: soda encrypt-public [OPTIONS] PRIVATE_KEY_FILE PUBLIC_KEY_FILE
                           MESSAGE_FILE

  Encrypt Message (Public).

Options:
  -t, --text                     Treat message as text (binary if not
                                 specified).
  -s, --key-passphrase TEXT      Private Key passphrase.
  --key-encoding ENCODING        See `soda encodings`.  [default: base64]
  -e, --data-encoding ENCODING   See `soda encodings`.  [default: base64]
  -c, --compression COMPRESSION  See `soda compression`.  [default: brotli]
  -o, --output-file FILE         Write output to file.
  -g, --group-len INTEGER        [default: 0]
  --line-len INTEGER             [default: 80]
  --padding INTEGER              [default: 0]
  -v, --verbose                  Show verbose output.
  -h, --help                     Show this message and exit.
```

#### Decryption

```
% soda decrypt-public bob alice_pub encrypted
A telegraph key is a specialized electrical switch used by a trained operator to
transmit text messages in Morse code in a telegraphy system.
The first telegraph key was invented by Alfred Vail, an associate of Samuel Morse.
(c) Wikipedia
```


## Secret key encryption

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

rtty-soda intentionally uses deterministic key derivation.
The tool does not embed metadata, salt, or format headers
into ciphertext in order to avoid recognizable message structure.
As a result, identical passwords derive identical keys.

```
% echo qwerty | soda kdf - -p interactive
HqbvUXflAG+no3YS9njezZ3leyr8IwERAyeNoG2l41U=

% soda kdf -h
Usage: soda kdf [OPTIONS] PASSWORD_FILE

  Key Derivation Function.

Options:
  -s, --key-passphrase TEXT  Private Key passphrase.
  -e, --encoding ENCODING    See `soda encodings`.  [default: base64]
  -p, --profile PROFILE      See `soda kdf-profiles`.  [default: sensitive]
  -o, --output-file FILE     Write output to file.
  -g, --group-len INTEGER    [default: 0]
  --line-len INTEGER         [default: 80]
  --padding INTEGER          [default: 0]
  -v, --verbose              Show verbose output.
  -h, --help                 Show this message and exit.
```

![KDF diagram](https://github.com/theosaveliev/rtty-soda/raw/main/diagram/kdf.png)


## Text compression

That works as follows:
1. The plaintext is prepared:
   - In binary mode (default), the message is read as bytes
   - In text mode (`-t, --text`), the message is read as a string, stripped, and encoded with SCSU, reducing the size of Unicode messages by 15–50%
2. The plaintext is compressed with the compression lib
3. The 16-byte MAC and 24-byte nonce are added
4. The result is encoded with Base64, which adds ~33% overhead

```
% soda es shared message -t -v -c brotli > /dev/null
Plaintext: 238
Ciphertext: 216
Overhead: 0.908
Groups: 1
% soda es shared message -t -v -c zstd > /dev/null
Plaintext: 238
Ciphertext: 276
Overhead: 1.160
Groups: 1
% soda es shared message -t -v -c zlib > /dev/null
Plaintext: 238
Ciphertext: 280
Overhead: 1.176
Groups: 1
% soda es shared message -t -v -c bz2 > /dev/null
Plaintext: 238
Ciphertext: 336
Overhead: 1.412
Groups: 1
% soda es shared message -t -v -c lzma > /dev/null
Plaintext: 238
Ciphertext: 320
Overhead: 1.345
Groups: 1
% soda es shared message -t -v -c raw > /dev/null
Plaintext: 238
Ciphertext: 372
Overhead: 1.563
Groups: 1
```


## Encoding

The rtty-soda supports various encodings:

```
% soda encrypt-public alice bob_pub message --data-encoding base36 --group-len 5 --text
17H2B R6W06 41BFL HPSQH 6FOQM VKBJ5 DB8P1 V5QL1 M1T2E ZBVON BZRJN Q0PKH IB2VA
FT1EI NT16E ODI4I 6HFEX 6ZB82 1LESF 7O0G0 TL129 JM76U 97FJA 5MTD8 8ZPOF SUEHJ
ZFWG1 BVV8Q 2DC0M T16AZ HVH5M 422VN FLVOK A9CJG GH0Q0 7IA8B OYN3I CX26T 74H8A
CTMYW AY1DQ RIUCB 7QGEB M4ZWM D6L85 AW5F7 6HT1B NRHCW 353A5 RGA
```


## Environment variables

Common options can be set in the environment variables:

```
% cat ~/.soda/example.env
SODA_TEXT=0
SODA_KEY_PASSPHRASE="Speed has never killed anyone. Suddenly becoming stationary, that's what gets you."
SODA_KEY_ENCODING=binary
SODA_DATA_ENCODING=binary
SODA_COMPRESSION=brotli
SODA_KDF_PROFILE=sensitive
SODA_GROUP_LEN=0
SODA_LINE_LEN=0
SODA_PADDING=0
SODA_VERBOSE=0
```


## Private/Secret key passphrase

The key can be protected with an additional passphrase, similar to SSH keys.
When `--key-passphrase <passphrase>` is used, the private key is automatically
encrypted or decrypted using the same parameters as the following command:

```
% soda encrypt-password <passphrase> <key> --kdf-profile sensitive --data-encoding binary --compression raw
```

This process is slow, and there is limited room for making it faster.
RFC 9106 recommends using Argon2id with 2 GiB of memory and 1 pass,
while soda uses half that memory (1 GiB) and compensates with 4 passes.


## Alternative usage

- Password source
  ```
  % echo "A line from a book or a poem" | soda kdf - -e base94 -p interactive
  x\R9"~8Ujh^_uh:Ty<!t(ZNzK=5w^ukew~#-x!n
  ```

- WireGuard keyer
  ```
  % echo "A line from a book or a poem" | soda kdf - -p interactive -o privkey
  % cat privkey
  uIoBJdgaz8ZP3/n/9KzdUNvFi7DxbUQdQ9t8ujwGnMk=
  % soda pubkey privkey
  F2B674kXVcTznnRPWCVasx1miCT+yUtXQ3P5Ecee4zI=
  % cat privkey | wg pubkey
  F2B674kXVcTznnRPWCVasx1miCT+yUtXQ3P5Ecee4zI=
  ```

- Secure storage
  ```
  % echo "A remarkable example of misplaced confidence" > sensitive_data
  % echo "Blessed with opinions, cursed with thought" > data_password
  % soda ep data_password sensitive_data -e binary -p interactive -o encrypted_data
  % echo "Too serious to be wise" > offset_password
  % soda kdf offset_password -e base10 -p interactive -g 10 | head -1
  6174465709 4962164854 2541023297 3274271197 5950333784 2118297875 9632383288
  % sudo dd if=./encrypted_data of=/dev/sdb1 bs=1 seek=6174465709
  75+0 records in
  75+0 records out
  75 bytes transferred in 0.000769 secs (97529 bytes/sec)
  ```

  ![dd diagram](https://github.com/theosaveliev/rtty-soda/raw/main/diagram/dd.png)

- Google Authenticator keyer
  ```
  % soda genkey -e base32 | tee totp_key
  ISJBJCPLB6HS5ISQ5JX4SQDMEGAMGSXYLPFCIIESB7SCPUNA2WDA====
  % soda ga totp_key
  316 412 (expires in 5s)
  ```


## Compatibility

During the initial development (versions prior to 1.0.0),
I can break backwards compatibility.


## Releases

This project follows a rolling release cycle.
Each version bump represents where I completed a full test cycle.
When testing passes successfully, I commit and release - so every release is a verified stable point.