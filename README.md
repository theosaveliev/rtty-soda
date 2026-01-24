# rtty-soda

A CLI tool for Unix-like environments to encrypt a RTTY session using NaCl.


#### Features

- Public Key encryption (Curve25519-XSalsa20-Poly1305)
- Secret Key encryption (XSalsa20-Poly1305)
- Key derivation (Argon2id-Blake2b)
- Text compression (brotli, zstd, zlib, bz2, lzma)
- Custom encodings:
  - Base10 (Decimal)
  - Base26 (Latin)
  - Base31 (Cyrillic)
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
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.3.11
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.3.11-tools
```


## Getting help

All commands have `[-h | --help]` option.

```
% soda
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
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
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
HT6UNhua+slsp+GBWyIiLjw55iWGOSvgdHtOaidbQSc=

% soda genkey | tee bob | soda pubkey - | tee bob_pub
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
8+tcGctkBSSCsWv6oGduS5/DcCdKx4A6GOiEfBiyBWE=

% soda genkey -h
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Usage: soda genkey [OPTIONS]

  Generate Private Key.

  Encoding: base10 | base26 | base31 | base36 | base64 | base94 | binary

Options:
  -e, --encoding TEXT      [default: base64]
  -o, --output-file FILE   Write output to file.
  -g, --group-len INTEGER  [default: 0]
  --line-len INTEGER       [default: 80]
  --padding INTEGER        [default: 0]
  -v, --verbose            Show verbose output.
  -h, --help               Show this message and exit.
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
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
lbu7UO4XgNUJcYKfX0IonastYWzwhL1h8OnW4Ks2nyTCwAsJK78NSa/iUqjmjGN9PlwXiDakvJHFigZD

% soda encrypt-public -h
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Usage: soda encrypt-public [OPTIONS] PRIVATE_KEY_FILE PUBLIC_KEY_FILE
                           MESSAGE_FILE

  Encrypt Message (Public).

  Encoding: base10 | base26 | base31 | base36 | base64 | base94 | binary

  Compression: brotli | zstd | zlib | bz2 | lzma | raw

Options:
  -t, --text                Treat message as text (binary if not specified).
  --key-encoding TEXT       [default: base64]
  -e, --data-encoding TEXT  [default: base64]
  -c, --compression TEXT    [default: brotli]
  -o, --output-file FILE    Write output to file.
  -g, --group-len INTEGER   [default: 0]
  --line-len INTEGER        [default: 80]
  --padding INTEGER         [default: 0]
  -v, --verbose             Show verbose output.
  -h, --help                Show this message and exit.
```

#### Decryption

```
% soda decrypt-public bob alice_pub encrypted
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
A telegraph key is a specialized electrical switch used by a trained operator to
transmit text messages in Morse code in a telegraphy system.
The first telegraph key was invented by Alfred Vail, an associate of Samuel Morse.
(c) Wikipedia
```


## Secret Key encryption

Alice and Bob share a key for symmetric encryption:

```
% soda genkey > shared
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.% soda encrypt-secret shared message -o encrypted
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
% echo qwerty | soda kdf - -p interactive
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
HqbvUXflAG+no3YS9njezZ3leyr8IwERAyeNoG2l41U=

% soda kdf -h
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Usage: soda kdf [OPTIONS] PASSWORD_FILE

  Key Derivation Function.

  Encoding: base10 | base26 | base31 | base36 | base64 | base94 | binary

  Profile: interactive | moderate | sensitive

Options:
  -e, --encoding TEXT      [default: base64]
  -p, --profile TEXT       [default: sensitive]
  -o, --output-file FILE   Write output to file.
  -g, --group-len INTEGER  [default: 0]
  --line-len INTEGER       [default: 80]
  --padding INTEGER        [default: 0]
  -v, --verbose            Show verbose output.
  -h, --help               Show this message and exit.
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
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Plaintext: 238
Ciphertext: 216
Overhead: 0.908
Groups: 1
% soda es shared message -t -v -c zstd > /dev/null
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Plaintext: 238
Ciphertext: 276
Overhead: 1.160
Groups: 1
% soda es shared message -t -v -c zlib > /dev/null
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Plaintext: 238
Ciphertext: 280
Overhead: 1.176
Groups: 1
% soda es shared message -t -v -c bz2 > /dev/null
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Plaintext: 238
Ciphertext: 336
Overhead: 1.412
Groups: 1
% soda es shared message -t -v -c lzma > /dev/null
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Plaintext: 238
Ciphertext: 320
Overhead: 1.345
Groups: 1
% soda es shared message -t -v -c raw > /dev/null
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
Plaintext: 238
Ciphertext: 372
Overhead: 1.563
Groups: 1
```


## Encoding

The rtty-soda supports various encodings:

```
% soda encrypt-public alice bob_pub message --data-encoding base36 --group-len 5 --text
<frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
513S7 9BLUG AVKLP S8PV8 GGOAJ I4ZG2 W0CLI O2H8J P270K Z36S0 17ZSN 4VJVR 0L2GL
QD3S3 K9LYV K1NTU 0QYYD IL032 60P67 U0NNO UY7S2 WO55O 6CNHV OMUEM IDFQ5 PIAIU
OHX15 1OM4H 4T1IR SAH2U V87ZS SC2TB IFE8X 3YB0H YUL2C LXQLW 37PJZ IJ50M JJH0X
VX8IM MQ4ON 9DRX2 RGX2J WXW1P RYHP9 G3AJ9 6PJOC DPREK 6ND5Q RHV
```


## Environment variables

Common options can be set in the environment variables:

```
% cat ~/.soda/bin.env
SODA_TEXT=0
SODA_KEY_ENCODING=binary
SODA_DATA_ENCODING=binary
SODA_COMPRESSION=brotli
SODA_KDF_PROFILE=sensitive
SODA_GROUP_LEN=0
SODA_LINE_LEN=0
SODA_PADDING=0
SODA_VERBOSE=0
```


## Alternative usage

- Password source
  ```
  % echo "A line from a book or a poem" | soda kdf - -e base94 -p interactive
  <frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
x\R9"~8Ujh^_uh:Ty<!t(ZNzK=5w^ukew~#-x!n
  ```

- WireGuard keyer
  ```
  % echo "A line from a book or a poem" | soda kdf - -p interactive -o privkey
  % cat privkey
  uIoBJdgaz8ZP3/n/9KzdUNvFi7DxbUQdQ9t8ujwGnMk=
  % soda pubkey privkey
  <frozen importlib._bootstrap>:491: RuntimeWarning: The global interpreter lock (GIL) has been enabled to load module '_brotli', which has not declared that it can run safely without the GIL. To override this behavior and keep the GIL disabled (at your own risk), run with PYTHON_GIL=0 or -Xgil=0.
F2B674kXVcTznnRPWCVasx1miCT+yUtXQ3P5Ecee4zI=
  % cat privkey | wg pubkey
  F2B674kXVcTznnRPWCVasx1miCT+yUtXQ3P5Ecee4zI=
  ```


## Compatibility

During the initial development (versions prior to 1.0.0),
I can break backwards compatibility.


## Releases

This project follows a rolling release cycle.
Each version bump represents where I completed a full test cycle.
When testing passes successfully, I commit and release - so every release is a verified stable point.