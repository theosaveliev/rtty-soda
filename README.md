# rtty-soda

A CLI tool for Unix-like environments to encrypt a RTTY session using NaCl.


#### Features

- Public Key encryption (Curve25519-XSalsa20-Poly1305)
- Secret Key encryption (XSalsa20-Poly1305)
- Key derivation (Argon2id-Blake2b)
- Text compression (brotli, zstd, zlib, bz2, lzma)
- Custom encodings:
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
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.3.6
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.3.6-tools
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
lP/FZNIPA3tSdMrheYi7lGwvhslghqD7NUBfqHOrE2I=

% soda genkey | tee bob | soda pubkey - | tee bob_pub
lTtI9SNbMLsbwD5YZF5Hbciw2hI3GdhfvGS/ownNsjk=

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

% soda encrypt-public alice bob_pub message | tee encrypted | cut -c 1-80
1gpVRRv3f+pLFef+GMtdRF96rvbsRxgXg5XTCaSw+gyrIf0VeewAlYV+88wB2KFL0QOdm7QlX6/Ae4ms

% soda encrypt-public -h
Usage: soda encrypt-public [OPTIONS] PRIVATE_KEY_FILE PUBLIC_KEY_FILE
                           MESSAGE_FILE

  Encrypt Message (Public).

  Encoding: base26 | base31 | base36 | base64 | base94 | binary

  Compression: brotli | zstd | zlib | bz2 | lzma | raw

Options:
  -t, --text                Treat message as text (binary if not specified).
  --key-encoding TEXT       [default: base64]
  -e, --data-encoding TEXT  [default: base64]
  -c, --compression TEXT    [default: brotli]
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
% echo qwerty | soda kdf - -p interactive
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
1. The plaintext is prepared:
   - In binary mode (default), the message is read as bytes
   - In text mode (`-t, --text`), the message is read as a string, stripped, and encoded with SCSU, reducing its size by 15–50%
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
5NCZ8 XC217 P27TJ 2WSQI 3RIUZ D6KH7 UD1J5 FS0F8 2H8JA 80AT7 CZ9FW O8V9O Q90GP
VK6B0 8V49M ZDB17 AWGPA ELJUP KLNRD ZH7Y9 2VW4H E3LDI QQY9F I8U3O CA3TF WXE1O
837K0 U17UC EAJ1U FZ47Y 34CYD MMW2S 3HDOK W3NKH 1XOI8 NLQZZ PD291 XHFJV 1C6U7
H4PE9 KNLI5 PHBZD 2I5FO BDJV1 G713E SKW2D UOWOJ X79CP NLPA8 PLK
```


## Environment variables

Common options can be set in the environment variables:

```
% cat ~/.soda/ru.env
SODA_TEXT=1
SODA_KEY_ENCODING=base31
SODA_DATA_ENCODING=base31
SODA_COMPRESSION=brotli
SODA_KDF_PROFILE=sensitive
SODA_GROUP_LEN=5
SODA_LINE_LEN=69
SODA_PADDING=0
SODA_VERBOSE=0
```


## Tutorial for the Underground Moscow Museum

```
% docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.3.6-tools

% source ~/.soda/ru.env
% soda genkey | tee 173-закрытый | soda pubkey - | tee 173-публичный
БФЫВЯ УДЗФО ЗНОЕЕ МЫВЯН ЙЬЩОЛ ЭГПМБ ПЭМЮЦ ОХМКК ЩКАРЗ ЗУЫЧХ ОО
% soda genkey | tee 305-закрытый | soda pubkey - | tee 305-публичный
ДМЩЕК ЧЗЩМИ ЕСКЙЗ ЭВСЩА СГТХД ТДЬЗБ ВИОНД ЬУСЯЧ ДЛЛУШ УГЭБЛ Я

% cat телеграмма
Телетайп — стартстопный приёмно-передающий телеграфный аппарат с клавиатурой
как у пищущей машинки, применявшийся также в качестве терминала устройств
вычислительной техники.
Наиболее совершенные телетайпы являются полностью электронными устройствами
и используют дисплей вместо принтера.
(c) Wikipedia

% soda e 173-закрытый 305-публичный телеграмма -v
ВГСЯЯ ИОТОД ЙУЙКМ ШЬХХБ УБГИТ ЗЙЧЭМ ШХЮУЧ ЧАПЦН ОБЬИЭ АИЙСР ХОИЮД
ЗМБСЩ БИДХН ЬОВШЕ ОХШЮЙ РЫЛАВ ВТВХМ ЧЦАЩЭ ЧТЙИО АЛДЫЩ МСЬЯТ АЯХДЯ
ТАПЧР УРЩУА ЧЕВЬК ХФЕЬЯ ЬЗЩРЯ МЛАНС ЛБЧМН РРЗХЕ ТГСКЦ ЦШЙУГ ЗИОЗО
ЦЯЕРД ЦНЯШХ УАЖЦУ КШЕШМ СЖЖУИ УЭЫИШ ЬПЙЦЮ ЙЗУСГ ВЖХМУ ЧСВГЛ УЛТЧБ
ЫЖЮЭЙ АКЙЧЗ ЙЯЫЕЧ ЬООЭЙ ЦЮКОД ЬЩЛЗЖ ДУРЖЮ НФЬЗЧ ИТДОЗ ЗФГЧД БЧЧФЩ
ВШТНЙ ТРЩИИ ЛШЖЮА ШБФУО ПЦНМГ КММГЫ СИЛЫЯ СЙВРЫ ЖКВПЩ ЖПШТФ БКГПИ
СТНКО ЯНСГР ЯЫВРЕ ДЯЧЗТ ЭЗХЖТ ЭЦСЬЯ ЙСЫЫЕ ЧМКАГ АЗКЖР ДРКЗЧ ФИЫЛЫ
ЩУУШЭ ВИЙЯЛ СПТДЫ ОАДНЬ ЬРРЛЕ ФЭФРЧ РБКК
Plaintext: 302
Ciphertext: 419
Overhead: 1.387
Groups: 84
```


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

- Data store
  
  The `-tools` image features `steganon-cli` to support the following flow:
  
  ![Flow diagram](https://github.com/theosaveliev/rtty-soda/raw/main/diagram/soda.png)

  ```
  % docker run -it --rm -h rtty-soda -v .:/app/host nett/rtty-soda:0.3.6-tools
  % source ~/.soda/bin.env
  % echo decoy > decoy
  % echo password | soda ep - message -o encrypted
  % steganon-cli hide -i cover.png -d "decoy | encrypted" -s "seed1 | seed2" -o stego.png
  % exiftool -TagsFromFile cover.png -all:all -overwrite_original stego.png
  % steganon-cli extract -i stego.png -s "seed1 | seed2" -o "decoy | encrypted"
  % echo password | soda dp - encrypted -o message
  ```


## Compatibility

During the initial development (versions prior to 1.0.0),
I can break backwards compatibility.


## Releases

This project follows a rolling release cycle.
Each version bump represents where I completed a full test cycle.
When testing passes successfully, I commit and release - so every release is a verified stable point.