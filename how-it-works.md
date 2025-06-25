# zakosign concepts

ZakoSign works for ELF files and potentially other kinds of files.
It can create an E-Signature for that file.

An E-Signature data is layed out in the following format:

- `8` Magic Value (`0x7a616b6f7369676e`, which is `zakosign`)
- `8` Version
- Public key
    - `32` Ed25519 public key
    - `3` Ceritificate chain in ID
- `[Optional]` Timestamp from Timestamping Authority
- `64` Signature
- Ceritificate Store
    - `1` Amount of ceritificates in this ceritificate store
    - `/` Ceritificates
        - `1` id
        - `8` length of this ceritificate
        - `/` certificate data in DER format

## Timestamping Authority

To simplify TSA process, we're not going to use RFA standards.
Instead, a TSA Sever is basically a HTTP server with the following JSON API endpoints:

### `POST` `/token`

Aquiring a timestamp for your signature.

#### Request

| Field     | Type   | Explaination                                           |
|-----------|--------|--------------------------------------------------------|
| version   | int    | Current TSA API version is 1                           |
| signature | string | A base64 encoded signature                             |
| public    | string | Ed25519 Public key starting -----BEGIN PUBLIC KEY----- |

#### Response

| Field       | Type     | Explaination                 |
|-------------|----------|------------------------------|
| version     | int      | Current TSA API version is 1 |
| timestamp   | int      | Server time                  |
| token       | string   | base64 encoded token         |
| key         | string   | Server's Ed25519 Public key starting -----BEGIN PUBLIC KEY-----|
| certificate | string[] | A list of certificate chain issued to the key. (Maximum 3, including RootCA) |

### `POST` `/register`

Rate limit per public key may apply. An extention to the above api:

#### Request
| Field       | Type     | Explaination                                                                 |
|-------------|----------|------------------------------------------------------------------------------|
| key         | string   | Ed25519 Public key starting -----BEGIN PUBLIC KEY-----                       |
| certificate | string[] | A list of certificate chain issued to the key. (Maximum 3, including RootCA) |

#### Response
| Field | Type | Explaination               |
|-------|------|----------------------------|
| rate  | int  | Maximum timestamps per day |

### `POST` `/status`

Rate limit per public key may apply. An extention to the above api:

#### Request
| Field       | Type     | Explaination                                                                 |
|-------------|----------|------------------------------------------------------------------------------|
| key         | string   | Ed25519 Public key starting -----BEGIN PUBLIC KEY-----                       |

#### Response
| Field | Type | Explaination                              |
|-------|------|-------------------------------------------|
| rate  | int  | Allowed timestamps request left for today |
