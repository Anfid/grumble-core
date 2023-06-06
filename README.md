# Grumble backend service

## About

Grumble is a chat service that is being worked on to gain a better hands-on understanding of complexities that arise
during the development of backend services. Idea is to make a simple chat app with acceptable UX that would allow
scaling the userbase to a real-world volumes without many issues or downtime.

## Current progress

- [x] Authentification service
  - [x] Storing user authentification info
  - [x] Issuing signed JWTs and refresh tokens on login
  - [x] Verification of previously issued JWTs to authorize users
  - [x] Refresh token rotation
  - [x] Refresh token revoke on logout request
  - [x] Refresh token family revoke on reuse
- [ ] Messaging service
  - [ ] Storing chat and message data
  - [ ] Instant updates with WebSockets
- [ ] Document API
- [ ] Split into smaller services
- [ ] Initialization rework
- [ ] Live configuration reload


## API

API is currently unstable and will be documented at a later stage of the project.


## Development setup

Running this project requires diesel CLI util with postgres feature.

```sh
$ cargo install diesel_cli --no-default-features --features postgres
```

To run this project you also have to have postgres service running in the background. Consult postgres documentation
for your system on how to do that.

Authentification service needs a dedicated key pair for signing and verifying user authentification tokens. Currently
only ed25519 keys are supported (subject to change, more keys will be supported after initialization process rework).

Note: Following step is also a subject to change, as a dedicated configuration file is likely to be introduced.

Once everything is set up and running, copy `.env.example` file to `.env` in the project root directory.

```sh
$ cp .env.example .env
```

And update it's contents according to your setup.

Variables:
* `DATABASE_URL` - URL to connect to your running Postgres instance;
* `BIND_ADDRESS` - An IP address and port that running service will use;
* `PHASH_SECRET_KEY` - Extra secret key used during password hashing, can be left empty for dev setup;
* `AUTH_PRIVATE_KEY_PATH` - Path to private key used for signing auth tokens;
* `AUTH_PUBLIC_KEY_PATH` - Path to public key used for verifying auth tokens;
* `RUST_LOG` - Rust log level, for more info on allowed values see `env_logger` crate documentation.

After updating .env file you can test and run the project with cargo.

```sh
$ cargo test
$ cargo run
```
