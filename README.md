# auth_for_warp

A proof-of-concept for a simple and reusable auth module that can be plugged into any [warp](https://crates.io/crates/warp)-based server application.

Passwords are salted and hashed using [argon2](https://crates.io/crates/argon2). On successful login, a JSON Web Token is generated using [jsonwebtoken](https://crates.io/crates/jsonwebtoken) and returned to the client. A warp filter is provided to authenticate subsequent requests against that token via bearer authentication.

Some limitiations (certainly not an exhaustive list):
- TLS is necessary to avoid leaking passwords on the wire (no PAKE).
- Only supports username + password (no OAuth, no TOTP, etc).
- All credential storage is left up to the application.
- User ID allocation probably ought to be left up to the application.
- Only handles authentication, supporting authorization will need some design work.
