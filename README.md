# hydra-express-plugin-jwt-auth

## Summary

Uses the [fwsp-jwt-auth](http://github.com/flywheelsports/fwsp-jwt-auth) module to decode and validate JWT tokens.

There should be a root-level `jwtPublicCert` entry in the service config with the path to the public key file.

This plugin does not require a config entry in the `hydra.plugins` section.

Express middleware `hydraExpress.validateJwtToken()` decodes valid, unexpired auth tokens into `req.authToken`, or returns a 401 response otherwise.

These tokens should be in the `authorization` header of the request, as described [here](https://jwt.io/introduction/).

## Usage

```javascript
const hydraExpress = require('hydra-express');
const JWTAuthPlugin = require('hydra-express-plugin-jwt-auth');
hydraExpress.use(new JWTAuthPlugin());

api.get('/needsLogin', hydraExpress.validateJwtToken(), (req, res) => {
  res.json({decodedToken: req.authToken});
});
```
