'use strict';

const HydraExpressPlugin = require('hydra-express/plugin');
const jwtAuth = require('fwsp-jwt-auth');

/**
 * @name JWTAuthPlugin
 * @summary HydraExpressPlugin for JWT auth
 * @extends HydraExpressPlugin
 */
class JWTAuthPlugin extends HydraExpressPlugin {
  constructor() {
    super('jwt-auth');
  }
  /**
   * @override
   */
  setHydraExpress(hydraExpress) {
    super.setHydraExpress(hydraExpress);
    hydraExpress.validateJwtToken = () => this.getMiddleware();
  }
  /**
   * @override
   */
  setConfig(serviceConfig) {
    super.setConfig(serviceConfig);    
    jwtAuth.loadCerts(null, serviceConfig.jwtPublicCert);
  }
  /**
   * @override
   */
  onServiceReady() { /*noop*/ }
  /**
  * @name getMiddleware
  * @summary Express middleware to validate a JWT sent via the req.authorization header
  * @return {function} Middleware function
  */
  getMiddleware() {
    const ServerResponse = this.hydraExpress.getHydra().getServerResponseHelper();
    return (req, res, next) => {
      let authHeader = req.headers.authorization;
      if (!authHeader) {
        this.hydraExpress.sendResponse(ServerResponse.HTTP_UNAUTHORIZED, res, {
          result: {
            reason: 'Invalid token'
          }
        });
      } else {
        let token = authHeader.split(' ')[1];
        if (token) {
          return jwtAuth.verifyToken(token)
            .then((decoded) => {
              req.authToken = decoded;
              next();
            })
            .catch((err) => {
              this.hydraExpress.sendResponse(ServerResponse.HTTP_UNAUTHORIZED, res, {
                result: {
                  reason: err.message
                }
              });
            });
        } else {
          this.hydraExpress.sendResponse(ServerResponse.HTTP_UNAUTHORIZED, res, {
            result: {
              reason: 'Invalid token'
            }
          });
        }
      }
    };
  }
}

module.exports = JWTAuthPlugin;
