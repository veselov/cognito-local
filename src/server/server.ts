import bodyParser from "body-parser";
import cors from "cors";
import express from "express";
import * as http from "http";
import type { Logger } from "pino";
import * as uuid from "uuid";
import { CognitoError, UnsupportedError } from "../errors";
import { Router } from "./Router";
import PublicKey from "../keys/cognitoLocal.public.json";
import PrivateKey from "../keys/cognitoLocal.private.json";
import jwkToPem from "jwk-to-pem";
import Pino from "pino-http";
import { CognitoService } from "../services";
import { AppClient } from "../services/appClient";
import jwt, { JwtPayload, VerifyOptions } from "jsonwebtoken";

export interface ServerOptions {
  port: number;
  hostname: string;
  development: boolean;
}

export interface Server {
  application: any; // eslint-disable-line
  start(options?: Partial<ServerOptions>): Promise<http.Server>;
}

export const createServer = (
  router: Router,
  logger: Logger,
  cognito: CognitoService,
  options: Partial<ServerOptions> = {}
): Server => {
  const pino = Pino({
    logger,
    useLevel: "debug",
    genReqId: () => uuid.v4().split("-")[0],
    quietReqLogger: true,
    autoLogging: {
      ignore: (req) => req.method === "OPTIONS",
    },
  });
  const app = express();

  app.use(pino);

  app.use(
    cors({
      origin: "*",
    })
  );
  app.use(
    bodyParser.json({
      type: "application/x-amz-json-1.1",
    })
  );
  app.use(express.urlencoded({ extended: true }));

  app.get("/:userPoolId/.well-known/jwks.json", (req, res) => {
    res.status(200).json({
      keys: [PublicKey.jwk],
    });
  });

  app.get("/:userPoolId/.well-known/openid-configuration", (req, res) => {
    const proxyHost = req.headers["x-forwarded-host"];
    const host = proxyHost ? proxyHost : req.headers.host;
    const url = `http://${host}/${req.params.userPoolId}`;

    res.status(200).json({
      subject_types_supported: ["public", "pairwise"],
      grant_types_supported: ["authorization_code"],
      id_token_signing_alg_values_supported: ["RS256"],
      jwks_uri: `${url}/.well-known/jwks.json`,
      issuer: `${url}`,
      token_endpoint: `${url}/oauth2/token`,
      userinfo_endpoint: `${url}/oauth2/userinfo`,
    });
  });

  app.get("/health", (req, res) => {
    res.status(200).json({ ok: true });
  });

  app.post("/:userPoolId/oauth2/token", (req, res, next) => {
    const handleRequest = async () => {
      const grantType = req.body.grant_type;

      if (grantType !== "password") {
        res.status(400).json({
          error: "unsupported_grant_type",
          description: "only 'password' grant type is supported",
        });
        return;
      }

      const clientId = req.body.client_id;

      let userPoolClient: AppClient | null;

      try {
        userPoolClient = await cognito.getAppClient(
          { logger: req.log },
          clientId
        );
      } catch (e) {
        res.status(500).json({
          error: "server_error",
          description: "failed to retrieve user pool client" + e,
        });
        return;
      }

      if (!userPoolClient) {
        res.status(500).json({
          error: "server_error",
          description: "failed to retrieve user pool client",
        });
        return;
      }

      const userPool = await cognito.getUserPoolForClientId(
        { logger: req.log },
        clientId
      );

      const user = await userPool.getUserByUsername(
        { logger: req.log },
        req.body.username
      );

      if (!user) {
        res.status(400).json({
          error: "server_error",
          description: "user " + req.body.username + " not found",
        });
        return;
      }
      const attr = user.Attributes;
      const appData2 = attr.find(
        (attribute) => attribute.Name === "custom:appIds"
      );
      const sub = attr.find((attribute) => attribute.Name === "sub");
      const status = user.Enabled ? "ACTIVE" : "INACTIVE";

      if (!userPoolClient) {
        res.status(400).json({
          error: "invalid_client",
          description: "invalid user pool client",
        });
        return;
      }

      const now = Math.floor(Date.now() / 1000);

      const accessToken = {
        sub: sub?.Value,
        client_id: clientId,
        scope: req.body.scope,
        jti: uuid.v4(),
        auth_time: now,
        iat: now,
        nbf: now,
        aud: clientId,
        token_use: "access",
        "custom:login": user.Username,
        "custom:status": status,
      };

      const idToken = {
        sub: sub?.Value,
        client_id: clientId,
        jti: uuid.v4(),
        auth_time: now,
        iat: now,
        aud: clientId,
        token_use: "id",
        "custom:appIds": appData2?.Value,
      };

      res.status(200).json({
        access_token: jwt.sign(accessToken, PrivateKey.pem, {
          algorithm: "RS256",
          issuer: `http://${req.headers.host}/${userPoolClient.UserPoolId}`,
          expiresIn: 3600,
          keyid: "CognitoLocal",
        }),
        expiresIn: 3600,
        id_token: jwt.sign(idToken, PrivateKey.pem, {
          algorithm: "RS256",
          issuer: `http://${req.headers.host}/${userPoolClient.UserPoolId}`,
          expiresIn: 3600,
          keyid: "CognitoLocal",
        }),
        token_type: "Bearer",
      });
    };

    handleRequest().catch(next);
  });

  app.get("/:userPoolId/oauth2/userinfo", (req, res, next) => {
    const handleRequest = async () => {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          error: "invalid_token",
          description:
            "Authorization header must be provided with a Bearer token",
        });
      }

      const { userPoolId } = req.params;
      const token = authHeader.split(" ")[1];
      const pem = jwkToPem(PublicKey.jwk);

      const verifyOptions: VerifyOptions = {
        algorithms: ["RS256"],
        issuer: `http://${req.headers.host}/${userPoolId}`,
      };

      try {
        const decodedToken = jwt.verify(
          token,
          pem,
          verifyOptions
        ) as JwtPayload;

        if (typeof decodedToken === "object" && decodedToken.aud) {
          const clientId = decodedToken["client_id"];

          const userPool = await cognito.getUserPoolForClientId(
            { logger: req.log },
            clientId
          );

          if (!userPool) {
            res.status(404).json({
              error: "user_pool_not_found",
              description: "User pool not found for the provided client ID",
            });
            return;
          }
          const users = await userPool.listUsers({ logger: req.log });

          const user = users.find((user) => {
            const subAttribute = user.Attributes.find(
              (attr) => attr.Name === "sub"
            );
            return subAttribute && subAttribute.Value === decodedToken.sub;
          });

          if (!user) {
            res.status(404).json({
              error: "user_not_found",
              description: "User not found",
            });
            return;
          }

          const attr = user.Attributes;
          if (!attr) {
            res.status(400).json({
              error: "missing_attributes",
              description: "User attributes are missing",
            });
            return;
          }

          const userInfo = {
            given_name: attr.find(
              (attribute) => attribute.Name === "given_name"
            )?.Value,
            family_name: attr.find(
              (attribute) => attribute.Name === "family_name"
            )?.Value,
            sub: decodedToken.sub,
            email: attr.find((attribute) => attribute.Name === "email")?.Value,
          };

          return res.status(200).json(userInfo);
        } else {
          return res.status(400).json({
            error: "invalid_token",
            description: "Token is missing required claims",
          });
        }
      } catch (err) {
        return res.status(401).json({
          error: "invalid_token",
          description: "Token is invalid or expired: " + err,
        });
      }
    };

    handleRequest().catch(next);
  });

  app.post("/", (req, res) => {
    const xAmzTarget = req.headers["x-amz-target"];

    if (!xAmzTarget) {
      res.status(400).json({ message: "Missing x-amz-target header" });
      return;
    } else if (xAmzTarget instanceof Array) {
      res.status(400).json({ message: "Too many x-amz-target headers" });
      return;
    }

    const [, target] = xAmzTarget.split(".");
    if (!target) {
      res.status(400).json({ message: "Invalid x-amz-target header" });
      return;
    }

    const route = router(target);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const replacer: (this: any, key: string, value: any) => any = function (
      key,
      value
    ) {
      if (this[key] instanceof Date) {
        return Math.floor(this[key].getTime() / 1000);
      }
      return value;
    };

    route({ logger: req.log }, req.body).then(
      (output) =>
        res.status(200).type("json").send(JSON.stringify(output, replacer)),
      (ex) => {
        if (ex instanceof UnsupportedError) {
          if (options.development) {
            req.log.info("======");
            req.log.info("");
            req.log.info("Unsupported target");
            req.log.info("");
            req.log.info(`x-amz-target: ${xAmzTarget}`);
            req.log.info("Body:");
            req.log.info(JSON.stringify(req.body, undefined, 2));
            req.log.info("");
            req.log.info("======");
          }

          req.log.error(`Cognito Local unsupported feature: ${ex.message}`);
          res.status(500).json({
            __type: "CognitoLocal#Unsupported",
            message: `Cognito Local unsupported feature: ${ex.message}`,
          });
          return;
        } else if (ex instanceof CognitoError) {
          req.log.warn(ex, `Error handling target: ${target}`);
          res.status(400).json({
            __type: ex.code,
            message: ex.message,
          });
          return;
        } else {
          req.log.error(ex, `Error handling target: ${target}`);
          res.status(500).json(ex);
          return;
        }
      }
    );
  });

  return {
    application: app,
    start(startOptions) {
      const actualOptions: ServerOptions = {
        port: options?.port ?? 9229,
        hostname: options?.hostname ?? "localhost",
        development: options?.development ?? false,
        ...options,
        ...startOptions,
      };

      return new Promise((resolve, reject) => {
        const httpServer = app.listen(
          actualOptions.port,
          actualOptions.hostname,
          () => resolve(httpServer)
        );
        httpServer.on("error", reject);
      });
    },
  };
};
