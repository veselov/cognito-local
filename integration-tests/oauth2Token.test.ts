import supertest from "supertest";
import jwt from "jsonwebtoken";
import { MockLogger } from "../src/__tests__/mockLogger";
import { newMockCognitoService } from "../src/__tests__/mockCognitoService";
import { newMockUserPoolService } from "../src/__tests__/mockUserPoolService";
import * as TDB from "../src/__tests__/testDataBuilder";
import { createServer } from "../src";

describe("OAuth2 token endpoint", () => {
  const issueIdToken = async (attributes: { Name: string; Value: string }[]) => {
    const userPool = newMockUserPoolService({ Id: "test-pool" });
    const cognito = newMockCognitoService(userPool);
    const client = TDB.appClient({ UserPoolId: "test-pool" });
    cognito.getAppClient.mockResolvedValue(client);
    userPool.getUserByUsername.mockResolvedValue(
      TDB.user({ Username: "jdoe", Attributes: attributes })
    );

    const server = createServer(jest.fn(), MockLogger as any, cognito);
    const response = await supertest(server.application)
      .post("/test-pool/oauth2/token")
      .type("form")
      .send({
        grant_type: "password",
        client_id: client.ClientId,
        username: "jdoe",
        password: "irrelevant",
      });

    expect(response.status).toEqual(200);
    return jwt.decode(response.body.id_token) as Record<string, unknown>;
  };

  it("puts an unverified email address into the ID token", async () => {
    const idToken = await issueIdToken([
      { Name: "sub", Value: "sub-1" },
      { Name: "email", Value: "jdoe@example.com" },
      { Name: "email_verified", Value: "false" },
    ]);

    expect(idToken.email).toEqual("jdoe@example.com");
    expect(idToken.email_verified).toBe(false);
    expect(idToken.token_use).toEqual("id");
  });

  it("puts a verified email address into the ID token", async () => {
    const idToken = await issueIdToken([
      { Name: "sub", Value: "sub-1" },
      { Name: "email", Value: "jdoe@example.com" },
      { Name: "email_verified", Value: "true" },
    ]);

    expect(idToken.email).toEqual("jdoe@example.com");
    expect(idToken.email_verified).toBe(true);
  });

  it("has no email claims for a user without an email address", async () => {
    const idToken = await issueIdToken([{ Name: "sub", Value: "sub-1" }]);

    expect(idToken).not.toHaveProperty("email");
    expect(idToken).not.toHaveProperty("email_verified");
  });
});
