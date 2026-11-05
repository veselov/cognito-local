import { emailClaims } from "./emailClaims";

describe("emailClaims", () => {
  it("has no claims without an email attribute", () => {
    expect(emailClaims(undefined)).toEqual({});
    expect(emailClaims([{ Name: "sub", Value: "abc" }])).toEqual({});
    expect(
      emailClaims([{ Name: "email_verified", Value: "true" }])
    ).toEqual({});
  });

  it("reports a verified email address", () => {
    expect(
      emailClaims([
        { Name: "email", Value: "user@example.com" },
        { Name: "email_verified", Value: "true" },
      ])
    ).toEqual({ email: "user@example.com", email_verified: true });
  });

  it("reports an unverified email address", () => {
    expect(
      emailClaims([
        { Name: "email", Value: "user@example.com" },
        { Name: "email_verified", Value: "false" },
      ])
    ).toEqual({ email: "user@example.com", email_verified: false });
  });

  it("counts a missing email_verified attribute as unverified", () => {
    expect(
      emailClaims([{ Name: "email", Value: "user@example.com" }])
    ).toEqual({ email: "user@example.com", email_verified: false });
  });
});
