import { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";

export interface EmailClaims {
  email?: string;
  email_verified?: boolean;
}

/**
 * The email claims of an ID token, as Cognito issues them: `email` when the user has the `email`
 * attribute, and `email_verified` as a boolean that is `true` only when the user's
 * `email_verified` attribute is `"true"`. A user without an email address gets neither claim.
 */
export const emailClaims = (
  attributes: AttributeListType | undefined
): EmailClaims => {
  const email = attributes?.find((a) => a.Name === "email")?.Value;
  if (email === undefined) {
    return {};
  }
  const verified = attributes?.find((a) => a.Name === "email_verified")?.Value;
  return {
    email,
    email_verified: verified === "true",
  };
};
