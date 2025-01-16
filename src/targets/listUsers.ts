import {
  ListUsersRequest,
  ListUsersResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { Services } from "../services";
import { userToResponseObject } from "./responses";
import { Target } from "./Target";

export type ListUsersTarget = Target<ListUsersRequest, ListUsersResponse>;

export const ListUsers =
  ({ cognito }: Pick<Services, "cognito">): ListUsersTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    let users = await userPool.listUsers(ctx, req.Filter);

    let limit = req.Limit;
    if (limit === undefined || limit > 60) {
      limit = 60;
    }

    let start = 0;

    const pt = req.PaginationToken;
    if (pt !== undefined) {
      start = parseInt(pt, 10);
      users = users.slice(start, users.length);
    }

    if (users.length > limit) {
      users = users.slice(0, limit);
    }

    // TODO: support AttributesToGet
    // TODO: support Filter
    // TODO: support Limit
    // TODO: support PaginationToken

    return {
      Users: users.map(userToResponseObject),
      PaginationToken: String(users.length + start + 1),
    };
  };
