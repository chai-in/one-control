import { InMemoryWebStorage, UserManager, WebStorageStateStore } from "oidc-client-ts";

const issuer = import.meta.env.VITE_OIDC_ISSUER;
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID;
export const identity =
  issuer && clientId
    ? new UserManager({
        authority: issuer,
        client_id: clientId,
        redirect_uri: `${window.location.origin}/auth/callback`,
        post_logout_redirect_uri: window.location.origin,
        response_type: "code",
        scope: "openid profile",
        automaticSilentRenew: false,
        loadUserInfo: false,
        stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
        userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
        extraQueryParams: import.meta.env.VITE_OIDC_AUDIENCE
          ? { audience: import.meta.env.VITE_OIDC_AUDIENCE }
          : {},
      })
    : null;
let callback: ReturnType<UserManager["signinRedirectCallback"]> | undefined;
export function completeSignIn() {
  if (!identity) throw new Error("Organisation sign-in unavailable");
  callback ??= identity.signinRedirectCallback();
  return callback;
}
