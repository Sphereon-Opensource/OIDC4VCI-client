import { DynamicRegistrationClientMetadata, SigningAlgo } from '@sphereon/oid4vc-common';

export type OAuthResponseType = 'code' | 'token' | 'id_token' | 'code token' | 'code id_token' | 'token id_token' | 'code token id_token';

export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'none';

export type TokenEndpointAuthSigningAlg =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'HS256'
  | 'HS384'
  | 'HS512';

export type OAuthScope = 'openid' | 'profile' | 'email' | 'address' | 'phone' | 'offline_access';

export type OAuthResponseMode = 'query' | 'fragment' | 'form_post';

export type OAuthGrantType =
  | 'authorization_code'
  | 'implicit'
  | 'password'
  | 'client_credentials'
  | 'refresh_token'
  | 'urn:ietf:params:oauth:grant-type:device_code'
  | 'urn:ietf:params:oauth:grant-type:saml2-bearer'
  | 'urn:ietf:params:oauth:grant-type:jwt-bearer';

export type RevocationEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'none';

export type RevocationEndpointAuthSigningAlg =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'HS256'
  | 'HS384'
  | 'HS512';

export type PKCECodeChallengeMethod = 'plain' | 'S256';

export interface AuthorizationServerMetadata extends DynamicRegistrationClientMetadata {
  issuer: string;
  authorization_endpoint?: string;
  authorization_challenge_endpoint?: string;
  token_endpoint?: string;
  token_endpoint_auth_methods_supported?: Array<TokenEndpointAuthMethod>;
  token_endpoint_auth_signing_alg_values_supported?: Array<TokenEndpointAuthSigningAlg>;

  registration_endpoint?: string;
  scopes_supported?: Array<OAuthScope | string>;
  response_types_supported: Array<OAuthResponseType>;
  response_modes_supported?: Array<OAuthResponseMode>;
  grant_types_supported?: Array<OAuthGrantType>;
  service_documentation?: string;
  ui_locales_supported?: string[];
  op_policy_uri?: string;
  op_tos_uri?: string;

  revocation_endpoint?: string;
  revocation_endpoint_auth_methods_supported?: Array<RevocationEndpointAuthMethod>;
  revocation_endpoint_auth_signing_alg_values_supported?: Array<RevocationEndpointAuthSigningAlg>;

  introspection_endpoint?: string;
  code_challenge_methods_supported?: Array<PKCECodeChallengeMethod>;

  // TODO below fields are not in the rfc8414 spec, do we need them?
  pushed_authorization_request_endpoint?: string; // The URL of the pushed authorization request endpoint at which a client can post an authorization request to exchange for a request_uri value usable at the authorization server
  // Note that the presence of pushed_authorization_request_endpoint is sufficient for a client to determine that it may use the PAR flow. A request_uri value obtained from the PAR endpoint is usable at the authorization endpoint regardless of other authorization server metadata such as request_uri_parameter_supported or require_request_uri_registration
  require_pushed_authorization_requests?: boolean; // Boolean parameter indicating whether Indicates whether the client is required to use PAR to initiate authorization. If omitted, the default value is false.
  'pre-authorized_grant_anonymous_access_supported': boolean; // OPTIONAL. A JSON Boolean indicating whether the issuer accepts a Token Request with a Pre-Authorized Code but without a client id. The default is false
  // A JSON array containing a list of the JWS alg values (from the [IANA.JOSE.ALGS] registry) supported by the authorization server for DPoP proof JWTs.
  dpop_signing_alg_values_supported?: (string | SigningAlgo)[];
  // OIDC values
  frontchannel_logout_supported?: boolean;
  frontchannel_logout_session_supported?: boolean;
  backchannel_logout_supported?: boolean;
  backchannel_logout_session_supported?: boolean;
  userinfo_endpoint?: string;
  check_session_iframe?: string;
  end_session_endpoint?: string;
  acr_values_supported?: string[];
  subject_types_supported?: string[];
  request_object_signing_alg_values_supported?: string[];
  display_values_supported?: string[];
  claim_types_supported?: string[];
  claims_supported?: string[];
  claims_parameter_supported?: boolean;

  // VCI values. In case an AS provides a credential_endpoint itself
  credential_endpoint?: string;
  deferred_credential_endpoint?: string;

  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure
}

// These can be used be a reducer
export const authorizationServerMetadataFieldNames: Array<keyof AuthorizationServerMetadata> = [
  'issuer',
  'authorization_endpoint',
  'authorization_challenge_endpoint',
  'token_endpoint',
  'jwks_uri',
  'registration_endpoint',
  'scopes_supported',
  'response_types_supported',
  'response_modes_supported',
  'grant_types_supported',
  'token_endpoint_auth_methods_supported',
  'token_endpoint_auth_signing_alg_values_supported',
  'service_documentation',
  'ui_locales_supported',
  'op_policy_uri',
  'op_tos_uri',
  'revocation_endpoint',
  'revocation_endpoint_auth_methods_supported',
  'revocation_endpoint_auth_signing_alg_values_supported',
  'introspection_endpoint',
  'introspection_endpoint_auth_methods_supported',
  'introspection_endpoint_auth_signing_alg_values_supported',
  'code_challenge_methods_supported',
  'signed_metadata',
] as const;

export enum WellKnownEndpoints {
  OPENID_CONFIGURATION = '/.well-known/openid-configuration',
  OAUTH_AS = '/.well-known/oauth-authorization-server',
  OPENID4VCI_ISSUER = '/.well-known/openid-credential-issuer',
}

export type AuthorizationServerType = 'OIDC' | 'OAuth 2.0' | 'OID4VCI'; // OID4VCI means the Issuer hosts a token endpoint itself

export interface EndpointMetadata {
  issuer: string;
  token_endpoint: string;
  credential_endpoint: string;
  deferred_credential_endpoint?: string;
  authorization_server?: string;
  authorization_endpoint?: string; // Can be undefined in pre-auth flow
  authorization_challenge_endpoint?: string;
}
