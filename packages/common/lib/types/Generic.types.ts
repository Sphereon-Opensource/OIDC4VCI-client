import { OpenID4VCIServerMetadata } from './OpenID4VCIServerMetadata';

export interface ErrorResponse extends Response {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export const PRE_AUTH_CODE_LITERAL = 'pre-authorized_code';

export enum WellKnownEndpoints {
  OPENID_CONFIGURATION = '/.well-known/openid-configuration',
  OAUTH_AS = '/.well-known/oauth-authorization-server',
  OPENID4VCI_ISSUER = '/.well-known/openid-credential-issuer',
}

export interface EndpointMetadata {
  issuer: string;
  token_endpoint: string;
  credential_endpoint: string;
  authorization_endpoint?: string;
  pushed_authorization_request_endpoint?: string;
  require_pushed_authorization_endpoint?: boolean;
  openid4vci_metadata?: OpenID4VCIServerMetadata;
}
