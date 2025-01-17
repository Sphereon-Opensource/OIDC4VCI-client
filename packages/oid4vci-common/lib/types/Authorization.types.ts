import { CreateDPoPClientOpts } from '@sphereon/oid4vc-common';

import { Alg, CredentialOfferPayload, ProofOfPossessionCallbacks, UniformCredentialOffer } from './CredentialIssuance.types';
import {
  ErrorResponse,
  IssuerCredentialSubject,
  JsonLdIssuerCredentialDefinition,
  OID4VCICredentialFormat,
  PRE_AUTH_CODE_LITERAL,
  TxCode,
} from './Generic.types';
import { EndpointMetadata } from './ServerMetadata';

export interface CommonAuthorizationRequest {
  /**
   * REQUIRED.  Value MUST be set to "code". for Authorization Code Grant
   */
  response_type: ResponseType.AUTH_CODE;
  /**
   * The authorization server issues the registered client a client
   *    identifier -- a unique string representing the registration
   *    information provided by the client.
   */
  client_id: string;
  /**
   * If the "code_challenge_method" from Section 4.3 was "S256", the
   *    received "code_verifier" is hashed by SHA-256, base64url-encoded, and
   *    then compared to the "code_challenge", i.e.:
   *    BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
   *
   * If the "code_challenge_method" from Section 4.3 was "plain", they are
   *    compared directly, i.e.:
   *    code_verifier == code_challenge.
   */
  code_challenge: string;
  /**
   * value must be set either to "S256" or a value defined by a cryptographically secure
   */
  code_challenge_method: CodeChallengeMethod;
  /**
   * The redirection endpoint URI MUST be an absolute URI as defined by: absolute-URI  = scheme ":" hier-part [ "?" query ]
   */
  redirect_uri: string;
  /**
   * The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings.
   */
  scope?: string;
  /**
   * There are two possible ways to request issuance of a specific Credential type in an Authorization Request.
   * One way is to use of the authorization_details request parameter as defined in [I-D.ietf-oauth-rar]
   * with one or more authorization details objects of type openid_credential Section 5.1.1.
   * (The other is through the use of scopes as defined in Section 5.1.2.)
   */
  authorization_details?: AuthorizationDetails[] | AuthorizationDetails;
  /**
   * OPTIONAL. JSON string containing the Wallet's OpenID Connect issuer URL. The Credential Issuer will use the discovery process as defined in
   * [SIOPv2] to determine the Wallet's capabilities and endpoints. RECOMMENDED in Dynamic Credential Request.
   */
  wallet_issuer?: string;
  /**
   * OPTIONAL. JSON string containing an opaque user hint the Wallet MAY use in subsequent callbacks to optimize the user's experience.
   * RECOMMENDED in Dynamic Credential Request.
   */
  user_hint?: string;
  /**
   * OPTIONAL. String value identifying a certain processing context at the Credential Issuer. A value for this parameter is typically passed in
   * an issuance initation request from the Credential Issuer to the Wallet (see (Section 4.1). This request parameter is used to pass the
   * issuer_state value back to the Credential Issuer.
   */
  issuer_state?: string;
}

// https://www.ietf.org/archive/id/draft-parecki-oauth-first-party-apps-02.html#name-authorization-challenge-req
export interface CommonAuthorizationChallengeRequest {
  /**
   * REQUIRED if the client is not authenticating with the authorization server and if no auth_session is included..
   */
  client_id?: string;
  /**
   * OPTIONAL. String value identifying a certain processing context at the Credential Issuer. A value for this parameter is typically passed in
   * an issuance initation request from the Credential Issuer to the Wallet. This request parameter is used to pass the
   * issuer_state value back to the Credential Issuer.
   */
  issuer_state?: string
  /**
   * The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings.
   */
  scope?: string; // TODO what we do with this
  /**
   * OPTIONAL. A random string or a JWE. The auth session allows the authorization server to associate subsequent
   * requests by this client with an ongoing authorization request sequence. The client MUST include the
   * auth_session in follow-up requests to the authorization challenge endpoint if it receives one along with
   * the error response.
   */
  auth_session?: string
  /**
   * OPTIONAL. If the "code_challenge_method" from Section 4.3 was "S256", the
   *    received "code_verifier" is hashed by SHA-256, base64url-encoded, and
   *    then compared to the "code_challenge", i.e.:
   *    BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
   *
   * If the "code_challenge_method" from Section 4.3 was "plain", they are
   *    compared directly, i.e.:
   *    code_verifier == code_challenge.
   */
  code_challenge?: string; // TODO what we do with this
  /**
   * OPTIONAL. value must be set either to "S256" or a value defined by a cryptographically secure
   */
  code_challenge_method?: CodeChallengeMethod; // TODO what we do with this
  /**
   * OPTIONAL. String containing information about the session when credential presentation is happening during issuance of another
   * credential. The content of this parameter is opaque to the wallet. When this parameter is present the Wallet MUST use this parameter in
   * the subsequent Authorization Challenge Request. This allows the Issuer to determine which it can be used by to prevent session
   * fixation attacks. The Response URI MAY return this parameter in response to successful Authorization Responses or for Error
   * Responses.
   */
  presentation_during_issuance_session?: string;
}

export interface AuthorizationChallengeRequestOpts {
  clientId?: string;
  issuerState?: string
  authSession?: string
  scope?: string
  codeChallenge?: string
  codeChallengeMethod?: CodeChallengeMethod
  presentationDuringIssuanceSession?: string;
  metadata?: EndpointMetadata;
  credentialIssuer?: string;
}

// https://www.ietf.org/archive/id/draft-parecki-oauth-first-party-apps-02.html#name-error-response
export interface AuthorizationChallengeErrorResponse {
  /**
   * A single ASCII error code of type AuthorizationChallengeError.
   */
  error: AuthorizationChallengeError
  /**
   * OPTIONAL. OPTIONAL. Human-readable ASCII text providing additional information, used
   * to assist the client developer in understanding the error that occurred. Values for the error_description
   * parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.
   */
  error_description?: string
  /**
   * OPTIONAL. A URI identifying a human-readable web page with information about the error, used
   * to provide the client developer with additional information about the error. Values for the error_uri
   * parameter MUST conform to the URI-reference syntax and thus MUST NOT include characters outside the
   * set %x21 / %x23-5B / %x5D-7E.
   */
  error_uri?: string
  /**
   * OPTIONAL. A random string or a JWE. The auth session allows the authorization server to associate subsequent
   * requests by this client with an ongoing authorization request sequence. The client MUST include the
   * auth_session in follow-up requests to the authorization challenge endpoint if it receives one along with
   * the error response.
   */
  auth_session?: string
  /**
   * OPTIONAL. The request URI corresponding to the authorization request posted. This URI is a single-use reference
   * to the respective request data in the subsequent authorization request.
   */
  request_uri?: string
  /**
   * OPTIONAL. A JSON number that represents the lifetime of the request URI in seconds as a positive integer.
   */
  expires_in?: number
  /**
   * String containing the OID4VP request URI. The Wallet will use this URI to start the OID4VP flow.
   */
  presentation?: string
}

// https://www.ietf.org/archive/id/draft-parecki-oauth-first-party-apps-02.html#name-authorization-challenge-res
export interface AuthorizationChallengeCodeResponse {
  /**
   * The authorization code issued by the authorization server.
   */
  authorization_code: string
}

// https://www.ietf.org/archive/id/draft-parecki-oauth-first-party-apps-02.html#name-error-response
export enum AuthorizationChallengeError {
  invalid_request = 'invalid_request',
  invalid_client = 'invalid_client',
  unauthorized_client = 'unauthorized_client',
  invalid_session = 'invalid_session',
  invalid_scope = 'invalid_scope',
  insufficient_authorization = 'insufficient_authorization',
  redirect_to_web = 'redirect_to_web',
}

/**
 * string type added for conformity with our previous code in the client
 */
export type AuthorizationDetails =
  | (CommonAuthorizationDetails &
      (AuthorizationDetailsJwtVcJson | AuthorizationDetailsJwtVcJsonLdAndLdpVc | AuthorizationDetailsSdJwtVc | AuthorizationDetailsMsoMdoc))
  | string;

export type AuthorizationRequest =
  | AuthorizationRequestJwtVcJson
  | AuthorizationRequestJwtVcJsonLdAndLdpVc
  | AuthorizationRequestSdJwtVc
  | AuthorizationRequestMsoMdoc;

export interface AuthorizationRequestJwtVcJson extends CommonAuthorizationRequest {
  authorization_details?: AuthorizationDetailsJwtVcJson[];
}

export interface AuthorizationRequestJwtVcJsonLdAndLdpVc extends CommonAuthorizationRequest {
  authorization_details?: AuthorizationDetailsJwtVcJsonLdAndLdpVc[];
}

export interface AuthorizationRequestSdJwtVc extends CommonAuthorizationRequest {
  authorization_details?: AuthorizationDetailsSdJwtVc[];
}

export interface AuthorizationRequestMsoMdoc extends CommonAuthorizationRequest {
  authorization_details?: AuthorizationDetailsMsoMdoc[];
}

/*
export interface AuthDetails {
  type: 'openid_credential' | string;
  locations?: string | string[];
  format: CredentialFormat | CredentialFormat[];

  [s: string]: unknown;
}
*/

export interface CommonAuthorizationDetails {
  /**
   * REQUIRED. JSON string that determines the authorization details type.
   * MUST be set to openid_credential for the purpose of this specification.
   */
  type: 'openid_credential' | string;

  /**
   *  REQUIRED when format parameter is not present. String specifying a unique identifier of the Credential being described in the credential_configurations_supported map in the Credential Issuer Metadata as defined in Section 11.2.3. The referenced object in the credential_configurations_supported map conveys the details, such as the format, for issuance of the requested Credential. This specification defines Credential Format specific Issuer Metadata in Appendix A. It MUST NOT be present if format parameter is present.
   */
  credential_configuration_id?: string; // FIXME maybe split up and make this & format required again

  /**
   * REQUIRED. JSON string representing the format in which the Credential is requested to be issued.
   * This Credential format identifier determines further claims in the authorization details object
   * specifically used to identify the Credential type to be issued. This specification defines
   * Credential Format Profiles in Appendix E.
   */
  format?: OID4VCICredentialFormat;
  /**
   * If the Credential Issuer metadata contains an authorization_server parameter,
   * the authorization detail's locations common data field MUST be set to the Credential Issuer Identifier value.
   */
  locations?: string[];

  /* // eslint-disable-next-line @typescript-eslint/no-explicit-any
  // [key: string]: any;*/
}

export interface AuthorizationDetailsJwtVcJson extends CommonAuthorizationDetails {
  format: 'jwt_vc_json' | 'jwt_vc'; // jwt_vc added for backward compat

  /**
   * A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential.
   * The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the
   * verifiable credential to be issued. This object indicates the claims the Wallet would like to turn up in the
   * credential to be issued.
   */
  credentialSubject?: IssuerCredentialSubject;

  types: string[]; // This claim contains the type values the Wallet requests authorization for at the issuer.
}

export interface AuthorizationDetailsJwtVcJsonLdAndLdpVc extends CommonAuthorizationDetails {
  format: 'ldp_vc' | 'jwt_vc_json-ld';

  /**
   * REQUIRED. JSON object containing (and isolating) the detailed description of the credential type.
   * This object MUST be processed using full JSON-LD processing. It consists of the following sub-claims:
   *   - @context: REQUIRED. JSON array as defined in Appendix E.1.3.2
   *   - types: REQUIRED. JSON array as defined in Appendix E.1.3.2.
   *            This claim contains the type values the Wallet shall request in the subsequent Credential Request
   */
  credential_definition: JsonLdIssuerCredentialDefinition;
}

export interface AuthorizationDetailsSdJwtVc extends CommonAuthorizationDetails {
  format: 'vc+sd-jwt';

  vct: string;
  claims?: IssuerCredentialSubject;
}

export interface AuthorizationDetailsMsoMdoc extends CommonAuthorizationDetails {
  format: 'mso_mdoc';

  doctype: string;
  claims?: IssuerCredentialSubject;
}

export enum GrantTypes {
  AUTHORIZATION_CODE = 'authorization_code',
  PRE_AUTHORIZED_CODE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  PASSWORD = 'password',
}

export enum Encoding {
  FORM_URL_ENCODED = 'application/x-www-form-urlencoded',
  UTF_8 = 'UTF-8',
}

export enum ResponseType {
  AUTH_CODE = 'code',
}

export enum CodeChallengeMethod {
  plain = 'plain',
  S256 = 'S256',
}

export interface AuthorizationServerOpts {
  allowInsecureEndpoints?: boolean;
  as?: string; // If not provided the issuer hostname will be used!
  tokenEndpoint?: string; // Allows to override the default '/token' endpoint
  clientOpts?: AuthorizationServerClientOpts;
}

export type AuthorizationServerClientOpts = {
  clientId: string;
  clientAssertionType?: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
  kid?: string;
  alg?: Alg;
  signCallbacks?: ProofOfPossessionCallbacks<never>;
};

export interface IssuerOpts {
  issuer: string;
  tokenEndpoint?: string;
  fetchMetadata?: boolean;
}

export interface AccessTokenFromAuthorizationResponseOpts extends AccessTokenRequestOpts {
  authorizationResponse: AuthorizationResponse;
}

export type TxCodeAndPinRequired = { isPinRequired?: boolean; txCode?: TxCode };

export interface AccessTokenRequestOpts {
  credentialOffer?: UniformCredentialOffer;
  credentialIssuer?: string;
  asOpts?: AuthorizationServerOpts;
  metadata?: EndpointMetadata;
  codeVerifier?: string; // only required for authorization flow
  code?: string; // only required for authorization flow
  redirectUri?: string; // only required for authorization flow
  pin?: string; // Pin-number. Only used when required
  pinMetadata?: TxCodeAndPinRequired; // OPTIONAL. String value containing a Transaction Code. This value MUST be present if a tx_code object was present in the Credential Offer (including if the object was empty). This parameter MUST only be used if the grant_type is urn:ietf:params:oauth:grant-type:pre-authorized_code.
  // if the CreateDPoPOpts are provided, a dPoP will be created using the provided callback,
  // if the authorization server indicates that it supports dPoP via the dpop_signing_alg_values_supported parameter.
  createDPoPOpts?: CreateDPoPClientOpts;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  additionalParams?: Record<string, any>;
}

/*export interface AuthorizationRequestOpts {
  clientId: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  authorizationDetails?: AuthorizationDetails[];
  redirectUri: string;
  scope?: string;
}*/

/**
 * Determinse whether PAR should be used when supported
 *
 * REQUIRE: Require PAR, if AS does not support it throw an error
 * AUTO: Use PAR is the AS supports it, otherwise construct a reqular URI,
 * NEVER: Do not use PAR even if the AS supports it (not recommended)
 */
export enum PARMode {
  REQUIRE,
  AUTO,
  NEVER,
}

/**
 * Optional options to provide PKCE params like code verifier and challenge yourself, or to disable PKCE altogether. If not provide PKCE will still be used! If individual params are not provide, they will be generated/calculated
 */
export interface PKCEOpts {
  /**
   * PKCE is enabled by default even if you do not provide these options. Set this to true to disable PKCE
   */
  disabled?: boolean;

  /**
   * Provide a code_challenge, otherwise it will be calculated using the code_verifier and method
   */
  codeChallenge?: string;

  /**
   * The code_challenge_method, should always by S256
   */
  codeChallengeMethod?: CodeChallengeMethod;

  /**
   * Provide a code_verifier, otherwise it will be generated
   */
  codeVerifier?: string;
}

export enum CreateRequestObjectMode {
  NONE,
  REQUEST_OBJECT,
  REQUEST_URI,
}

export type RequestObjectOpts = {
  requestObjectMode?: CreateRequestObjectMode;
  signCallbacks?: ProofOfPossessionCallbacks<never>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  clientMetadata?: Record<string, any>; // TODO: Merge SIOP/OID4VP
  iss?: string;
  jwksUri?: string;
  kid?: string;
};

export interface AuthorizationRequestOpts {
  clientId?: string;
  pkce?: PKCEOpts;
  parMode?: PARMode;
  authorizationDetails?: AuthorizationDetails | AuthorizationDetails[];
  redirectUri?: string;
  scope?: string;
  requestObjectOpts?: RequestObjectOpts;
  holderPreferredAuthzFlowTypeOrder?: AuthzFlowType[];
}

export interface AuthorizationResponse {
  code: string;
  scope?: string;
  state?: string;
}

export interface AuthorizationGrantResponse extends AuthorizationResponse {
  grant_type: string;
}

export interface AccessTokenRequest {
  client_id?: string;
  code?: string;
  code_verifier?: string;
  grant_type: GrantTypes;
  'pre-authorized_code': string;
  redirect_uri?: string;
  scope?: string;
  user_pin?: string; //this is for v11, not required in v13 anymore
  tx_code?: string; //draft 13
  [s: string]: unknown;
}

export interface OpenIDResponse<T, P = never> {
  origResponse: Response;
  successBody?: T;
  errorBody?: ErrorResponse;
  params?: P;
}

export interface DPoPResponseParams {
  dpop?: { dpopNonce: string };
}

export interface AccessTokenResponse {
  access_token: string;
  scope?: string;
  token_type?: string;
  expires_in?: number; // in seconds
  c_nonce?: string;
  c_nonce_expires_in?: number; // in seconds
  authorization_pending?: boolean;
  interval?: number; // in seconds
}

export enum AuthzFlowType {
  AUTHORIZATION_CODE_FLOW = 'Authorization Code Flow',
  PRE_AUTHORIZED_CODE_FLOW = 'Pre-Authorized Code Flow',
}

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace AuthzFlowType {
  export function valueOf(request: CredentialOfferPayload): AuthzFlowType {
    if (PRE_AUTH_CODE_LITERAL in request) {
      return AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW;
    }
    return AuthzFlowType.AUTHORIZATION_CODE_FLOW;
  }
}

export interface PushedAuthorizationResponse {
  request_uri: string;
  expires_in: number;
}
