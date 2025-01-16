// noinspection JSUnusedGlobalSymbols
import { JarmClientMetadata } from '@sphereon/jarm'
import {
  DynamicRegistrationClientMetadata,
  JWKS,
  SigningAlgo
} from '@sphereon/oid4vc-common'
import { Format, PresentationDefinitionV1, PresentationDefinitionV2 } from '@sphereon/pex-models'
import {
  AdditionalClaims,
  CompactSdJwtVc,
  IPresentation,
  IVerifiablePresentation,
  MdocOid4vpMdocVpToken,
  PresentationSubmission,
  W3CVerifiableCredential,
  W3CVerifiablePresentation,
  WrappedVerifiablePresentation
} from '@sphereon/ssi-types'
import { DcqlQuery } from 'dcql'

import {
  AuthorizationRequest,
  CreateAuthorizationRequestOpts,
  PropertyTargets,
  VerifyAuthorizationRequestOpts
} from '../authorization-request'
import {
  AuthorizationResponse,
  AuthorizationResponseOpts,
  PresentationDefinitionWithLocation,
  PresentationVerificationCallback,
  VerifyAuthorizationResponseOpts
} from '../authorization-response'
import { JwksMetadataParams } from '../helpers'
import { RequestObject, RequestObjectOpts } from '../request-object'
import { IRPSessionManager } from '../rp'

import { JWTPayload, VerifiedJWT } from './index'

export const DEFAULT_EXPIRATION_TIME = 10 * 60

// https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
// request and request_uri parameters MUST NOT be included in Request Objects.
export interface RequestObjectPayload extends RequestCommonPayload, JWTPayload {
  scope: string // REQUIRED. As specified in Section 3.1.2 of [OpenID.Core].
  response_type: ResponseType | string // REQUIRED. Constant string value id_token.
  client_id: string // REQUIRED. RP's identifier at the Self-Issued OP.
  client_id_scheme?: ClientIdScheme // The client_id_scheme enables deployments of this specification to use different mechanisms to obtain and validate metadata of the Verifier beyond the scope of [RFC6749]. The term client_id_scheme is used since the Verifier is acting as an OAuth 2.0 Client.
  entity_id?: string // OPTIONAL for OIDF
  client_metadata: ClientMetadataOpts
  redirect_uri?: string // REQUIRED before OID4VP v18, now optional because of response_uri. URI to which the Self-Issued OP Response will be sent
  response_uri?: string // New since OID4VP18 OPTIONAL. The Response URI to which the Wallet MUST send the Authorization Response using an HTTPS POST request as defined by the Response Mode direct_post. The Response URI receives all Authorization Response parameters as defined by the respective Response Type. When the response_uri parameter is present, the redirect_uri Authorization Request parameter MUST NOT be present. If the redirect_uri Authorization Request parameter is present when the Response Mode is direct_post, the Wallet MUST return an invalid_request Authorization Response error.
  nonce: string
  state: string
}

export type RequestObjectJwt = string

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8

export interface AuthorizationRequestCommonPayload extends RequestCommonPayload, JWTPayload {
  request?: string // OPTIONAL. Request Object value, as specified in Section 6.1 of [OpenID.Core]. The Request Object MAY be encrypted to the Self-Issued OP by the RP. In this case, the sub (subject) of a previously issued ID Token for this RP MUST be sent as the kid (Key ID) of the JWE.
  request_uri?: string // OPTIONAL. URL where Request Object value can be retrieved from, as specified in Section 6.2 of [OpenID.Core].
}

export interface RequestCommonPayload extends JWTPayload {
  scope?: string // REQUIRED. As specified in Section 3.1.2 of [OpenID.Core].
  response_type?: ResponseType | string // REQUIRED. Constant string value id_token.
  client_id?: string // REQUIRED. RP's identifier at the Self-Issued OP.
  redirect_uri?: string // REQUIRED. URI to which the Self-Issued OP Response will be sent

  id_token_hint?: string // OPTIONAL. As specified in Section 3.1.2 of [OpenID.Core]. If the ID Token is encrypted for the Self-Issued OP, the sub (subject) of the signed ID Token MUST be sent as the kid (Key ID) of the JWE.
  // claims?: ClaimPayloadCommon; // OPTIONAL. As specified in Section 5.5 of [OpenID.Core]
  nonce?: string
  state?: string
  response_mode?: ResponseMode // This specification introduces a new response mode post in accordance with [OAuth.Responses]. This response mode is used to request the Self-Issued OP to deliver the result of the authentication process to a certain endpoint using the HTTP POST method. The additional parameter response_mode is used to carry this value.
}

export interface AuthorizationRequestPayloadVID1 extends AuthorizationRequestCommonPayload, RequestRegistrationPayloadProperties {
  claims?: ClaimPayloadVID1
}

export interface AuthorizationRequestPayloadVD11
  extends AuthorizationRequestCommonPayload,
    RequestClientMetadataPayloadProperties,
    RequestIdTokenPayloadProperties {
  claims?: ClaimPayloadCommon // OPTIONAL. As specified in Section 5.5 of [OpenID.Core]
  presentation_definition?: PresentationDefinitionV1 | PresentationDefinitionV2 | PresentationDefinitionV1[] | PresentationDefinitionV2[]
  presentation_definition_uri?: string
}

export interface AuthorizationRequestPayloadVD12OID4VPD18
  extends AuthorizationRequestCommonPayload,
    RequestClientMetadataPayloadProperties,
    RequestIdTokenPayloadProperties {
  claims?: ClaimPayloadCommon // OPTIONAL. As specified in Section 5.5 of [OpenID.Core]
  presentation_definition?: PresentationDefinitionV1 | PresentationDefinitionV2 | PresentationDefinitionV1[] | PresentationDefinitionV2[]
  presentation_definition_uri?: string
  client_id_scheme?: ClientIdSchemeOID4VPD18
  response_uri?: string // New since OID4VP18 OPTIONAL. The Response URI to which the Wallet MUST send the Authorization Response using an HTTPS POST request as defined by the Response Mode direct_post. The Response URI receives all Authorization Response parameters as defined by the respective Response Type. When the response_uri parameter is present, the redirect_uri Authorization Request parameter MUST NOT be present. If the redirect_uri Authorization Request parameter is present when the Response Mode is direct_post, the Wallet MUST return an invalid_request Authorization Response error.
}

export interface AuthorizationRequestPayloadVD12OID4VPD20
  extends AuthorizationRequestCommonPayload,
    RequestClientMetadataPayloadProperties,
    RequestIdTokenPayloadProperties {
  claims?: ClaimPayloadCommon // OPTIONAL. As specified in Section 5.5 of [OpenID.Core]
  presentation_definition?: PresentationDefinitionV1 | PresentationDefinitionV2 | PresentationDefinitionV1[] | PresentationDefinitionV2[]
  presentation_definition_uri?: string
  client_id_scheme?: ClientIdSchemeOID4VPD20
  response_uri?: string // New since OID4VP18 OPTIONAL. The Response URI to which the Wallet MUST send the Authorization Response using an HTTPS POST request as defined by the Response Mode direct_post. The Response URI receives all Authorization Response parameters as defined by the respective Response Type. When the response_uri parameter is present, the redirect_uri Authorization Request parameter MUST NOT be present. If the redirect_uri Authorization Request parameter is present when the Response Mode is direct_post, the Wallet MUST return an invalid_request Authorization Response error.
  dcql_query?: string
}

export type ClientIdSchemeOID4VPD18 = 'pre-registered' | 'redirect_uri' | 'entity_id' | 'did'
export type ClientIdSchemeOID4VPD20 = ClientIdSchemeOID4VPD18 | 'x509_san_dns' | 'x509_san_uri' | 'entity_id' | 'verifier_attestation'
export type ClientIdScheme = ClientIdSchemeOID4VPD18 | ClientIdSchemeOID4VPD20

// https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html#section-10
export type AuthorizationRequestPayload =
  | AuthorizationRequestPayloadVID1
  | AuthorizationRequestPayloadVD11
  | AuthorizationRequestPayloadVD12OID4VPD18
  | AuthorizationRequestPayloadVD12OID4VPD20

export type JWTVcPresentationProfileAuthenticationRequestPayload = RequestIdTokenPayloadProperties

export interface RequestIdTokenPayloadProperties {
  id_token_type?: string // OPTIONAL. Space-separated string that specifies the types of ID token the RP wants to obtain, with the values appearing in order of preference. The allowed individual values are subject_signed and attester_signed (see Section 8.2). The default value is attester_signed. The RP determines the type if ID token returned based on the comparison of the iss and sub claims values (see(see Section 12.1). In order to preserve compatibility with existing OpenID Connect deployments, the OP MAY return an ID token that does not fulfill the requirements as expressed in this parameter. So the RP SHOULD be prepared to reliably handle such an outcome.
}

export interface RequestClientMetadataPayloadProperties {
  client_metadata?: RPRegistrationMetadataPayload // OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
  client_metadata_uri?: string // OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
}

export interface RequestRegistrationPayloadProperties {
  registration?: RPRegistrationMetadataPayload //This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in Section 2.2.1.
  registration_uri?: string // OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in 2.2.1.
}

export type ResponseURIType = 'response_uri' | 'redirect_uri'

export interface VerifiedAuthorizationRequest extends Partial<VerifiedJWT> {
  responseURIType: ResponseURIType
  responseURI?: string
  clientIdScheme?: string
  correlationId: string
  authorizationRequest: AuthorizationRequest
  authorizationRequestPayload: AuthorizationRequestPayload
  requestObject?: RequestObject // The Request object
  registrationMetadataPayload: RPRegistrationMetadataPayload
  presentationDefinitions?: PresentationDefinitionWithLocation[] // The optional presentation definition objects that the RP requests
  dcqlQuery?: DcqlQuery
  verifyOpts: VerifyAuthorizationRequestOpts // The verification options for the authentication request
  versions: SupportedVersion[]
}

export type IDTokenJwt = string

export interface IDTokenPayload extends JWTPayload {
  iss?: ResponseIss.SELF_ISSUED_V2 | string
  sub?: string // did (or thumbprint of sub_jwk key when type is jkt)
  aud?: string // redirect_uri from request
  iat?: number // Issued at time
  exp?: number // Expiration time
  auth_time?: number
  nonce?: string
  _vp_token?: {
    /*
      This profile currently supports including only a single VP in the VP Token.
      In such cases, as defined in section 5.2 of OpenID4VP ID1, when the Self-Issued OP returns a single VP in the vp_token,
      VP Token is not an array, and a single VP is passed as a vp_token. In this case, the descriptor map would contain a simple path expression “$”.
      * It's not clear from the ID1 specs how to handle presentation submission in case of multiple VPs
    */
    presentation_submission: PresentationSubmission
  }
}

export type EncodedDcqlQueryVpToken = string

export interface AuthorizationResponsePayload {
  access_token?: string
  token_type?: string
  refresh_token?: string
  expires_in?: number
  state?: string
  id_token?: string
  vp_token?:
    | Array<W3CVerifiablePresentation | CompactSdJwtVc | MdocOid4vpMdocVpToken>
    | W3CVerifiablePresentation
    | CompactSdJwtVc
    | MdocOid4vpMdocVpToken
    | EncodedDcqlQueryVpToken
  presentation_submission?: PresentationSubmission
  verifiedData?: IPresentation | AdditionalClaims
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export interface IdTokenClaimPayload {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export interface VpTokenClaimPayload {
  presentation_definition?: PresentationDefinitionV1 | PresentationDefinitionV2
  presentation_definition_uri?: string
  dcql_query?: string
}

export interface ClaimPayloadCommon {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export interface ClaimPayloadVID1 extends ClaimPayloadCommon {
  id_token?: IdTokenClaimPayload
  vp_token?: VpTokenClaimPayload
}

/**
 * A wrapper for verifiablePresentation
 *
 */
export interface VerifiablePresentationWithFormat {
  format: VerifiablePresentationTypeFormat
  presentation: W3CVerifiablePresentation
}

export interface RequestStateInfo {
  client_id: string // RP ID

  // sub: string
  nonce?: string
  state?: string
  iat?: number
}

interface DiscoveryMetadataCommonOpts {
  //TODO add the check: Mandatory if PassBy.Value
  authorizationEndpoint?: Schema | string
  // this is a confusion point. In the interop profile it mentions "https://self-issued.me/v2/openid-vc", but in the SIOPv2 it's mentioning "https://self-issued.me/v2"
  // @Niels also created an issue here: https://github.com/decentralized-identity/jwt-vc-presentation-profile/issues/63 so we can keep an eye on this for clarification
  //TODO add the check: Mandatory if PassBy.Value
  issuer?: ResponseIss | string
  //TODO add the check: Mandatory if PassBy.Value
  responseTypesSupported?: ResponseType[] | ResponseType
  scopesSupported?: Scope[] | Scope
  subjectTypesSupported?: SubjectType[] | SubjectType
  idTokenSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo
  requestObjectSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo
  //TODO add the check: Mandatory if PassBy.Value
  subject_syntax_types_supported?: string[]
  tokenEndpoint?: string // from openid connect discovery 1_0
  userinfoEndpoint?: string // from openid connect discovery 1_0
  jwksUri?: string // from openid connect discovery 1_0
  registrationEndpoint?: string // from openid connect discovery 1_0
  responseModesSupported?: ResponseMode[] | ResponseMode // from openid connect discovery 1_0
  grantTypesSupported?: GrantType[] | GrantType // from openid connect discovery 1_0
  acrValuesSupported?: AuthenticationContextReferences[] | AuthenticationContextReferences // from openid connect discovery 1_0
  idTokenEncryptionAlgValuesSupported?: SigningAlgo[] | SigningAlgo // from openid connect discovery 1_0
  idTokenEncryptionEncValuesSupported?: string[] | string // from openid connect discovery 1_0
  userinfoSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo // from openid connect discovery 1_0
  userinfoEncryptionAlgValuesSupported?: SigningAlgo[] | SigningAlgo // from openid connect discovery 1_0
  userinfoEncryptionEncValuesSupported?: string[] | string // from openid connect discovery 1_0
  requestObjectEncryptionAlgValuesSupported?: SigningAlgo[] | SigningAlgo // from openid connect discovery 1_0
  requestObjectEncryptionEncValuesSupported?: string[] | string // from openid connect discovery 1_0
  tokenEndpointAuthMethodsSupported?: TokenEndpointAuthMethod[] | TokenEndpointAuthMethod // from openid connect discovery 1_0
  tokenEndpointAuthSigningAlgValuesSupported?: SigningAlgo[] | SigningAlgo // from openid connect discovery 1_0
  displayValuesSupported?: string[] | string // from openid connect discovery 1_0
  claimTypesSupported?: ClaimType[] | ClaimType // from openid connect discovery 1_0
  claimsSupported?: string[] | string // recommended, from openid connect discovery 1_0
  serviceDocumentation?: string // from openid connect discovery 1_0
  claimsLocalesSupported?: string[] | string // from openid connect discovery 1_0
  uiLocalesSupported?: string[] | string // from openid connect discovery 1_0
  claimsParameterSupported?: boolean // from openid connect discovery 1_0
  requestParameterSupported?: boolean // from openid connect discovery 1_0
  requestUriParameterSupported?: boolean // from openid connect discovery 1_0
  requireRequestUriRegistration?: boolean // from openid connect discovery 1_0
  opPolicyUri?: string // from openid connect discovery 1_0
  opTosUri?: string // from openid connect discovery 1_0

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

//same for jwt_vc
interface DiscoveryMetadataOptsVID1 extends DiscoveryMetadataCommonOpts {
  client_id?: string // from oidc4vp
  redirectUris?: string[] | string // from oidc4vp
  clientName?: string // from oidc4vp
  clientUri?: string // from oidc4vp
  scope?: string // from oidc4vp
  contacts?: string[] // from oidc4vp
  tosUri?: string // from oidc4vp
  policyUri?: string // from oidc4vp
  jwks?: JWKS // from oidc4vp
  softwareId?: string // from oidc4vp
  softwareVersion?: string // from oidc4vp
  tokenEndpointAuthMethod?: string // from oidc4vp
  applicationType?: string // from oidc4vp
  responseTypes?: string // from oidc4vp, also name suggests array
  grantTypes?: string // from oidc4vp, also name suggests array
  //TODO add the check: Mandatory if PassBy.Value
  vpFormats?: Format // from oidc4vp
}

interface JWT_VCDiscoveryMetadataOpts extends DiscoveryMetadataOptsVID1 {
  logo_uri?: string
  clientPurpose?: string
}

interface DiscoveryMetadataOptsVD11 extends DiscoveryMetadataCommonOpts {
  idTokenTypesSupported?: IdTokenType[] | IdTokenType
  vpFormatsSupported?: Format // from oidc4vp
}

// https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-8.2
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
interface DiscoveryMetadataCommonPayload {
  authorization_endpoint?: Schema | string
  issuer?: ResponseIss | string
  response_types_supported?: ResponseType[] | ResponseType
  scopes_supported?: Scope[] | Scope
  subject_types_supported?: SubjectType[] | SubjectType
  id_token_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo
  request_object_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo
  subject_syntax_types_supported?: string[]
  token_endpoint?: string
  userinfo_endpoint?: string
  jwks_uri?: string
  // marked as required by https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  registration_endpoint?: string
  response_modes_supported?: ResponseMode[] | ResponseMode
  grant_types_supported?: GrantType[] | GrantType
  acr_values_supported?: AuthenticationContextReferences[] | AuthenticationContextReferences
  id_token_encryption_alg_values_supported?: SigningAlgo[] | SigningAlgo
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
   */
  //TODO: maybe add an enum for this with: A256GCM, A128CBC-HS256, ...
  id_token_encryption_enc_values_supported?: string[] | string
  userinfo_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo
  userinfo_encryption_alg_values_supported?: SigningAlgo[] | SigningAlgo
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
   */
  userinfo_encryption_enc_values_supported?: string[] | string
  request_object_encryption_alg_values_supported?: SigningAlgo[] | SigningAlgo
  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by reference.
   */
  request_object_encryption_enc_values_supported?: string[] | string
  token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[] | TokenEndpointAuthMethod
  token_endpoint_auth_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo
  /**
   * OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
   */
  display_values_supported?: unknown[] | unknown
  /**
   * OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
   */
  claim_types_supported?: ClaimType[] | ClaimType
  /**
   * RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
   */
  claims_supported?: string[] | string
  service_documentation?: string
  claims_locales_supported?: string[] | string
  ui_locales_supported?: string[] | string
  claims_parameter_supported?: boolean
  request_parameter_supported?: boolean
  request_uri_parameter_supported?: boolean
  require_request_uri_registration?: boolean
  op_policy_uri?: string
  op_tos_uri?: string

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

interface DiscoveryMetadataPayloadVID1 extends DynamicRegistrationClientMetadata, DiscoveryMetadataCommonPayload {
  client_id?: string
  application_type?: string
  vp_formats?: Format
}

interface JWT_VCDiscoveryMetadataPayload extends DiscoveryMetadataPayloadVID1 {
  client_purpose?: string
}

interface DiscoveryMetadataPayloadVD11 extends DiscoveryMetadataCommonPayload {
  id_token_types_supported?: IdTokenType[] | IdTokenType
  vp_formats_supported?: Format // from oidc4vp
}

export type DiscoveryMetadataPayload = DiscoveryMetadataPayloadVID1 | JWT_VCDiscoveryMetadataPayload | DiscoveryMetadataPayloadVD11

export type DiscoveryMetadataOpts = (JWT_VCDiscoveryMetadataOpts | DiscoveryMetadataOptsVID1 | DiscoveryMetadataOptsVD11) &
  DiscoveryMetadataCommonOpts

export type ClientMetadataOpts = RPRegistrationMetadataOpts & ClientMetadataProperties & JarmClientMetadata & JwksMetadataParams

export type ResponseRegistrationOpts = DiscoveryMetadataOpts & ClientMetadataProperties

export type RPRegistrationMetadataOpts = Partial<
  Pick<
    DiscoveryMetadataOpts,
    | 'client_id'
    | 'idTokenSigningAlgValuesSupported'
    | 'requestObjectSigningAlgValuesSupported'
    | 'responseTypesSupported'
    | 'scopesSupported'
    | 'subjectTypesSupported'
    | 'subject_syntax_types_supported'
    | 'vpFormatsSupported'
    | 'clientName'
    | 'logo_uri'
    | 'tos_uri'
    | 'clientPurpose'
  >
> & {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export type RPRegistrationMetadataPayload = Pick<
  DiscoveryMetadataPayload,
  | 'client_id'
  | 'id_token_signing_alg_values_supported'
  | 'request_object_signing_alg_values_supported'
  | 'response_types_supported'
  | 'scopes_supported'
  | 'subject_types_supported'
  | 'subject_syntax_types_supported'
  | 'vp_formats'
  | 'client_name'
  | 'logo_uri'
  | 'client_purpose'
> & {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export interface CommonSupportedMetadata {
  subject_syntax_types_supported?: string[]
  vp_formats: Format
}

export interface ObjectBy {
  passBy: PassBy
  reference_uri?: string // for pass by reference

  targets?: PropertyTargets
}

export enum AuthenticationContextReferences {
  PHR = 'phr',
  PHRH = 'phrh',
}

export enum ClaimType {
  NORMAL = 'normal',
  AGGREGATED = 'aggregated',
  DISTRIBUTED = 'distributed',
}

export enum IdTokenType {
  SUBJECT_SIGNED = 'subject_signed',
  ATTESTER_SIGNED = 'attester_signed',
}

export interface ClientMetadataProperties extends ObjectBy {
  id_token_encrypted_response_alg?: EncKeyAlgorithm
  id_token_encrypted_response_enc?: EncSymmetricAlgorithmCode
}

export enum VerifiablePresentationTypeFormat {
  JWT_VP = 'jwt_vp',
  LDP_VP = 'ldp_vp',
  SD_JWT_VC = 'vc+sd-jwt',
  MSO_MDOC = 'mso_mdoc',
}

export enum VerifiableCredentialTypeFormat {
  LDP_VC = 'ldp_vc',
  JWT_VC = 'jwt_vc',
  SD_JWT_VC = 'vc+sd-jwt',
  MSO_MDOC = 'mso_mdoc',
}

export enum EncSymmetricAlgorithmCode {
  XC20P = 'XC20P', // default
}

export enum EncKeyAlgorithm {
  ECDH_ES = 'ECDH-ES', // default
}

export enum PassBy {
  NONE = 'NONE',
  REFERENCE = 'REFERENCE',
  VALUE = 'VALUE',
}

export enum ResponseContext {
  RP = 'rp',
  OP = 'op',
}

export interface Verification {
  presentationVerificationCallback?: PresentationVerificationCallback
  revocationOpts?: RevocationOpts
  replayRegistry?: IRPSessionManager
}

export interface ResponseClaims {
  verified_claims?: string
  encryption_key?: JsonWebKey
}

export interface VerifiedIDToken {
  jwt: string
  payload: IDTokenPayload
  verifyOpts: VerifyAuthorizationResponseOpts
}

export interface VerifiedOpenID4VPSubmissionDcql {
  dcqlQuery: DcqlQuery
  presentation: { [credentialQueryId: string]: WrappedVerifiablePresentation }
  nonce?: string
}

export interface VerifiedOpenID4VPSubmission {
  submissionData: PresentationSubmission
  presentationDefinitions: PresentationDefinitionWithLocation[]
  presentations: WrappedVerifiablePresentation[]
  nonce?: string
}

export interface VerifiedAuthorizationResponse {
  correlationId: string

  authorizationResponse: AuthorizationResponse

  oid4vpSubmission?: VerifiedOpenID4VPSubmission
  oid4vpSubmissionDcql?: VerifiedOpenID4VPSubmissionDcql

  nonce?: string
  state: string

  idToken?: VerifiedIDToken
  verifyOpts?: VerifyAuthorizationResponseOpts
}

export enum GrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  IMPLICIT = 'implicit',
}

export enum ResponseMode {
  FRAGMENT = 'fragment',
  FORM_POST = 'form_post',
  POST = 'post', // Used in OID4VP spec <= version 17
  // Defined in openid4vp spec > 17 and replaces POST above
  // See https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post
  DIRECT_POST = 'direct_post',
  QUERY = 'query',

  DIRECT_POST_JWT = 'direct_post.jwt',
  QUERY_JWT = 'query.jwt',
  FRAGMENT_JWT = 'fragment.jwt',
}

export enum ProtocolFlow {
  SAME_DEVICE = 'same_device',
  CROSS_DEVICE = 'cross_device',
}

export interface SignatureResponse {
  jws: string
}

export enum UrlEncodingFormat {
  FORM_URL_ENCODED = 'application/x-www-form-urlencoded',
}

export type SIOPURI = {
  encodedUri: string // The encoded URI
  encodingFormat: UrlEncodingFormat // The encoding format used
}

export interface UriResponse extends SIOPURI {
  responseMode?: ResponseMode // The response mode as passed in during creation
  bodyEncoded?: string // The URI encoded body (JWS)
}

export interface AuthorizationRequestURI extends SIOPURI {
  scheme: string
  requestObjectBy: ObjectBy // The supplied request opts as passed in to the method
  authorizationRequestPayload: AuthorizationRequestPayload // The authorization request payload
  requestObjectJwt?: RequestObjectJwt // The JWT request object
}

export interface ParsedAuthorizationRequestURI extends SIOPURI {
  scheme: string
  requestObjectJwt?: RequestObjectJwt
  authorizationRequestPayload: AuthorizationRequestPayload // The json payload that ends up signed in the JWT
  registration: RPRegistrationMetadataPayload
}

export enum KeyType {
  EC = 'EC',
}

export enum KeyCurve {
  SECP256k1 = 'secp256k1',
  ED25519 = 'ed25519',
}

export enum TokenEndpointAuthMethod {
  CLIENT_SECRET_POST = 'client_secret_post',
  CLIENT_SECRET_BASIC = 'client_secret_basic',
  CLIENT_SECRET_JWT = 'client_secret_jwt',
  PRIVATE_KEY_JWT = 'private_key_jwt',
}

export enum Scope {
  OPENID = 'openid',
  OPENID_DIDAUTHN = 'openid did_authn',
  //added based on the https://openid.net/specs/openid-connect-implicit-1_0.html#SelfIssuedDiscovery
  PROFILE = 'profile',
  EMAIL = 'email',
  ADDRESS = 'address',
  PHONE = 'phone',
}

export enum ResponseType {
  ID_TOKEN = 'id_token',
  VP_TOKEN = 'vp_token',
}

export enum SubjectIdentifierType {
  JKT = 'jkt',
  DID = 'did',
}

export enum SubjectSyntaxTypesSupportedValues {
  DID = 'did',
  JWK_THUMBPRINT = 'urn:ietf:params:oauth:jwk-thumbprint',
}

export enum CredentialFormat {
  JSON_LD = 'w3cvc-jsonld',
  JWT = 'jwt',
}

export enum SubjectType {
  PUBLIC = 'public',
  PAIRWISE = 'pairwise',
}

export enum Schema {
  OPENID = 'openid:',
  OPENID_VC = 'openid-vc:',
}

export enum ResponseIss {
  SELF_ISSUED_V1 = 'https://self-issued.me',
  SELF_ISSUED_V2 = 'https://self-issued.me/v2',
  JWT_VC_PRESENTATION_V1 = 'https://self-issued.me/v2/openid-vc',
}

export enum RequestAud {
  SELF_ISSUED_V2 = 'https://self-issued.me/v2',
}

export const isRequestOpts = (object: CreateAuthorizationRequestOpts | AuthorizationResponseOpts): object is CreateAuthorizationRequestOpts =>
  'requestBy' in object

export const isResponseOpts = (
  object: RequestObjectOpts<RequestCommonPayload> | AuthorizationResponseOpts,
): object is RequestObjectOpts<RequestCommonPayload> => 'did' in object

export const isRequestPayload = (
  object: AuthorizationRequestPayload | RequestObjectPayload | AuthorizationResponsePayload | IDTokenPayload,
): object is AuthorizationRequestPayload => 'response_mode' in object && 'response_type' in object

export const isResponsePayload = (object: RequestObjectPayload | IDTokenPayload): object is IDTokenPayload => 'iss' in object && 'aud' in object

export const isVP = (object: IVerifiablePresentation | IPresentation): object is IVerifiablePresentation => 'presentation' in object
export const isPresentation = (object: IVerifiablePresentation | IPresentation): object is IPresentation => 'presentation_submission' in object

export enum RevocationStatus {
  VALID = 'valid',
  INVALID = 'invalid',
}

export interface IRevocationVerificationStatus {
  status: RevocationStatus
  error?: string
}

export type RevocationVerificationCallback = (
  vc: W3CVerifiableCredential,
  type: VerifiableCredentialTypeFormat,
) => Promise<IRevocationVerificationStatus>

export enum RevocationVerification {
  NEVER = 'never', // We don't want to verify revocation
  IF_PRESENT = 'if_present', // If credentialStatus is present, did-auth-siop will verify revocation. If present and not valid an exception is thrown
  ALWAYS = 'always', // We'll always check the revocation, if not present or not valid, throws an exception
}

export interface RevocationOpts {
  revocationVerification: RevocationVerification
  revocationVerificationCallback?: RevocationVerificationCallback
}

export enum SupportedVersion {
  SIOPv2_ID1 = 70,
  SIOPv2_D11 = 110,
  SIOPv2_D12_OID4VP_D18 = 180,
  SIOPv2_D12_OID4VP_D20 = 200,
  JWT_VC_PRESENTATION_PROFILE_v1 = 71,
}

export interface SIOPResonse<T> {
  origResponse: Response
  successBody?: T
  errorBody?: ErrorResponse
}

export interface ErrorResponse extends Response {
  error: string
  error_description?: string
  error_uri?: string
  state?: string
}

export enum ContentType {
  FORM_URL_ENCODED = 'application/x-www-form-urlencoded',
  UTF_8 = 'UTF-8',
}

export { JarmClientMetadata }
