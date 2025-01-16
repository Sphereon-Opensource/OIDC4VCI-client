import { SigningAlgo } from '@sphereon/oid4vc-common'
import { Hasher } from '@sphereon/ssi-types'

import { DcqlQueryPayloadOpts, PresentationDefinitionPayloadOpts } from '../authorization-response'
import { RequestObjectOpts } from '../request-object'
import {
  ClientIdScheme,
  ClientMetadataOpts,
  IdTokenClaimPayload,
  ResponseMode,
  ResponseType,
  Schema,
  Scope,
  SubjectType,
  SupportedVersion,
  Verification,
} from '../types'
import { VerifyJwtCallback } from '../types/VpJwtVerifier'

export interface ClaimPayloadOptsVID1 extends ClaimPayloadCommonOpts {
  id_token?: IdTokenClaimPayload
  vp_token?: PresentationDefinitionPayloadOpts | DcqlQueryPayloadOpts
}

export interface ClaimPayloadCommonOpts {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

export interface AuthorizationRequestPayloadOpts<CT extends ClaimPayloadCommonOpts> extends Partial<RequestObjectPayloadOpts<CT>> {
  request_uri?: string // The Request object payload if provided by reference
  // Note we do not list the request property here, as the lib constructs the value, and we do not want people to pass that value in directly as it will lead to people not understanding why things fail
}
export interface RequestObjectPayloadOpts<CT extends ClaimPayloadCommonOpts> {
  scope: string // from openid-connect-self-issued-v2-1_0-ID1
  response_type: string // from openid-connect-self-issued-v2-1_0-ID1
  client_id: string // from openid-connect-self-issued-v2-1_0-ID1
  client_id_scheme?: ClientIdScheme
  redirect_uri?: string // from openid-connect-self-issued-v2-1_0-ID1
  response_uri?: string // from openid-connect-self-issued-v2-1_0-D18 // either response uri or redirect uri
  id_token_hint?: string // from openid-connect-self-issued-v2-1_0-ID1
  claims?: CT // from openid-connect-self-issued-v2-1_0-ID1 look at https://openid.net/specs/openid-connect-core-1_0.html#Claims
  nonce?: string // An optional nonce, will be generated if not provided
  state?: string // An optional state, will be generated if not provided
  aud?: string // The audience of the request
  authorization_endpoint?: string
  response_mode?: ResponseMode // How the URI should be returned. This is not being used by the library itself, allows an implementor to make a decision
  response_types_supported?: ResponseType[] | ResponseType
  scopes_supported?: Scope[] | Scope
  subject_types_supported?: SubjectType[] | SubjectType
  request_object_signing_alg_values_supported?: SigningAlgo[] | SigningAlgo

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any
}

interface AuthorizationRequestCommonOpts<CT extends ClaimPayloadCommonOpts> {
  // Yes, this includes common payload properties both at the payload level as well as in the requestObject.payload property. That is to support OAuth2 with or without a signed OpenID requestObject
  version: SupportedVersion
  clientMetadata?: ClientMetadataOpts // this maps to 'registration' for older SIOPv2 specs! OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP that would normally be provided to an OP during Dynamic RP Registration, as specified in {#rp-registration-parameter}.
  payload?: AuthorizationRequestPayloadOpts<CT>
  requestObject: RequestObjectOpts<CT>
  uriScheme?: Schema | string // Use a custom scheme for the URI. By default openid:// will be used
}

export type AuthorizationRequestOptsVID1 = AuthorizationRequestCommonOpts<ClaimPayloadOptsVID1>

export interface AuthorizationRequestOptsVD11 extends AuthorizationRequestCommonOpts<ClaimPayloadCommonOpts> {
  idTokenType?: string // OPTIONAL. Space-separated string that specifies the types of ID token the RP wants to obtain, with the values appearing in order of preference. The allowed individual values are subject_signed and attester_signed (see Section 8.2). The default value is attester_signed.
}

export type CreateAuthorizationRequestOpts = AuthorizationRequestOptsVID1 | AuthorizationRequestOptsVD11

export interface VerifyAuthorizationRequestOpts {
  correlationId: string
  verification: Verification
  verifyJwtCallback: VerifyJwtCallback
  nonce?: string // If provided the nonce in the request needs to match
  state?: string // If provided the state in the request needs to match
  supportedVersions?: SupportedVersion[]
  hasher?: Hasher
}

/**
 * Determines where a property will end up. Methods that support this argument are optional. If you do not provide any value it will default to all targets.
 */
export enum PropertyTarget {
  // The property will end up in the oAuth2 authorization request
  AUTHORIZATION_REQUEST = 'authorization-request',

  // OpenID Request Object (the JWT)
  REQUEST_OBJECT = 'request-object',
}

export type PropertyTargets = PropertyTarget | PropertyTarget[]

export interface RequestPropertyWithTargets<T> {
  targets?: PropertyTargets
  propertyValue: T
}
