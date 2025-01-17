import { JwtIssuer } from '@sphereon/oid4vc-common'
import { IPresentationDefinition, PresentationSignCallBackParams } from '@sphereon/pex'
import { Format } from '@sphereon/pex-models'
import {
  CompactSdJwtVc,
  Hasher,
  MdocOid4vpIssuerSigned,
  MdocOid4vpMdocVpToken,
  PresentationSubmission,
  W3CVerifiablePresentation,
} from '@sphereon/ssi-types'

import {
  ResponseMode,
  ResponseRegistrationOpts,
  ResponseType,
  ResponseURIType,
  SupportedVersion,
  VerifiablePresentationWithFormat,
  Verification,
} from '../types'
import { CreateJwtCallback } from '../types/VpJwtIssuer'
import { VerifyJwtCallback } from '../types/VpJwtVerifier'

import { AuthorizationResponse } from './AuthorizationResponse'

export interface AuthorizationResponseOpts {
  // redirectUri?: string; // It's typically comes from the request opts as a measure to prevent hijacking.
  responseURI?: string // This is either the redirect URI or response URI. See also responseURIType. response URI is used when response_mode is `direct_post`
  responseURIType?: ResponseURIType
  registration?: ResponseRegistrationOpts
  version?: SupportedVersion
  audience?: string
  createJwtCallback: CreateJwtCallback
  jwtIssuer?: JwtIssuer
  responseMode?: ResponseMode
  responseType?: [ResponseType]
  // did: string;
  expiresIn?: number
  accessToken?: string
  tokenType?: string
  refreshToken?: string
  presentationExchange?: PresentationExchangeResponseOpts
  isFirstParty?: boolean
}

export interface PresentationExchangeResponseOpts {
  /* presentationSignCallback?: PresentationSignCallback;
  signOptions?: PresentationSignOptions,
*/
  /*  credentialsAndDefinitions: {
    presentationDefinition: IPresentationDefinition,
    selectedCredentials: W3CVerifiableCredential[]
  }[],*/

  verifiablePresentations: Array<W3CVerifiablePresentation | CompactSdJwtVc | MdocOid4vpMdocVpToken>
  vpTokenLocation?: VPTokenLocation
  presentationSubmission?: PresentationSubmission
  restrictToFormats?: Format
  restrictToDIDMethods?: string[]
}

export interface PresentationExchangeRequestOpts {
  presentationVerificationCallback?: PresentationVerificationCallback
}

export interface PresentationDefinitionPayloadOpts {
  presentation_definition?: IPresentationDefinition
  presentation_definition_uri?: string
}

export interface PresentationDefinitionWithLocation {
  version?: SupportedVersion
  location: PresentationDefinitionLocation
  definition: IPresentationDefinition
}

export interface VerifiablePresentationWithSubmissionData extends VerifiablePresentationWithFormat {
  vpTokenLocation: VPTokenLocation

  submissionData: PresentationSubmission
}

export enum PresentationDefinitionLocation {
  CLAIMS_VP_TOKEN = 'claims.vp_token',
  TOPLEVEL_PRESENTATION_DEF = 'presentation_definition',
}

export enum VPTokenLocation {
  AUTHORIZATION_RESPONSE = 'authorization_response',
  ID_TOKEN = 'id_token',
  TOKEN_RESPONSE = 'token_response',
}

export type PresentationVerificationResult = { verified: boolean; reason?: string }

export type PresentationVerificationCallback = (
  args: W3CVerifiablePresentation | CompactSdJwtVc | MdocOid4vpIssuerSigned,
  presentationSubmission: PresentationSubmission,
) => Promise<PresentationVerificationResult>

export type PresentationSignCallback = (args: PresentationSignCallBackParams) => Promise<W3CVerifiablePresentation | CompactSdJwtVc>

export interface VerifyAuthorizationResponseOpts {
  correlationId: string
  verification: Verification
  verifyJwtCallback: VerifyJwtCallback
  hasher?: Hasher
  nonce?: string // To verify the response against the supplied nonce
  state?: string // To verify the response against the supplied state
  presentationDefinitions?: PresentationDefinitionWithLocation | PresentationDefinitionWithLocation[] // The presentation definitions to match against VPs in the response
  audience?: string // The audience/redirect_uri
  restrictToFormats?: Format // Further restrict to certain VC formats, not expressed in the presentation definition
  restrictToDIDMethods?: string[]
  // claims?: ClaimPayloadCommonOpts; // The claims, typically the same values used during request creation
  // verifyCallback?: VerifyCallback;
  // presentationVerificationCallback?: PresentationVerificationCallback;
}

export interface AuthorizationResponseWithCorrelationId {
  // The URI to send the response to. Can be derived from either the redirect_uri or the response_uri
  responseURI: string
  response: AuthorizationResponse
  correlationId: string
}
