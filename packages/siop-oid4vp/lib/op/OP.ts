import { EventEmitter } from 'events'

import { jarmAuthResponseSend, JarmClientMetadata, jarmMetadataValidate, JarmServerMetadata } from '@sphereon/jarm'
import { JwtIssuer, uuidv4 } from '@sphereon/oid4vc-common'
import { IIssuerId } from '@sphereon/ssi-types'

import { AuthorizationRequest, URI, VerifyAuthorizationRequestOpts } from '../authorization-request'
import { mergeVerificationOpts } from '../authorization-request/Opts'
import {
  AuthorizationResponse,
  AuthorizationResponseOpts,
  AuthorizationResponseWithCorrelationId,
  DcqlQueryResponseOpts,
  PresentationExchangeResponseOpts,
} from '../authorization-response'
import { encodeJsonAsURI, post } from '../helpers'
import { extractJwksFromJwksMetadata, JwksMetadataParams } from '../helpers/ExtractJwks'
import { authorizationRequestVersionDiscovery } from '../helpers/SIOPSpecVersion'
import {
  AuthorizationEvent,
  AuthorizationEvents,
  AuthorizationResponsePayload,
  ContentType,
  ParsedAuthorizationRequestURI,
  RegisterEventListener,
  RequestObjectPayload,
  ResponseIss,
  ResponseMode, RPRegistrationMetadataPayload,
  SIOPErrors,
  SupportedVersion,
  UrlEncodingFormat,
  Verification,
  VerifiedAuthorizationRequest,
} from '../types'

import { OPBuilder } from './OPBuilder'
import { createResponseOptsFromBuilderOrExistingOpts, createVerifyRequestOptsFromBuilderOrExistingOpts } from './Opts'

// The OP publishes the formats it supports using the vp_formats_supported metadata parameter as defined above in its "openid-configuration".
export class OP {
  private readonly _createResponseOptions: AuthorizationResponseOpts
  private readonly _verifyRequestOptions: Partial<VerifyAuthorizationRequestOpts>
  private readonly _eventEmitter?: EventEmitter

  private constructor(opts: { builder?: OPBuilder; responseOpts?: AuthorizationResponseOpts; verifyOpts?: VerifyAuthorizationRequestOpts }) {
    this._createResponseOptions = { ...createResponseOptsFromBuilderOrExistingOpts(opts) }
    this._verifyRequestOptions = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) }
    this._eventEmitter = opts.builder?.eventEmitter
  }

  /**
   * This method tries to infer the SIOP specs version based on the request payload.
   * If the version cannot be inferred or is not supported it throws an exception.
   * This method needs to be called to ensure the OP can handle the request
   * @param requestJwtOrUri
   * @param requestOpts
   */

  public async verifyAuthorizationRequest(
    requestJwtOrUri: string | URI,
    requestOpts?: { correlationId?: string; verification?: Verification },
  ): Promise<VerifiedAuthorizationRequest> {
    const correlationId = requestOpts?.correlationId || uuidv4()

    let authorizationRequest: AuthorizationRequest
    try {
      authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestJwtOrUri)
      await this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_SUCCESS, { correlationId, subject: authorizationRequest })
    } catch (error) {
      if (error instanceof Error) {
        await this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_FAILED, {
          correlationId,
          subject: requestJwtOrUri,
          error,
        })
      }
      throw error
    }

    try {
      const verifiedAuthorizationRequest = await authorizationRequest.verify(
        this.newVerifyAuthorizationRequestOpts({ ...requestOpts, correlationId }),
      )

      await this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_SUCCESS, {
        correlationId,
        subject: verifiedAuthorizationRequest.authorizationRequest,
      })
      return verifiedAuthorizationRequest
    } catch (error) {
      await this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_FAILED, {
        correlationId,
        subject: authorizationRequest,
        error,
      })
      throw error
    }
  }

  public async createAuthorizationResponse(
    verifiedAuthorizationRequest: VerifiedAuthorizationRequest,
    responseOpts: {
      jwtIssuer?: JwtIssuer
      version?: SupportedVersion
      correlationId?: string
      audience?: string
      issuer?: ResponseIss | string
      verification?: Verification
      presentationExchange?: PresentationExchangeResponseOpts
      dcqlQuery?: DcqlQueryResponseOpts
    },
  ): Promise<AuthorizationResponseWithCorrelationId> {
    if (
      verifiedAuthorizationRequest.correlationId &&
      responseOpts?.correlationId &&
      verifiedAuthorizationRequest.correlationId !== responseOpts.correlationId
    ) {
      throw new Error(
        `Request correlation id ${verifiedAuthorizationRequest.correlationId} is different from option correlation id ${responseOpts.correlationId}`,
      )
    }
    let version = responseOpts?.version
    const rpSupportedVersions = authorizationRequestVersionDiscovery(await verifiedAuthorizationRequest.authorizationRequest.mergedPayloads())
    if (version && rpSupportedVersions.length > 0 && !rpSupportedVersions.includes(version)) {
      throw Error(`RP does not support spec version ${version}, supported versions: ${rpSupportedVersions.toString()}`)
    } else if (!version) {
      version = rpSupportedVersions.reduce(
        (previous, current) => (current.valueOf() > previous.valueOf() ? current : previous),
        SupportedVersion.SIOPv2_ID1,
      )
    }
    const correlationId = responseOpts?.correlationId ?? verifiedAuthorizationRequest.correlationId ?? uuidv4()
    try {
      // IF using DIRECT_POST, the response_uri takes precedence over the redirect_uri
      let responseUri = verifiedAuthorizationRequest.responseURI
      if (verifiedAuthorizationRequest.payload?.response_mode === ResponseMode.DIRECT_POST) {
        responseUri = verifiedAuthorizationRequest.authorizationRequestPayload.response_uri ?? responseUri
      }

      const response = await AuthorizationResponse.fromVerifiedAuthorizationRequest(
        verifiedAuthorizationRequest,
        this.newAuthorizationResponseOpts({
          ...responseOpts,
          version,
          correlationId,
        }),
        verifiedAuthorizationRequest.verifyOpts,
      )
      void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_SUCCESS, {
        correlationId,
        subject: response,
      })
      return { correlationId, response, responseURI: responseUri }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
      void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_FAILED, {
        correlationId,
        subject: verifiedAuthorizationRequest.authorizationRequest,
        error,
      })
      throw error
    }
  }

  public static async extractEncJwksFromClientMetadata(clientMetadata: JwksMetadataParams) {
    // TODO: Currently no mechanisms are in place to deal with multiple 'enc' keys in the client metadata.
    // TODO: Maybe we should return all 'enc' keys in the client metadata. In addition the JWKS from the jwks_uri are not fetched if jwks are present.
    // TODO: Is that the expected behavior?
    const jwks = await extractJwksFromJwksMetadata(clientMetadata)
    const encryptionJwk = jwks?.keys.find((key) => key.use === 'enc')
    if (!encryptionJwk) {
      throw new Error('No encryption jwk could be extracted from the client metadata.')
    }

    return encryptionJwk
  }

  // TODO SK Can you please put some documentation on it?
  public async submitAuthorizationResponse(
    authorizationResponse: AuthorizationResponseWithCorrelationId,
    createJarmResponse?: (opts: {
      authorizationResponsePayload: AuthorizationResponsePayload
      requestObjectPayload: RequestObjectPayload
      clientMetadata: JwksMetadataParams
    }) => Promise<{
      response: string
    }>,
  ): Promise<Response> {
    const { correlationId, response } = authorizationResponse
    if (!correlationId) {
      throw Error('No correlation Id provided')
    }

    const isJarmResponseMode = (responseMode: string): responseMode is 'jwt' | 'direct_post.jwt' | 'query.jwt' | 'fragment.jwt' => {
      return responseMode === ResponseMode.DIRECT_POST_JWT || responseMode === ResponseMode.QUERY_JWT || responseMode === ResponseMode.FRAGMENT_JWT
    }

    const requestObjectPayload = await response.authorizationRequest.requestObject?.getPayload()
    const responseMode = requestObjectPayload?.response_mode ?? response.options?.responseMode

    if (
      !response ||
      (response.options?.responseMode &&
        !(
          responseMode === ResponseMode.POST ||
          responseMode === ResponseMode.FORM_POST ||
          responseMode === ResponseMode.DIRECT_POST ||
          isJarmResponseMode(responseMode)
        ))
    ) {
      throw new Error(SIOPErrors.BAD_PARAMS)
    }

    const payload = response.payload
    const idToken = await response.idToken?.payload()
    const responseUri = authorizationResponse.responseURI ?? idToken?.aud
    if (!responseUri) {
      throw Error('No response URI present')
    }

    if (isJarmResponseMode(responseMode)) {
      if (responseMode !== ResponseMode.DIRECT_POST_JWT) {
        throw new Error('Only direct_post.jwt response mode is supported for JARM at the moment.')
      }
      let responseType: 'id_token' | 'id_token vp_token' | 'vp_token'
      if (idToken && payload.vp_token) {
        responseType = 'id_token vp_token'
      } else if (idToken) {
        responseType = 'id_token'
      } else if (payload.vp_token) {
        responseType = 'vp_token'
      } else {
        throw new Error('No id_token or vp_token present in the response payload')
      }

      const clientMetadata = authorizationResponse.response.authorizationRequest.options?.clientMetadata ?? requestObjectPayload.client_metadata
      const { response } = await createJarmResponse({
        requestObjectPayload,
        authorizationResponsePayload: payload,
        clientMetadata,
      })

      try {
        const jarmResponse = await jarmAuthResponseSend({
          authRequestParams: {
            response_uri: responseUri,
            response_mode: responseMode,
            response_type: responseType,
          },
          authResponse: response,
          state: requestObjectPayload.state
        })
        void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_SUCCESS, { correlationId, subject: response })
        return jarmResponse
      } catch (error) {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_FAILED, {
          correlationId,
          subject: response,
          error,
        })
        throw error
      }
    }

    const authResponseAsURI = encodeJsonAsURI(payload, { arraysWithIndex: ['presentation_submission'] })
    try {
      const result = await post(responseUri, authResponseAsURI, { contentType: ContentType.FORM_URL_ENCODED, exceptionOnHttpErrorStatus: true })
      await this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_SUCCESS, { correlationId, subject: response })
      return result.origResponse
    } catch (error) {
      await this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_FAILED, { correlationId, subject: response, error: error as Error })
      throw error
    }
  }

  /**
   * Create an Authentication Request Payload from a URI string
   *
   * @param encodedUri
   * @param rpRegistrationMetadata
   */
  public async parseAuthorizationRequestURI(encodedUri: string, rpRegistrationMetadata?: RPRegistrationMetadataPayload): Promise<ParsedAuthorizationRequestURI> {
    const { scheme, requestObjectJwt, authorizationRequestPayload, registrationMetadata } = await URI.parseAndResolve(encodedUri, rpRegistrationMetadata)

    return {
      encodedUri,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      scheme: scheme,
      requestObjectJwt,
      authorizationRequestPayload,
      registration: registrationMetadata,
    }
  }

  private newAuthorizationResponseOpts(opts: {
    correlationId: string
    version?: SupportedVersion
    issuer?: IIssuerId | ResponseIss
    audience?: string
    presentationExchange?: PresentationExchangeResponseOpts
    dcqlQuery?: DcqlQueryResponseOpts
  }): AuthorizationResponseOpts {
    const version = opts.version ?? this._createResponseOptions.version
    let issuer = opts.issuer ?? this._createResponseOptions?.registration?.issuer
    if (version === SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1) {
      issuer = ResponseIss.JWT_VC_PRESENTATION_V1
    } else if (version === SupportedVersion.SIOPv2_ID1) {
      issuer = ResponseIss.SELF_ISSUED_V2
    }

    if (!issuer) {
      throw Error(`No issuer value present. Either use IDv1, JWT VC Presentation profile version, or provide a DID as issuer value`)
    }
    // We are taking the whole presentationExchange object from a certain location
    const presentationExchange = opts.presentationExchange ?? this._createResponseOptions.presentationExchange
    const dcqlQuery = opts.dcqlQuery ?? this._createResponseOptions.dcqlQuery

    const responseURI = opts.audience ?? this._createResponseOptions.responseURI
    return {
      ...this._createResponseOptions,
      ...opts,
      ...(presentationExchange && { presentationExchange }),
      ...(dcqlQuery && { dcqlQuery }),
      registration: { ...this._createResponseOptions?.registration, issuer },
      responseURI,
      responseURIType:
        this._createResponseOptions.responseURIType ?? (version < SupportedVersion.SIOPv2_D12_OID4VP_D18 && responseURI ? 'redirect_uri' : undefined),
    }
  }

  private newVerifyAuthorizationRequestOpts(requestOpts: { correlationId: string; verification?: Verification }): VerifyAuthorizationRequestOpts {
    const verification: VerifyAuthorizationRequestOpts = {
      ...this._verifyRequestOptions,
      verifyJwtCallback: this._verifyRequestOptions.verifyJwtCallback,
      ...requestOpts,
      verification: mergeVerificationOpts(this._verifyRequestOptions, requestOpts),
      correlationId: requestOpts.correlationId,
    }

    return verification
  }

  private async emitEvent(
    type: AuthorizationEvents,
    payload: {
      correlationId: string
      subject: AuthorizationRequest | AuthorizationResponse | string | URI
      error?: Error
    },
  ): Promise<void> {
    if (this._eventEmitter) {
      this._eventEmitter.emit(type, new AuthorizationEvent(payload))
    }
  }

  public addEventListener(register: RegisterEventListener) {
    if (!this._eventEmitter) {
      throw Error('Cannot add listeners if no event emitter is available')
    }
    const events = Array.isArray(register.event) ? register.event : [register.event]
    for (const event of events) {
      this._eventEmitter.addListener(event, register.listener)
    }
  }

  public static fromOpts(responseOpts: AuthorizationResponseOpts, verifyOpts: VerifyAuthorizationRequestOpts): OP {
    return new OP({ responseOpts, verifyOpts })
  }

  public static builder() {
    return new OPBuilder()
  }

  get createResponseOptions(): AuthorizationResponseOpts {
    return this._createResponseOptions
  }

  get verifyRequestOptions(): Partial<VerifyAuthorizationRequestOpts> {
    return this._verifyRequestOptions
  }

  public static validateJarmMetadata(input: { client_metadata: JarmClientMetadata; server_metadata: Partial<JarmServerMetadata> }) {
    return jarmMetadataValidate(input)
  }
}
