import { EventEmitter } from 'events'

import {
  jarmAuthResponseDirectPostJwtValidate,
  JarmAuthResponseParams,
  JarmDirectPostJwtAuthResponseValidationContext,
  JarmDirectPostJwtResponseParams,
} from '@sphereon/jarm'
import { decodeProtectedHeader, JwtIssuer, uuidv4 } from '@sphereon/oid4vc-common'
import { Hasher } from '@sphereon/ssi-types'

import {
  AuthorizationRequest,
  ClaimPayloadCommonOpts,
  CreateAuthorizationRequestOpts,
  PropertyTarget,
  RequestObjectPayloadOpts,
  RequestPropertyWithTargets,
  URI,
} from '../authorization-request'
import { mergeVerificationOpts } from '../authorization-request/Opts'
import {
  AuthorizationResponse,
  extractPresentationsFromVpToken,
  PresentationDefinitionWithLocation,
  VerifyAuthorizationResponseOpts,
} from '../authorization-response'
import { base64urlToString, getNonce, getState } from '../helpers'
import {
  AuthorizationEvent,
  AuthorizationEvents,
  AuthorizationResponsePayload,
  DecryptCompact,
  PassBy,
  RegisterEventListener,
  RequestObjectPayload,
  ResponseURIType,
  SIOPErrors,
  SupportedVersion,
  Verification,
  VerifiedAuthorizationResponse,
} from '../types'

import {
  createRequestOptsFromBuilderOrExistingOpts,
  createVerifyResponseOptsFromBuilderOrExistingOpts,
  isTargetOrNoTargets
} from './Opts'
import { RPBuilder } from './RPBuilder'
import { IRPSessionManager } from './types'

export class RP {
  get sessionManager(): IRPSessionManager {
    return this._sessionManager
  }

  private readonly _createRequestOptions: CreateAuthorizationRequestOpts
  private readonly _verifyResponseOptions: Partial<VerifyAuthorizationResponseOpts>
  private readonly _eventEmitter?: EventEmitter
  private readonly _sessionManager?: IRPSessionManager
  private readonly _responseRedirectUri?: string

  private constructor(opts: {
    builder?: RPBuilder
    createRequestOpts?: CreateAuthorizationRequestOpts
    verifyResponseOpts?: VerifyAuthorizationResponseOpts
  }) {
    // const claims = opts.builder?.claims || opts.createRequestOpts?.payload.claims;
    this._createRequestOptions = createRequestOptsFromBuilderOrExistingOpts(opts)
    this._verifyResponseOptions = { ...createVerifyResponseOptsFromBuilderOrExistingOpts(opts) }
    this._eventEmitter = opts.builder?.eventEmitter
    this._sessionManager = opts.builder?.sessionManager
    this._responseRedirectUri = opts.builder?._responseRedirectUri
  }

  public static fromRequestOpts(opts: CreateAuthorizationRequestOpts): RP {
    return new RP({ createRequestOpts: opts })
  }

  public static builder(opts?: { requestVersion?: SupportedVersion }): RPBuilder {
    return RPBuilder.newInstance(opts?.requestVersion)
  }

  public async createAuthorizationRequest(opts: {
    correlationId: string
    nonce: string | RequestPropertyWithTargets<string>
    state: string | RequestPropertyWithTargets<string>
    jwtIssuer?: JwtIssuer
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>
    version?: SupportedVersion
    requestByReferenceURI?: string
    responseURI?: string
    responseURIType?: ResponseURIType
  }): Promise<AuthorizationRequest> {
    const authorizationRequestOpts = this.newAuthorizationRequestOpts(opts)
    return AuthorizationRequest.fromOpts(authorizationRequestOpts)
      .then((authorizationRequest: AuthorizationRequest) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, {
          correlationId: opts.correlationId,
          subject: authorizationRequest,
        })
        return authorizationRequest
      })
      .catch((error: Error) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_FAILED, {
          correlationId: opts.correlationId,
          error,
        })
        throw error
      })
  }

  public async createAuthorizationRequestURI(opts: {
    correlationId: string
    nonce: string | RequestPropertyWithTargets<string>
    state: string | RequestPropertyWithTargets<string>
    jwtIssuer?: JwtIssuer
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>
    version?: SupportedVersion
    requestByReferenceURI?: string
    responseURI?: string
    responseURIType?: ResponseURIType
  }): Promise<URI> {
    const authorizationRequestOpts = this.newAuthorizationRequestOpts(opts)

    return await URI.fromOpts(authorizationRequestOpts)
      .then(async (uri: URI) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_SUCCESS, {
          correlationId: opts.correlationId,
          subject: await AuthorizationRequest.fromOpts(authorizationRequestOpts),
        })
        return uri
      })
      .catch((error: Error) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_CREATED_FAILED, {
          correlationId: opts.correlationId,
          error,
        })
        throw error
      })
  }

  public async signalAuthRequestRetrieved(opts: { correlationId: string; error?: Error }) {
    if (!this.sessionManager) {
      throw Error(`Cannot signal auth request retrieval when no session manager is registered`)
    }
    const state = await this.sessionManager.getRequestStateByCorrelationId(opts.correlationId, true)
    void this.emitEvent(opts?.error ? AuthorizationEvents.ON_AUTH_REQUEST_SENT_FAILED : AuthorizationEvents.ON_AUTH_REQUEST_SENT_SUCCESS, {
      correlationId: opts.correlationId,
      ...(!opts?.error ? { subject: state.request } : {}),
      ...(opts?.error ? { error: opts.error } : {}),
    })
  }

  static async processJarmAuthorizationResponse(
    response: string,
    opts: {
      decryptCompact: DecryptCompact
      getAuthRequestPayload: (input: JarmDirectPostJwtResponseParams | JarmAuthResponseParams) => Promise<{ authRequestParams: RequestObjectPayload }>
      hasher?: Hasher
    },
  ) {
    const { decryptCompact, getAuthRequestPayload, hasher } = opts

    const getParams = getAuthRequestPayload as JarmDirectPostJwtAuthResponseValidationContext['openid4vp']['authRequest']['getParams']

    const validatedResponse = await jarmAuthResponseDirectPostJwtValidate(
      { response },
      {
        openid4vp: { authRequest: { getParams } },
        jwe: { decryptCompact },
      },
    )

    const presentations = await extractPresentationsFromVpToken(validatedResponse.authResponseParams.vp_token, { hasher })
    const mdocVerifiablePresentations = (Array.isArray(presentations) ? presentations : [presentations]).filter((p) => p.format === 'mso_mdoc')

    if (mdocVerifiablePresentations.length) {
      if (validatedResponse.type !== 'encrypted') {
        throw new Error(`Cannot verify mdoc request nonce. Response should be 'encrypted' but is '${validatedResponse.type}'`)
      }
      const requestParamsNonce = validatedResponse.authRequestParams.nonce

      const jweProtectedHeader = decodeProtectedHeader(response) as { apv?: string; apu?: string }
      const apv = jweProtectedHeader.apv
      if (!apv) {
        throw new Error(`Missing required apv parameter in the protected header of the jarm response.`)
      }

      const requestNonce = base64urlToString(apv)
      if (!requestParamsNonce || requestParamsNonce !== requestNonce) {
        throw new Error(`Invalid request nonce found in the jarm protected Header. Expected '${requestParamsNonce}' received '${requestNonce}'`)
      }
    }

    return validatedResponse
  }

  public async verifyAuthorizationResponse(
    authorizationResponsePayload: AuthorizationResponsePayload,
    opts?: {
      correlationId?: string
      hasher?: Hasher
      audience?: string
      state?: string
      nonce?: string
      verification?: Verification
      presentationDefinitions?: PresentationDefinitionWithLocation | PresentationDefinitionWithLocation[]
    },
  ): Promise<VerifiedAuthorizationResponse> {
    const state = opts?.state || this.verifyResponseOptions.state
    let correlationId: string | undefined = opts?.correlationId || state
    let authorizationResponse: AuthorizationResponse
    try {
      authorizationResponse = await AuthorizationResponse.fromPayload(authorizationResponsePayload)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
      void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_FAILED, {
        correlationId: correlationId ?? uuidv4(), // correlation id cannot be derived from state in payload possible, hence a uuid as fallback
        subject: authorizationResponsePayload,
        error,
      })
      throw error
    }

    try {
      const verifyAuthenticationResponseOpts = await this.newVerifyAuthorizationResponseOpts(authorizationResponse, {
        ...opts,
        correlationId,
      })
      correlationId = verifyAuthenticationResponseOpts.correlationId ?? correlationId
      void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_RECEIVED_SUCCESS, {
        correlationId,
        subject: authorizationResponse,
      })

      const verifiedAuthorizationResponse = await authorizationResponse.verify(verifyAuthenticationResponseOpts)
      void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_SUCCESS, {
        correlationId,
        subject: authorizationResponse,
      })
      return verifiedAuthorizationResponse
    } catch (error) {
      void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_VERIFIED_FAILED, {
        correlationId,
        subject: authorizationResponse,
        error,
      })
      throw error
    }
  }

  get createRequestOptions(): CreateAuthorizationRequestOpts {
    return this._createRequestOptions
  }

  get verifyResponseOptions(): Partial<VerifyAuthorizationResponseOpts> {
    return this._verifyResponseOptions
  }

  public getResponseRedirectUri(mappings?: Record<string, string>): string | undefined {
    if (!this._responseRedirectUri) {
      return undefined
    }
    if (!mappings) {
      return this._responseRedirectUri
    }
    return Object.entries(mappings).reduce((uri, [key, value]) => uri.replace(`:${key}`, value), this._responseRedirectUri)
  }

  private newAuthorizationRequestOpts(opts: {
    correlationId: string
    nonce: string | RequestPropertyWithTargets<string>
    state: string | RequestPropertyWithTargets<string>
    jwtIssuer?: JwtIssuer
    claims?: ClaimPayloadCommonOpts | RequestPropertyWithTargets<ClaimPayloadCommonOpts>
    version?: SupportedVersion
    requestByReferenceURI?: string
    responseURIType?: ResponseURIType
    responseURI?: string
  }): CreateAuthorizationRequestOpts {
    const nonceWithTarget =
      typeof opts.nonce === 'string'
        ? { propertyValue: opts.nonce, targets: PropertyTarget.REQUEST_OBJECT }
        : (opts?.nonce as RequestPropertyWithTargets<string>)
    const stateWithTarget =
      typeof opts.state === 'string'
        ? { propertyValue: opts.state, targets: PropertyTarget.REQUEST_OBJECT }
        : (opts?.state as RequestPropertyWithTargets<string>)
    const claimsWithTarget =
      opts?.claims && !('propertyValue' in opts.claims)
        ? { propertyValue: opts.claims, targets: PropertyTarget.REQUEST_OBJECT }
        : (opts?.claims as RequestPropertyWithTargets<ClaimPayloadCommonOpts>)

    const version = opts?.version ?? this._createRequestOptions.version
    if (!version) {
      throw Error(SIOPErrors.NO_REQUEST_VERSION)
    }
    const referenceURI = opts.requestByReferenceURI ?? this._createRequestOptions?.requestObject?.reference_uri

    let responseURIType: ResponseURIType = opts?.responseURIType
    let responseURI = this._createRequestOptions.requestObject.payload?.redirect_uri ?? this._createRequestOptions.payload?.redirect_uri
    if (responseURI) {
      responseURIType = 'redirect_uri'
    } else {
      responseURI =
        opts.responseURI ?? this._createRequestOptions.requestObject.payload?.response_uri ?? this._createRequestOptions.payload?.response_uri
      responseURIType = opts?.responseURIType ?? 'response_uri'
    }
    if (!responseURI) {
      throw Error(`A response or redirect URI is required at this point`)
    } else {
      if (responseURIType === 'redirect_uri') {
        if (this._createRequestOptions?.requestObject?.payload) {
          this._createRequestOptions.requestObject.payload.redirect_uri = responseURI
        }
        if (!referenceURI && !this._createRequestOptions.payload?.redirect_uri) {
          this._createRequestOptions.payload.redirect_uri = responseURI
        }
      } else if (responseURIType === 'response_uri') {
        if (this._createRequestOptions?.requestObject?.payload) {
          this._createRequestOptions.requestObject.payload.response_uri = responseURI
        }
        if (!referenceURI && !this._createRequestOptions.payload?.response_uri) {
          this._createRequestOptions.payload.response_uri = responseURI
        }
      }
    }

    const newOpts = { ...this._createRequestOptions, version }
    newOpts.requestObject = { ...newOpts.requestObject, jwtIssuer: opts.jwtIssuer }

    newOpts.requestObject.payload = newOpts.requestObject.payload ?? ({} as RequestObjectPayloadOpts<ClaimPayloadCommonOpts>)
    newOpts.payload = newOpts.payload ?? {}
    if (referenceURI) {
      if (newOpts.requestObject.passBy && newOpts.requestObject.passBy !== PassBy.REFERENCE) {
        throw Error(`Cannot pass by reference with uri ${referenceURI} when mode is ${newOpts.requestObject.passBy}`)
      }
      newOpts.requestObject.reference_uri = referenceURI
      newOpts.requestObject.passBy = PassBy.REFERENCE
    }

    const state = getState(stateWithTarget.propertyValue)
    if (stateWithTarget.propertyValue) {
      if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, stateWithTarget.targets)) {
        newOpts.payload.state = state
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, stateWithTarget.targets)) {
        newOpts.requestObject.payload.state = state
      }
    }

    const nonce = getNonce(state, nonceWithTarget.propertyValue)
    if (nonceWithTarget.propertyValue) {
      if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, nonceWithTarget.targets)) {
        newOpts.payload.nonce = nonce
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, nonceWithTarget.targets)) {
        newOpts.requestObject.payload.nonce = nonce
      }
    }
    if (claimsWithTarget?.propertyValue) {
      if (isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, claimsWithTarget.targets)) {
        newOpts.payload.claims = { ...newOpts.payload.claims, ...claimsWithTarget.propertyValue }
      }
      if (isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, claimsWithTarget.targets)) {
        newOpts.requestObject.payload.claims = { ...newOpts.requestObject.payload.claims, ...claimsWithTarget.propertyValue }
      }
    }
    return newOpts
  }

  private async newVerifyAuthorizationResponseOpts(
    authorizationResponse: AuthorizationResponse,
    opts: {
      correlationId: string
      hasher?: Hasher
      state?: string
      nonce?: string
      verification?: Verification
      audience?: string
      presentationDefinitions?: PresentationDefinitionWithLocation | PresentationDefinitionWithLocation[]
    },
  ): Promise<VerifyAuthorizationResponseOpts> {
    let correlationId = opts?.correlationId ?? this._verifyResponseOptions.correlationId
    let state = opts?.state ?? this._verifyResponseOptions.state
    let nonce = opts?.nonce ?? this._verifyResponseOptions.nonce
    if (this.sessionManager) {
      const resNonce = (await authorizationResponse.getMergedProperty('nonce', {
        consistencyCheck: false,
        hasher: opts.hasher ?? this._verifyResponseOptions.hasher,
      })) as string
      const resState = (await authorizationResponse.getMergedProperty('state', {
        consistencyCheck: false,
        hasher: opts.hasher ?? this._verifyResponseOptions.hasher,
      })) as string
      if (resNonce && !correlationId) {
        correlationId = await this.sessionManager.getCorrelationIdByNonce(resNonce, false)
      }
      if (!correlationId) {
        correlationId = await this.sessionManager.getCorrelationIdByState(resState, false)
      }
      if (!correlationId) {
        correlationId = nonce
      }
      const requestState = await this.sessionManager.getRequestStateByCorrelationId(correlationId, false)
      if (requestState) {
        const reqNonce: string = await requestState.request.getMergedProperty('nonce')
        const reqState: string = await requestState.request.getMergedProperty('state')
        nonce = nonce ?? reqNonce
        state = state ?? reqState
      }
    }

    return {
      ...this._verifyResponseOptions,
      verifyJwtCallback: this._verifyResponseOptions.verifyJwtCallback,
      ...opts,
      correlationId,
      audience: opts?.audience ?? this._verifyResponseOptions.audience ?? this._createRequestOptions.payload.client_id,
      state,
      nonce,
      verification: mergeVerificationOpts(this._verifyResponseOptions, opts),
      presentationDefinitions: opts?.presentationDefinitions ?? this._verifyResponseOptions.presentationDefinitions,
    }
  }

  private async emitEvent(
    type: AuthorizationEvents,
    payload: { correlationId: string; subject?: AuthorizationRequest | AuthorizationResponse | AuthorizationResponsePayload; error?: Error },
  ): Promise<void> {
    if (this._eventEmitter) {
      try {
        this._eventEmitter.emit(type, new AuthorizationEvent(payload))
      } catch (e) {
        //Let's make sure events do not cause control flow issues
        console.log(`Could not emit event ${type} for ${payload.correlationId} initial error if any: ${payload?.error}`)
      }
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
}
