import { decodeJwt, decodeProtectedHeader, uuidv4 } from '@sphereon/oid4vc-common'
import {
  ACCESS_TOKEN_ISSUER_REQUIRED_ERROR,
  AccessTokenRequest,
  adjustUrl,
  AuthorizationChallengeCodeResponse,
  AuthorizationChallengeError,
  AuthorizationChallengeErrorResponse,
  AuthorizationRequest,
  CommonAuthorizationChallengeRequest,
  CredentialIssuerMetadataOptsV1_0_13,
  CredentialOfferMode,
  CredentialOfferRESTRequest,
  CredentialRequestV1_0_13,
  determineGrantTypes,
  determineSpecVersionFromOffer,
  EVENTS,
  extractBearerToken,
  generateRandomString,
  getNumberOrUndefined,
  Grant,
  IssueStatusResponse,
  JWT_SIGNER_CALLBACK_REQUIRED_ERROR,
  JWTHeader,
  JWTVerifyCallback,
  JwtVerifyResult,
  NotificationRequest,
  NotificationStatusEventNames,
  OpenId4VCIVersion,
  TokenErrorResponse,
  trimBoth,
  trimEnd,
  trimStart,
  validateJWT,
  WellKnownEndpoints
} from '@sphereon/oid4vci-common'
import { ITokenEndpointOpts, LOG, VcIssuer } from '@sphereon/oid4vci-issuer'
import {
  env,
  ISingleEndpointOpts,
  oidcDiscoverIssuer,
  oidcGetClient,
  sendErrorResponse
} from '@sphereon/ssi-express-support'
import { InitiatorType, SubSystem, System } from '@sphereon/ssi-types'
import { NextFunction, Request, Response, Router } from 'express'

import { handleTokenRequest, verifyTokenRequest } from './IssuerTokenEndpoint'
import {
  IAuthorizationChallengeEndpointOpts,
  ICreateCredentialOfferEndpointOpts,
  ICreateCredentialOfferURIResponse,
  IGetCredentialOfferEndpointOpts,
  IGetIssueStatusEndpointOpts
} from './OID4VCIServer'
import { validateRequestBody } from './expressUtils'

import { ClientMetadata } from './index'

const expiresIn = process.env.EXPIRES_IN ? parseInt(process.env.EXPIRES_IN) : 90

export function getIssueStatusEndpoint<DIDDoc extends object>(router: Router, issuer: VcIssuer<DIDDoc>, opts: IGetIssueStatusEndpointOpts) {
  const path = determinePath(opts.baseUrl, opts?.path ?? '/webapp/credential-offer-status', { stripBasePath: true })
  LOG.log(`[OID4VCI] getIssueStatus endpoint enabled at ${path}`)
  router.post(path, async (request: Request, response: Response) => {
    try {
      const { id } = request.body
      const session = await issuer.getCredentialOfferSessionById(id)
      if (!session || !session.credentialOffer) {
        return sendErrorResponse(response, 404, {
          error: 'invalid_request',
          error_description: `Credential offer ${id} not found`,
        })
      }

      const authStatusBody: IssueStatusResponse = {
        createdAt: session.createdAt,
        lastUpdatedAt: session.lastUpdatedAt,
        status: session.status,
        statusLists: session.statusLists,
        ...(session.error && { error: session.error }),
        ...(session.clientId && { clientId: session.clientId }),
      }
      return response.json(authStatusBody)
    } catch (e) {
      return sendErrorResponse(
        response,
        500,
        {
          error: 'invalid_request',
          error_description: (e as Error).message,
        },
        e,
      )
    }
  })
}

export function getIssuePayloadEndpoint<DIDDoc extends object>(router: Router, issuer: VcIssuer<DIDDoc>, opts: IGetIssueStatusEndpointOpts) : string {
  const path = determinePath(opts.baseUrl, opts?.path ?? '/credential-offers/:id', { stripBasePath: true })
  LOG.log(`[OID4VCI] getIssuePayloadEndpoint endpoint enabled at ${path}`)
  router.get(path, async (request: Request, response: Response) => {
    try {
      const { id } = request.params
      if (!id) {
        return sendErrorResponse(response, 404, {
          error: 'invalid_request',
          error_description: `query parameter 'id' is missing`
        })
      }
      
      let session
      try {
        session = await issuer.getCredentialOfferSessionById(id as string, 'preAuthorizedCode')
      } catch (e) { /* will crash with 500 instead of 404 if we do not catch */ }

      if (!session || !session.credentialOffer) {
        return sendErrorResponse(response, 404, {
          error: 'invalid_request',
          error_description: `Credential offer ${id} not found`,
        })
      }

      return response.json(session.credentialOffer.credential_offer)
    } catch (e) {
      return sendErrorResponse(
        response,
        500,
        {
          error: 'invalid_request',
          error_description: (e as Error).message,
        },
        e,
      )
    }
  })
  return path
}

function isExternalAS(issuerMetadata: CredentialIssuerMetadataOptsV1_0_13) {
  return issuerMetadata.authorization_servers?.some((as) => !as.includes(issuerMetadata.credential_issuer))
}

export function authorizationChallengeEndpoint<DIDDoc extends object>(
  router: Router,
  issuer: VcIssuer<DIDDoc>,
  opts: IAuthorizationChallengeEndpointOpts & { baseUrl: string | URL },
) {
  const endpoint = issuer.authorizationServerMetadata.authorization_challenge_endpoint ?? issuer.issuerMetadata.authorization_challenge_endpoint
  const baseUrl = getBaseUrl(opts.baseUrl)
  if (!endpoint) {
    LOG.info('authorization challenge endpoint disabled as no "authorization_challenge_endpoint" has been configured in issuer metadata')
    return
  }
  const path = determinePath(baseUrl, endpoint, { stripBasePath: true })
  LOG.log(`[OID4VCI] authorization challenge endpoint at ${path}`)
  router.post(path, async (request: Request, response: Response) => {
    const authorizationChallengeRequest = request.body as CommonAuthorizationChallengeRequest
    const { client_id, issuer_state, auth_session, presentation_during_issuance_session } = authorizationChallengeRequest

    try {
      if (!client_id && !auth_session) {
        const authorizationChallengeErrorResponse: AuthorizationChallengeErrorResponse = {
          error: AuthorizationChallengeError.invalid_request,
          error_description: 'No client id or auth session present',
        } as AuthorizationChallengeErrorResponse
        throw authorizationChallengeErrorResponse
      }

      if (!auth_session && issuer_state) {
        const session = await issuer.credentialOfferSessions.get(issuer_state)
        if (!session) {
          const authorizationChallengeErrorResponse: AuthorizationChallengeErrorResponse = {
            error: AuthorizationChallengeError.invalid_session,
            error_description: 'Session is invalid',
          }
          throw authorizationChallengeErrorResponse
        }

        const authRequestURI = await opts.createAuthRequestUriCallback(issuer_state) // TODO generate some error
        const authorizationChallengeErrorResponse: AuthorizationChallengeErrorResponse = {
          error: AuthorizationChallengeError.insufficient_authorization,
          auth_session: issuer_state,
          presentation: authRequestURI,
        }
        throw authorizationChallengeErrorResponse
      }

      if (auth_session && presentation_during_issuance_session) {
        const session = await issuer.credentialOfferSessions.get(auth_session)
        if (!session) {
          const authorizationChallengeErrorResponse: AuthorizationChallengeErrorResponse = {
            error: AuthorizationChallengeError.invalid_session,
            error_description: 'Session is invalid',
          }
          throw authorizationChallengeErrorResponse
        }

        const verifiedResponse = await opts.verifyAuthResponseCallback(presentation_during_issuance_session) // TODO generate some error
        if (verifiedResponse) {
          const authorizationCode = generateRandomString(16, 'base64url')
          session.authorizationCode = authorizationCode
          await issuer.credentialOfferSessions.set(auth_session, session)
          const authorizationChallengeCodeResponse: AuthorizationChallengeCodeResponse = {
            authorization_code: authorizationCode,
          }
          return response.json(authorizationChallengeCodeResponse)
        }
      }

      const authorizationChallengeErrorResponse: AuthorizationChallengeErrorResponse = {
        error: AuthorizationChallengeError.invalid_request,
      }
      throw authorizationChallengeErrorResponse
    } catch (e) {
      return sendErrorResponse(response, 400, e as Error, e)
    }
  })
}

export function accessTokenEndpoint<DIDDoc extends object>(
  router: Router,
  issuer: VcIssuer<DIDDoc>,
  opts: ITokenEndpointOpts & ISingleEndpointOpts & { baseUrl: string | URL },
) {
  const tokenEndpoint = issuer.issuerMetadata.token_endpoint
  const externalAS = isExternalAS(issuer.issuerMetadata)
  if (externalAS) {
    LOG.log(`[OID4VCI] External Authorization Server ${tokenEndpoint} is being used. Not enabling issuer token endpoint`)
    return
  } else if (opts?.enabled === false) {
    LOG.log(`[OID4VCI] Token endpoint is not enabled`)
    return
  }
  const accessTokenIssuer =
    opts?.accessTokenIssuer ??
    process.env.ACCESS_TOKEN_ISSUER ??
    issuer.issuerMetadata.authorization_servers?.[0] ??
    issuer.issuerMetadata.credential_issuer

  const preAuthorizedCodeExpirationDuration =
    opts?.preAuthorizedCodeExpirationDuration ?? getNumberOrUndefined(process.env.PRE_AUTHORIZED_CODE_EXPIRATION_DURATION) ?? 300
  const interval = opts?.interval ?? getNumberOrUndefined(process.env.INTERVAL) ?? 300
  const tokenExpiresIn = opts?.tokenExpiresIn ?? 300

  // todo: this means we cannot sign JWTs or issue access tokens when configured from env vars!
  if (opts?.accessTokenSignerCallback === undefined) {
    throw new Error(JWT_SIGNER_CALLBACK_REQUIRED_ERROR)
  } else if (!accessTokenIssuer) {
    throw new Error(ACCESS_TOKEN_ISSUER_REQUIRED_ERROR)
  }

  const baseUrl = getBaseUrl(opts.baseUrl)

  // issuer is also AS
  const path = determinePath(baseUrl, opts?.tokenPath ?? process.env.TOKEN_PATH ?? '/token', {
    skipBaseUrlCheck: false,
    stripBasePath: true,
  })
  // let's fix any baseUrl ending with a slash as path will always start with a slash, and we already removed it at the end of the base url

  const url = new URL(`${baseUrl}${path}`)

  LOG.log(`[OID4VCI] Token endpoint enabled at ${url.toString()}`)

  // this.issuer.issuerMetadata.token_endpoint = url.toString()
  router.post(
    determinePath(baseUrl, url.pathname, { stripBasePath: true }),
    verifyTokenRequest({
      issuer,
      preAuthorizedCodeExpirationDuration,
    }),
    handleTokenRequest({
      issuer,
      accessTokenSignerCallback: opts.accessTokenSignerCallback,
      cNonceExpiresIn: issuer.cNonceExpiresIn,
      interval,
      tokenExpiresIn,
      accessTokenIssuer,
    }),
  )
}

export function getCredentialEndpoint<DIDDoc extends object>(
  router: Router,
  issuer: VcIssuer<DIDDoc>,
  opts: Pick<ITokenEndpointOpts, 'accessTokenVerificationCallback' | 'accessTokenSignerCallback' | 'tokenExpiresIn' | 'cNonceExpiresIn'> &
    ISingleEndpointOpts & { baseUrl: string | URL },
) {
  const endpoint = issuer.issuerMetadata.credential_endpoint
  const baseUrl = getBaseUrl(opts.baseUrl)
  let path: string
  if (!endpoint) {
    path = `/credentials`
    issuer.issuerMetadata.credential_endpoint = `${baseUrl}${path}`
  } else {
    path = determinePath(baseUrl, endpoint, { stripBasePath: true, skipBaseUrlCheck: false })
  }
  path = determinePath(baseUrl, path, { stripBasePath: true })
  LOG.log(`[OID4VCI] getCredential endpoint enabled at ${path}`)
  router.post(path, async (request: Request, response: Response) => {
    try {
      const credentialRequest = request.body as CredentialRequestV1_0_13
      LOG.log(`credential request received`, credentialRequest)
      try {
        const jwt = extractBearerToken(request.header('Authorization'))
        await validateJWT(jwt, { accessTokenVerificationCallback: opts.accessTokenVerificationCallback })
      } catch (e) {
        LOG.warning(e)
        return sendErrorResponse(response, 400, {
          error: 'invalid_token',
        })
      }

      const credential = await issuer.issueCredential({
        credentialRequest: credentialRequest,
        tokenExpiresIn: opts.tokenExpiresIn,
        cNonceExpiresIn: opts.cNonceExpiresIn,
      })
      return response.json(credential)
    } catch (e) {
      return sendErrorResponse(
        response,
        500,
        {
          error: 'invalid_request',
          error_description: (e as Error).message,
        },
        e,
      )
    }
  })
}

export function notificationEndpoint<DIDDoc extends object>(
  router: Router,
  issuer: VcIssuer<DIDDoc>,
  opts: ISingleEndpointOpts & Pick<ITokenEndpointOpts, 'accessTokenVerificationCallback'> & { baseUrl: string | URL },
) {
  const endpoint = issuer.issuerMetadata.notification_endpoint
  const baseUrl = getBaseUrl(opts.baseUrl)
  if (!endpoint) {
    LOG.warning('Notification endpoint disabled as no "notification_endpoint" has been configured in issuer metadata')
    return
  }
  const path = determinePath(baseUrl, endpoint, { stripBasePath: true })
  LOG.log(`[OID4VCI] notification endpoint enabled at ${path}`)
  router.post(path, async (request: Request, response: Response) => {
    try {
      const notificationRequest = request.body as NotificationRequest
      LOG.log(
        `notification ${notificationRequest.event}/${notificationRequest.event_description} received for ${notificationRequest.notification_id}`,
      )
      const jwt = extractBearerToken(request.header('Authorization'))
      EVENTS.emit(NotificationStatusEventNames.OID4VCI_NOTIFICATION_RECEIVED, {
        eventName: NotificationStatusEventNames.OID4VCI_NOTIFICATION_RECEIVED,
        id: uuidv4(),
        data: notificationRequest,
        initiator: jwt,
        initiatorType: InitiatorType.EXTERNAL,
        system: System.OID4VCI,
        subsystem: SubSystem.API,
      })
      try {
        const jwtResult = await validateJWT(jwt, { accessTokenVerificationCallback: opts.accessTokenVerificationCallback })
        const accessToken = jwtResult.jwt.payload as AccessTokenRequest
        const errorOrSession = await issuer.processNotification({
          preAuthorizedCode: accessToken['pre-authorized_code'],
          /*TODO: authorizationCode*/ notification: notificationRequest,
        })
        if (errorOrSession instanceof Error) {
          EVENTS.emit(NotificationStatusEventNames.OID4VCI_NOTIFICATION_ERROR, {
            eventName: NotificationStatusEventNames.OID4VCI_NOTIFICATION_ERROR,
            id: uuidv4(),
            data: notificationRequest,
            initiator: jwtResult.jwt,
            initiatorType: InitiatorType.EXTERNAL,
            system: System.OID4VCI,
            subsystem: SubSystem.API,
          })
          return sendErrorResponse(response, 400, errorOrSession.message)
        } else {
          EVENTS.emit(NotificationStatusEventNames.OID4VCI_NOTIFICATION_PROCESSED, {
            eventName: NotificationStatusEventNames.OID4VCI_NOTIFICATION_PROCESSED,
            id: uuidv4(),
            data: notificationRequest,
            initiator: jwtResult.jwt,
            initiatorType: InitiatorType.EXTERNAL,
            system: System.OID4VCI,
            subsystem: SubSystem.API,
          })
        }
      } catch (e) {
        LOG.warning(e)
        return sendErrorResponse(response, 400, {
          error: 'invalid_token',
        })
      }
      return response.status(204).send()
    } catch (e) {
      return sendErrorResponse(
        response,
        400,
        {
          error: 'invalid_notification_request',
          error_description: (e as Error).message,
        },
        e,
      )
    }
  })
}

export function getCredentialOfferEndpoint<DIDDoc extends object>(router: Router, issuer: VcIssuer<DIDDoc>, opts?: IGetCredentialOfferEndpointOpts) {
  const path = determinePath(opts?.baseUrl, opts?.path ?? '/webapp/credential-offers/:id', { stripBasePath: true })
  LOG.log(`[OID4VCI] getCredentialOffer endpoint enabled at ${path}`)
  router.get(path, async (request: Request, response: Response) => {
    try {
      const { id } = request.params
      const session = await issuer.credentialOfferSessions.get(id)
      if (!session || !session.credentialOffer) {
        return sendErrorResponse(response, 404, {
          error: 'invalid_request',
          error_description: `Credential offer ${id} not found`,
        })
      }
      return response.json(session.credentialOffer.credential_offer)
    } catch (e) {
      return sendErrorResponse(
        response,
        500,
        {
          error: 'invalid_request',
          error_description: (e as Error).message,
        },
        e,
      )
    }
  })
}

export function deleteCredentialOfferEndpoint<DIDDoc extends object>(
  router: Router,
  issuer: VcIssuer<DIDDoc>,
  opts?: IGetCredentialOfferEndpointOpts,
) {
  const path = determinePath(opts?.baseUrl, opts?.path ?? '/webapp/credential-offers/:id', { stripBasePath: true })
  LOG.log(`[OID4VCI] deleteCredentialOffer endpoint enabled at ${path}`)
  router.delete(path, async (request: Request, response: Response) => {
    try {
      const { id } = request.params
      await issuer.deleteCredentialOfferSessionById(id)
      return response.sendStatus(204)
    } catch (e) {
      return sendErrorResponse(
        response,
        500,
        {
          error: 'invalid_request',
          error_description: (e as Error).message,
        },
        e,
      )
    }
  })
}

function buildIssuerPayloadUri(request: Request<CredentialOfferRESTRequest>, issuerPayloadPathConst?: string) {
  if (!issuerPayloadPathConst) {
    return Promise.reject(Error('issuePayloadPath must bet set for offerMode REFERENCE!'))
  }

  const protocol = request.headers['x-forwarded-proto']?.toString() ?? request.protocol
  let host = request.headers['x-forwarded-host']?.toString() ?? request.get('host')
  const forwardedPort = request.headers['x-forwarded-port']?.toString()

  if (forwardedPort && !(protocol === 'https' && forwardedPort === '443') && !(protocol === 'http' && forwardedPort === '80')) {
    host += `:${forwardedPort}`
  }

  const forwardedPrefix = request.headers['x-forwarded-prefix']?.toString() ?? ''

  return `${protocol}://${host}${forwardedPrefix}${request.baseUrl}${issuerPayloadPathConst}`
}


export function createCredentialOfferEndpoint<DIDDoc extends object>(
  router: Router,
  issuer: VcIssuer<DIDDoc>,
  opts?: ICreateCredentialOfferEndpointOpts & { baseUrl?: string },
  issuerPayloadPath?: string
) {
  const issuerPayloadPathConst = issuerPayloadPath
  const path = determinePath(opts?.baseUrl, opts?.path ?? '/webapp/credential-offers', { stripBasePath: true })

  LOG.log(`[OID4VCI] createCredentialOffer endpoint enabled at ${path}`)
  router.post(path, async (request: Request<CredentialOfferRESTRequest>, response: Response<ICreateCredentialOfferURIResponse>) => {
    try {
      const specVersion = determineSpecVersionFromOffer(request.body.original_credential_offer)
      if (specVersion < OpenId4VCIVersion.VER_1_0_13) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_client,
          error_description: 'credential offer request should be of spec version 1.0.13 or above',
        })
      }

      const grantTypes = determineGrantTypes(request.body)
      if (grantTypes.length === 0) {
        return sendErrorResponse(response, 400, { error: TokenErrorResponse.invalid_grant, error_description: 'No grant type supplied' })
      }
      const grants = request.body.grants as Grant
      const credentialConfigIds = request.body.credential_configuration_ids as string[]
      if (!credentialConfigIds || credentialConfigIds.length === 0) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_request,
          error_description: 'credential_configuration_ids missing credential_configuration_ids in credential offer payload',
        })
      }
      const qrCodeOpts = request.body.qrCodeOpts ?? opts?.qrCodeOpts
      const offerMode: CredentialOfferMode = request.body.offerMode
        ?? opts?.defaultCredentialOfferPayloadMode
        ?? 'VALUE' // default to existing mode when nothing specified


      const result = await issuer.createCredentialOfferURI({
        ...request.body,
        offerMode: offerMode,
        ...(offerMode === 'REFERENCE' && { issuerPayloadUri: buildIssuerPayloadUri(request, issuerPayloadPathConst) }),
        qrCodeOpts,
        grants
      })
      const resultResponse: ICreateCredentialOfferURIResponse = result
      if ('session' in resultResponse) {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        delete resultResponse.session
      }
      return response.json(resultResponse)
    } catch (e) {
      return sendErrorResponse(
        response,
        500,
        {
          error: TokenErrorResponse.invalid_request,
          error_description: (e as Error).message,
        },
        e,
      )
    }
  })
}

export function pushedAuthorizationEndpoint<DIDDoc extends object>(
  router: Router,
  issuer: VcIssuer<DIDDoc>,
  authRequestsData: Map<string, AuthorizationRequest>,
  opts?: ISingleEndpointOpts,
) {
  const handleHttpStatus400 = async (req: Request, res: Response, next: NextFunction) => {
    if (!req.body) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Request body must be present' })
    }
    const required = ['client_id', 'code_challenge_method', 'code_challenge', 'redirect_uri']
    const conditional = ['authorization_details', 'scope']
    try {
      validateRequestBody({ required, conditional, body: req.body })
    } catch (e: unknown) {
      return sendErrorResponse(res, 400, {
        error: 'invalid_request',
        error_description: (e as Error).message,
      })
    }
    return next()
  }

  router.post('/par', handleHttpStatus400, (req: Request, res: Response) => {
    // FIXME Fake client for testing, it needs to come from a registered client
    const client = {
      scope: ['openid', 'test'],
      redirectUris: ['http://localhost:8080/*', 'https://www.test.com/*', 'https://test.nl', 'http://*/chart', 'http:*'],
    }

    // For security reasons the redirect_uri from the request needs to be matched against the ones present in the registered client
    const matched = client.redirectUris.filter((s: string) => new RegExp(s.replace('*', '.*')).test(req.body.redirect_uri))
    if (!matched.length) {
      return sendErrorResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'redirect_uri is not valid for the given client',
      })
    }

    // The scopes from the request need to be matched against the ones present in the registered client
    if (!req.body.scope.split(',').every((scope: string) => client.scope.includes(scope))) {
      return sendErrorResponse(res, 400, {
        error: 'invalid_scope',
        error_description: 'scope is not valid for the given client',
      })
    }

    //TODO Implement authorization_details verification

    // TODO: Both UUID and requestURI need to be configurable for the server
    const uuid = uuidv4()
    const requestUri = `urn:ietf:params:oauth:request_uri:${uuid}`
    // The redirect_uri is created and set in a map, to keep track of the actual request
    authRequestsData.set(requestUri, req.body)
    // Invalidates the request_uri removing it from the mapping after it is expired, needs to be refactored because
    // some of the properties will be needed in subsequent steps if the authorization succeeds
    // TODO in the /token endpoint the code_challenge must be matched against the hashed code_verifier
    setTimeout(() => {
      authRequestsData.delete(requestUri)
    }, expiresIn * 1000)

    return res.status(201).json({ request_uri: requestUri, expires_in: expiresIn })
  })
}

export function getMetadataEndpoints<DIDDoc extends object>(router: Router, issuer: VcIssuer<DIDDoc>) {
  const credentialIssuerHandler = (request: Request, response: Response) => {
    return response.json(issuer.issuerMetadata)
  }
  router.get(WellKnownEndpoints.OPENID4VCI_ISSUER, credentialIssuerHandler)

  const authorizationServerHandler = (request: Request, response: Response) => {
    return response.json(issuer.authorizationServerMetadata)
  }
  router.get(WellKnownEndpoints.OAUTH_AS, authorizationServerHandler)
}

export function determinePath(
  baseUrl: URL | string | undefined,
  endpoint: string,
  opts?: { skipBaseUrlCheck?: boolean; prependUrl?: string; stripBasePath?: boolean },
) {
  const basePath = baseUrl ? getBasePath(baseUrl) : ''
  let path = endpoint
  if (opts?.prependUrl) {
    path = adjustUrl(path, { prepend: opts.prependUrl })
  }
  if (opts?.skipBaseUrlCheck !== true) {
    assertEndpointHasIssuerBaseUrl(baseUrl, endpoint)
  }
  if (endpoint.includes('://')) {
    path = new URL(endpoint).pathname
  }
  path = `/${trimBoth(path, '/')}`
  if (opts?.stripBasePath && path.startsWith(basePath)) {
    path = trimStart(path, basePath)
    path = `/${trimBoth(path, '/')}`
  }
  return path
}

function assertEndpointHasIssuerBaseUrl(baseUrl: URL | string | undefined, endpoint: string) {
  if (!validateEndpointHasIssuerBaseUrl(baseUrl, endpoint)) {
    throw Error(`endpoint '${endpoint}' does not have base url '${baseUrl ? getBaseUrl(baseUrl) : '<no baseurl supplied>'}'`)
  }
}

function validateEndpointHasIssuerBaseUrl(baseUrl: URL | string | undefined, endpoint: string): boolean {
  if (!endpoint) {
    return false
  } else if (!endpoint.includes('://')) {
    return true //absolute or relative path, not containing a hostname
  } else if (!baseUrl) {
    return true
  }
  return endpoint.startsWith(getBaseUrl(baseUrl))
}

export function getBaseUrl(url?: URL | string | undefined) {
  let baseUrl = url
  if (!baseUrl) {
    const envUrl = env('BASE_URL', process?.env?.ENV_PREFIX)
    if (envUrl && envUrl.length > 0) {
      baseUrl = new URL(envUrl)
    }
  }
  if (!baseUrl) {
    throw Error(`No base URL provided`)
  }
  return trimEnd(baseUrl.toString(), '/')
}

export function getBasePath(url?: URL | string) {
  const basePath = new URL(getBaseUrl(url)).pathname
  if (basePath === '' || basePath === '/') {
    return ''
  }
  return `/${trimBoth(basePath, '/')}`
}

export async function oidcAccessTokenVerifyCallback(opts: {
  credentialIssuer: string
  authorizationServer: string
  clientMetadata?: ClientMetadata
}): Promise<JWTVerifyCallback> {
  const callback = async (args: { jwt: string; kid?: string }): Promise<JwtVerifyResult> => {
    const introspection = await oidcClient.introspect(args.jwt)
    if (!introspection.active) {
      return Promise.reject(Error('Access token is not active or invalid'))
    }
    const jwt = { header: decodeProtectedHeader(args.jwt) as JWTHeader, payload: decodeJwt(args.jwt) }

    return {
      jwt,
      alg: jwt.header.alg,
      ...(jwt.header.jwk && { jwk: jwt.header.jwk }),
      ...(jwt.header.x5c && { x5c: jwt.header.x5c }),
      ...(jwt.header.kid && { kid: jwt.header.kid }),
      // We could resolve the did document here if the kid is a VM
    }
  }

  const clientMetadata = opts.clientMetadata ?? { client_id: opts.credentialIssuer }
  const oidcIssuer = await oidcDiscoverIssuer({ issuerUrl: opts.authorizationServer })
  const oidcClient = await oidcGetClient(oidcIssuer.issuer, clientMetadata)
  return callback
}
