import { uuidv4 } from '@sphereon/oid4vc-common'
import {
  ALG_ERROR,
  AUD_ERROR,
  AuthorizationServerMetadata,
  CNonceState,
  CreateCredentialOfferURIResult,
  CREDENTIAL_MISSING_ERROR,
  CredentialConfigurationSupportedV1_0_13,
  CredentialDataSupplierInput,
  CredentialEventNames,
  CredentialIssuerMetadata,
  CredentialIssuerMetadataOptsV1_0_13,
  CredentialOfferEventNames,
  CredentialOfferMode,
  CredentialOfferSession,
  CredentialOfferV1_0_13,
  CredentialRequest,
  CredentialRequestV1_0_13,
  CredentialResponse,
  DID_NO_DIDDOC_ERROR,
  EVENTS,
  IAT_ERROR,
  ISSUER_CONFIG_ERROR,
  IssueStatus,
  IStateManager,
  JsonLdIssuerCredentialDefinition,
  JWT_VERIFY_CONFIG_ERROR,
  JWTVerifyCallback,
  JwtVerifyResult,
  KID_DID_NO_DID_ERROR,
  KID_JWK_X5C_ERROR,
  NO_ISS_IN_AUTHORIZATION_CODE_CONTEXT,
  NotificationRequest,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  PRE_AUTH_GRANT_LITERAL,
  QRCodeOpts,
  StatusListOpts,
  TokenErrorResponse,
  toUniformCredentialOfferRequest,
  TxCode,
  TYP_ERROR,
  URIState
} from '@sphereon/oid4vci-common'
import {
  CompactSdJwtVc,
  CredentialMapper,
  InitiatorType,
  SubSystem,
  System,
  W3CVerifiableCredential
} from '@sphereon/ssi-types'
import ShortUUID from 'short-uuid'

import {
  assertValidPinNumber,
  createCredentialOfferObject,
  createCredentialOfferURIFromObject,
  CredentialOfferGrantInput
} from './functions'
import { LookupStateManager } from './state-manager'
import {
  CredentialDataSupplier,
  CredentialDataSupplierArgs,
  CredentialIssuanceInput,
  CredentialSignerCallback
} from './types'


import { LOG } from './index'

const shortUUID = ShortUUID()

export class VcIssuer<DIDDoc extends object> {
  private readonly _issuerMetadata: CredentialIssuerMetadataOptsV1_0_13
  private readonly _authorizationServerMetadata: AuthorizationServerMetadata
  private readonly _defaultCredentialOfferBaseUri?: string
  private readonly _credentialSignerCallback?: CredentialSignerCallback<DIDDoc>
  private readonly _jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
  private readonly _credentialDataSupplier?: CredentialDataSupplier
  private readonly _credentialOfferSessions: IStateManager<CredentialOfferSession>
  private readonly _cNonces: IStateManager<CNonceState>
  private readonly _uris?: IStateManager<URIState>
  private readonly _cNonceExpiresIn: number

  constructor(
    issuerMetadata: CredentialIssuerMetadataOptsV1_0_13,
    authorizationServerMetadata: AuthorizationServerMetadata,
    args: {
      txCode?: TxCode
      baseUri?: string
      credentialOfferSessions: IStateManager<CredentialOfferSession>
      defaultCredentialOfferBaseUri?: string
      cNonces: IStateManager<CNonceState>
      uris?: IStateManager<URIState>
      credentialSignerCallback?: CredentialSignerCallback<DIDDoc>
      jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
      credentialDataSupplier?: CredentialDataSupplier
      cNonceExpiresIn?: number | undefined // expiration duration in seconds
    },
  ) {
    this.setDefaultTokenEndpoint(issuerMetadata)
    this._issuerMetadata = issuerMetadata
    this._authorizationServerMetadata = authorizationServerMetadata
    this._defaultCredentialOfferBaseUri = args.defaultCredentialOfferBaseUri
    this._credentialOfferSessions = args.credentialOfferSessions
    this._cNonces = args.cNonces
    this._uris = args.uris
    this._credentialSignerCallback = args?.credentialSignerCallback
    this._jwtVerifyCallback = args?.jwtVerifyCallback
    this._credentialDataSupplier = args?.credentialDataSupplier
    this._cNonceExpiresIn = (args?.cNonceExpiresIn ?? (process.env.C_NONCE_EXPIRES_IN ? parseInt(process.env.C_NONCE_EXPIRES_IN) : 300)) as number
  }

  public async getCredentialOfferSessionById(id: string, lookup?: 'uri' | 'id' | 'preAuthorizedCode'): Promise<CredentialOfferSession> {
    if (!this.uris) {
      return Promise.reject(Error('Cannot lookup credential offer by id if URI state manager is not set'))
    }
    if (lookup) {
      return new LookupStateManager<URIState, CredentialOfferSession>(this.uris, this._credentialOfferSessions, lookup).getAsserted(id)
    }
    const session = await this._credentialOfferSessions.get(id)
    if (!session) {
      return Promise.reject(Error(`No session found for id ${id}`))
    }
    return session
  }

  public async deleteCredentialOfferSessionById(id: string, lookup: 'uri' | 'id' = 'id'): Promise<CredentialOfferSession> {
    const session = await this.getCredentialOfferSessionById(id, lookup)
    if (session) {
      if (session.preAuthorizedCode && (await this._credentialOfferSessions.has(session.preAuthorizedCode))) {
        await this._credentialOfferSessions.delete(session.preAuthorizedCode)
      }
      if (session.issuerState && (await this._credentialOfferSessions.has(session.issuerState))) {
        await this._credentialOfferSessions.delete(session.issuerState)
      }
    }
    return session
  }

  public async processNotification({
    preAuthorizedCode,
    issuerState,
    notification,
  }: {
    preAuthorizedCode?: string
    issuerState?: string
    notification: NotificationRequest
  }): Promise<Error | CredentialOfferSession> {
    const sessionId = preAuthorizedCode ?? issuerState
    const session = sessionId ? await this.getCredentialOfferSessionById(sessionId) : undefined
    if (!session || !sessionId) {
      LOG.error(`No session or session id found ${sessionId}`)
      return Error('invalid_notification_request')
    }
    if (notification.notification_id !== session.notification_id) {
      LOG.error(`Notification id ${notification.notification_id} not found in session. session notification id ${session.notification_id}`)
      return Error('invalid_notification_id')
    } else if (session.notification) {
      LOG.info(`Overwriting existing notification, as a new notification came in ${session.notification_id}`)
    }
    await this.updateSession({ preAuthorizedCode: preAuthorizedCode, issuerState: issuerState, notification })
    LOG.info(`Processed notification ${notification} for ${session.notification_id}`)
    return session
  }

  public async createCredentialOfferURI(opts: {
    offerMode: CredentialOfferMode
    issuerPayloadUri?: string
    grants?: CredentialOfferGrantInput
    credential_configuration_ids?: Array<string>
    credentialDefinition?: JsonLdIssuerCredentialDefinition
    credentialOfferUri?: string
    credentialDataSupplierInput?: CredentialDataSupplierInput // Optional storage that can help the credential Data Supplier. For instance to store credential input data during offer creation, if no additional data can be supplied later on
    baseUri?: string
    scheme?: string
    pinLength?: number
    qrCodeOpts?: QRCodeOpts,
    statusListOpts?: Array<StatusListOpts>
  }): Promise<CreateCredentialOfferURIResult> {
    const { offerMode, issuerPayloadUri, credential_configuration_ids, statusListOpts } = opts
    if (offerMode === 'REFERENCE' && !issuerPayloadUri) {
      return Promise.reject(Error('issuePayloadPath must bet set for offerMode REFERENCE!'))
    }

    const grants = opts.grants ? { ...opts.grants } : {}
    // for backwards compat, would be better if user sets the prop on the grants directly
    if (opts.pinLength !== undefined) {
      if (grants[PRE_AUTH_GRANT_LITERAL]) {
        grants[PRE_AUTH_GRANT_LITERAL].tx_code = {
          ...grants[PRE_AUTH_GRANT_LITERAL].tx_code,
          length: grants[PRE_AUTH_GRANT_LITERAL].tx_code?.length ?? opts.pinLength,
        }
      }
    }
    if (grants[PRE_AUTH_GRANT_LITERAL]?.tx_code && !grants[PRE_AUTH_GRANT_LITERAL]?.tx_code?.length) {
      grants[PRE_AUTH_GRANT_LITERAL].tx_code.length = 4
    }


    const baseUri = opts?.baseUri ?? this.defaultCredentialOfferBaseUri
    const credentialOfferObject = createCredentialOfferObject(this._issuerMetadata, {
      ...opts,
      grants,
      credentialOffer: credential_configuration_ids
        ? {
            credential_issuer: this._issuerMetadata.credential_issuer,
            credential_configuration_ids,
          }
        : undefined,
    })

    const preAuthGrant = credentialOfferObject.credential_offer.grants?.[PRE_AUTH_GRANT_LITERAL]
    const authGrant = credentialOfferObject.credential_offer.grants?.authorization_code

    const preAuthorizedCode = preAuthGrant?.['pre-authorized_code']
    const issuerState = authGrant?.issuer_state
    const txCode = preAuthGrant?.tx_code

    let userPin: string | undefined
    if (preAuthGrant?.tx_code) {
      const pinLength = preAuthGrant.tx_code.length ?? 4

      userPin = ('' + Math.round((Math.pow(10, pinLength) - 1) * Math.random())).padStart(pinLength, '0')
      assertValidPinNumber(userPin, pinLength)
    }
    const createdAt = +new Date()
    const lastUpdatedAt = createdAt
    if (offerMode === 'REFERENCE') {
      if (!this.uris) {
        throw Error('No URI state manager set, whilst apparently credential offer URIs are being used')
      }
      const credentialOfferCorrelationId = shortUUID.generate()// TODO allow to be supplied
      credentialOfferObject.credential_offer_uri = opts.credentialOfferUri ?? `${issuerPayloadUri?.replace(':id', credentialOfferCorrelationId)}` // TODO how is this going to work with auth code flow?
      await this.uris.set(credentialOfferCorrelationId, {
        uri: credentialOfferObject.credential_offer_uri,
        createdAt: createdAt,
        preAuthorizedCode,
        issuerState,
        credentialOfferCorrelationId
      })
    }


    const credentialOffer = await toUniformCredentialOfferRequest(
      {
        credential_offer: credentialOfferObject.credential_offer,
        credential_offer_uri: credentialOfferObject.credential_offer_uri,
      } as CredentialOfferV1_0_13,
      {
        version: OpenId4VCIVersion.VER_1_0_13,
        resolve: false, // We are creating the object, so do not resolve
      },
    )

    const status = IssueStatus.OFFER_CREATED
    const session: CredentialOfferSession = {
      preAuthorizedCode,
      issuerState,
      createdAt,
      lastUpdatedAt,
      status,
      notification_id: uuidv4(),
      ...(userPin && { txCode: userPin }), // We used to use userPin according to older specs. We map these onto txCode now. If both are used, txCode in the end wins, even if they are different
      ...(opts.credentialDataSupplierInput && { credentialDataSupplierInput: opts.credentialDataSupplierInput }),
      credentialOffer,
      statusLists: statusListOpts
    }

    if (preAuthorizedCode) {
      await this.credentialOfferSessions.set(preAuthorizedCode, session)
    }
    // todo: check whether we could have the same value for issuer state and pre auth code if both are supported.
    if (issuerState) {
      await this.credentialOfferSessions.set(issuerState, session)
    }

    const uri = createCredentialOfferURIFromObject(credentialOffer, offerMode, { ...opts, baseUri })
    let qrCodeDataUri: string | undefined
    if (opts.qrCodeOpts) {
      const { AwesomeQR } = await import('awesome-qr')
      const qrCode = new AwesomeQR({ ...opts.qrCodeOpts, text: uri })
      qrCodeDataUri = `data:image/png;base64,${(await qrCode.draw())!.toString('base64')}`
    }
    EVENTS.emit(CredentialOfferEventNames.OID4VCI_OFFER_CREATED, {
      eventName: CredentialOfferEventNames.OID4VCI_OFFER_CREATED,
      id: uuidv4(),
      data: uri,
      initiator: '<unknown>',
      initiatorType: InitiatorType.EXTERNAL,
      system: System.OID4VCI,
      // todo: Issuer
      subsystem: SubSystem.API,
    })
    return {
      session,
      uri,
      qrCodeDataUri,
      txCode,
      ...(userPin !== undefined && { userPin, pinLength: userPin?.length ?? 0 }),
    }
  }

  /**
   * issueCredentialFromIssueRequest
   * @param opts issuerRequestParams
   *  - issueCredentialsRequest the credential request
   *  - issuerState the state of the issuer
   *  - jwtVerifyCallback callback that verifies the Proof of Possession JWT
   *  - issuerCallback callback to issue a Verifiable Credential
   *  - cNonce an existing c_nonce
   */
  public async issueCredential(opts: {
    credentialRequest: CredentialRequest
    credential?: CredentialIssuanceInput
    credentialDataSupplier?: CredentialDataSupplier
    credentialDataSupplierInput?: CredentialDataSupplierInput
    newCNonce?: string
    cNonceExpiresIn?: number // expiration duration in seconds
    tokenExpiresIn?: number // expiration duration in seconds
    jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
    credentialSignerCallback?: CredentialSignerCallback<DIDDoc>
    responseCNonce?: string
  }): Promise<CredentialResponse> {
    /*if (!('credential_identifier' in opts.credentialRequest)) {
      throw new Error('credential request should be of spec version 1.0.13 or above')
    }*/
    const credentialRequest = opts.credentialRequest as CredentialRequestV1_0_13
    let preAuthorizedCode: string | undefined
    let issuerState: string | undefined
    try {
      if (!('credential_identifier' in credentialRequest) && !credentialRequest.format) {
        throw new Error('credential request should either have a credential_identifier or format and type')
      }
      if (credentialRequest.format && !this.isMetadataSupportCredentialRequestFormat(credentialRequest.format)) {
        throw new Error(TokenErrorResponse.invalid_request)
      }
      const validated = await this.validateCredentialRequestProof({
        ...opts,
        tokenExpiresIn: opts.tokenExpiresIn ?? 180,
      })
      preAuthorizedCode = validated.preAuthorizedCode
      issuerState = validated.issuerState

      const { preAuthSession, authSession, cNonceState, jwtVerifyResult } = validated
      const did = jwtVerifyResult.did
      const jwk = jwtVerifyResult.jwk
      const kid = jwtVerifyResult.kid
      const newcNonce = opts.newCNonce ? opts.newCNonce : uuidv4()
      const newcNonceState = {
        cNonce: newcNonce,
        createdAt: +new Date(),
        ...(authSession?.issuerState && { issuerState: authSession.issuerState }),
        ...(preAuthSession && { preAuthorizedCode: preAuthSession.preAuthorizedCode }),
      }
      await this.cNonces.set(newcNonce, newcNonceState)

      if (!opts.credential && this._credentialDataSupplier === undefined && opts.credentialDataSupplier === undefined) {
        throw Error(`Either a credential needs to be supplied or a credentialDataSupplier`)
      }
      let credential: CredentialIssuanceInput | undefined
      let format: OID4VCICredentialFormat | undefined = credentialRequest.format
      let signerCallback: CredentialSignerCallback<DIDDoc> | undefined = opts.credentialSignerCallback
      const session: CredentialOfferSession | undefined = preAuthorizedCode && preAuthSession ? preAuthSession : authSession
      if (opts.credential) {
        credential = opts.credential
      } else {
        const credentialDataSupplier: CredentialDataSupplier | undefined =
          typeof opts.credentialDataSupplier === 'function' ? opts.credentialDataSupplier : this._credentialDataSupplier
        if (typeof credentialDataSupplier !== 'function') {
          throw Error('Data supplier is mandatory if no credential is supplied')
        }
        if (!session) {
          throw Error('Either a preAuth or Auth session is required, none found')
        }
        const credentialOffer = session.credentialOffer
        if (!credentialOffer) {
          throw Error('Credential Offer missing')
        }
        const credentialDataSupplierInput = opts.credentialDataSupplierInput ?? session.credentialDataSupplierInput

        const result = await credentialDataSupplier({
          ...cNonceState,
          credentialRequest: opts.credentialRequest,
          credentialSupplierConfig: this._issuerMetadata.credential_supplier_config,
          credentialOffer /*todo: clientId: */,
          ...(credentialDataSupplierInput && { credentialDataSupplierInput }),
        } as CredentialDataSupplierArgs)
        credential = result.credential
        if (result.format) {
          format = result.format
        }
        if (typeof result.signCallback === 'function') {
          signerCallback = result.signCallback
        }
      }
      if (!credential) {
        throw Error('A credential needs to be supplied at this point')
      }
      // Bind credential to the provided proof of possession
      if (CredentialMapper.isSdJwtDecodedCredentialPayload(credential) && (kid || jwk) && !credential.cnf) {
        if (kid) {
          credential.cnf = {
            kid,
          }
        } else if (jwk) {
          credential.cnf = {
            jwk,
          }
        }
      } else if (did && !CredentialMapper.isSdJwtDecodedCredentialPayload(credential) && credential.credentialSubject !== undefined) {
        const credentialSubjects = Array.isArray(credential.credentialSubject) ? credential.credentialSubject : [credential.credentialSubject]
        credentialSubjects.map((subject) => {
          if (!subject.id) {
            subject.id = did
          }
          return subject
        })
        credential.credentialSubject = Array.isArray(credential.credentialSubject) ? credentialSubjects : credentialSubjects[0]
      } else {
        // Mdoc Format
        // Nothing to do here
      }

      let issuer: string | undefined = undefined
      if (credential.iss) {
        issuer = credential.iss
      } else if (credential.issuer) {
        if (typeof credential.issuer === 'string') {
          issuer = credential.issuer
        } else if (typeof credential.issuer === 'object' && 'id' in credential.issuer && typeof credential.issuer.id === 'string') {
          issuer = credential.issuer.id
        }
      }

      const verifiableCredential = await this.issueCredentialImpl(
        {
          credentialRequest: opts.credentialRequest,
          format,
          credential,
          jwtVerifyResult,
          issuer,
          ...(session && {statusLists: session.statusLists})
        },
        signerCallback,
      )
      // TODO implement acceptance_token (deferred response)
      // TODO update verification accordingly
      if (!verifiableCredential) {
        // credential: OPTIONAL. Contains issued Credential. MUST be present when acceptance_token is not returned. MAY be a JSON string or a JSON object, depending on the Credential format. See Appendix E for the Credential format specific encoding requirements
        throw new Error(CREDENTIAL_MISSING_ERROR)
      }
      // remove the previous nonce
      await this.cNonces.delete(cNonceState.cNonce)

      let notification_id: string | undefined

      if (preAuthorizedCode && preAuthSession) {
        preAuthSession.lastUpdatedAt = +new Date()
        preAuthSession.status = IssueStatus.CREDENTIAL_ISSUED
        notification_id = preAuthSession.notification_id
        await this._credentialOfferSessions.set(preAuthorizedCode, preAuthSession)
      } else if (issuerState && authSession) {
        // If both were set we used the pre auth flow above as well, hence the else if
        authSession.lastUpdatedAt = +new Date()
        authSession.status = IssueStatus.CREDENTIAL_ISSUED
        notification_id = authSession.notification_id
        await this._credentialOfferSessions.set(issuerState, authSession)
      }

      const response: CredentialResponse = {
        credential: verifiableCredential,
        // format: credentialRequest.format,
        c_nonce: newcNonce,
        c_nonce_expires_in: this._cNonceExpiresIn,
        ...(notification_id && { notification_id }),
      }
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const experimentalSubjectIssuance = opts.credentialRequest.credential_subject_issuance
      if (experimentalSubjectIssuance?.subject_proof_mode) {
        if (experimentalSubjectIssuance.subject_proof_mode !== 'proof_replace') {
          throw Error('Only proof replace is supported currently')
        }
        response.transaction_id = authSession?.issuerState
        response.credential_subject_issuance = experimentalSubjectIssuance
      }
      return response
    } catch (error: unknown) {
      await this.updateSession({ preAuthorizedCode, issuerState, error })
      throw error
    }
  }

  private async updateSession({
    preAuthorizedCode,
    error,
    issuerState,
    notification,
  }: {
    preAuthorizedCode?: string
    issuerState?: string
    error?: unknown
    notification?: NotificationRequest
  }) {
    let issueState: IssueStatus | undefined = undefined
    if (error) {
      issueState = IssueStatus.ERROR
    } else if (notification) {
      if (notification.event == 'credential_accepted') {
        issueState = IssueStatus.NOTIFICATION_CREDENTIAL_ACCEPTED
      } else if (notification.event == 'credential_deleted') {
        issueState = IssueStatus.NOTIFICATION_CREDENTIAL_DELETED
      } else if (notification.event == 'credential_failure') {
        issueState = IssueStatus.NOTIFICATION_CREDENTIAL_FAILURE
      }
    }

    if (preAuthorizedCode) {
      const preAuthSession = await this._credentialOfferSessions.get(preAuthorizedCode)
      if (preAuthSession) {
        preAuthSession.lastUpdatedAt = +new Date()
        if (issueState) {
          preAuthSession.status = issueState
        }
        if (error) {
          preAuthSession.error = error instanceof Error ? error.message : error?.toString()
        }
        preAuthSession.notification_id
        if (notification) {
          preAuthSession.notification = notification
        }
        await this._credentialOfferSessions.set(preAuthorizedCode, preAuthSession)
      }
    }
    if (issuerState) {
      const authSession = await this._credentialOfferSessions.get(issuerState)
      if (authSession) {
        authSession.lastUpdatedAt = +new Date()
        if (issueState) {
          authSession.status = issueState
        }
        if (error) {
          authSession.error = error instanceof Error ? error.message : error?.toString()
        }
        if (notification) {
          authSession.notification = notification
        }
        await this._credentialOfferSessions.set(issuerState, authSession)
      }
    }
  }

  /*
    private async retrieveGrantsAndCredentialOfferSession(id: string): Promise<{
      clientId?: string;
      grants?: Grant,
      session: CredentialOfferSession
    }> {
      const session: CredentialOfferSession | undefined = await this._credentialOfferSessions.getAsserted(id)
      const clientId = session?.clientId
      const grants = session?.credentialOffer?.credential_offer?.grants
      if (!grants?.authorization_code?.issuer_state && !grants?.[PRE_AUTH_GRANT_LITERAL]?.[PRE_AUTH_CODE_LITERAL]) {
        throw new Error(GRANTS_MUST_NOT_BE_UNDEFINED)
      }
      return { session, clientId, grants }
    }*/

  private async validateCredentialRequestProof({
    credentialRequest,
    jwtVerifyCallback,
    tokenExpiresIn,
  }: {
    credentialRequest: CredentialRequest
    tokenExpiresIn: number // expiration duration in seconds
    // grants?: Grant,
    clientId?: string
    jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
  }) {
    let preAuthorizedCode: string | undefined
    let issuerState: string | undefined

    const supportedIssuanceFormats = ['jwt_vc_json', 'jwt_vc_json-ld', 'vc+sd-jwt', 'ldp_vc', 'mso_mdoc']
    try {
      if (credentialRequest.format && !supportedIssuanceFormats.includes(credentialRequest.format)) {
        throw Error(`Format ${credentialRequest.format} not supported yet`)
      } else if (typeof this._jwtVerifyCallback !== 'function' && typeof jwtVerifyCallback !== 'function') {
        throw new Error(JWT_VERIFY_CONFIG_ERROR)
      } else if (!credentialRequest.proof) {
        throw Error('Proof of possession is required. No proof value present in credential request')
      }

      const jwtVerifyResult = jwtVerifyCallback
        ? await jwtVerifyCallback(credentialRequest.proof)
        : // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          await this._jwtVerifyCallback!(credentialRequest.proof)

      const { didDocument, did, jwt } = jwtVerifyResult
      const { header, payload } = jwt
      const { iss, aud, iat, nonce } = payload
      if (!nonce) {
        throw Error('No nonce was found in the Proof of Possession')
      }
      const cNonceState = await this.cNonces.getAsserted(nonce)
      preAuthorizedCode = cNonceState.preAuthorizedCode
      issuerState = cNonceState.issuerState
      const createdAt = cNonceState.createdAt
      // The verify callback should set the correct values, but let's look at the JWT ourselves to to be sure
      const alg = jwtVerifyResult.alg ?? header.alg
      const kid = jwtVerifyResult.kid ?? header.kid
      const jwk = jwtVerifyResult.jwk ?? header.jwk
      const x5c = jwtVerifyResult.x5c ?? header.x5c
      const typ = header.typ

      if (typ !== 'openid4vci-proof+jwt') {
        throw Error(TYP_ERROR)
      } else if (!alg) {
        throw Error(ALG_ERROR)
      } else if (!([kid, jwk, x5c].filter((x) => !!x).length === 1)) {
        // only 1 is allowed, but need to look into whether jwk and x5c are allowed together
        throw Error(KID_JWK_X5C_ERROR)
      } else if (kid && !did) {
        if (!jwk && !x5c) {
          // Make sure the callback function extracts the DID from the kid
          throw Error(KID_DID_NO_DID_ERROR)
        } else {
          // If JWK or x5c is present, log the information and proceed
          console.log(`KID present but no DID, using JWK or x5c`)
        }
      } else if (did && !didDocument) {
        // Make sure the callback function does DID resolution when a did is present
        throw Error(DID_NO_DIDDOC_ERROR)
      }

      const preAuthSession = preAuthorizedCode ? await this.credentialOfferSessions.get(preAuthorizedCode) : undefined
      const authSession = issuerState ? await this.credentialOfferSessions.get(issuerState) : undefined
      if (!preAuthSession && !authSession) {
        throw Error('Either a pre-authorized code or issuer state needs to be present')
      }
      if (preAuthSession) {
        if (!preAuthSession.preAuthorizedCode || preAuthSession.preAuthorizedCode !== preAuthorizedCode) {
          throw Error('Invalid pre-authorized code')
        }
        preAuthSession.lastUpdatedAt = +new Date()
        preAuthSession.status = IssueStatus.CREDENTIAL_REQUEST_RECEIVED
        await this._credentialOfferSessions.set(preAuthorizedCode, preAuthSession)
      }
      if (authSession) {
        if (!authSession.issuerState || authSession.issuerState !== issuerState) {
          throw Error('Invalid issuer state')
        }
        authSession.lastUpdatedAt = +new Date()
        authSession.status = IssueStatus.CREDENTIAL_REQUEST_RECEIVED
      }

      // https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1
      // A client MAY use the "client_id" request parameter to identify itself
      // when sending requests to the token endpoint.  In the
      // "authorization_code" "grant_type" request to the token endpoint, an
      // unauthenticated client MUST send its "client_id" to prevent itself
      // from inadvertently accepting a code intended for a client with a
      // different "client_id".  This protects the client from substitution of
      // the authentication code.  (It provides no additional security for the
      // protected resource.)
      if (!iss && authSession?.credentialOffer.credential_offer?.grants?.authorization_code) {
        throw new Error(NO_ISS_IN_AUTHORIZATION_CODE_CONTEXT)
      }
      // iss: OPTIONAL (string). The value of this claim MUST be the client_id of the client making the credential request.
      // This claim MUST be omitted if the Access Token authorizing the issuance call was obtained from a Pre-Authorized Code Flow through anonymous access to the Token Endpoint.
      // TODO We need to investigate further what the comment above means, because it's not clear if the client or the user may be authorized anonymously
      // if (iss && grants && grants[PRE_AUTH_GRANT_LITERAL]) {
      //   throw new Error(ISS_PRESENT_IN_PRE_AUTHORIZED_CODE_CONTEXT)
      // }
      /*if (iss && iss !== clientId) {
        throw new Error(ISS_MUST_BE_CLIENT_ID + `iss: ${iss}, client_id: ${clientId}`)
      }*/
      if (!aud || aud !== this._issuerMetadata.credential_issuer) {
        throw new Error(AUD_ERROR)
      }
      if (!iat) {
        throw new Error(IAT_ERROR)
      } else if (iat > Math.round(createdAt / 1000) + tokenExpiresIn) {
        // createdAt is in milliseconds whilst iat and tokenExpiresIn are in seconds
        throw new Error(IAT_ERROR)
      }
      // todo: Add a check of iat against current TS on server with a skew

      return { jwtVerifyResult, preAuthorizedCode, preAuthSession, issuerState, authSession, cNonceState }
    } catch (error: unknown) {
      await this.updateSession({ preAuthorizedCode, issuerState, error })
      throw error
    }
  }

  private isMetadataSupportCredentialRequestFormat(requestFormat: string | string[]): boolean {
    if (!this._issuerMetadata.credential_configurations_supported) {
      return false
    }
    for (const credentialSupported of Object.values(
      this._issuerMetadata['credential_configurations_supported'] as Record<string, CredentialConfigurationSupportedV1_0_13>,
    )) {
      if (!Array.isArray(requestFormat) && credentialSupported.format === requestFormat) {
        return true
      } else if (Array.isArray(requestFormat)) {
        for (const format of requestFormat as string[]) {
          if (credentialSupported.format === format) {
            return true
          }
        }
      }
    }

    return false
  }

  private async issueCredentialImpl(
    opts: {
      credentialRequest: CredentialRequest
      credential: CredentialIssuanceInput
      jwtVerifyResult: JwtVerifyResult<DIDDoc>
      format?: OID4VCICredentialFormat
      issuer?: string
      statusLists?: Array<StatusListOpts>
    },
    issuerCallback?: CredentialSignerCallback<DIDDoc>,
  ): Promise<W3CVerifiableCredential | CompactSdJwtVc> {
    if ((!opts.credential && !opts.credentialRequest) || !this._credentialSignerCallback) {
      throw new Error(ISSUER_CONFIG_ERROR)
    }
    const credential = issuerCallback ? await issuerCallback(opts) : await this._credentialSignerCallback(opts)

    // TODO: Create builder
    EVENTS.emit(CredentialEventNames.OID4VCI_CREDENTIAL_ISSUED, {
      eventName: CredentialEventNames.OID4VCI_CREDENTIAL_ISSUED,
      id: uuidv4(),
      data: credential,
      // TODO: Format, request etc
      initiator: opts.issuer ?? '<unknown>',
      initiatorType: InitiatorType.EXTERNAL,
      system: System.OID4VCI,
      subsystem: SubSystem.VC_ISSUER,
    })

    return credential
  }

  private setDefaultTokenEndpoint(issuerMetadata: Partial<CredentialIssuerMetadata>) {
    if (!issuerMetadata.token_endpoint) {
      issuerMetadata.token_endpoint = `${issuerMetadata.credential_issuer}/token`
    }
  }

  get credentialSignerCallback(): CredentialSignerCallback<DIDDoc> | undefined {
    return this._credentialSignerCallback
  }

  get jwtVerifyCallback(): JWTVerifyCallback<DIDDoc> | undefined {
    return this._jwtVerifyCallback
  }

  get credentialDataSupplier(): CredentialDataSupplier | undefined {
    return this._credentialDataSupplier
  }

  get uris(): IStateManager<URIState> | undefined {
    return this._uris
  }

  get cNonceExpiresIn(): number {
    return this._cNonceExpiresIn
  }

  public get credentialOfferSessions(): IStateManager<CredentialOfferSession> {
    return this._credentialOfferSessions
  }

  public get cNonces(): IStateManager<CNonceState> {
    return this._cNonces
  }

  get defaultCredentialOfferBaseUri(): string | undefined {
    return this._defaultCredentialOfferBaseUri
  }

  public get issuerMetadata() {
    return this._issuerMetadata
  }

  public get authorizationServerMetadata() {
    return this._authorizationServerMetadata
  }
}
