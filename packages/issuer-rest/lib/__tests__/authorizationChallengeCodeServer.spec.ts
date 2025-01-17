import { uuidv4 } from '@sphereon/oid4vc-common'
import {
  AuthorizationChallengeError,
  CNonceState,
  CredentialIssuerMetadataOptsV1_0_13,
  CredentialOfferSession,
  IssueStatus
} from '@sphereon/oid4vci-common'
import { VcIssuer } from '@sphereon/oid4vci-issuer'
import { AuthorizationServerMetadataBuilder } from '@sphereon/oid4vci-issuer'
import { MemoryStates } from '@sphereon/oid4vci-issuer/dist/state-manager'
import { ExpressBuilder, ExpressSupport } from '@sphereon/ssi-express-support'
import { DIDDocument } from 'did-resolver'
import { Express } from 'express'
import requests from 'supertest'

import { OID4VCIServer } from '../OID4VCIServer'

const authorizationServerMetadata = new AuthorizationServerMetadataBuilder()
  .withIssuer('test-issuer')
  .withAuthorizationChallengeEndpoint('http://localhost:3456/test/authorize-challenge')
  .withResponseTypesSupported(['code', 'token', 'id_token'])
  .build()

describe('OID4VCIServer', () => {
  let app: Express
  let expressSupport: ExpressSupport
  const sessionId = 'c1413695-8744-4369-845b-c2bd0ee8d5e4'

  beforeAll(async () => {
    const credentialOfferState1: CredentialOfferSession = {
      txCode: '493536',
      notification_id: uuidv4(),
      createdAt: +new Date(),
      lastUpdatedAt: +new Date(),
      status: IssueStatus.OFFER_CREATED,
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'test_issuer',
          credentials: [
            {
              format: 'ldp_vc',
              credential_definition: {
                '@context': ['test_context'],
                types: ['VerifiableCredential'],
                credentialSubject: {},
              },
            },
          ]
        },
      },
    }
    const credentialOfferSessions = new MemoryStates<CredentialOfferSession>()
    await credentialOfferSessions.set(sessionId, credentialOfferState1)

    const vcIssuer: VcIssuer<DIDDocument> = new VcIssuer<DIDDocument>(
      {
        credential_endpoint: 'http://localhost:9000',
        authorization_challenge_endpoint: 'http://localhost:9000/authorize-challenge',
      } as CredentialIssuerMetadataOptsV1_0_13,
      authorizationServerMetadata,
      {
        cNonceExpiresIn: 300,
        credentialOfferSessions,
        cNonces: new MemoryStates<CNonceState>(),
      },
    )

    expressSupport = ExpressBuilder.fromServerOpts({
      startListening: false,
      port: 9000,
      hostname: '0.0.0.0',
    }).build({ startListening: false })
    const vcIssuerServer = new OID4VCIServer(expressSupport, {
      issuer: vcIssuer,
      baseUrl: 'http://localhost:9000',
      endpointOpts: {
        tokenEndpointOpts: {
          tokenEndpointDisabled: true
        },
        authorizationChallengeOpts: {
          enabled: true,
          verifyAuthResponseCallback: async () => true,
          createAuthRequestUriCallback: async () => '/authorize?client_id=..&request_uri=https://rp.example.com/oidc/request/1234'
        }
      },
    })
    expressSupport.start()
    app = vcIssuerServer.app
  })

  afterAll(async () => {
    if (expressSupport) {
      await expressSupport.stop()
    }
    await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  it('should return http code 400 with error invalid_request', async () => {
    const res = await requests(app)
    .post('/authorize-challenge')
    .send(`client_id=${uuidv4()}`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: AuthorizationChallengeError.invalid_request
    })
  })

  it('should return http code 400 with message No client id or auth session present', async () => {
    const res = await requests(app)
      .post('/authorize-challenge')
      .send()
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: AuthorizationChallengeError.invalid_request,
      error_description: 'No client id or auth session present'
    })
  })

  it('should return http code 400 with message Session is invalid with invalid issuer_state', async () => {
    const res = await requests(app)
      .post('/authorize-challenge')
      .send(`client_id=${uuidv4()}&issuer_state=${uuidv4()}`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: AuthorizationChallengeError.invalid_session,
      error_description: 'Session is invalid'
    })
  })

  it('should return http code 400 with error insufficient_authorization', async () => {
    const res = await requests(app)
      .post('/authorize-challenge')
      .send(`client_id=${uuidv4()}&issuer_state=${sessionId}`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: AuthorizationChallengeError.insufficient_authorization,
      auth_session: "c1413695-8744-4369-845b-c2bd0ee8d5e4",
      presentation: "/authorize?client_id=..&request_uri=https://rp.example.com/oidc/request/1234"
    })
  })

  it('should return http code 400 with message Session is invalid with invalid auth_session', async () => {
    const res = await requests(app)
      .post('/authorize-challenge')
      .send(`auth_session=${uuidv4()}&presentation_during_issuance_session=${uuidv4()}`)
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: AuthorizationChallengeError.invalid_session,
      error_description: 'Session is invalid'
    })
  })

  it('should return http code 200 with authorization_code', async () => {
    const res = await requests(app)
      .post('/authorize-challenge')
      .send(`auth_session=${sessionId}&presentation_during_issuance_session=${uuidv4()}`)
    expect(res.statusCode).toEqual(200)
    const actual = JSON.parse(res.text)
    expect(actual).toBeDefined()
    expect(actual.authorization_code).toBeDefined()
  })

})
