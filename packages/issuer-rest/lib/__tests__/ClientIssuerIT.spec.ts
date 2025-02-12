import { KeyObject } from 'crypto'

import * as didKeyDriver from '@digitalcredentials/did-method-key'
import { OpenID4VCIClientV1_0_13 } from '@sphereon/oid4vci-client'
import {
  AccessTokenResponse,
  Alg,
  CredentialConfigurationSupportedV1_0_13,
  CredentialOfferSession,
  IssuerCredentialSubjectDisplay,
  IssueStatus,
  Jwt,
  JWTHeader,
  JWTPayload,
  OpenId4VCIVersion,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTH_GRANT_LITERAL
} from '@sphereon/oid4vci-common'
import { AuthorizationServerMetadataBuilder } from '@sphereon/oid4vci-issuer'
import { VcIssuer } from '@sphereon/oid4vci-issuer/dist/VcIssuer'
import { CredentialSupportedBuilderV1_13, VcIssuerBuilder } from '@sphereon/oid4vci-issuer/dist/builder'
import { MemoryStates } from '@sphereon/oid4vci-issuer/dist/state-manager'
import { ExpressBuilder, ExpressSupport } from '@sphereon/ssi-express-support'
import { IProofPurpose, IProofType } from '@sphereon/ssi-types'
import { DIDDocument } from 'did-resolver'
import * as jose from 'jose'
import requests from 'supertest'

import { OID4VCIServer } from '../OID4VCIServer'

const ISSUER_URL = 'http://localhost:3456/test'

let expressSupport: ExpressSupport

let subjectKeypair: KeyPair // Proof of Possession JWT
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let subjectDIDKey: { didDocument: any; keyPairs: any; methodFor: any } // Json LD VC issuance

export const generateDid = async () => {
  const didKD = didKeyDriver.driver()
  const { didDocument, keyPairs, methodFor } = await didKD.generate()
  return { didDocument, keyPairs, methodFor }
}

interface KeyPair {
  publicKey: KeyObject
  privateKey: KeyObject
}

jest.setTimeout(15000)

describe('VcIssuer', () => {
  let vcIssuer: VcIssuer<DIDDocument>
  let server: OID4VCIServer<DIDDocument>
  let accessToken: AccessTokenResponse
  const issuerState = 'previously-created-state'
  // const clientId = 'sphereon:wallet'
  const preAuthorizedCode = 'test_code'

  const authorizationServerMetadata = new AuthorizationServerMetadataBuilder()
    .withIssuer(ISSUER_URL)
    .withCredentialEndpoint('http://localhost:3456/test/credential-endpoint')
    .withTokenEndpoint('http://localhost:3456/test/token')
    .withAuthorizationEndpoint('https://token-endpoint.example.com/authorize')
    .withAuthorizationChallengeEndpoint('http://localhost:3456/test/authorize-challenge')
    .withTokenEndpointAuthMethodsSupported(['none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post'])
    .withResponseTypesSupported(['code', 'token', 'id_token'])
    .withScopesSupported(['openid', 'abcdef'])
    .build()
  /*const preAuthorizedCode1 = 'SplxlOBeZQQYbYS6WxSbIA1'
  const preAuthorizedCode2 = 'SplxlOBeZQQYbYS6WxSbIA2'
  const preAuthorizedCode3 = 'SplxlOBeZQQYbYS6WxSbIA3'
*/
  beforeAll(async () => {
    jest.clearAllMocks()

    const { privateKey, publicKey } = await jose.generateKeyPair('ES256')
    subjectKeypair = { publicKey: publicKey as KeyObject, privateKey: privateKey as KeyObject }
    subjectDIDKey = await generateDid()

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const accessTokenSignerCallback = async (jwt: Jwt, kid?: string): Promise<string> => {
      const privateKey = (await jose.generateKeyPair(Alg.ES256)).privateKey as KeyObject
      return new jose.SignJWT({ ...jwt.payload }).setProtectedHeader({ ...jwt.header, alg: Alg.ES256 }).sign(privateKey)
    }

    const credentialsSupported: Record<string, CredentialConfigurationSupportedV1_0_13> = new CredentialSupportedBuilderV1_13()
      .withCredentialSigningAlgValuesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withCredentialName('UniversityDegree_JWT')
      .withCredentialDefinition({
        type: ['VerifiableCredential', 'UniversityDegree_JWT'],
      })
      .withCredentialSupportedDisplay({
        name: 'University Credential',
        locale: 'en-US',
        logo: {
          url: 'https://exampleuniversity.com/public/logo.png',
          alt_text: 'a square logo of a university',
        },
        background_color: '#12107c',
        text_color: '#FFFFFF',
      })
      .addCredentialSubjectPropertyDisplay('given_name', {
        name: 'given name',
        locale: 'en-US',
      } as IssuerCredentialSubjectDisplay)
      .build()
    const stateManager = new MemoryStates<CredentialOfferSession>()

    const credential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: 'did:key:test',
      issuanceDate: new Date().toISOString(),
      credentialSubject: {},
    }

    vcIssuer = new VcIssuerBuilder<DIDDocument>()
      .withAuthorizationMetadata(authorizationServerMetadata)
      .withCredentialEndpoint('http://localhost:3456/test/credential-endpoint')
      .withDefaultCredentialOfferBaseUri('http://localhost:3456/test')
      .withCredentialIssuer(ISSUER_URL)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialConfigurationsSupported(credentialsSupported)
      .withCredentialOfferStateManager(stateManager)
      .withInMemoryCNonceState()
      .withInMemoryCredentialOfferURIState()
      .withCredentialDataSupplier(() =>
        Promise.resolve({
          format: 'ldp_vc',
          credential,
        }),
      )
      .withCredentialSignerCallback(() =>
        Promise.resolve({
          ...credential,
          proof: {
            type: IProofType.JwtProof2020,
            jwt: 'ye.ye.ye',
            created: new Date().toISOString(),
            proofPurpose: IProofPurpose.assertionMethod,
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf',
          },
        }),
      )
      .withJWTVerifyCallback((args: { jwt: string; kid?: string }) => {
        const header = jose.decodeProtectedHeader(args.jwt)
        const payload = jose.decodeJwt(args.jwt)

        const kid = header.kid ?? args.kid
        const did = kid!.split('#')[0]
        const didDocument: DIDDocument = {
          '@context': 'https://www.w3.org/ns/did/v1',
          id: did,
        }
        const alg = header.alg ?? 'ES256k'
        return Promise.resolve({
          alg,
          kid,
          did,
          didDocument,
          jwt: {
            header: header as JWTHeader,
            payload: payload as JWTPayload,
          },
        })
      })

      .build()
    expressSupport = ExpressBuilder.fromServerOpts({
      port: 3456,
      hostname: 'localhost',
    }).build({ startListening: false })

    server = new OID4VCIServer(expressSupport, {
      issuer: vcIssuer,
      baseUrl: 'http://localhost:3456/test',
      endpointOpts: {
        // serverOpts: { baseUrl: 'http://localhost:3456/test', port: 3456 },
        tokenEndpointOpts: { accessTokenSignerCallback, tokenPath: '/test/token' },
      }
    })
    expressSupport.start()
  })

  afterAll(async () => {
    jest.clearAllMocks()
    await server.stop()
    // await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  let credOfferSession: CredentialOfferSession
  let uri: string
  let client: OpenID4VCIClientV1_0_13
  it('should create credential offer', async () => {
    expect(server.issuer).toBeDefined()
    uri = await vcIssuer
      .createCredentialOfferURI({
        offerMode: 'VALUE',
        grants: {
          authorization_code: {
            issuer_state: issuerState,
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': preAuthorizedCode,
            tx_code: {
              input_mode: 'text',
              length: 4,
            },
          },
        },
        credential_configuration_ids: ['UniversityDegree_JWT'],
        scheme: 'http',
      })
      .then((response) => response.uri)
    expect(uri).toEqual(
      'http://localhost:3456/test?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A3456%2Ftest%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegree_JWT%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22test_code%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22text%22%2C%22length%22%3A4%7D%7D%2C%22authorization_code%22%3A%7B%22issuer_state%22%3A%22previously-created-state%22%7D%7D%7D',
    )
  })

  it('should create client from credential offer URI', async () => {
    client = await OpenID4VCIClientV1_0_13.fromURI({
      uri: `http://localhost:3456/test?credential_offer=%7B%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22previously-created-state%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22test_code%22%7D%7D%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegree_JWT%22%5D%2C%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A3456%2Ftest%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegree_JWT%22%5D%7D`,
      kid: subjectDIDKey.didDocument.authentication[0],
      alg: 'ES256',
      createAuthorizationRequestURL: false,
    })
    expect(client.credentialOffer).toEqual({
      baseUrl: 'http://localhost:3456/test',
      credential_offer: {
        credential_issuer: 'http://localhost:3456/test',
        credential_configuration_ids: ['UniversityDegree_JWT'],
        grants: {
          authorization_code: {
            issuer_state: 'previously-created-state',
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'test_code',
          },
        },
      },
      issuerState: 'previously-created-state',
      original_credential_offer: {
        credential_issuer: 'http://localhost:3456/test',
        credential_configuration_ids: ['UniversityDegree_JWT'],
        grants: {
          authorization_code: {
            issuer_state: 'previously-created-state',
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'test_code',
          },
        },
      },
      preAuthorizedCode: 'test_code',
      scheme: 'http',
      supportedFlows: ['Authorization Code Flow', 'Pre-Authorized Code Flow'],
      userPinRequired: false,
      version: 1013,
    })
    expect(client.getIssuer()).toEqual(ISSUER_URL)
    expect(client.version()).toEqual(OpenId4VCIVersion.VER_1_0_13)
  })

  it('should retrieve server metadata', async () => {
    await expect(client.retrieveServerMetadata()).resolves.toEqual({
      authorizationServerMetadata: {
        authorization_challenge_endpoint: 'http://localhost:3456/test/authorize-challenge',
        authorization_endpoint: 'https://token-endpoint.example.com/authorize',
        credential_endpoint: 'http://localhost:3456/test/credential-endpoint',
        issuer: 'http://localhost:3456/test',
        response_types_supported: ['code', 'token', 'id_token'],
        scopes_supported: ['openid', 'abcdef'],
        token_endpoint: 'http://localhost:3456/test/token',
        token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post'],
      },
      authorizationServerType: 'OID4VCI',
      authorization_challenge_endpoint: 'http://localhost:3456/test/authorize-challenge',
      authorization_endpoint: 'https://token-endpoint.example.com/authorize',
      deferred_credential_endpoint: undefined,
      authorization_server: 'http://localhost:3456/test',
      credentialIssuerMetadata: {
        credential_endpoint: 'http://localhost:3456/test/credential-endpoint',
        credential_issuer: 'http://localhost:3456/test',
        token_endpoint: 'http://localhost:3456/test/token',
        credential_configurations_supported: {
          UniversityDegree_JWT: {
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegree_JWT'],
            },
            cryptographic_binding_methods_supported: ['did'],
            credential_signing_alg_values_supported: ['ES256K'],
            display: [
              {
                background_color: '#12107c',
                locale: 'en-US',
                logo: {
                  alt_text: 'a square logo of a university',
                  url: 'https://exampleuniversity.com/public/logo.png',
                },
                name: 'University Credential',
                text_color: '#FFFFFF',
              },
            ],
            format: 'jwt_vc_json',
          },
        },
        display: [
          {
            locale: 'en-US',
            name: 'example issuer',
          },
        ],
      },
      credential_endpoint: 'http://localhost:3456/test/credential-endpoint',
      issuer: 'http://localhost:3456/test',
      token_endpoint: 'http://localhost:3456/test/token',
    })
  })

  it('should get state on server side', async () => {
    const preAuthCode = client.credentialOffer!.credential_offer.grants?.[PRE_AUTH_GRANT_LITERAL]?.[PRE_AUTH_CODE_LITERAL]
    expect(preAuthCode).toBeDefined()

    if (preAuthCode) {
      credOfferSession = await vcIssuer.credentialOfferSessions.getAsserted(preAuthCode)
    }
    expect(credOfferSession).toBeDefined()
  })

  // TODO: ksadjad remove the skipped test
  it.skip('should acquire access token', async () => {
    client = await OpenID4VCIClientV1_0_13.fromURI({
      uri: `http://localhost:3456/test?credential_offer=%7B%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22previously-created-state%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22testcode%22%7D%7D%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegree_JWT%22%5D%2C%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A3456%2Ftest%22%7D`,
      kid: subjectDIDKey.didDocument.authentication[0],
      alg: 'ES256',
      createAuthorizationRequestURL: false,
    })
    accessToken = await client.acquireAccessToken({ pin: 'testcode' })
    expect(accessToken).toBeDefined()
  })

  // TODO: ksadjad remove the skipped test
  it.skip('should issue credential', async () => {
    async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
      return await new jose.SignJWT({ ...args.payload })
        .setProtectedHeader({ ...args.header })
        .setIssuedAt(args.payload.iat ?? Math.round(+new Date() / 1000))
        .setIssuer(kid!)
        .setAudience(args.payload.aud!)
        .setExpirationTime('2h')
        .sign(subjectKeypair.privateKey)
    }
    client = await OpenID4VCIClientV1_0_13.fromURI({
      uri: `http://localhost:3456/test?credential_offer=%7B%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22previously-created-state%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22testcode%22%7D%7D%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegree_JWT%22%5D%2C%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A3456%2Ftest%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegree_JWT%22%5D%7D`,
      kid: subjectDIDKey.didDocument.authentication[0],
      alg: 'ES256',
      createAuthorizationRequestURL: false,
    })
    console.log('getting access token')
    accessToken = await client.acquireAccessToken({
      pin: 'testcode',
    })
    console.log(`access token: ${accessToken}`)
    const credentialResponse = await client.acquireCredentials({
      credentialIdentifier: 'VerifiableCredential',
      format: 'jwt_vc_json',
      proofCallbacks: { signCallback: proofOfPossessionCallbackFunction },
    })
    expect(credentialResponse).toMatchObject({
      c_nonce_expires_in: 300,
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        credentialSubject: {},
        issuer: 'did:key:test',
        proof: {
          jwt: 'ye.ye.ye',
          proofPurpose: 'assertionMethod',
          type: 'JwtProof2020',
          verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf',
        },
        type: ['VerifiableCredential'],
      },
      format: 'jwt_vc_json',
    })
  })

  describe('Credential Offer Endpoints', () => {
    let testServer: OID4VCIServer<DIDDocument>
    let testExpressSupport: ExpressSupport
    let testVcIssuer: VcIssuer<DIDDocument>

    beforeAll(async () => {
      const stateManager = new MemoryStates<CredentialOfferSession>()
      testVcIssuer = new VcIssuerBuilder<DIDDocument>()
        .withAuthorizationMetadata(authorizationServerMetadata)
        .withCredentialEndpoint('http://localhost:4000/credential-endpoint')
        .withDefaultCredentialOfferBaseUri('http://localhost:4000')
        .withCredentialIssuer('http://localhost:4000')
        .withIssuerDisplay({ name: 'test issuer', locale: 'en-US' })
        .withCredentialConfigurationsSupported({})
        .withCredentialOfferStateManager(stateManager)
        .withInMemoryCNonceState()
        .withInMemoryCredentialOfferURIState()
        .withCredentialDataSupplier(() => Promise.resolve({
          format: 'ldp_vc',
          credential: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            issuer: 'did:example:123',
            issuanceDate: new Date().toISOString(),
            credentialSubject: {}
          }
        }))
        .withCredentialSignerCallback(() => Promise.resolve({
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          issuer: 'did:example:123',
          issuanceDate: new Date().toISOString(),
          credentialSubject: {},
          proof: {
            type: 'Ed25519Signature2018',
            created: new Date().toISOString(),
            proofPurpose: 'assertionMethod',
            verificationMethod: 'did:example:123#key-1',
            jws: 'dummy-jws'
          }
        }))
        .build()

      testExpressSupport = ExpressBuilder.fromServerOpts({ startListening: false, port: 4000, hostname: 'localhost' }).build({ startListening: false })


      const dummyAccessTokenSignerCallback = async (jwt: Jwt, kid?: string): Promise<string> => {
        return 'dummy-signed-token'
      }

      const endpointOpts = {
        getIssuePayloadOpts: { enabled: true, baseUrl: 'http://localhost:4000' },
        createCredentialOfferOpts: { enabled: true, baseUrl: 'http://localhost:4000' },
        tokenEndpointOpts: {
          accessTokenSignerCallback: dummyAccessTokenSignerCallback
        }
      }

      testServer = new OID4VCIServer(testExpressSupport, {
        issuer: testVcIssuer,
        baseUrl: 'http://localhost:4000',
        endpointOpts,
      })
      testExpressSupport.start()
    })

    afterAll(async () => {
      await testExpressSupport.stop()
    })

    it('should return error when credential offer session not found in getIssuePayloadEndpoint', async () => {
      const res = await requests(testServer.app).get('/credential-offers/nonexistent')
      expect(res.statusCode).toEqual(404)
      const actual = JSON.parse(res.text)
      expect(actual).toEqual({
        error: 'invalid_request',
        error_description: 'Credential offer nonexistent not found'
      })
    })

    it('should return credential offer when session exists in getIssuePayloadEndpoint', async () => {
      const dummySession: CredentialOfferSession = {
        notification_id: '123',
        createdAt: Date.now(),
        lastUpdatedAt: Date.now(),
        status: IssueStatus.OFFER_CREATED,
        preAuthorizedCode: 'test-session',
        credentialOffer: {
          credential_offer: {
            credential_issuer: 'test_issuer',
            grants: { authorization_code: { issuer_state: 'dummy' } },
            credential_configuration_ids: ['UniversityDegree_JWT']
          }
        }
      }

      await testVcIssuer.credentialOfferSessions.set('test-session', dummySession)
      await testVcIssuer.uris!.set('test-session',  {
        uri: 'https://dummy.com',
        createdAt: new Date().getTime(),
        preAuthorizedCode: 'test-session',
        issuerState:  'dummy'
      })
      const res = await requests(testServer.app).get('/credential-offers/test-session')
      expect(res.statusCode).toEqual(200)
      const actual = JSON.parse(res.text)
      expect(actual).toEqual(dummySession.credentialOffer.credential_offer)
    })

    it('should use default offerMode VALUE when not provided in createCredentialOfferEndpoint', async () => {
      const createOfferMock = jest.fn().mockResolvedValue({ uri: 'dummy-uri' })
      testVcIssuer.createCredentialOfferURI = createOfferMock
      const requestBody = {
        original_credential_offer: { version: OpenId4VCIVersion.VER_1_0_13 },
        grants: { authorization_code: { issuer_state: 'state' } },
        credential_configuration_ids: ['dummy']
      }
      const res = await requests(testServer.app).post('/webapp/credential-offers').send(requestBody)
      expect(res.statusCode).toEqual(200)
      expect(createOfferMock).toHaveBeenCalled()
      const args = createOfferMock.mock.calls[0][0]
      expect(args.offerMode).toEqual('VALUE')
    })

    it('should include issuerPayloadUri when offerMode is REFERENCE and forwarded headers are provided', async () => {
      const createOfferMock = jest.fn().mockResolvedValue({ uri: 'dummy-uri' })
      testVcIssuer.createCredentialOfferURI = createOfferMock
      const requestBody = {
        original_credential_offer: { version: OpenId4VCIVersion.VER_1_0_13 },
        grants: { authorization_code: { issuer_state: 'state' } },
        credential_configuration_ids: ['dummy'],
        offerMode: 'REFERENCE'
      }
      const res = await requests(testServer.app)
        .post('/webapp/credential-offers')
        .set('x-forwarded-proto', 'http')
        .set('x-forwarded-host', 'example.com')
        .set('x-forwarded-port', '8080')
        .set('x-forwarded-prefix', '/prefix')
        .send(requestBody)
      expect(res.statusCode).toEqual(200)
      expect(createOfferMock).toHaveBeenCalled()
      const args = createOfferMock.mock.calls[0][0]
      expect(args.offerMode).toEqual('REFERENCE')
      expect(args.issuerPayloadUri).toContain('http://example.com:8080')
      expect(args.issuerPayloadUri).toContain('/prefix')
    })

    it('should return error when createCredentialOfferURI throws an error', async () => {
      testVcIssuer.createCredentialOfferURI = jest.fn().mockRejectedValue(new Error('Test error'))
      const requestBody = {
        original_credential_offer: { version: OpenId4VCIVersion.VER_1_0_13 },
        grants: { authorization_code: { issuer_state: 'state' } },
        credential_configuration_ids: ['dummy']
      }
      const res = await requests(testServer.app).post('/webapp/credential-offers').send(requestBody)
      expect(res.statusCode).toEqual(500)
      const actual = JSON.parse(res.text)
      expect(actual.error_description).toEqual('Test error')
    })
  })

})
