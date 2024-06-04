import { OpenID4VCIClient } from '@sphereon/oid4vci-client'
import {
  Alg,
  ALG_ERROR,
  CredentialConfigurationSupportedV1_0_13,
  CredentialOfferSession,
  IssuerCredentialSubjectDisplay,
  IssueStatus,
  STATE_MISSING_ERROR,
} from '@sphereon/oid4vci-common'
import { IProofPurpose, IProofType } from '@sphereon/ssi-types'
import { DIDDocument } from 'did-resolver'

import { VcIssuer } from '../VcIssuer'
import { CredentialSupportedBuilderV1_13, VcIssuerBuilder } from '../builder'
import { MemoryStates } from '../state-manager'

const IDENTIPROOF_ISSUER_URL = 'https://issuer.research.identiproof.io'

const verifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
  id: 'http://university.example/credentials/1872',
  type: ['VerifiableCredential', 'ExampleAlumniCredential'],
  issuer: 'https://university.example/issuers/565049',
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    alumniOf: {
      id: 'did:example:c276e12ec21ebfeb1f712ebc6f1',
      name: 'Example University',
    },
  },
}

describe('VcIssuer', () => {
  let vcIssuer: VcIssuer<DIDDocument>
  const issuerState = 'previously-created-state'
  const clientId = 'sphereon:wallet'
  const preAuthorizedCode = 'test_code'

  const jwtVerifyCallback: jest.Mock = jest.fn()

  beforeEach(async () => {
    jest.clearAllMocks()
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
    await stateManager.set('previously-created-state', {
      issuerState,
      clientId,
      preAuthorizedCode,
      createdAt: +new Date(),
      lastUpdatedAt: +new Date(),
      status: IssueStatus.OFFER_CREATED,
      userPin: '123456',
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'did:key:test',
          credentials: [
            {
              format: 'ldp_vc',
              credential_definition: {
                types: ['VerifiableCredential'],
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                credentialSubject: {},
              },
            },
          ],
          grants: {
            authorization_code: { issuer_state: issuerState },
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': preAuthorizedCode,
              tx_code: {
                input_mode: 'text',
                length: 4,
              },
            },
          },
        },
      },
    })
    vcIssuer = new VcIssuerBuilder<DIDDocument>()
      .withAuthorizationServers('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer(IDENTIPROOF_ISSUER_URL)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialConfigurationsSupported(credentialsSupported)
      .withCredentialOfferStateManager(stateManager)
      .withInMemoryCNonceState()
      .withInMemoryCredentialOfferURIState()
      .withCredentialSignerCallback(() =>
        Promise.resolve({
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          issuer: 'did:key:test',
          issuanceDate: new Date().toISOString(),
          credentialSubject: {},
          proof: {
            type: IProofType.JwtProof2020,
            jwt: 'ye.ye.ye',
            created: new Date().toISOString(),
            proofPurpose: IProofPurpose.assertionMethod,
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf',
          },
        }),
      )
      .withJWTVerifyCallback(jwtVerifyCallback)
      .build()
  })

  afterAll(async () => {
    jest.clearAllMocks()
    // await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  it.skip('should create credential offer', async () => {
    const { uri, ...rest } = await vcIssuer.createCredentialOfferURI({
      grants: {
        authorization_code: {
          issuer_state: issuerState,
        },
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
          user_pin_required: true,
        },
      },
      scheme: 'http',
      baseUri: 'issuer-example.com',
      qrCodeOpts: {
        size: 400,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: 2,
      },
    })

    console.log(JSON.stringify(rest, null, 2))
    expect(uri).toEqual(
      'http://issuer-example.com?credential_offer=%7B%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22previously-created-state%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22test_code%22%2C%22user_pin_required%22%3Atrue%7D%7D%2C%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.research.identiproof.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%5D%2C%22credentialSubject%22%3A%7B%22given_name%22%3A%7B%22name%22%3A%22given%20name%22%2C%22locale%22%3A%22en-US%22%7D%7D%2C%22cryptographic_suites_supported%22%3A%5B%22ES256K%22%5D%2C%22cryptographic_binding_methods_supported%22%3A%5B%22did%22%5D%2C%22id%22%3A%22UniversityDegree_JWT%22%2C%22display%22%3A%5B%7B%22name%22%3A%22University%20Credential%22%2C%22locale%22%3A%22en-US%22%2C%22logo%22%3A%7B%22url%22%3A%22https%3A%2F%2Fexampleuniversity.com%2Fpublic%2Flogo.png%22%2C%22alt_text%22%3A%22a%20square%20logo%20of%20a%20university%22%7D%2C%22background_color%22%3A%22%2312107c%22%2C%22text_color%22%3A%22%23FFFFFF%22%7D%5D%7D%5D%7D',
    )

    const client = await OpenID4VCIClient.fromURI({ uri })
    expect(client.credentialOffer).toEqual({
      baseUrl: 'http://issuer-example.com',
      credential_offer: {
        credential_issuer: 'https://issuer.research.identiproof.io',
        credentials: [
          {
            credentialSubject: {
              given_name: {
                locale: 'en-US',
                name: 'given name',
              },
            },
            cryptographic_binding_methods_supported: ['did'],
            cryptographic_suites_supported: ['ES256K'],
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
            id: 'UniversityDegree_JWT',
            types: ['VerifiableCredential'],
          },
        ],
        grants: {
          authorization_code: {
            issuer_state: 'previously-created-state',
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'test_code',
            user_pin_required: true,
          },
        },
      },
      issuerState: 'previously-created-state',
      original_credential_offer: {
        credential_issuer: 'https://issuer.research.identiproof.io',
        credentials: [
          {
            credentialSubject: {
              given_name: {
                locale: 'en-US',
                name: 'given name',
              },
            },
            cryptographic_binding_methods_supported: ['did'],
            cryptographic_suites_supported: ['ES256K'],
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
            id: 'UniversityDegree_JWT',
            types: ['VerifiableCredential'],
          },
        ],
        grants: {
          authorization_code: {
            issuer_state: 'previously-created-state',
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'test_code',
            user_pin_required: true,
          },
        },
      },
      preAuthorizedCode: 'test_code',
      scheme: 'http',
      supportedFlows: ['Authorization Code Flow', 'Pre-Authorized Code Flow'],
      userPinRequired: true,
      version: 1011,
    })
  })

  it('should create credential offer uri', async () => {
    await expect(
      vcIssuer
        .createCredentialOfferURI({
          grants: {
            authorization_code: {
              issuer_state: issuerState,
            },
          },
          scheme: 'http',
          baseUri: 'issuer-example.com',
          credential_configuration_ids: ['VerifiableCredential'],
          credentialOfferUri: 'https://somehost.com/offer-id',
        })
        .then((response) => response.uri),
    ).resolves.toEqual('http://issuer-example.com?credential_offer_uri=https://somehost.com/offer-id')
  })

  // Of course this doesn't work. The state is part of the proof to begin with
  it('should fail issuing credential if an invalid state is used', async () => {
    jwtVerifyCallback.mockResolvedValue({
      did: 'did:example:1234',
      kid: 'did:example:1234#auth',
      alg: Alg.ES256K,
      didDocument: {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: 'did:example:1234',
      },
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: Alg.ES256K,
          kid: 'test-kid',
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce',
        },
      },
    })

    await expect(
      vcIssuer.issueCredential({
        credentialRequest: {
          credential_identifier: 'VerifiableCredential',
          format: 'jwt_vc_json',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye',
          },
        },
        // issuerState: 'invalid state',
      }),
    ).rejects.toThrow(Error(STATE_MISSING_ERROR + ' (test-nonce)'))
  })

  it.each([...Object.values<string>(Alg), 'CUSTOM'])('should issue %s signed credential if a valid state is passed in', async (alg: string) => {
    jwtVerifyCallback.mockResolvedValue({
      did: 'did:example:1234',
      kid: 'did:example:1234#auth',
      alg: alg,
      didDocument: {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: 'did:example:1234',
      },
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: alg,
          kid: 'test-kid',
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce',
        },
      },
    })

    const createdAt = +new Date()
    await vcIssuer.cNonces.set('test-nonce', {
      cNonce: 'test-nonce',
      preAuthorizedCode: 'test-pre-authorized-code',
      createdAt: createdAt,
    })
    await vcIssuer.credentialOfferSessions.set('test-pre-authorized-code', {
      createdAt: createdAt,
      preAuthorizedCode: 'test-pre-authorized-code',
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'did:key:test',
          credentials: [],
        },
      },
      lastUpdatedAt: createdAt,
      status: IssueStatus.ACCESS_TOKEN_CREATED,
    })

    expect(
      vcIssuer.issueCredential({
        credential: verifiableCredential,
        credentialRequest: {
          credential_identifier: 'VerifiableCredential',
          format: 'jwt_vc_json',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye',
          },
        },
        newCNonce: 'new-test-nonce',
      }),
    ).resolves.toEqual({
      c_nonce: 'new-test-nonce',
      c_nonce_expires_in: 300,
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        credentialSubject: {},
        issuanceDate: expect.any(String),
        issuer: 'did:key:test',
        proof: {
          created: expect.any(String),
          jwt: 'ye.ye.ye',
          proofPurpose: 'assertionMethod',
          type: 'JwtProof2020',
          verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf',
        },
        type: ['VerifiableCredential'],
      },
      // format: 'jwt_vc_json',
    })
  })

  it('should fail issuing credential if the signing algorithm is missing', async () => {
    const createdAt = +new Date()
    await vcIssuer.cNonces.set('test-nonce', {
      cNonce: 'test-nonce',
      preAuthorizedCode: 'test-pre-authorized-code',
      createdAt: createdAt,
    })

    jwtVerifyCallback.mockResolvedValue({
      did: 'did:example:1234',
      kid: 'did:example:1234#auth',
      alg: undefined,
      didDocument: {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: 'did:example:1234',
      },
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: undefined,
          kid: 'test-kid',
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce',
        },
      },
    })

    expect(
      vcIssuer.issueCredential({
        credentialRequest: {
          credential_identifier: 'VerifiableCredential',
          format: 'jwt_vc_json',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye',
          },
        },
      }),
    ).rejects.toThrow(Error(ALG_ERROR))
  })
})
