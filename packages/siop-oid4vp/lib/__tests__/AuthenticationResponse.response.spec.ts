import { SigningAlgo } from '@sphereon/oid4vc-common'
import { IPresentationDefinition } from '@sphereon/pex'
import {
  ICredential,
  IPresentation,
  IProofType,
  IVerifiableCredential,
  IVerifiablePresentation,
  OriginalVerifiableCredential,
} from '@sphereon/ssi-types'
import { DcqlCredential, DcqlPresentation, DcqlQuery, DcqlQueryResult } from 'dcql'

import {
  AuthorizationResponse,
  AuthorizationResponseOpts,
  CreateAuthorizationRequestOpts,
  PassBy,
  PresentationExchange,
  PresentationSignCallback,
  RequestObject,
  ResponseIss,
  ResponseMode,
  ResponseType,
  Scope,
  SubjectIdentifierType,
  SubjectType,
  SupportedVersion,
  VerifyAuthorizationRequestOpts,
  VPTokenLocation,
} from '..'
import { createPresentationSubmission } from '../authorization-response'
import SIOPErrors from '../types/Errors'

import { getCreateJwtCallback, getVerifyJwtCallback } from './DidJwtTestUtils'
import { getResolver } from './ResolverTestUtils'
import { mockedGetEnterpriseAuthToken, pexHasher, WELL_KNOWN_OPENID_FEDERATION } from './TestUtils'
import {
  UNIT_TEST_TIMEOUT,
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData'

jest.setTimeout(30000)

const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts'
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f'
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0'
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1'

const validButExpiredJWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1NjEzNTEyOTAsImV4cCI6MTU2MTM1MTg5MCwicmVzcG9uc2VfdHlwZSI6ImlkX3Rva2VuIiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWQiOiJkaWQ6ZXRocjoweDQ4NzNFQzc0MUQ4RDFiMjU4YUYxQjUyNDczOEIzNjNhQTIxOTk5MjAiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2FjbWUuY29tL2hlbGxvIiwiaXNzIjoiZGlkOmV0aHI6MHg0ODczRUM3NDFEOEQxYjI1OGFGMUI1MjQ3MzhCMzYzYUEyMTk5OTIwIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJyZXNwb25zZV9jb250ZXh0IjoicnAiLCJub25jZSI6IlVTLU9wY1FHLXlXS3lWUTRlTU53UFB3Um10UVVGdmpkOHJXeTViRC10MXciLCJzdGF0ZSI6IjdmMjcxYzZjYjk2ZThmOThhMzkxYWU5ZCIsInJlZ2lzdHJhdGlvbiI6eyJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVkRFNBIiwiRVMyNTYiXSwicmVxdWVzdF9vYmplY3Rfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFZERTQSIsIkVTMjU2Il0sInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJpZF90b2tlbiJdLCJzY29wZXNfc3VwcG9ydGVkIjpbIm9wZW5pZCBkaWRfYXV0aG4iLCJvcGVuaWQiXSwic3ViamVjdF90eXBlc19zdXBwb3J0ZWQiOlsicGFpcndpc2UiXSwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDpldGhyOiIsImRpZCJdLCJ2cF9mb3JtYXRzIjp7ImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSIsIkVjZHNhU2VjcDI1NmsxU2lnbmF0dXJlMjAxOSJdfX19fQ.Wd6I7BT7fWZSuYozUwHnyEsEoAe6OjdyzEEKXnWk8bY'

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello'

describe('create JWT from Request JWT should', () => {
  const responseOpts: AuthorizationResponseOpts = {
    responseURI: EXAMPLE_REDIRECT_URL,
    responseURIType: 'redirect_uri',
    responseMode: ResponseMode.POST,
    registration: {
      authorizationEndpoint: 'www.myauthorizationendpoint.com',
      responseTypesSupported: [ResponseType.ID_TOKEN],
      subject_syntax_types_supported: ['did:web'],
      vpFormats: {
        ldp_vc: {
          proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
        },
      },
      issuer: ResponseIss.SELF_ISSUED_V2,

      passBy: PassBy.REFERENCE,
      reference_uri: EXAMPLE_REFERENCE_URL,

      logo_uri: VERIFIER_LOGO_FOR_CLIENT,
      clientName: VERIFIER_NAME_FOR_CLIENT,
      'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100310',
      clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
    },
    createJwtCallback: getCreateJwtCallback({
      did: DID,
      hexPrivateKey: HEX_KEY,
      kid: KID,
      alg: SigningAlgo.ES256K,
    }),
    jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
  }

  const resolver = getResolver('ethr')
  const verifyOpts: VerifyAuthorizationRequestOpts = {
    hasher: pexHasher,
    verifyJwtCallback: getVerifyJwtCallback(resolver),
    verification: {},
    supportedVersions: [SupportedVersion.SIOPv2_ID1],
    correlationId: '1234',
  }

  it('throw NO_JWT when no jwt is passed', async () => {
    expect.assertions(1)
    await expect(AuthorizationResponse.fromRequestObject(undefined as never, responseOpts, verifyOpts)).rejects.toThrow(SIOPErrors.NO_JWT)
  })
  it('throw BAD_PARAMS when no responseOpts is passed', async () => {
    expect.assertions(1)
    await expect(AuthorizationResponse.fromRequestObject(validButExpiredJWT, undefined as never, verifyOpts)).rejects.toThrow(SIOPErrors.BAD_PARAMS)
  })
  it('throw VERIFY_BAD_PARAMS when no verifyOpts is passed', async () => {
    expect.assertions(1)
    await expect(AuthorizationResponse.fromRequestObject(validButExpiredJWT, responseOpts, undefined as never)).rejects.toThrow(
      SIOPErrors.VERIFY_BAD_PARAMS,
    )
  })

  it('throw JWT_ERROR when expired but valid JWT is passed in', async () => {
    expect.assertions(1)
    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY')
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY')
    const requestOpts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      /*payload: {
        nonce: '12345',
        state: '12345',
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        scope: 'test',
        response_type: 'id_token',
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },*/
      requestObject: {
        passBy: PassBy.REFERENCE,
        jwtIssuer: { method: 'did', didUrl: `${mockReqEntity.did}#controller`, alg: SigningAlgo.ES256K },
        reference_uri: 'https://my-request.com/here',
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: mockReqEntity.hexPrivateKey,
          did: mockReqEntity.did,
          kid: `${mockReqEntity.did}#controller`,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          nonce: '12345',
          state: '12345',
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: 'id_token',
          redirect_uri: EXAMPLE_REDIRECT_URL,
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100311',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }
    const responseOpts: AuthorizationResponseOpts = {
      responseURI: EXAMPLE_REDIRECT_URL,
      responseURIType: 'redirect_uri',
      registration: {
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        issuer: ResponseIss.SELF_ISSUED_V2,
        responseTypesSupported: [ResponseType.ID_TOKEN],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormats: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },

        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100312',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
      createJwtCallback: getCreateJwtCallback({
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`,
        alg: SigningAlgo.ES256K,
      }),
      jwtIssuer: { method: 'did', didUrl: `${mockResEntity.did}#controller`, alg: SigningAlgo.ES256K },
      responseMode: ResponseMode.POST,
    }

    jest.useFakeTimers().setSystemTime(new Date('2020-01-01'))
    jest.useFakeTimers().setSystemTime(new Date('2020-01-01'))

    const requestObject = await RequestObject.fromOpts(requestOpts)
    const jwt = await requestObject.toJwt()
    if (!jwt) throw new Error('JWT is undefined')
    jest.useRealTimers()
    await expect(AuthorizationResponse.fromRequestObject(jwt, responseOpts, verifyOpts)).rejects.toThrow(/invalid_jwt: JWT has expired: exp: /)
  })

  it(
    'succeed when valid JWT is passed in',
    async () => {
      expect.assertions(1)

      const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY')
      const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY')
      const requestOpts: CreateAuthorizationRequestOpts = {
        version: SupportedVersion.SIOPv2_ID1,

        requestObject: {
          passBy: PassBy.REFERENCE,
          reference_uri: 'https://my-request.com/here',
          jwtIssuer: { method: 'did', didUrl: `${mockReqEntity.did}#controller`, alg: SigningAlgo.ES256K },
          createJwtCallback: getCreateJwtCallback({
            hexPrivateKey: mockReqEntity.hexPrivateKey,
            did: mockReqEntity.did,
            kid: `${mockReqEntity.did}#controller`,
            alg: SigningAlgo.ES256K,
          }),
          payload: {
            client_id: WELL_KNOWN_OPENID_FEDERATION,
            scope: 'test',
            response_type: 'id_token',
            redirect_uri: EXAMPLE_REDIRECT_URL,
          },
        },
        clientMetadata: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          vpFormatsSupported: {
            ldp_vc: {
              proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
            },
          },
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100313',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        },
      }
      const responseOpts: AuthorizationResponseOpts = {
        responseURI: EXAMPLE_REDIRECT_URL,
        responseURIType: 'redirect_uri',
        registration: {
          authorizationEndpoint: 'www.myauthorizationendpoint.com',
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          issuer: ResponseIss.SELF_ISSUED_V2,
          responseTypesSupported: [ResponseType.ID_TOKEN],
          subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
          vpFormats: {
            ldp_vc: {
              proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
            },
          },

          passBy: PassBy.REFERENCE,
          reference_uri: EXAMPLE_REFERENCE_URL,

          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100314',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        },
        createJwtCallback: getCreateJwtCallback({
          did: mockResEntity.did,
          hexPrivateKey: mockResEntity.hexPrivateKey,
          kid: `${mockResEntity.did}#controller`,
          alg: SigningAlgo.ES256K,
        }),
        jwtIssuer: { method: 'did', didUrl: `${mockResEntity.did}#controller`, alg: SigningAlgo.ES256K },
        responseMode: ResponseMode.POST,
      }

      const requestObject = await RequestObject.fromOpts(requestOpts)
      // console.log(JSON.stringify(await AuthorizationResponse.fromRequestObject(await requestObject.toJwt(), responseOpts, verifyOpts)));
      const jwt = await requestObject.toJwt()
      if (!jwt) throw new Error('JWT is undefined')
      const response = await AuthorizationResponse.fromRequestObject(jwt, responseOpts, verifyOpts)
      await expect(response).toBeDefined()
    },
    UNIT_TEST_TIMEOUT,
  )

  it('succeed when valid JWT with PD is passed in', async () => {
    expect.assertions(1)

    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY')
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY')
    const presentationSignCallback: PresentationSignCallback = async (_args) => ({
      ...(_args.presentation as IPresentation),
      proof: {
        type: 'RsaSignature2018',
        created: '2018-09-14T21:19:10Z',
        proofPurpose: 'authentication',
        verificationMethod: 'did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1',
        challenge: '1f44d55f-f161-4938-a659-f8026467f126',
        domain: '4jt78h47fh47',
        jws: 'eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4vGHSrQyHUGlcTwLtjPAnKb78',
      },
    })
    const definition: IPresentationDefinition = {
      id: 'Credentials',
      input_descriptors: [
        {
          id: 'ID Card Credential',
          schema: [
            {
              uri: 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential',
            },
          ],
          constraints: {
            //limit_disclosure: 'required',
            fields: [
              {
                path: ['$.issuer.id'],
                purpose: 'We can only verify bank accounts if they are attested by a source.',
                filter: {
                  type: 'string',
                  pattern: 'did:example:issuer',
                },
              },
            ],
          },
        },
      ],
    }
    const requestOpts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      requestObject: {
        passBy: PassBy.REFERENCE,
        reference_uri: 'https://my-request.com/here',
        jwtIssuer: { method: 'did', didUrl: mockReqEntity.did, alg: SigningAlgo.ES256K },
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: mockReqEntity.hexPrivateKey,
          did: mockReqEntity.did,
          kid: `${mockReqEntity.did}#controller`,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: 'id_token vp_token',
          redirect_uri: EXAMPLE_REDIRECT_URL,
          claims: {
            vp_token: {
              presentation_definition: definition,
            },
          },
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100315',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }
    const vc: ICredential = {
      id: 'https://example.com/credentials/1872',
      type: ['VerifiableCredential', 'IDCardCredential'],
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential'],
      issuer: {
        id: 'did:example:issuer',
      },
      issuanceDate: '2010-01-01T19:23:24Z',
      credentialSubject: {
        given_name: 'Fredrik',
        family_name: 'Stremberg',
        birthdate: '1949-01-22',
      },
    }
    const presentation: IVerifiablePresentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      presentation_submission: undefined,
      type: ['verifiablePresentation'],
      holder: 'did:example:holder',
      verifiableCredential: [vc as IVerifiableCredential],
      proof: undefined as any,
    }

    const pex = new PresentationExchange({
      allDIDs: ['did:example:holder'],
      allVerifiableCredentials: presentation.verifiableCredential as OriginalVerifiableCredential[],
    })
    await pex.selectVerifiableCredentialsForSubmission(definition)
    const verifiablePresentationResult = await pex.createVerifiablePresentation(
      definition,
      presentation.verifiableCredential as OriginalVerifiableCredential[],
      presentationSignCallback,
      {},
    )
    const responseOpts: AuthorizationResponseOpts = {
      responseURI: EXAMPLE_REDIRECT_URL,
      responseURIType: 'redirect_uri',
      registration: {
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        issuer: ResponseIss.SELF_ISSUED_V2,
        responseTypesSupported: [ResponseType.ID_TOKEN],
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormats: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100316',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
      createJwtCallback: getCreateJwtCallback({
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`,
        alg: SigningAlgo.ES256K,
      }),
      jwtIssuer: { method: 'did', didUrl: `${mockResEntity.did}#controller`, alg: SigningAlgo.ES256K },
      presentationExchange: {
        verifiablePresentations: verifiablePresentationResult.verifiablePresentations,
        vpTokenLocation: VPTokenLocation.ID_TOKEN,
        presentationSubmission: await createPresentationSubmission(verifiablePresentationResult.verifiablePresentations, {
          presentationDefinitions: [definition],
        }),
      },
      responseMode: ResponseMode.POST,
    }

    const requestObject = await RequestObject.fromOpts(requestOpts)
    /* console.log(
      JSON.stringify(await AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts))
    );*/
    const jwt = await requestObject.toJwt()
    if (!jwt) throw new Error('JWT is undefined')
    const authorizationRequest = await AuthorizationResponse.fromRequestObject(jwt, responseOpts, verifyOpts)
    await expect(authorizationRequest).toBeDefined()
  })

  it('succeed when valid JWT with PD is passed in for id_token', async () => {
    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY')
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY')
    const definition: IPresentationDefinition = {
      id: 'Credentials',
      input_descriptors: [
        {
          id: 'ID Card Credential',
          schema: [
            {
              uri: 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential',
            },
          ],
          constraints: {
            // limit_disclosure: 'required',
            fields: [
              {
                path: ['$.issuer.id'],
                purpose: 'We can only verify bank accounts if they are attested by a source.',
                filter: {
                  type: 'string',
                  pattern: 'did:example:issuer',
                },
              },
            ],
          },
        },
      ],
    }
    const requestOpts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        /*scope: 'test',
        response_type: 'token_id',
        redirect_uri: EXAMPLE_REDIRECT_URL,
        claims: {
          vp_token: {
            presentation_definition: definition,
          },
        },*/
      },
      requestObject: {
        jwtIssuer: { method: 'did', didUrl: `${mockReqEntity.did}#controller`, alg: SigningAlgo.ES256K },
        passBy: PassBy.REFERENCE,
        reference_uri: 'https://my-request.com/here',
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: mockReqEntity.hexPrivateKey,
          did: mockReqEntity.did,
          kid: `${mockReqEntity.did}#controller`,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: ResponseType.ID_TOKEN,
          redirect_uri: EXAMPLE_REDIRECT_URL,
          claims: {
            vp_token: {
              presentation_definition: definition,
            },
          },
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }
    const vc: ICredential = {
      id: 'https://example.com/credentials/1872',
      type: ['VerifiableCredential', 'IDCardCredential'],
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1/IDCardCredential'],
      issuer: {
        id: 'did:example:issuer',
      },
      issuanceDate: '2010-01-01T19:23:24Z',
      credentialSubject: {
        given_name: 'Fredrik',
        family_name: 'Stremberg',
        birthdate: '1949-01-22',
      },
    }
    const presentation: IVerifiablePresentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      presentation_submission: undefined,
      type: ['verifiablePresentation'],
      holder: 'did:example:holder',
      verifiableCredential: [vc as IVerifiableCredential],
      proof: undefined as any,
    }

    const pex = new PresentationExchange({
      allDIDs: ['did:example:holder'],
      allVerifiableCredentials: presentation.verifiableCredential as OriginalVerifiableCredential[],
    })
    await pex.selectVerifiableCredentialsForSubmission(definition)
    const presentationSignCallback: PresentationSignCallback = async (_args) => ({
      ...(_args.presentation as IPresentation),
      proof: {
        type: 'RsaSignature2018',
        created: '2018-09-14T21:19:10Z',
        proofPurpose: 'authentication',
        verificationMethod: 'did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1',
        challenge: '1f44d55f-f161-4938-a659-f8026467f126',
        domain: '4jt78h47fh47',
        jws: 'eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqsLfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh4vGHSrQyHUGlcTwLtjPAnKb78',
      },
    })
    const verifiablePresentationResult = await pex.createVerifiablePresentation(
      definition,
      presentation.verifiableCredential as OriginalVerifiableCredential[],
      presentationSignCallback,
      {},
    )
    const responseOpts: AuthorizationResponseOpts = {
      responseURI: EXAMPLE_REDIRECT_URL,
      responseURIType: 'redirect_uri',
      registration: {
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        issuer: ResponseIss.SELF_ISSUED_V2,
        responseTypesSupported: [ResponseType.ID_TOKEN],

        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormats: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL,
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
      createJwtCallback: getCreateJwtCallback({
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`,
        alg: SigningAlgo.ES256K,
      }),
      jwtIssuer: { method: 'did', didUrl: `${mockResEntity.did}#controller`, alg: SigningAlgo.ES256K },
      presentationExchange: {
        verifiablePresentations: verifiablePresentationResult.verifiablePresentations,
        presentationSubmission: await createPresentationSubmission(verifiablePresentationResult.verifiablePresentations, {
          presentationDefinitions: [definition],
        }),
        vpTokenLocation: VPTokenLocation.ID_TOKEN,
      },

      responseMode: ResponseMode.POST,
    }

    const requestObject = await RequestObject.fromOpts(requestOpts)
    const jwt = await requestObject.toJwt()
    if (!jwt) throw new Error('JWT is undefined')
    const authResponse = AuthorizationResponse.fromRequestObject(jwt, responseOpts, verifyOpts)
    await expect(authResponse).toBeDefined()
  })

  it('succeed when valid JWT with DCQL query is passed in', async () => {
    expect.assertions(1)

    const mockReqEntity = await mockedGetEnterpriseAuthToken('REQ COMPANY')
    const mockResEntity = await mockedGetEnterpriseAuthToken('RES COMPANY')

    const dcqlQuery: DcqlQuery = {
      credentials: [
        {
          id: 'Credentials',
          format: 'vc+sd-jwt',
          claims: [
            {
              path: ['given_name'],
              values: ['John'],
            },
          ],
        },
      ],
    }

    const dcqlParsedQuery = DcqlQuery.parse(dcqlQuery)
    DcqlQuery.validate(dcqlParsedQuery)

    const requestOpts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_D12_OID4VP_D20,
      requestObject: {
        passBy: PassBy.REFERENCE,
        reference_uri: 'https://my-request.com/here',
        jwtIssuer: { method: 'did', didUrl: mockReqEntity.did, alg: SigningAlgo.ES256K },
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: mockReqEntity.hexPrivateKey,
          did: mockReqEntity.did,
          kid: `${mockReqEntity.did}#controller`,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: 'id_token vp_token',
          redirect_uri: EXAMPLE_REDIRECT_URL,
          dcql_query: JSON.stringify(dcqlParsedQuery),
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100315',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }

    const sdjwt = {
      compactJwtVc:
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lTMGRwYzNodlUzaDJhVzB4YTFOSU1XSnROMnhmUkhCeVIyczNZa2RrWkVaYVdXWnRjVXB1VjJWb1NTSXNJbmtpT2lKYVEzQldUVVZSTkhsNGNUSlZiVGRDVGpoSVQyNUdlamszTTFBMFVUQlVkbmRuZVhWUlgyRmlURlZWSW4wIzAiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lXRkpXUVhsNVJIQldNbXBNTm5oNlUwSktZM1JIZW0xS1pqbFFlV0Z4WHpNdFRVeHJlR0ZoUlRBNFRTSXNJbmtpT2lKQ1NtOUtWM05WYTBaQlUyVlRZMmx4VDFsNVNWTTBZMFpoZVU4emFHaEJTalZaYjJ0dU9IcFRTVEZuSW4wIzAiLCJpc3MiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lTMGRwYzNodlUzaDJhVzB4YTFOSU1XSnROMnhmUkhCeVIyczNZa2RrWkVaYVdXWnRjVXB1VjJWb1NTSXNJbmtpT2lKYVEzQldUVVZSTkhsNGNUSlZiVGRDVGpoSVQyNUdlamszTTFBMFVUQlVkbmRuZVhWUlgyRmlURlZWSW4wIzAiLCJpYXQiOjE3MzQ0NTgwNDIsInZjdCI6InVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSIsIl9zZCI6WyIwWWdpR25hck1LSERnVWx1QktteGdRZUJ4OF8xazMwd3NSRVN1X2t1Y0JFIiwiNEpwU2JzUEsxZndUQzRhR24zZ0hXb1BkVEJrMExOTWZMOEJXeEIxZ1JPWSIsIjRpZmplQUZveUEyQmc0STVNWEFrMVlyc1AtUVBQQXRnZGlHY0RMQTZiTFEiLCJBdTFjdURISUNISE1jUjZxM2R3d1pHbHp5dzMwSXhvTGVhWlNxRktEbmo4IiwiQ0QxbWxOY19VaVBoQUp6YkJveTVMY3dtekFNZTM3d0VLZF9iMTB6QTNxNCIsInFwZ1FOUVRac0VJWHdxUk9fT24xdUVCSVVNODBTcTJLR2tlN0JSU2N0WHciXSwiX3NkX2FsZyI6IlNIQS0yNTYifQ.P84d0CoS4M-zQ29l3S97RMatfJMYkoTgR5EqSMTdYlZAMp4e8iiuz2PXQMfJ-_undCvg4SRXxDACGiLL3Tt7Bw~WyJlNTFiNWI2NS0wNzM3LTQ0MjQtYTUxYS1jNGYzZGNlZGFmMmYiLCJnaXZlbl9uYW1lIiwiSm9obiJd~WyIxM2I1NDIwNi1kYWQ3LTQ3N2UtODYyZC03N2ZiMTQ1MDE5NjUiLCJmYW1pbHlfbmFtZSIsIkRvZSJd~WyJkMmQxNjg3Zi04ZmY4LTRlOTMtYWJjYi1hYTNlNGVjYzY0ZTMiLCJlbWFpbCIsImpvaG5kZW9AZXhhbXBsZS5jb20iXQ~WyIyZDA4YTk2YS03YzYwLTQ3NDEtYTI5YS00ZjBjYTFlNGQ3M2IiLCJwaG9uZSIsIisxLTIwMi01NTUtMDEwMSJd~WyI2YjVkN2FmOS01ZmIxLTQzNTEtYWM1ZS1hMzA1YTBkNjU0ZDUiLCJhZGRyZXNzIix7InN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsImNvdW50cnkiOiJVUyJ9XQ~WyI5MmYzY2M5ZC0yMjQ2LTRiODQtYTk5OS0xYmQyM2U0OGQ0MGEiLCJiaXJ0aGRhdGUiLCIxOTQwLTAxLTAxIl0~',
      decodedPayload: {
        header: {
          typ: 'vc+sd-jwt',
          kid: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiS0dpc3hvU3h2aW0xa1NIMWJtN2xfRHByR2s3YkdkZEZaWWZtcUpuV2VoSSIsInkiOiJaQ3BWTUVRNHl4cTJVbTdCTjhIT25Gejk3M1A0UTBUdndneXVRX2FiTFVVIn0#0',
          alg: 'ES256',
        },
        payload: {
          sub: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiWFJWQXl5RHBWMmpMNnh6U0JKY3RHem1KZjlQeWFxXzMtTUxreGFhRTA4TSIsInkiOiJCSm9KV3NVa0ZBU2VTY2lxT1l5SVM0Y0ZheU8zaGhBSjVZb2tuOHpTSTFnIn0#0',
          iss: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiS0dpc3hvU3h2aW0xa1NIMWJtN2xfRHByR2s3YkdkZEZaWWZtcUpuV2VoSSIsInkiOiJaQ3BWTUVRNHl4cTJVbTdCTjhIT25Gejk3M1A0UTBUdndneXVRX2FiTFVVIn0#0',
          iat: 1734458042,
          vct: 'urn:eu.europa.ec.eudi:pid:1',
          given_name: 'John',
          email: 'johndeo@example.com',
          birthdate: '1940-01-01',
          phone: '+1-202-555-0101',
          address: {
            street_address: '123 Main St',
            locality: 'Anytown',
            region: 'Anystate',
            country: 'US',
          },
          family_name: 'Doe',
        },
        kb: undefined,
      },
    }

    const vc: DcqlCredential = {
      credential_format: 'vc+sd-jwt',
      vct: sdjwt.decodedPayload.payload.vct,
      claims: sdjwt.decodedPayload.payload,
    }

    const dcqlQueryResult: DcqlQueryResult = DcqlQuery.query(dcqlQuery, [vc])

    const presentation: DcqlPresentation.Output = {}
    for (const [key, value] of Object.entries(dcqlQueryResult.credential_matches)) {
      if (value.success) {
        presentation[key] = sdjwt.compactJwtVc
      }
    }

    const dcqlPresentation = DcqlPresentation.parse(presentation)

    const responseOpts: AuthorizationResponseOpts = {
      responseURI: EXAMPLE_REDIRECT_URL,
      responseURIType: 'redirect_uri',
      createJwtCallback: getCreateJwtCallback({
        did: mockResEntity.did,
        hexPrivateKey: mockResEntity.hexPrivateKey,
        kid: `${mockResEntity.did}#controller`,
        alg: SigningAlgo.ES256K,
      }),
      jwtIssuer: { method: 'did', didUrl: `${mockResEntity.did}#controller`, alg: SigningAlgo.ES256K },
      dcqlQuery: {
        dcqlPresentation
      },
      responseMode: ResponseMode.DIRECT_POST,
    }

    const requestObject = await RequestObject.fromOpts(requestOpts)
    /* console.log(
      JSON.stringify(await AuthenticationResponse.createJWTFromRequestJWT(requestWithJWT.jwt, responseOpts, verifyOpts))
    );*/
    const jwt = await requestObject.toJwt()
    if (!jwt) throw new Error('JWT is undefined')
    const authorizationRequest = await AuthorizationResponse.fromRequestObject(jwt, responseOpts, verifyOpts)
    expect(authorizationRequest).toBeDefined()
  })
})
