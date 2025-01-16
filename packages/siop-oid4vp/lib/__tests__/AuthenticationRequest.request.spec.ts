import { parse } from 'querystring'

import { SigningAlgo } from '@sphereon/oid4vc-common'
import { IPresentationDefinition } from '@sphereon/pex'
import { IProofType } from '@sphereon/ssi-types'

import {
  CreateAuthorizationRequestOpts,
  PassBy,
  RequestObject,
  ResponseType,
  Scope,
  SubjectIdentifierType,
  SubjectType,
  SupportedVersion,
  URI,
} from '..'
import SIOPErrors from '../types/Errors'

import { getCreateJwtCallback } from './DidJwtTestUtils'
import { WELL_KNOWN_OPENID_FEDERATION } from './TestUtils'
import {
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData'
import { DcqlQuery } from 'dcql'

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello'
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts'
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f'
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0'
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1'

describe('create Request Uri should', () => {
  it('throw BAD_PARAMS when no responseOpts is passed', async () => {
    expect.assertions(1)
    await expect(URI.fromOpts(undefined as never)).rejects.toThrow(SIOPErrors.BAD_PARAMS)
  })

  it('throw BAD_PARAMS when no responseOpts.redirectUri is passed', async () => {
    expect.assertions(1)
    const opts = {}
    await expect(URI.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.BAD_PARAMS)
  })

  it('throw BAD_PARAMS when no responseOpts.requestObject is passed', async () => {
    expect.assertions(1)
    const opts = { payload: { redirect_uri: EXAMPLE_REDIRECT_URL } }
    await expect(URI.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.BAD_PARAMS)
  })

  it('throw BAD_PARAMS when no responseOpts.requestBy is passed', async () => {
    expect.assertions(1)
    const opts = {
      payload: {
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {},
    }
    await expect(URI.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET)
  })

  it('throw REQUEST_OBJECT_TYPE_NOT_SET when responseOpts.requestBy type is different from REFERENCE or VALUE', async () => {
    expect.assertions(1)
    const opts = {
      payload: {
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        passBy: 'other type',
      },
    }
    await expect(URI.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET)
  })

  it('throw NO_REFERENCE_URI when responseOpts.requestBy type is REFERENCE and no referenceUri is passed', async () => {
    expect.assertions(1)
    const opts = {
      payload: {
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        passBy: PassBy.REFERENCE,
      },
    }
    await expect(URI.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.NO_REFERENCE_URI)
  })

  it('return a reference url', async () => {
    expect.assertions(12)
    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        scope: 'openid',
        response_type: 'id_token',
        request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        jwtIssuer: {
          method: 'did',
          didUrl: KID,
          alg: SigningAlgo.ES256,
        },
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          alg: SigningAlgo.ES256,
          did: DID,
          kid: KID,
        }),
        payload: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'openid',
          response_type: 'id_token',
          request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          redirect_uri: EXAMPLE_REDIRECT_URL,
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100300',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }

    const uriRequest = await URI.fromOpts(opts)
    expect(uriRequest).toBeDefined()
    expect(uriRequest).toHaveProperty('encodedUri')
    expect(uriRequest).toHaveProperty('encodingFormat')
    expect(uriRequest).toHaveProperty('requestObjectJwt')
    expect(uriRequest).toHaveProperty('authorizationRequestPayload')
    expect(uriRequest.authorizationRequestPayload).toBeDefined()

    const uriDecoded = decodeURIComponent(uriRequest.encodedUri)
    expect(uriDecoded).toContain(`openid4vp://`)
    expect(uriDecoded).toContain(`response_type=${ResponseType.ID_TOKEN}`)
    expect(uriDecoded).toContain(`&redirect_uri=${opts.payload?.redirect_uri}`)
    expect(uriDecoded).toContain(`&scope=${Scope.OPENID}`)
    expect(uriDecoded).toContain(`&request_uri=`)

    const data = parse(uriDecoded)
    expect(data.request_uri).toStrictEqual(opts.requestObject.reference_uri)
    // expect(data.registration).toContain('client_purpose#nl-NL');
  })

  it('return a reference url when using did:key', async () => {
    expect.assertions(4)
    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        scope: 'test',
        response_type: 'id_token',
        request_object_signing_alg_values_supported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256 },
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey:
            'd474ffdb3ea75fbb3f07673e67e52002a3b7eb42767f709f4100acf493c7fc8743017577997b72e7a8b4bce8c32c8e78fd75c1441e95d6aaa888056d1200beb3',
          did: 'did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc',
          kid: 'did:key:z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc#z6MkixpejjET5qJK4ebN5m3UcdUPmYV4DPSCs1ALH8x2UCfc',
          alg: SigningAlgo.EDDSA,
        }),
        payload: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: 'id_token',
          request_object_signing_alg_values_supported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
          redirect_uri: EXAMPLE_REDIRECT_URL,
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100301',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }

    const uriRequest = await URI.fromOpts(opts)
    const uriDecoded = decodeURIComponent(uriRequest.encodedUri)

    const data = URI.parse(uriDecoded)
    expect(uriRequest).toHaveProperty('requestObjectJwt')
    expect(uriRequest.authorizationRequestPayload).toBeDefined()
    expect(data.authorizationRequestPayload.request_uri).toEqual(opts.requestObject.reference_uri)
    expect(uriRequest.authorizationRequestPayload.request_uri).toEqual(EXAMPLE_REFERENCE_URL)
  })

  it('return an url with an embedded token value', async () => {
    expect.assertions(4)
    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        scope: 'test',
        response_type: 'id_token',
        request_object_signing_alg_values_supported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        passBy: PassBy.VALUE,
        jwtIssuer: {
          method: 'did',
          didUrl: KID,
          alg: SigningAlgo.ES256K,
        },
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: 'id_token',
          request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          redirect_uri: EXAMPLE_REDIRECT_URL,
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100302',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }

    const uriRequest = await URI.fromOpts(opts)

    const uriDecoded = decodeURIComponent(uriRequest.encodedUri)
    expect(uriDecoded).toContain(`request=eyJhbGciOi`)
    expect(uriDecoded.startsWith(`openid4vp://?client_id=https://www.example.com/`)).toBeTruthy()

    const data = URI.parse(uriDecoded)
    expect(data.scheme).toEqual('openid4vp://')
    expect(data.authorizationRequestPayload.request).toContain(`eyJhbGciOi`)
  })
})

describe('create Request JWT should', () => {
  it('throw REQUEST_OBJECT_TYPE_NOT_SET when requestBy type is different from REFERENCE and VALUE', async () => {
    expect.assertions(1)
    const opts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
        passBy: 'other type' as never,
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
      },
    }
    await expect(RequestObject.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.REQUEST_OBJECT_TYPE_NOT_SET)
  })

  it('throw NO_REFERENCE_URI when no referenceUri is passed with REFERENCE requestBy type is set', async () => {
    expect.assertions(1)
    const opts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        passBy: PassBy.REFERENCE,
        jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.VALUE,
      },
    }
    await expect(RequestObject.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.NO_REFERENCE_URI)
  })

  it('throw REGISTRATION_OBJECT_TYPE_NOT_SET when registrationBy type is neither REFERENCE nor VALUE', async () => {
    expect.assertions(1)
    const opts = {
      requestObject: {
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,
        signature: {
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
        },
        payload: {
          redirect_uri: EXAMPLE_REDIRECT_URL,
        },
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        type: 'FAILURE',
      },
    }
    await expect(RequestObject.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET)
  })

  it('throw NO_REFERENCE_URI when registrationBy type is REFERENCE and no referenceUri is passed', async () => {
    expect.assertions(1)
    const opts = {
      version: SupportedVersion.SIOPv2_ID1,

      requestObject: {
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        signature: {
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
        },
        payload: {
          redirect_uri: EXAMPLE_REDIRECT_URL,
        },
      },
      registration: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },
        passBy: PassBy.REFERENCE,
      },
    }
    await expect(RequestObject.fromOpts(opts as never)).rejects.toThrow(SIOPErrors.NO_REFERENCE_URI)
  })

  it('succeed when all params are set', async () => {
    // expect.assertions(1);
    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: 'test_client_id',
        scope: 'test',
        response_type: 'id_token',
        request_object_signing_alg_values_supported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },

      requestObject: {
        jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          client_id: 'test_client_id',
          scope: 'test',
          response_type: 'id_token',
          request_object_signing_alg_values_supported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
          redirect_uri: EXAMPLE_REDIRECT_URL,
        },
      },
      clientMetadata: {
        client_id: 'test_client_id',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },

        passBy: PassBy.VALUE,

        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100303',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }

    const expected = {
      response_type: 'id_token',
      scope: 'test',
      client_id: 'test_client_id',
      redirect_uri: 'https://acme.com/hello',
      registration: {
        id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        response_types_supported: [ResponseType.ID_TOKEN],
        scopes_supported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_types_supported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did:ethr:', 'did'],
        vp_formats: {
          ldp_vc: {
            proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
          },
        },
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        client_name: VERIFIER_NAME_FOR_CLIENT,
        'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100303',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },

      /*opts: {
        redirectUri: 'https://acme.com/hello',
        requestBy: {
          type: 'REFERENCE',
          reference_uri: 'https://rp.acme.com/siop/jwts',
        },
        withSignature: {
          hexPrivateKey: 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f',
          did: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0',
          kid: 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1',
        },
        registration: {
          idTokenSigningAlgValuesSupported: ['EdDSA', 'ES256'],
          subjectSyntaxTypesSupported: ['did:ethr:', 'did'],
          vpFormatsSupported: {
            ldp_vc: {
              proof_type: ['EcdsaSecp256k1Signature2019', 'EcdsaSecp256k1Signature2019'],
            },
          },
          registrationBy: {
            type: 'VALUE',
          },
        },
      },*/
    }

    // await URI.fromOpts(opts).then((uri) => console.log(uri.encodedUri));
    await expect((await RequestObject.fromOpts(opts)).getPayload()).resolves.toMatchObject(expected)
  })

  it('succeed when requesting with a valid PD', async () => {
    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        scope: 'test',
        response_type: 'id_token',
        request_object_signing_alg_values_supported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: 'id_token',
          redirect_uri: EXAMPLE_REDIRECT_URL,
          request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          claims: {
            vp_token: {
              presentation_definition: {
                id: 'Insurance Plans',
                input_descriptors: [
                  {
                    id: 'Ontario Health Insurance Plan',
                    schema: [
                      {
                        uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },

        passBy: PassBy.VALUE,

        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100305',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }

    const uriRequest = await URI.fromOpts(opts)

    const uriDecoded = decodeURIComponent(uriRequest.encodedUri)
    expect(uriDecoded.startsWith('openid4vp://?')).toBeTruthy()
    expect(uriDecoded).toContain(`request_uri=https://rp.acme.com/siop/jwts`)
    expect((await (await uriRequest.toAuthorizationRequest())?.requestObject?.getPayload())?.claims.vp_token).toBeDefined()
  })

  it('should throw error if presentation definition object is not valid', async () => {
    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: 'test_client_id',
        scope: 'test',
        response_type: 'id_token',
        redirect_uri: EXAMPLE_REDIRECT_URL,
        request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      },

      requestObject: {
        jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          client_id: 'test_client_id',
          scope: 'test',
          response_type: 'id_token',
          redirect_uri: EXAMPLE_REDIRECT_URL,
          request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          claims: {
            vp_token: {
              presentation_definition: {
                input_descriptors: [
                  {
                    id: 'Ontario Health Insurance Plan',
                    schema: [
                      {
                        uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
                      },
                    ],
                  },
                ],
              } as IPresentationDefinition,
            },
          },
        },
      },
      clientMetadata: {
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },

        passBy: PassBy.VALUE,

        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100306',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }
    await expect(URI.fromOpts(opts)).rejects.toThrow(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_DEFINITION_NOT_VALID)
  })

  it('should succeed when requesting with a valid dcql query', async () => {
    const dcqlQuery: DcqlQuery = {
      credentials: [
        {
          id: 'Credentials',
          format: 'jwt_vc_json',
          claims: [
            {
              id: 'ID Card Credential',
              path: ['$.issuer.id'],
              values: ['did:example:issuer'],
            },
          ],
        },
      ],
    }
    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        scope: 'test',
        response_type: 'vp_token',
        request_object_signing_alg_values_supported: [SigningAlgo.ES256, SigningAlgo.EDDSA],
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
        payload: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          scope: 'test',
          response_type: 'vp_token',
          redirect_uri: EXAMPLE_REDIRECT_URL,
          request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          claims: {
            vp_token: {
              dcql_query: JSON.stringify(dcqlQuery)
            },
          },
        },
      },
      clientMetadata: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        vpFormatsSupported: {
          ldp_vc: {
            proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
          },
        },

        passBy: PassBy.VALUE,

        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100305',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }

    const uriRequest = await URI.fromOpts(opts)

    const uriDecoded = decodeURIComponent(uriRequest.encodedUri)
    expect(uriDecoded.startsWith('openid4vp://?')).toBeTruthy()
    expect(uriDecoded).toContain(`request_uri=https://rp.acme.com/siop/jwts`)
    expect((await (await uriRequest.toAuthorizationRequest())?.requestObject?.getPayload())?.claims.vp_token).toBeDefined()
  })
})
