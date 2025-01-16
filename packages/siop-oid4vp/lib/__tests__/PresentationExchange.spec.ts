import { SigningAlgo } from '@sphereon/oid4vc-common'
import { PEX } from '@sphereon/pex'
import { PresentationDefinitionV1, PresentationDefinitionV2 } from '@sphereon/pex-models'
import { CredentialMapper, IPresentation, IProofType, IVerifiableCredential } from '@sphereon/ssi-types'
import { W3CVerifiablePresentation } from '@sphereon/ssi-types/src/types/w3c-vc'
import nock from 'nock'

import {
  AuthorizationRequestPayload,
  AuthorizationRequestPayloadVID1,
  getNonce,
  getState,
  IdTokenType,
  PresentationDefinitionWithLocation,
  PresentationExchange,
  PresentationSignCallback,
  ResponseType,
  Scope,
  SubjectIdentifierType,
  SubjectType,
} from '..'
import { SIOPErrors } from '../types'

import { mockedGetEnterpriseAuthToken, pexHasher } from './TestUtils'
import {
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData'

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21'
const EXAMPLE_PD_URL = 'http://my_own_pd.com/pd/'

const KB_JWT = `${Buffer.from(JSON.stringify({ typ: 'kb+jwt' })).toString('base64url')}.${Buffer.from(JSON.stringify({ sd_hash: 'real_hash', iat: 900, nonce: 'nonce' })).toString('base64url')}.signature`
const SD_JWT_VC_CALIFORNIA_DRIVERS_LICENSE =
  'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpYXQiOjE3MDA0NjQ3MzYwNzYsImlzcyI6ImRpZDprZXk6c29tZS1yYW5kb20tZGlkLWtleSIsIm5iZiI6MTcwMDQ2NDczNjE3NiwidmN0IjoiaHR0cHM6Ly9kcml2ZXJzLWxpY2Vuc2UuZ292L2NhbGlmb3JuaWEiLCJ1c2VyIjp7Il9zZCI6WyI5QmhOVDVsSG5QVmpqQUp3TnR0NDIzM216MFVVMUd3RmFmLWVNWkFQV0JNIiwiSVl5d1FQZl8tNE9hY2Z2S2l1cjRlSnFMa1ZleWRxcnQ1Y2UwMGJReWNNZyIsIlNoZWM2TUNLakIxeHlCVl91QUtvLURlS3ZvQllYbUdBd2VGTWFsd05xbUEiLCJXTXpiR3BZYmhZMkdoNU9pWTRHc2hRU1dQREtSeGVPZndaNEhaQW5YS1RZIiwiajZ6ZFg1OUJYZHlTNFFaTGJITWJ0MzJpenRzWXdkZzRjNkpzWUxNc3ZaMCIsInhKR3Radm41cFM4VEhqVFlJZ3MwS1N5VC1uR3BSR3hDVnp6c1ZEbmMyWkUiXX0sImxpY2Vuc2UiOnsibnVtYmVyIjoxMH0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwieSI6Ilp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIl90YnpMeHBaeDBQVHVzV2hPOHRUZlVYU2ZzQjVlLUtrbzl3dmZaaFJrYVkiLCJ1WmNQaHdUTmN4LXpNQU1zemlYMkFfOXlJTGpQSEhobDhEd2pvVXJLVVdZIl19.signature~WyJHeDZHRUZvR2t6WUpWLVNRMWlDREdBIiwiZGF0ZU9mQmlydGgiLCIyMDAwMDEwMSJd~WyJ1LUt3cmJvMkZfTExQekdSZE1XLUtBIiwibmFtZSIsIkpvaG4iXQ~WyJNV1ZieGJqVFZxUXdLS3h2UGVZdWlnIiwibGFzdE5hbWUiLCJEb2UiXQ~' +
  KB_JWT
const SD_JWT_VC_WASHINGTON_DRIVERS_LICENSE =
  'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpYXQiOjE3MDA0NjQ3MzYwNzYsImlzcyI6ImRpZDprZXk6c29tZS1yYW5kb20tZGlkLWtleSIsIm5iZiI6MTcwMDQ2NDczNjE3NiwidmN0IjoiaHR0cHM6Ly9kcml2ZXJzLWxpY2Vuc2UuZ292L3dhc2hpbmd0b24iLCJ1c2VyIjp7Il9zZCI6WyI5QmhOVDVsSG5QVmpqQUp3TnR0NDIzM216MFVVMUd3RmFmLWVNWkFQV0JNIiwiSVl5d1FQZl8tNE9hY2Z2S2l1cjRlSnFMa1ZleWRxcnQ1Y2UwMGJReWNNZyIsIlNoZWM2TUNLakIxeHlCVl91QUtvLURlS3ZvQllYbUdBd2VGTWFsd05xbUEiLCJXTXpiR3BZYmhZMkdoNU9pWTRHc2hRU1dQREtSeGVPZndaNEhaQW5YS1RZIiwiajZ6ZFg1OUJYZHlTNFFaTGJITWJ0MzJpenRzWXdkZzRjNkpzWUxNc3ZaMCIsInhKR3Radm41cFM4VEhqVFlJZ3MwS1N5VC1uR3BSR3hDVnp6c1ZEbmMyWkUiXX0sImxpY2Vuc2UiOnsibnVtYmVyIjoxMH0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwieSI6Ilp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIl90YnpMeHBaeDBQVHVzV2hPOHRUZlVYU2ZzQjVlLUtrbzl3dmZaaFJrYVkiLCJ1WmNQaHdUTmN4LXpNQU1zemlYMkFfOXlJTGpQSEhobDhEd2pvVXJLVVdZIl19.signature~WyJHeDZHRUZvR2t6WUpWLVNRMWlDREdBIiwiZGF0ZU9mQmlydGgiLCIyMDAwMDEwMSJd~WyJ1LUt3cmJvMkZfTExQekdSZE1XLUtBIiwibmFtZSIsIkpvaG4iXQ~WyJNV1ZieGJqVFZxUXdLS3h2UGVZdWlnIiwibGFzdE5hbWUiLCJEb2UiXQ~' +
  KB_JWT

const PRESENTATION_DEFINITION_SD_JWT_DRIVERS_LICENSES = {
  id: '32f54163-7166-48f1-93d8-ff217bdb0653',
  name: 'Conference Entry Requirements',
  purpose: 'We can only allow people associated with Washington State business representatives into conference areas',
  format: {
    'vc+sd-jwt': {},
  },
  input_descriptors: [
    {
      id: 'wa_driver_license',
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            path: ['$.vct'],
            filter: {
              type: 'string',
              const: 'https://drivers-license.gov/washington',
            },
          },
        ],
      },
    },
    {
      id: 'ca_driver_license',
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            path: ['$.vct'],
            filter: {
              type: 'string',
              const: 'https://drivers-license.gov/california',
            },
          },
        ],
      },
    },
  ],
} satisfies PresentationDefinitionV2

async function getPayloadVID1Val({ pd }: { pd?: PresentationDefinitionV2 } = {}): Promise<AuthorizationRequestPayloadVID1> {
  const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp')
  const state = getState()
  return {
    redirect_uri: '',
    scope: Scope.OPENID,
    response_type: ResponseType.ID_TOKEN,
    client_id: mockEntity.did,
    state,
    nonce: getNonce(state),
    registration: {
      client_id: mockEntity.did,
      id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      id_token_types_supported: [IdTokenType.SUBJECT_SIGNED],
      request_object_signing_alg_values_supported: [SigningAlgo.ES256K, SigningAlgo.ES256, SigningAlgo.EDDSA],
      response_types_supported: [ResponseType.ID_TOKEN],
      scopes_supported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
      subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
      subject_types_supported: [SubjectType.PAIRWISE],
      vp_formats: {
        ldp_vc: {
          proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
        },
        jwt_vc: {
          alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
        },
      },
      logo_uri: VERIFIER_LOGO_FOR_CLIENT,
      client_name: VERIFIER_NAME_FOR_CLIENT,
      'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100337',
      client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
    },
    claims: {
      id_token: {
        acr: null,
      },
      vp_token: {
        presentation_definition: pd ?? {
          id: 'Insurance Plans',
          input_descriptors: [
            {
              id: 'Ontario Health Insurance Plan',
              schema: [
                {
                  uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
                },
                {
                  uri: 'https://www.w3.org/2018/credentials/v1',
                },
              ],
              constraints: {
                limit_disclosure: 'preferred',
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
        },
      },
    },
  }
}

async function getPayloadPdRef(): Promise<AuthorizationRequestPayload> {
  const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp')
  const state = getState()
  return {
    redirect_uri: '',
    scope: Scope.OPENID,
    response_type: ResponseType.ID_TOKEN,
    client_id: mockEntity.did,
    state,
    nonce: getNonce(state),
    registration: {
      id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
      id_token_types_supported: [IdTokenType.SUBJECT_SIGNED],
      request_object_signing_alg_values_supported: [SigningAlgo.ES256K, SigningAlgo.ES256, SigningAlgo.EDDSA],
      response_types_supported: [ResponseType.ID_TOKEN],
      scopes_supported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
      subject_syntax_types_supported: ['did:ethr:', SubjectIdentifierType.DID],
      subject_types_supported: [SubjectType.PAIRWISE],
      vp_formats: {
        ldp_vc: {
          proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
        },
        jwt_vc: {
          alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
        },
      },
      logo_uri: VERIFIER_LOGO_FOR_CLIENT,
      client_name: VERIFIER_NAME_FOR_CLIENT,
      'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100338',
      client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
    },
    claims: {
      id_token: {
        acr: null,
      },
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
                {
                  uri: 'https://www.w3.org/2018/credentials/v1',
                },
              ],
              constraints: {
                limit_disclosure: 'preferred',
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
        },
      },
    },
  }
}

function getVCs(): IVerifiableCredential[] {
  return [
    {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
      issuanceDate: '2021-11-01T03:05:06T000z',
      id: 'https://example.com/credentials/1872',
      type: ['VerifiableCredential', 'IDCardCredential'],
      issuer: {
        id: 'did:example:issuer',
      },
      credentialSubject: {
        given_name: 'Fredrik',
        family_name: 'Stremberg',
        birthdate: '1949-01-22',
      },
      proof: {
        type: 'BbsBlsSignatureProof2020',
        created: '2020-04-25',
        verificationMethod: 'did:example:489398593#test',
        proofPurpose: 'assertionMethod',
        proofValue:
          'kTTbA3pmDa6Qia/JkOnIXDLmoBz3vsi7L5t3DWySI/VLmBqleJ/Tbus5RoyiDERDBEh5rnACXlnOqJ/U8yFQFtcp/mBCc2FtKNPHae9jKIv1dm9K9QK1F3GI1AwyGoUfjLWrkGDObO1ouNAhpEd0+et+qiOf2j8p3MTTtRRx4Hgjcl0jXCq7C7R5/nLpgimHAAAAdAx4ouhMk7v9dXijCIMaG0deicn6fLoq3GcNHuH5X1j22LU/hDu7vvPnk/6JLkZ1xQAAAAIPd1tu598L/K3NSy0zOy6obaojEnaqc1R5Ih/6ZZgfEln2a6tuUp4wePExI1DGHqwj3j2lKg31a/6bSs7SMecHBQdgIYHnBmCYGNQnu/LZ9TFV56tBXY6YOWZgFzgLDrApnrFpixEACM9rwrJ5ORtxAAAAAgE4gUIIC9aHyJNa5TBklMOh6lvQkMVLXa/vEl+3NCLXblxjgpM7UEMqBkE9/QcoD3Tgmy+z0hN+4eky1RnJsEg=',
      },
    },
  ]
}

const presentation_submission = {
  id: 'L4tK2DK3rLC9sJhkPgeg_',
  definition_id: 'Insurance Plans',
  descriptor_map: [
    {
      id: 'Ontario Health Insurance Plan',
      format: 'ldp_vc',
      path: '$.verifiableCredential[0]',
    },
  ],
}

describe('presentation exchange manager tests', () => {
  it("validatePresentationAgainstDefinition: should throw error if provided VP doesn't match the PD val", async function () {
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val()
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    const vcs = getVCs()
    vcs[0].issuer = { id: 'did:example:totallyDifferentIssuer' }
    await expect(
      PresentationExchange.validatePresentationsAgainstDefinition(
        pd[0].definition,
        CredentialMapper.toWrappedVerifiablePresentation({
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiablePresentation', 'PresentationSubmission'],
          verifiableCredential: vcs,
          presentation_submission,
        } as W3CVerifiablePresentation),
      ),
    ).rejects.toThrow(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD)
  })

  it("validatePresentationAgainstDefinition: should throw error if provided VP doesn't match the PD ref", async function () {
    const payload: AuthorizationRequestPayload = await getPayloadPdRef()
    const response = {
      id: 'Insurance Plans',
      input_descriptors: [
        {
          id: 'Ontario Health Insurance Plan',
          schema: [
            {
              uri: 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan',
            },
            {
              uri: 'https://www.w3.org/2018/credentials/v1',
            },
          ],
          constraints: {
            limit_disclosure: 'preferred',
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
    nock('http://my_own_pd.com')
      .persist()
      .get(/pd/)
      .reply(200, { ...response })
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    const vcs = getVCs()
    vcs[0].issuer = { id: 'did:example:totallyDifferentIssuer' }
    await expect(
      PresentationExchange.validatePresentationsAgainstDefinition(pd[0].definition, [
        CredentialMapper.toWrappedVerifiablePresentation({
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiablePresentation', 'PresentationSubmission'],
          presentation_submission,
          verifiableCredential: vcs,
        } as W3CVerifiablePresentation),
      ]),
    ).rejects.toThrow(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD)
  })

  it('validatePresentationAgainstDefinition: should throw error if both pd and pd_ref is present', async function () {
    const payload = await getPayloadVID1Val()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(payload.claims?.vp_token as any).presentation_definition_uri = EXAMPLE_PD_URL
    await expect(PresentationExchange.findValidPresentationDefinitions(payload)).rejects.toThrow(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_NON_EXCLUSIVE)
  })

  it('validatePresentationAgainstDefinition: should pass if provided VP match the PD', async function () {
    const payload = await getPayloadVID1Val()
    const vcs = getVCs()
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    const result = await PresentationExchange.validatePresentationsAgainstDefinition(
      pd[0].definition,
      CredentialMapper.toWrappedVerifiablePresentation({
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation', 'PresentationSubmission'],
        presentation_submission,
        verifiableCredential: vcs,
      } as W3CVerifiablePresentation),
    )
    expect(result.errors?.length).toBe(0)
    expect(result.value?.definition_id).toBe('Insurance Plans')
  })

  it('submissionFrom: should pass if a valid presentationSubmission object created', async function () {
    const vcs = getVCs()
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: vcs })
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val()
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    await PresentationExchange.validatePresentationsAgainstDefinition(pd[0].definition, [
      CredentialMapper.toWrappedVerifiablePresentation({
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation', 'PresentationSubmission'],
        presentation_submission,
        verifiableCredential: vcs,
      } as W3CVerifiablePresentation),
    ])
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
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
    const result = await pex.createVerifiablePresentation(pd[0].definition, vcs, presentationSignCallback, {})
    expect(result.presentationSubmission.definition_id).toBe('Insurance Plans')
    expect(result.presentationSubmission.descriptor_map.length).toBe(1)
    expect(result.presentationSubmission.descriptor_map[0]).toStrictEqual({
      format: 'ldp_vp',
      id: 'Ontario Health Insurance Plan',
      path: '$',
      path_nested: {
        format: 'ldp_vc',
        id: 'Ontario Health Insurance Plan',
        path: '$.verifiableCredential[0]',
      },
    })
  })

  it('selectVerifiableCredentialsForSubmission: should fail if selectResults object contains error', async function () {
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val()
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    const vcs = getVCs()
    vcs[0].issuer = undefined as any
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: vcs })
    try {
      await expect(pex.selectVerifiableCredentialsForSubmission(pd[0].definition)).rejects.toThrow()
    } catch (e) {
      expect(e.message).toContain(SIOPErrors.COULD_NOT_FIND_VCS_MATCHING_PD)
    }
  })

  it('selectVerifiableCredentialsForSubmission: should pass if a valid selectResults object created', async function () {
    const vcs = getVCs()
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: vcs })
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val()
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    const result = await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
    expect(result.errors?.length).toBe(0)
    expect(result.matches?.length).toBe(1)
    expect(result.matches?.[0].vc_path.length).toBe(1)
    expect(result.matches?.[0].vc_path[0]).toBe('$.verifiableCredential[0]')
  })

  it('pass if no PresentationDefinition is found', async () => {
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val()
    payload.claims = undefined
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    expect(pd.length).toBe(0)
  })

  it('pass if findValidPresentationDefinitions finds a valid presentation_definition', async () => {
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val()
    const pd = await PresentationExchange.findValidPresentationDefinitions(payload)
    const definition = pd[0].definition as PresentationDefinitionV1
    expect(definition['id']).toBe('Insurance Plans')
    expect(definition['input_descriptors'][0].schema.length).toBe(2)
  })

  it('should validate a single VerifiablePresentations against a list of PresentationDefinitions', async () => {
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val()
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    const vcs = getVCs()
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: vcs })
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
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
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, vcs, presentationSignCallback, {})
    await PresentationExchange.validatePresentationsAgainstDefinitions(
      pd,
      verifiablePresentationResult.verifiablePresentations.map((verifiablePresentation) =>
        CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation),
      )[0],
      undefined,
      {
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
      },
    )
  })

  it('should validate a list of VerifiablePresentations against a list of PresentationDefinitions', async () => {
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val({
      pd: PRESENTATION_DEFINITION_SD_JWT_DRIVERS_LICENSES,
    })
    const pd = await PresentationExchange.findValidPresentationDefinitions(payload)

    // PEX/OID4VP doesn't have all functionality yet to create multi-vp submissions
    // but it can make a submission based on already created presentations
    const vps = [SD_JWT_VC_CALIFORNIA_DRIVERS_LICENSE, SD_JWT_VC_WASHINGTON_DRIVERS_LICENSE]

    const pex = new PEX({ hasher: pexHasher })
    const evaluated = pex.evaluatePresentation(pd[0].definition, vps, { generatePresentationSubmission: true })
    if (!evaluated.value) throw new Error('No presentation submission was generated')

    await PresentationExchange.validatePresentationsAgainstDefinitions(
      pd,
      vps.map((vp) => CredentialMapper.toWrappedVerifiablePresentation(vp, { hasher: pexHasher })),
      undefined,
      {
        presentationSubmission: evaluated.value,
        hasher: pexHasher,
      },
    )
  })

  it("'validatePresentationsAgainstDefinitions' should fail if not all presentations required for a presentation definition are present", async () => {
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val({
      pd: PRESENTATION_DEFINITION_SD_JWT_DRIVERS_LICENSES,
    })
    const pd = await PresentationExchange.findValidPresentationDefinitions(payload)

    const vps = [
      SD_JWT_VC_CALIFORNIA_DRIVERS_LICENSE,
      // Do not include required washington drivers license
      // SD_JWT_VC_WASHINGTON_DRIVERS_LICENSE
    ]

    // Manually created submission as we can't generate an invalid submission with PEX
    const presentationSubmission = {
      id: 'Z4JeKevZqmGFAfKmghwdf',
      definition_id: '32f54163-7166-48f1-93d8-ff217bdb0653',
      descriptor_map: [{ id: 'ca_driver_license', format: 'vc+sd-jwt', path: '$[0]' }],
    }

    await expect(
      PresentationExchange.validatePresentationsAgainstDefinitions(
        pd,
        vps.map((vp) => CredentialMapper.toWrappedVerifiablePresentation(vp, { hasher: pexHasher })),
        undefined,
        {
          presentationSubmission,
          hasher: pexHasher,
        },
      ),
    ).rejects.toThrow(
      `message: Could not find VerifiableCredentials matching presentationDefinition object in the provided VC list, details: [{"status":"error","tag":"SubmissionDoesNotSatisfyDefinition","message":"Expected all input descriptors ('wa_driver_license', 'ca_driver_license') to be satisfied in submission, but found 'ca_driver_license'. Missing 'wa_driver_license'"}]`,
    )
  })

  it("'validatePresentationsAgainstDefinitions' should fail if provided VP verification callback fails", async () => {
    const payload: AuthorizationRequestPayload = await getPayloadVID1Val()
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(payload)
    const vcs = getVCs()
    const pex = new PresentationExchange({ allDIDs: [HOLDER_DID], allVerifiableCredentials: vcs })
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
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
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, vcs, presentationSignCallback, {})

    await expect(
      PresentationExchange.validatePresentationsAgainstDefinitions(
        pd,
        verifiablePresentationResult.verifiablePresentations.map((verifiablePresentation) =>
          CredentialMapper.toWrappedVerifiablePresentation(verifiablePresentation),
        )[0],
        () => {
          throw new Error('Verification failed')
        },
        {
          presentationSubmission: verifiablePresentationResult.presentationSubmission,
        },
      ),
    ).rejects.toThrow(SIOPErrors.VERIFIABLE_PRESENTATION_SIGNATURE_NOT_VALID)
  })
})
