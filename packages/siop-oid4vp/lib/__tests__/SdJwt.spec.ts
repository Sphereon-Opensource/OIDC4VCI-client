import { defaultHasher, SigningAlgo } from '@sphereon/oid4vc-common'
import { IPresentationDefinition } from '@sphereon/pex'
import { decodeSdJwtVc, OriginalVerifiableCredential } from '@sphereon/ssi-types'
import { DcqlCredential, DcqlQuery } from 'dcql'

import {
  OP,
  PassBy,
  PresentationDefinitionWithLocation,
  PresentationExchange,
  PresentationVerificationCallback,
  PropertyTarget,
  ResponseIss,
  ResponseMode,
  ResponseType,
  RevocationVerification,
  RP,
  Scope,
  SubjectType,
  SupportedVersion,
  VPTokenLocation,
} from '../'

import { getVerifyJwtCallback, internalSignature } from './DidJwtTestUtils'
import { getResolver } from './ResolverTestUtils'
import { mockedGetEnterpriseAuthToken, pexHasher, sdJwtVcPresentationSignCallback, WELL_KNOWN_OPENID_FEDERATION } from './TestUtils'
import {
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData'

jest.setTimeout(30000)

type Json = string | number | boolean | null | { // Not exported from dcql
  [key: string]: Json;
} | Json[];


const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello'

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21'
const SD_JWT_VC =
  'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpYXQiOjE3MDA0NjQ3MzYwNzYsImlzcyI6ImRpZDprZXk6c29tZS1yYW5kb20tZGlkLWtleSIsIm5iZiI6MTcwMDQ2NDczNjE3NiwidmN0IjoiaHR0cHM6Ly9oaWdoLWFzc3VyYW5jZS5jb20vU3RhdGVCdXNpbmVzc0xpY2Vuc2UiLCJ1c2VyIjp7Il9zZCI6WyI5QmhOVDVsSG5QVmpqQUp3TnR0NDIzM216MFVVMUd3RmFmLWVNWkFQV0JNIiwiSVl5d1FQZl8tNE9hY2Z2S2l1cjRlSnFMa1ZleWRxcnQ1Y2UwMGJReWNNZyIsIlNoZWM2TUNLakIxeHlCVl91QUtvLURlS3ZvQllYbUdBd2VGTWFsd05xbUEiLCJXTXpiR3BZYmhZMkdoNU9pWTRHc2hRU1dQREtSeGVPZndaNEhaQW5YS1RZIiwiajZ6ZFg1OUJYZHlTNFFaTGJITWJ0MzJpenRzWXdkZzRjNkpzWUxNc3ZaMCIsInhKR3Radm41cFM4VEhqVFlJZ3MwS1N5VC1uR3BSR3hDVnp6c1ZEbmMyWkUiXX0sImxpY2Vuc2UiOnsibnVtYmVyIjoxMH0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwieSI6Ilp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIl90YnpMeHBaeDBQVHVzV2hPOHRUZlVYU2ZzQjVlLUtrbzl3dmZaaFJrYVkiLCJ1WmNQaHdUTmN4LXpNQU1zemlYMkFfOXlJTGpQSEhobDhEd2pvVXJLVVdZIl19.HAcudVInhNpXkTPQGNosjKTFRJWgKj90NpfloRaDQchGd4zxc1ChWTCCPXzUXTBypASKrzgjZCiXlTr0bzmLAg~WyJHeDZHRUZvR2t6WUpWLVNRMWlDREdBIiwiZGF0ZU9mQmlydGgiLCIyMDAwMDEwMSJd~WyJ1LUt3cmJvMkZfTExQekdSZE1XLUtBIiwibmFtZSIsIkpvaG4iXQ~WyJNV1ZieGJqVFZxUXdLS3h2UGVZdWlnIiwibGFzdE5hbWUiLCJEb2UiXQ~'
const KB_SD_JWT_PRESENTATION = 'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnNvbWUtcmFuZG9tLWRpZC1rZXkiLCJpYXQiOjE3MzU4MzY0NzY1NjksInZjdCI6Imh0dHBzOi8vaGlnaC1hc3N1cmFuY2UuY29tL1N0YXRlQnVzaW5lc3NMaWNlbnNlIiwiX3NkIjpbIk5ub3U2OGN6VG9qQWY0Z3dIMmJiNFBaWHB4WHJzQ29oWm5CbEZvQ293TTAiLCJ1ajZZZVZwSnRwUjhVWHRpbmVDOGM5LXpTRFJVQzJzSGhsRkNNNWtkLXlNIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.X1pNBBmR-7h6SgxtmZY9GL_nSBzoIvWNw7nqqgJVCnSEbvyTjqTgu4bLSPKeaxf1jY2zHJK1jdxiDzIizRZ0gA~WyI4OTE4YjkxZGFjMzk1OTdkIiwidXNlciIseyJkYXRlX29mX2JpcnRoIjoiMDEvMDEvMTk3MCIsIl9zZCI6WyJ6UE8zb1RCT3BxMmRNcWQtekt5SmF2UlQyWVIwSHBPaV9jczZRajEtVmR3Il19XQ~WyIyOTc4NTNiODE5MTI0MTJkIiwibmFtZSIsIkpvaG4iXQ~WyJkYjEzNDQ4NTgxMzY0M2JlIiwibGljZW5zZSIseyJfc2QiOlsiWUFUR3A3TGxjNEMtTWtYWkZWTEF6RHRtbDFTMVpFWFFyTW5CdmVDWVFwayJdfV0~WyJlOTc3MzhiNmM0OGNhMWJlIiwibnVtYmVyIiwxMF0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MzU4MzY0NzYsImF1ZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJub25jZSI6InFCclI3bXFuWTNRcjQ5ZEFaeWNQRjhGemdFODNtNkgwYzJsMGJ6UDR4U2ciLCJjdXN0b20iOiJkYXRhIiwic2RfaGFzaCI6IlVwYzNYQWpzRU1mdnVmSzJ5Q3RkNDZXUFJmTDVfVDc4UThEZVNZQXlEX28ifQ.Crw56nLFFnVulRQElpq9HoskdKIyd5Mj6vg9UVNSWfhxQ0oGe10RHtifUv4BiFharSvWN99y_DnkhCPu1sPIYw'

function getPresentationDefinition(): IPresentationDefinition {
  return {
    id: '32f54163-7166-48f1-93d8-ff217bdb0653',
    name: 'Conference Entry Requirements',
    purpose: 'We can only allow people associated with Washington State business representatives into conference areas',
    format: {
      'vc+sd-jwt': {},
    },
    input_descriptors: [
      {
        id: 'wa_driver_license',
        name: 'Washington State Business License',
        purpose: 'We can only allow licensed Washington State business representatives into the WA Business Conference',
        constraints: {
          limit_disclosure: 'required',
          fields: [
            {
              path: ['$.vct'],
              filter: {
                type: 'string',
                const: 'https://high-assurance.com/StateBusinessLicense',
              },
            },
            {
              path: ['$.license.number'],
              filter: {
                type: 'number',
              },
            },
            {
              path: ['$.user.name'],
              filter: {
                type: 'string',
              },
            },
          ],
        },
      },
    ],
  }
}

const sdJwtVcQuery: DcqlQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'vc+sd-jwt',
      meta: {
        vct_values: ['https://high-assurance.com/StateBusinessLicense'],
      },
      claims: [{ path: ['license', 'number'] }, { path: ['user', 'name'] }],
    },
  ],
}

DcqlQuery.validate(sdJwtVcQuery)

function getVCs(): OriginalVerifiableCredential[] {
  return [SD_JWT_VC]
}

describe.skip('RP and OP interaction should', () => {
  // FIXME SDK-45 Uniresolver failing
  it('succeed when calling with presentation definitions and right verifiable presentation', async () => {
    const opMock = await mockedGetEnterpriseAuthToken('OP')
    const opMockEntity = {
      ...opMock,
      didKey: `${opMock.did}#controller`,
    }
    const rpMock = await mockedGetEnterpriseAuthToken('RP')
    const rpMockEntity = {
      ...rpMock,
      didKey: `${rpMock.did}#controller`,
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => {
      return { verified: true }
    }

    const resolver = getResolver('ethr')
    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withHasher(pexHasher)
      .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withPresentationDefinition({ definition: getPresentationDefinition() }, [PropertyTarget.REQUEST_OBJECT, PropertyTarget.AUTHORIZATION_REQUEST])
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withCreateJwtCallback(internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:key'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build()

    const op = OP.builder()
      .withPresentationSignCallback(sdJwtVcPresentationSignCallback)
      .withExpiresIn(1000)
      .withHasher(pexHasher)
      .withCreateJwtCallback(internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build()

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    })

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri)
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined()
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined()

    if (!parsedAuthReqURI.requestObjectJwt) throw new Error('requestObjectJwt is undefined')
    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt)
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did)
    const pex = new PresentationExchange({
      allDIDs: [HOLDER_DID],
      allVerifiableCredentials: getVCs(),
      hasher: pexHasher,
    })
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      parsedAuthReqURI.authorizationRequestPayload,
    )
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), sdJwtVcPresentationSignCallback, {
      proofOptions: {
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      },
    })
    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      presentationExchange: {
        verifiablePresentations: verifiablePresentationResult.verifiablePresentations,
        vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
      },
    })
    expect(authenticationResponseWithJWT.response.payload).toBeDefined()
    expect(authenticationResponseWithJWT.response.idToken).toBeDefined()

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
    })

    expect(verifiedAuthResponseWithJWT.idToken?.jwt).toBeDefined()
    expect(verifiedAuthResponseWithJWT.idToken?.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg')
  })

  it('succeed when calling with presentation definitions and right verifiable presentation without id token', async () => {
    const opMockEntity = await mockedGetEnterpriseAuthToken('OP')
    const rpMockEntity = await mockedGetEnterpriseAuthToken('RP')

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => {
      return { verified: true }
    }

    const resolver = getResolver('ethr')
    const rp = RP.builder({
      requestVersion: SupportedVersion.SIOPv2_D12_OID4VP_D18,
    })
      .withClientId(rpMockEntity.did)
      .withHasher(pexHasher)
      .withResponseType([ResponseType.VP_TOKEN])
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withPresentationDefinition({ definition: getPresentationDefinition() }, [PropertyTarget.REQUEST_OBJECT, PropertyTarget.AUTHORIZATION_REQUEST])
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withCreateJwtCallback(internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.VP_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:key'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build()
    const op = OP.builder()
      .withPresentationSignCallback(sdJwtVcPresentationSignCallback)
      .withExpiresIn(1000)
      .withHasher(pexHasher)
      .withCreateJwtCallback(internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
      .build()

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
      jwtIssuer: { method: 'did', alg: SigningAlgo.ES256K, didUrl: `${rpMockEntity.did}#controller` },
    })

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri)
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined()
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined()

    if (!parsedAuthReqURI.requestObjectJwt) throw new Error('requestObjectJwt is undefined')
    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt)
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did)
    const pex = new PresentationExchange({
      allDIDs: [HOLDER_DID],
      allVerifiableCredentials: getVCs(),
      hasher: pexHasher,
    })
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      parsedAuthReqURI.authorizationRequestPayload,
    )
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, getVCs(), sdJwtVcPresentationSignCallback, {
      proofOptions: {
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      },
    })
    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      jwtIssuer: {
        method: 'did',
        alg: SigningAlgo.ES256K,
        didUrl: `${rpMockEntity.did}#controller`,
      },
      presentationExchange: {
        verifiablePresentations: verifiablePresentationResult.verifiablePresentations,
        vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
      },
    })
    expect(authenticationResponseWithJWT.response.payload).toBeDefined()
    expect(authenticationResponseWithJWT.response.idToken).toBeUndefined()

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
    })

    expect(verifiedAuthResponseWithJWT.oid4vpSubmission?.nonce).toEqual('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg')
    expect(verifiedAuthResponseWithJWT.idToken).toBeUndefined()
  })

  it('succeed when calling with DCQL and right verifiable presentation', async () => {
    const opMock = await mockedGetEnterpriseAuthToken('OP')
    const opMockEntity = {
      ...opMock,
      didKey: `${opMock.did}#controller`,
    }
    const rpMock = await mockedGetEnterpriseAuthToken('RP')
    const rpMockEntity = {
      ...rpMock,
      didKey: `${rpMock.did}#controller`,
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => {
      return { verified: true }
    }

    const resolver = getResolver('ethr')
    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_D12_OID4VP_D20 })
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withHasher(pexHasher)
      .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
      .withResponseMode(ResponseMode.DIRECT_POST)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withDcqlQuery(sdJwtVcQuery, [PropertyTarget.REQUEST_OBJECT])
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withCreateJwtCallback(internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:key'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .build()

    const op = OP.builder()
      .withPresentationSignCallback(sdJwtVcPresentationSignCallback)
      .withExpiresIn(1000)
      .withHasher(pexHasher)
      .withCreateJwtCallback(internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_D12_OID4VP_D20)
      .build()

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    })

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri)
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined()
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined()

    if (!parsedAuthReqURI.requestObjectJwt) throw new Error('requestObjectJwt is undefined')
    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt)
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did)

    // The KB property is added to the JWT when the presentation is signed. Passing a VC will make the test fail
    const dcqlCredentials: DcqlCredential[] = [KB_SD_JWT_PRESENTATION].map(vc => ({ credential_format: 'vc+sd-jwt', claims: decodeSdJwtVc(vc as string, defaultHasher).decodedPayload as { [x: string]: Json }, vct: decodeSdJwtVc(vc as string, defaultHasher).decodedPayload.vct } ))

    const queryResult = DcqlQuery.query(sdJwtVcQuery, dcqlCredentials)

    expect(queryResult).toEqual({
      "canBeSatisfied": true,
      "credential_matches": {
        "my_credential": {
          "all": [
            [
              {
                "credential_index": 0,
                "output": {
                  "claims": {
                    "license": {
                      "number": 10
                    },
                    "user": {
                      "name": "John"
                    }
                  },
                  "vct": "https://high-assurance.com/StateBusinessLicense"
                },
                "success": true,
                "typed": true
              }
            ]
          ],
          "credential_index": 0,
          "output": {
            "claims": {
              "license": {
                "number": 10
              },
              "user": {
                "name": "John"
              }
            },
            "vct": "https://high-assurance.com/StateBusinessLicense"
          },
          "success": true,
          "typed": true
        }
      },
      "credentials": [
        {
          "claims": [
            {
              "path": [
                "license",
                "number"
              ]
            },
            {
              "path": [
                "user",
                "name"
              ]
            }
          ],
          "format": "vc+sd-jwt",
          "id": "my_credential",
          "meta": {
            "vct_values": [
              "https://high-assurance.com/StateBusinessLicense"
            ]
          }
        }
      ]
    })

    const dcqlPresentation: { [x: string]: string | { [x: string]: Json } } = {}

    for (const [key, _] of Object.entries(queryResult.credential_matches)) {
      dcqlPresentation[key] = KB_SD_JWT_PRESENTATION as string | { [x: string]: Json }
    }

    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      dcqlQuery: { dcqlPresentation },
    })
    expect(authenticationResponseWithJWT.response.payload).toBeDefined()
    expect(authenticationResponseWithJWT.response.idToken).toBeDefined()

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      dcqlQuery: sdJwtVcQuery,
    })

    expect(verifiedAuthResponseWithJWT.idToken?.jwt).toBeDefined()
    expect(verifiedAuthResponseWithJWT.idToken?.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg')
  })
})
