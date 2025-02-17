import { CredentialOfferPayloadV1_0_11, CredentialOfferPayloadV1_0_13, PRE_AUTH_CODE_LITERAL, PRE_AUTH_GRANT_LITERAL } from '@sphereon/oid4vci-common'

import { createCredentialOfferObject, createCredentialOfferURI, createCredentialOfferURIv1_0_11 } from '../index'

describe('CredentialOfferUtils should', () => {
  it('create a deeplink from credentialOffer object', () => {
    // below is the example from spec (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-sending-credential-offer-by) and is wrong, the issuer_state should be in the grants and not a top-level property
    // openid-credential-offer://credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D
    const credentialOffer = {
      credential_issuer: 'https://credential-issuer.example.com',
      credential_configuration_ids: ['UniversityDegreeCredential'],
      grants: {
        authorization_code: {
          issuer_state: 'eyJhbGciOiJSU0Et...FYUaBy',
        },
      },
    } satisfies CredentialOfferPayloadV1_0_13
    expect(createCredentialOfferURI(undefined, { credentialOffer })).toEqual(
      'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fcredential-issuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D%7D%7D',
    )
  })

  it('create a v13 credential offer with grants', () => {
    const credentialOffer = {
      credential_issuer: 'https://credential-issuer.example.com',
      credential_configuration_ids: ['UniversityDegreeCredential'],
      grants: {
        authorization_code: {
          issuer_state: 'eyJhbGciOiJSU0Et...FYUaBy',
        },
      },
    } satisfies CredentialOfferPayloadV1_0_13
    expect(
      createCredentialOfferObject(undefined, {
        credentialOfferUri: 'https://test.com',
        credentialOffer: {
          credential_configuration_ids: ['one'],
          credential_issuer: credentialOffer.credential_issuer,
        },
        grants: {
          authorization_code: {
            authorization_server: 'https://test.com',
          },
          [PRE_AUTH_GRANT_LITERAL]: {
            authorization_server: 'https://test.com',
          },
        },
      }),
    ).toEqual({
      credential_offer: {
        credential_configuration_ids: ['one'],
        credential_issuer: 'https://credential-issuer.example.com',
        grants: {
          authorization_code: {
            authorization_server: 'https://test.com',
            issuer_state: expect.any(String),
          },
          [PRE_AUTH_GRANT_LITERAL]: {
            [PRE_AUTH_CODE_LITERAL]: expect.any(String),
            authorization_server: 'https://test.com',
          },
        },
      },
      credential_offer_uri: 'https://test.com',
    })
  })

  it('create an https link from credentialOffer object', () => {
    // below is the example from spec (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-sending-credential-offer-by) and is wrong, the issuer_state should be in the grants and not a top-level property
    // https://credential-issuer.example.com?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D
    const credentialOffer = {
      credential_issuer: 'https://credential-issuer.example.com',

      credentials: [
        {
          format: 'jwt_vc_json',
          types: ['VerifiableCredential', 'UniversityDegreeCredential'],
        },
      ],
      grants: {
        authorization_code: {
          issuer_state: 'eyJhbGciOiJSU0Et...FYUaBy',
        },
      },
    } as CredentialOfferPayloadV1_0_11

    expect(
      createCredentialOfferURIv1_0_11(
        {
          credential_issuer: credentialOffer.credential_issuer,
          credential_endpoint: 'test_issuer',
          issuer: 'test_issuer',
          credentials_supported: [],
        },
        { credentialOffer, scheme: 'https' },
      ),
    ).toEqual(
      `${credentialOffer.credential_issuer}?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fcredential-issuer.example.com%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D%7D%7D`,
    )
  })

  it('create an http link from credentialOffer object', () => {
    // below is the example from spec (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-sending-credential-offer-by) and is wrong, the issuer_state should be in the grants and not a top-level property
    // http://credential-issuer.example.com?credential_offer=%7B%22credential_issuer%22:%22http://credential-issuer.example.com%22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D
    const credentialOffer = {
      credential_issuer: 'http://credential-issuer.example.com',
      credentials: [
        {
          format: 'jwt_vc_json',
          types: ['VerifiableCredential', 'UniversityDegreeCredential'],
        },
      ],
      grants: {
        authorization_code: {
          issuer_state: 'eyJhbGciOiJSU0Et...FYUaBy',
        },
      },
    } as CredentialOfferPayloadV1_0_11

    expect(
      createCredentialOfferURIv1_0_11(
        {
          credential_issuer: credentialOffer.credential_issuer,
          credential_endpoint: 'test_issuer',
          issuer: 'test_issuer',
          credentials_supported: [],
        },
        { credentialOffer, scheme: 'http' },
      ),
    ).toEqual(
      `${credentialOffer.credential_issuer}?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fcredential-issuer.example.com%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D%7D%7D`,
    )
  })
})
