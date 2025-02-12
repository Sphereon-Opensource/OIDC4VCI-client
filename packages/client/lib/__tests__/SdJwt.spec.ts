import {
  AccessTokenRequest,
  CredentialConfigurationSupportedSdJwtVcV1_0_13,
  CredentialConfigurationSupportedV1_0_13,
  CredentialSupportedSdJwtVc
} from '@sphereon/oid4vci-common'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock'

import { OpenID4VCIClientV1_0_13 } from '..'
import {
  AuthorizationServerMetadataBuilder,
  createAccessTokenResponse,
  IssuerMetadataBuilderV1_13,
  VcIssuerBuilder
} from '../../../issuer'

export const UNIT_TEST_TIMEOUT = 30000;

const alg = 'ES256';
const jwk = { kty: 'EC', crv: 'P-256', x: 'zQOowIC1gWJtdddB5GAt4lau6Lt8Ihy771iAfam-1pc', y: 'cjD_7o3gdQ1vgiQy3_sMGs7WrwCMU9FQYimA3HxnMlw' };

const issuerMetadata = new IssuerMetadataBuilderV1_13()
  .withCredentialIssuer('https://example.com')
  .withCredentialEndpoint('https://credential-endpoint.example.com')
  .withTokenEndpoint('https://token-endpoint.example.com')
  .addCredentialConfigurationsSupported('SdJwtCredentialId', {
    format: 'vc+sd-jwt',
    vct: 'SdJwtCredentialId',
    id: 'SdJwtCredentialId',
  } as CredentialConfigurationSupportedV1_0_13)
  .build();

const authorizationServerMetadata = new AuthorizationServerMetadataBuilder()
  .withIssuer(issuerMetadata.credential_issuer)
  .withCredentialEndpoint(issuerMetadata.credential_endpoint)
  .withTokenEndpoint(issuerMetadata.token_endpoint!)
  .withAuthorizationEndpoint('https://token-endpoint.example.com/authorize')
  .withTokenEndpointAuthMethodsSupported(['none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post'])
  .withResponseTypesSupported(['code', 'token', 'id_token'])
  .withScopesSupported(['openid', 'abcdef'])
  .build();

const vcIssuer = new VcIssuerBuilder()
  .withIssuerMetadata(issuerMetadata)
  .withAuthorizationMetadata(authorizationServerMetadata)
  .withInMemoryCNonceState()
  .withInMemoryCredentialOfferState()
  .withInMemoryCredentialOfferURIState()
  // TODO: see if we can construct an sd-jwt vc based on the input
  .withCredentialSignerCallback(async () => {
    return 'sd-jwt';
  })
  .withJWTVerifyCallback(() =>
    Promise.resolve({
      alg,
      jwk,
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg,
          jwk,
        },
        payload: {
          aud: issuerMetadata.credential_issuer,
          iat: +new Date() / 1000,
          nonce: 'a-c-nonce',
        },
      },
    }),
  )
  .build();

describe('sd-jwt vc', () => {
  beforeEach(() => {
    nock.cleanAll();
  });
  afterEach(() => {
    nock.cleanAll();
  });

  it(
    'succeed with a full flow',
    async () => {
      const offerUri = await vcIssuer.createCredentialOfferURI({
        offerMode: 'VALUE',
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            tx_code: {
              input_mode: 'text',
              length: 3,
            },
            'pre-authorized_code': '123',
          },
        },
        credential_configuration_ids: ['SdJwtCredential'],
      });

      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/openid-credential-issuer').reply(200, JSON.stringify(issuerMetadata));
      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/openid-configuration').reply(404);
      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/oauth-authorization-server').reply(404);

      expect(offerUri.uri).toEqual(
        'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fexample.com%22%2C%22credential_configuration_ids%22%3A%5B%22SdJwtCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22tx_code%22%3A%7B%22input_mode%22%3A%22text%22%2C%22length%22%3A3%7D%2C%22pre-authorized_code%22%3A%22123%22%7D%7D%7D',
      );

      const client = await OpenID4VCIClientV1_0_13.fromURI({
        uri: offerUri.uri,
      });

      expect(client.credentialOffer?.credential_offer).toEqual({
        credential_issuer: 'https://example.com',
        credential_configuration_ids: ['SdJwtCredential'],
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': '123',
            tx_code: {
              input_mode: 'text',
              length: 3,
            },
          },
        },
      });

      const supported = client.getCredentialsSupported('vc+sd-jwt');
      expect(supported).toEqual({ SdJwtCredentialId: { format: 'vc+sd-jwt', id: 'SdJwtCredentialId', vct: 'SdJwtCredentialId' } });

      const offered = supported['SdJwtCredentialId'] as CredentialConfigurationSupportedSdJwtVcV1_0_13;

      nock(issuerMetadata.token_endpoint as string)
        .post('/')
        .reply(200, async (_, body: string) => {
          const parsedBody = Object.fromEntries(body.split('&').map((x) => x.split('=')));
          return createAccessTokenResponse(parsedBody as AccessTokenRequest, {
            credentialOfferSessions: vcIssuer.credentialOfferSessions,
            accessTokenIssuer: 'https://issuer.example.com',
            cNonces: vcIssuer.cNonces,
            cNonce: 'a-c-nonce',
            accessTokenSignerCallback: async () => 'ey.val.ue',
            tokenExpiresIn: 500,
          });
        });

      await client.acquireAccessToken({ pin: '123' });
      nock(issuerMetadata.credential_endpoint as string)
        .post('/')
        .reply(200, async (_, body) =>
          vcIssuer.issueCredential({
            credentialRequest: { ...(body as any), credential_identifier: 'SdJwtCredentialId' },
            credential: {
              vct: 'Hello',
              iss: 'did:example:123',
              iat: 123,
              // Defines what can be disclosed (optional)
              __disclosureFrame: {
                name: true,
              },
            },
            newCNonce: 'new-c-nonce',
          }),
        );

      const credentials = await client.acquireCredentials({
        credentialIdentifier: offered.vct,
        // format: 'vc+sd-jwt',
        alg,
        jwk,
        proofCallbacks: {
          // When using sd-jwt for real, this jwt should include a jwk
          signCallback: async () => 'ey.ja.ja',
        },
      });

      expect(credentials).toEqual({
        notification_id: expect.any(String),
        access_token: 'ey.val.ue',
        c_nonce: 'new-c-nonce',
        c_nonce_expires_in: 300,
        credential: 'sd-jwt',
        // format: 'vc+sd-jwt',
      });
    },
    UNIT_TEST_TIMEOUT,
  );

  it(
    'succeed with a full flow without did',
    async () => {
      const offerUri = await vcIssuer.createCredentialOfferURI({
        offerMode: 'VALUE',
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            tx_code: {
              input_mode: 'text',
              length: 3,
            },
            'pre-authorized_code': '123',
          },
        },
        credential_configuration_ids: ['SdJwtCredential'],
      });

      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/openid-credential-issuer').reply(200, JSON.stringify(issuerMetadata));
      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/openid-configuration').reply(404);
      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/oauth-authorization-server').reply(404);

      expect(offerUri.uri).toEqual(
        'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fexample.com%22%2C%22credential_configuration_ids%22%3A%5B%22SdJwtCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22tx_code%22%3A%7B%22input_mode%22%3A%22text%22%2C%22length%22%3A3%7D%2C%22pre-authorized_code%22%3A%22123%22%7D%7D%7D',
      );

      const client = await OpenID4VCIClientV1_0_13.fromURI({
        uri: offerUri.uri,
      });

      expect(client.credentialOffer?.credential_offer).toEqual({
        credential_issuer: 'https://example.com',
        credential_configuration_ids: ['SdJwtCredential'],
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': '123',
            tx_code: {
              input_mode: 'text',
              length: 3,
            },
          },
        },
      });

      const supported = client.getCredentialsSupported('vc+sd-jwt');
      expect(supported).toEqual({ SdJwtCredentialId: { format: 'vc+sd-jwt', id: 'SdJwtCredentialId', vct: 'SdJwtCredentialId' } });

      const offered = supported['SdJwtCredentialId'] as CredentialSupportedSdJwtVc;

      nock(issuerMetadata.token_endpoint as string)
        .post('/')
        .reply(200, async (_, body: string) => {
          const parsedBody = Object.fromEntries(body.split('&').map((x) => x.split('=')));
          return createAccessTokenResponse(parsedBody as AccessTokenRequest, {
            credentialOfferSessions: vcIssuer.credentialOfferSessions,
            accessTokenIssuer: 'https://issuer.example.com',
            cNonces: vcIssuer.cNonces,
            cNonce: 'a-c-nonce',
            accessTokenSignerCallback: async () => 'ey.val.ue',
            tokenExpiresIn: 500,
          });
        });

      await client.acquireAccessToken({ pin: '123' });
      nock(issuerMetadata.credential_endpoint as string)
        .post('/')
        .reply(200, async (_, body) =>
          vcIssuer.issueCredential({
            credentialRequest: { ...(body as any), credential_identifier: offered.vct },
            credential: {
              vct: 'Hello',
              iss: 'example.com',
              iat: 123,
              // Defines what can be disclosed (optional)
              __disclosureFrame: {
                name: true,
              },
            },
            newCNonce: 'new-c-nonce',
          }),
        );

      const credentials = await client.acquireCredentials({
        credentialIdentifier: offered.vct,
        // format: 'vc+sd-jwt',
        alg,
        jwk,
        proofCallbacks: {
          // When using sd-jwt for real, this jwt should include a jwk
          signCallback: async () => 'ey.ja.ja',
        },
      });

      expect(credentials).toEqual({
        notification_id: expect.any(String),
        access_token: 'ey.val.ue',
        c_nonce: 'new-c-nonce',
        c_nonce_expires_in: 300,
        credential: 'sd-jwt',
        // format: 'vc+sd-jwt',
      });
    },
    UNIT_TEST_TIMEOUT,
  );
});
