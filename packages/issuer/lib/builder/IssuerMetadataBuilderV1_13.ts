import { CredentialConfigurationSupportedV1_0_13, IssuerMetadataV1_0_13, MetadataDisplay } from '@sphereon/oid4vci-common'

import { CredentialSupportedBuilderV1_13 } from './CredentialSupportedBuilderV1_13'
import { DisplayBuilder } from './DisplayBuilder'

export class IssuerMetadataBuilderV1_13 {
  credentialEndpoint?: string
  credentialIssuer?: string
  supportedBuilders: CredentialSupportedBuilderV1_13[] = []
  credentialConfigurationsSupported: Record<string, CredentialConfigurationSupportedV1_0_13> = {}
  displayBuilders: DisplayBuilder[] = []
  display: MetadataDisplay[] = []
  batchCredentialEndpoint?: string
  authorizationServers?: string[]
  tokenEndpoint?: string
  authorizationChallengeEndpoint?: string

  public withBatchCredentialEndpoint(batchCredentialEndpoint: string) {
    this.batchCredentialEndpoint = batchCredentialEndpoint
    throw Error(`Not supported yet`)
  }

  public withAuthorizationServers(authorizationServers: string[]) {
    this.authorizationServers = authorizationServers
    return this
  }

  public withAuthorizationServer(authorizationServer: string) {
    if (this.authorizationServers === undefined) {
      this.authorizationServers = []
    }
    this.authorizationServers.push(authorizationServer)
    return this
  }

  public withAuthorizationChallengeEndpoint(authorizationChallengeEndpoint: string) {
    this.authorizationChallengeEndpoint = authorizationChallengeEndpoint
    return this
  }

  public withTokenEndpoint(tokenEndpoint: string) {
    this.tokenEndpoint = tokenEndpoint
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): IssuerMetadataBuilderV1_13 {
    this.credentialEndpoint = credentialEndpoint
    return this
  }

  public withCredentialIssuer(credentialIssuer: string): IssuerMetadataBuilderV1_13 {
    this.credentialIssuer = credentialIssuer
    return this
  }

  public newSupportedCredentialBuilder(): CredentialSupportedBuilderV1_13 {
    const builder = new CredentialSupportedBuilderV1_13()
    this.addSupportedCredentialBuilder(builder)
    return builder
  }

  public addSupportedCredentialBuilder(supportedCredentialBuilder: CredentialSupportedBuilderV1_13) {
    this.supportedBuilders.push(supportedCredentialBuilder)
    return this
  }

  public addCredentialConfigurationsSupported(id: string, supportedCredential: CredentialConfigurationSupportedV1_0_13) {
    this.credentialConfigurationsSupported[id] = supportedCredential
    return this
  }

  public withIssuerDisplay(issuerDisplay: MetadataDisplay[] | MetadataDisplay): IssuerMetadataBuilderV1_13 {
    this.display = Array.isArray(issuerDisplay) ? issuerDisplay : [issuerDisplay]
    return this
  }

  public addDisplay(display: MetadataDisplay) {
    this.display.push(display)
  }

  public addDisplayBuilder(displayBuilder: DisplayBuilder) {
    this.displayBuilders.push(displayBuilder)
  }

  public newDisplayBuilder(): DisplayBuilder {
    const builder = new DisplayBuilder()
    this.addDisplayBuilder(builder)
    return builder
  }

  public build(): IssuerMetadataV1_0_13 {
    if (!this.credentialIssuer) {
      throw Error('No credential issuer supplied')
    } else if (!this.credentialEndpoint) {
      throw Error('No credential endpoint supplied')
    }
    const credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0_13> = this.credentialConfigurationsSupported
    const configurationsEntryList: Record<string, CredentialConfigurationSupportedV1_0_13>[] = this.supportedBuilders.map((builder) =>
      builder.build(),
    )
    configurationsEntryList.forEach((configRecord) => {
      Object.keys(configRecord).forEach((key) => {
        credential_configurations_supported[key] = configRecord[key]
      })
    })
    if (Object.keys(credential_configurations_supported).length === 0) {
      throw Error('No supported credentials supplied')
    }

    const display: MetadataDisplay[] = []
    display.push(...this.display)
    display.push(...this.displayBuilders.map((builder) => builder.build()))

    const issuerMetadata: IssuerMetadataV1_0_13 = {
      credential_issuer: this.credentialIssuer,
      credential_endpoint: this.credentialEndpoint,
      credential_configurations_supported,
      // batch_credential_endpoint: this.batchCredentialEndpoint; // not implemented yet
      ...(this.authorizationServers && { authorization_servers: this.authorizationServers }),
      ...(this.tokenEndpoint && { token_endpoint: this.tokenEndpoint }),
      ...(this.authorizationChallengeEndpoint && { authorization_challenge_endpoint: this.authorizationChallengeEndpoint }),
      ...(display.length > 0 && { display }),
    }

    return issuerMetadata
  }
}
