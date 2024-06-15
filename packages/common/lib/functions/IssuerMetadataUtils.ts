import { VCI_LOG_COMMON } from '../index';
import {
  AuthorizationServerMetadata,
  CredentialConfigurationSupported,
  CredentialConfigurationSupportedV1_0_13,
  CredentialIssuerMetadata,
  CredentialSupportedTypeV1_0_08,
  CredentialSupportedV1_0_08,
  IssuerMetadata,
  MetadataDisplay,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
} from '../types';

export function getSupportedCredentials(opts?: {
  issuerMetadata?: CredentialIssuerMetadata | IssuerMetadata;
  version: OpenId4VCIVersion;
  types?: string[][];
  format?: OID4VCICredentialFormat | string | (OID4VCICredentialFormat | string)[];
}): Record<string, CredentialConfigurationSupportedV1_0_13> | Array<CredentialConfigurationSupported> {
  const {version = OpenId4VCIVersion.VER_1_0_13, types} = opts ?? {}
  if (types && Array.isArray(types)) {
    if (version < OpenId4VCIVersion.VER_1_0_13) {
      return types.flatMap(typeSet => getSupportedCredential({ ...opts, version, types: typeSet }) as Array<CredentialConfigurationSupported>);
    } else {
      return types
        .map((typeSet) => {
          return getSupportedCredential({ ...opts, version, types: typeSet });
        })
        .reduce(
          (acc, result) => {
            Object.assign(acc, result);
            return acc;
          },
          {} as Record<string, CredentialConfigurationSupportedV1_0_13>,
        );
    }
  }

  return getSupportedCredential(opts ? { ...opts, types: undefined } : undefined);
}

export function getSupportedCredential(opts?: {
  issuerMetadata?: CredentialIssuerMetadata | IssuerMetadata;
  version: OpenId4VCIVersion;
  types?: string | string[];
  format?: OID4VCICredentialFormat | string | (OID4VCICredentialFormat | string)[];
}): Record<string, CredentialConfigurationSupportedV1_0_13> | Array<CredentialConfigurationSupported> {
  const { issuerMetadata, types, format, version = OpenId4VCIVersion.VER_1_0_13 } = opts ?? {};

  let credentialConfigurationsV11: Array<CredentialConfigurationSupported> | undefined = undefined;
  let credentialConfigurationsV13: Record<string, CredentialConfigurationSupportedV1_0_13> | undefined = undefined;
  if (version < OpenId4VCIVersion.VER_1_0_12 || issuerMetadata?.credentials_supported) {
    credentialConfigurationsV11 = issuerMetadata?.credential_supported ?? [];
  } else {
    credentialConfigurationsV13 =
      (issuerMetadata?.credential_configurations_supported as Record<string, CredentialConfigurationSupportedV1_0_13>) ?? {};
  }
  if (!issuerMetadata || (!issuerMetadata.credential_configurations_supported && !issuerMetadata.credentials_supported)) {
    VCI_LOG_COMMON.warning(`No credential issuer metadata or supported credentials found for issuer}`);
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return version < OpenId4VCIVersion.VER_1_0_13 ? credentialConfigurationsV11! : credentialConfigurationsV13!;
  }

  const normalizedTypes: string[] = Array.isArray(types) ? types : types ? [types] : [];
  const normalizedFormats: string[] = Array.isArray(format) ? format : format ? [format] : [];

  function filterMatchingConfig(config: CredentialConfigurationSupported): CredentialConfigurationSupported | undefined {
    let isTypeMatch = normalizedTypes.length === 0;
    if (!isTypeMatch) {
      if ('credential_definition' in config) {
        isTypeMatch = normalizedTypes.some((type) => config.credential_definition.type?.includes(type));
      } else if ('type' in config && Array.isArray(config.type)) {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        isTypeMatch = normalizedTypes.some((type) => config.type.includes(type));
      } else if ('types' in config) {
        isTypeMatch = normalizedTypes.some((type) => config.types?.includes(type));
      }
    }

    const isFormatMatch = normalizedFormats.length === 0 || normalizedFormats.includes(config.format);

    return isTypeMatch && isFormatMatch ? config : undefined;
  }

  if (credentialConfigurationsV13) {
    return Object.entries(credentialConfigurationsV13).reduce(
      (filteredConfigs, [id, config]) => {
        if (filterMatchingConfig(config)) {
          filteredConfigs[id] = config;
          // Added to enable support < 13. We basically assign the
          if (!config.id) {
            config.id = id;
          }
        }
        return filteredConfigs;
      },
      {} as Record<string, CredentialConfigurationSupportedV1_0_13>,
    );
  } else if (credentialConfigurationsV11) {
    return credentialConfigurationsV11.filter((config) => filterMatchingConfig(config));
  }
  throw Error(`Either < v11 configurations or V13 configurations should have been filtered at this point`);
}

export function getTypesFromCredentialSupported(
  credentialSupported: CredentialConfigurationSupported,
  opts?: { filterVerifiableCredential: boolean },
) {
  let types: string[] = [];
  if (
    credentialSupported.format === 'jwt_vc_json' ||
    credentialSupported.format === 'jwt_vc' ||
    credentialSupported.format === 'jwt_vc_json-ld' ||
    credentialSupported.format === 'ldp_vc'
  ) {
    types =
      (credentialSupported.types
        ? (credentialSupported.types as string[])
        : 'credential_definition' in credentialSupported
          ? credentialSupported.credential_definition?.type
          : []) ?? [];
  } else if (credentialSupported.format === 'vc+sd-jwt') {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    types = [credentialSupported.vct];
  }

  if (!types || types.length === 0) {
    throw Error('Could not deduce types from credential supported');
  }
  if (opts?.filterVerifiableCredential) {
    return types.filter((type) => type !== 'VerifiableCredential');
  }
  return types;
}

export function credentialsSupportedV8ToV13(supportedV8: CredentialSupportedTypeV1_0_08): Record<string, CredentialConfigurationSupported> {
  const credentialConfigsSupported: Record<string, CredentialConfigurationSupported> = {};
  Object.entries(supportedV8).flatMap((entry) => {
    const type = entry[0];
    const supportedV8 = entry[1];
    Object.assign(credentialConfigsSupported, credentialSupportedV8ToV13(type, supportedV8));
  });
  return credentialConfigsSupported;
}

export function credentialSupportedV8ToV13(key: string, supportedV8: CredentialSupportedV1_0_08): Record<string, CredentialConfigurationSupported> {
  const credentialConfigsSupported: Record<string, CredentialConfigurationSupported> = {};
  Object.entries(supportedV8.formats).map((entry) => {
    const format = entry[0];
    const credentialSupportBrief = entry[1];
    if (typeof format !== 'string') {
      throw Error(`Unknown format received ${JSON.stringify(format)}`);
    }
    const credentialConfigSupported: Partial<CredentialConfigurationSupported> = {
      format: format as OID4VCICredentialFormat,
      display: supportedV8.display,
      ...credentialSupportBrief,
      credentialSubject: supportedV8.claims,
    };
    credentialConfigsSupported[key] = credentialConfigSupported as CredentialConfigurationSupported;
  });
  return credentialConfigsSupported;
}

export function getIssuerDisplays(metadata: CredentialIssuerMetadata | IssuerMetadata, opts?: { prefLocales: string[] }): MetadataDisplay[] {
  const matchedDisplays =
    metadata.display?.filter(
      (item) => !opts?.prefLocales || opts.prefLocales.length === 0 || (item.locale && opts.prefLocales.includes(item.locale)) || !item.locale,
    ) ?? [];
  return matchedDisplays.sort((item) => (item.locale ? opts?.prefLocales.indexOf(item.locale) ?? 1 : Number.MAX_VALUE));
}

/**
 * TODO check again when WAL-617 is done to replace how we get the issuer name.
 */
export function getIssuerName(
  url: string,
  credentialIssuerMetadata?: Partial<AuthorizationServerMetadata> & (CredentialIssuerMetadata | IssuerMetadata),
): string {
  if (credentialIssuerMetadata) {
    const displays: Array<MetadataDisplay> = credentialIssuerMetadata ? getIssuerDisplays(credentialIssuerMetadata) : [];
    for (const display of displays) {
      if (display.name) {
        return display.name;
      }
    }
  }
  return url;
}
