import { AssertedUniformCredentialOffer } from './CredentialIssuance.types';
import { CredentialDataSupplierInput, NotificationRequest, StatusListOpts } from './Generic.types';

export interface StateType {
  createdAt: number;
}

export interface CredentialOfferSession extends StateType {
  clientId?: string;
  credentialOffer: AssertedUniformCredentialOffer;
  credentialDataSupplierInput?: CredentialDataSupplierInput; // Optional storage that can help the credential Data Supplier. For instance to store credential input data during offer creation, if no additional data can be supplied later on
  txCode?: string; // in here we only store the txCode, previously < V13 this was the userPin. We map the userPin onto this value
  status: IssueStatus;
  error?: string;
  lastUpdatedAt: number;
  notification_id: string;
  notification?: NotificationRequest;
  issuerState?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
  preAuthorizedCode?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
  authorizationCode?: string;
  statusLists?: Array<StatusListOpts>;
}

export enum IssueStatus {
  OFFER_CREATED = 'OFFER_CREATED', // An offer is created. This is the initial state
  ACCESS_TOKEN_REQUESTED = 'ACCESS_TOKEN_REQUESTED', // Optional state, given the token endpoint could also be on a separate AS
  ACCESS_TOKEN_CREATED = 'ACCESS_TOKEN_CREATED', // Optional state, given the token endpoint could also be on a separate AS
  CREDENTIAL_REQUEST_RECEIVED = 'CREDENTIAL_REQUEST_RECEIVED', // Credential request received. Next state would either be error or issued
  CREDENTIAL_ISSUED = 'CREDENTIAL_ISSUED', // The credential iss issued from the issuer's perspective
  NOTIFICATION_CREDENTIAL_ACCEPTED = 'NOTIFICATION_CREDENTIAL_ACCEPTED', // The holder/user stored the credential in the wallet (If notifications are enabled)
  NOTIFICATION_CREDENTIAL_DELETED = 'NOTIFICATION_CREDENTIAL_DELETED', // The holder/user did not store the credential in the wallet (If notifications are enabled)
  NOTIFICATION_CREDENTIAL_FAILURE = 'NOTIFICATION_CREDENTIAL_FAILURE',  // The holder/user encountered an error (If notifications are enabled)
  ERROR = 'ERROR', // An error occurred
}

export interface CNonceState extends StateType {
  cNonce: string;
  issuerState?: string;
  preAuthorizedCode?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
}

export interface URIState extends StateType {
  issuerState?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
  preAuthorizedCode?: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
  uri: string; //todo: Probably good to hash it here, since it would come in from the client and we could match the hash and thus use the client value
  credentialOfferCorrelationId?: string;
}

export interface IssueStatusResponse {
  createdAt: number;
  lastUpdatedAt: number;
  status: IssueStatus;
  error?: string;
  clientId?: string;
  statusLists?: Array<StatusListOpts>
}

export interface IStateManager<T extends StateType> {
  set(id: string, stateValue: T): Promise<void>;

  get(id: string): Promise<T | undefined>;

  has(id: string): Promise<boolean>;

  delete(id: string): Promise<boolean>;

  clearExpired(timestamp?: number): Promise<void>; // clears all expired states compared against timestamp if provided, otherwise current timestamp

  clearAll(): Promise<void>; // clears all states

  getAsserted(id: string): Promise<T>;

  startCleanupRoutine(timeout?: number): Promise<void>;

  stopCleanupRoutine(): Promise<void>;
}
