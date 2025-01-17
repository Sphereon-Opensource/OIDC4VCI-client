import { AuthorizationChallengeCodeResponse, AuthorizationResponse } from '../types'

import { convertURIToJsonObject } from './Encoding';

export const toAuthorizationResponsePayload = (input: AuthorizationResponse | AuthorizationChallengeCodeResponse | string): AuthorizationResponse | AuthorizationChallengeCodeResponse => {
  let response = input;
  if (typeof input === 'string') {
    if (input.trim().startsWith('{') && input.trim().endsWith('}')) {
      response = JSON.parse(input);
    } else if (input.includes('?') && input.includes('code')) {
      response = convertURIToJsonObject(input) as AuthorizationResponse;
    }
  }
  if (response && typeof response !== 'string') {
    return response;
  }
  throw Error(`Could not create authorization response from the input ${input}`);
};
