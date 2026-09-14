import { describe, expect, it } from 'vitest';

import { ruleForName, wordsOf } from './names.ts';

describe('names: a field name is read as words', () => {
  it.each([
    ['clientIP', ['client', 'ip']],
    ['userPIN', ['user', 'pin']],
    ['HMACKey', ['hmac', 'key']],
    ['x-api-key', ['x', 'api', 'key']],
    ['refresh_token', ['refresh', 'token']],
    ['dateOfBirth', ['date', 'of', 'birth']],
    ['ipv4Address', ['ipv4', 'address']],
    ['IBAN', ['iban']],
  ])('%s is %j', (name, words) => {
    expect(wordsOf(name)).toEqual(words);
  });
});

describe('SEC-DATA-05 names whose values are never logged', () => {
  it.each([
    // Secrets and credentials
    'password',
    'userPassword',
    'passwd',
    'pwd',
    'pass',
    'passphrase',
    'passcode',
    'secret',
    'clientSecret',
    'token',
    'accessToken',
    'refresh_token',
    'jwt',
    'authorization',
    'Authorization',
    'auth',
    'authCode',
    'cookie',
    'set-cookie',
    'apiKey',
    'x-api-key',
    'accessKey',
    'privateKey',
    'signingKey',
    'encryptionKey',
    'hmacKey',
    'webhookKey',
    'key',
    'pepper',
    'salt',
    'nonce',
    'codeVerifier',
    'credentials',
    'sessionId',
    'x-signature',
    'sig',
    'otp',
    'otpCode',
    'oneTimePasscode',
    'pin',
    'pinCode',
    'userPin',
    'verificationCode',
    'resetCode',
    // Payment details
    'iban',
    'payeeIban',
    'accountNumber',
    'accountNo',
    'cardNumber',
    'cardNo',
    'creditCard',
    'cvv',
    'cvc',
    'pan',
    // Personal data
    'email',
    'contactEmail',
    'phone',
    'mobileNumber',
    'msisdn',
    'address',
    'ipAddress',
    'remoteAddress',
    'ip',
    'clientIp',
    'beneficiaryName',
    'firstName',
    'lastName',
    'surname',
    'fullName',
    'displayName',
    'username',
    'userName',
    'holderName',
    'accountHolder',
    'payeeName',
    'customerName',
    'supplierName',
    'name',
    'dob',
    'dateOfBirth',
    'birthDate',
    'ssn',
    'passportNumber',
    'nationalId',
    'emiratesId',
    'taxId',
    // Connection details
    'dsn',
    'connectionString',
    'databaseUrl',
    // Never logged whole: request bodies and query strings
    'body',
    'requestBody',
    'rawBody',
    'query',
    'queryString',
  ])('%s', (name) => {
    expect(ruleForName(name)).toBe('redact');
  });
});

describe('names that are logged', () => {
  it.each([
    'correlationId',
    'orgId',
    'actor',
    'module',
    'event',
    'outcome',
    'durationMs',
    'mapping',
    'company',
    'shipping',
    'zip',
    'keyId',
    'keyVersion',
    'idempotencyKey',
    'publicKey',
    'author',
    'eventName',
    'moduleName',
    'status',
    'attempt',
    'count',
  ])('%s is kept', (name) => {
    expect(ruleForName(name)).toBe('keep');
  });

  it.each(['code', 'errorCode', 'reasonCode', 'statusCode', 'state', 'transactionState', 'countryCode'])(
    '%s is kept only when its value is plainly not a secret',
    (name) => {
      expect(ruleForName(name)).toBe('redact-unless-constant');
    },
  );
});
