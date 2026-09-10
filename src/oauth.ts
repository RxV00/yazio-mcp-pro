import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { InvalidGrantError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 365;
const AUTH_CODE_TTL_SECONDS = 5 * 60;

interface AuthCodePayload {
  type: 'code';
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  exp: number;
}

interface TokenPayload {
  type: 'access' | 'refresh';
  clientId: string;
  scopes: string[];
  exp: number;
}

function base64url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64url');
}

function sign(payload: AuthCodePayload | TokenPayload, secret: string): string {
  const body = base64url(JSON.stringify(payload));
  const signature = createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${signature}`;
}

function verify<T extends { exp: number }>(token: string, secret: string): T | null {
  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }
  const [body, signature] = parts;
  const expected = createHmac('sha256', secret).update(body).digest('base64url');
  const signatureBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expected);
  if (signatureBuf.length !== expectedBuf.length || !timingSafeEqual(signatureBuf, expectedBuf)) {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as T;
    if (Date.now() / 1000 > payload.exp) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

/**
 * Minimal stateless OAuth 2.1 authorization server for a single pre-shared client.
 * Codes and tokens are self-contained HMAC-signed strings (no server-side storage),
 * so it works correctly across Cloud Run's ephemeral, potentially multi-instance runtime.
 *
 * Dynamic client registration is intentionally unimplemented: without a registration
 * endpoint advertised, OAuth clients (e.g. Gemini) fall back to asking the user for a
 * static client ID/secret, which is the only registration flow this single-user server needs.
 */
export class StaticClientOAuthProvider implements OAuthServerProvider {
  private readonly client: OAuthClientInformationFull;
  private readonly signingSecret: string;
  private readonly staticBearerToken?: string;

  constructor(client: OAuthClientInformationFull, signingSecret: string, staticBearerToken?: string) {
    this.client = client;
    this.signingSecret = signingSecret;
    this.staticBearerToken = staticBearerToken;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    const client = this.client;
    return {
      getClient: (clientId) => (clientId === client.client_id ? client : undefined),
    };
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const code = sign(
      {
        type: 'code',
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        codeChallenge: params.codeChallenge,
        scopes: params.scopes ?? [],
        exp: Math.floor(Date.now() / 1000) + AUTH_CODE_TTL_SECONDS,
      },
      this.signingSecret
    );

    const redirectUrl = new URL(params.redirectUri);
    redirectUrl.searchParams.set('code', code);
    if (params.state !== undefined) {
      redirectUrl.searchParams.set('state', params.state);
    }
    res.redirect(302, redirectUrl.href);
  }

  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const payload = verify<AuthCodePayload>(authorizationCode, this.signingSecret);
    if (!payload || payload.type !== 'code') {
      throw new InvalidGrantError('Invalid or expired authorization code');
    }
    return payload.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string
  ): Promise<OAuthTokens> {
    const payload = verify<AuthCodePayload>(authorizationCode, this.signingSecret);
    if (!payload || payload.type !== 'code' || payload.clientId !== client.client_id) {
      throw new InvalidGrantError('Invalid or expired authorization code');
    }
    if (redirectUri !== undefined && redirectUri !== payload.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }

    return this.issueTokens(client.client_id, payload.scopes);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
    const payload = verify<TokenPayload>(refreshToken, this.signingSecret);
    if (!payload || payload.type !== 'refresh' || payload.clientId !== client.client_id) {
      throw new InvalidGrantError('Invalid or expired refresh token');
    }
    return this.issueTokens(client.client_id, scopes ?? payload.scopes);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    if (this.staticBearerToken && token === this.staticBearerToken) {
      // requireBearerAuth rejects tokens without a numeric expiresAt, so report one
      // far enough out that this pre-shared, non-expiring token is always accepted.
      return { token, clientId: 'static-bearer-token', scopes: [], expiresAt: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365 * 10 };
    }
    const payload = verify<TokenPayload>(token, this.signingSecret);
    if (!payload || payload.type !== 'access') {
      throw new InvalidTokenError('Invalid or expired access token');
    }
    return { token, clientId: payload.clientId, scopes: payload.scopes, expiresAt: payload.exp };
  }

  private issueTokens(clientId: string, scopes: string[]): OAuthTokens {
    const now = Math.floor(Date.now() / 1000);
    const accessToken = sign({ type: 'access', clientId, scopes, exp: now + ACCESS_TOKEN_TTL_SECONDS }, this.signingSecret);
    const refreshToken = sign({ type: 'refresh', clientId, scopes, exp: now + REFRESH_TOKEN_TTL_SECONDS }, this.signingSecret);

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refreshToken,
      scope: scopes.length > 0 ? scopes.join(' ') : undefined,
    };
  }
}
