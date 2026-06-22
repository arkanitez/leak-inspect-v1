"""Optional Keycloak OIDC bearer-token auth.

Disabled by default (demo). When AUTH_ENABLED=true, every API/UI route depends on
a valid RS256 JWT from the configured Keycloak realm, validated against the realm
JWKS with issuer and (optional) audience checks. In the air-gapped deployment the
JWKS URL points at the in-network Keycloak; nothing leaves the enclave.
"""
from fastapi import Header, HTTPException, status
from .config import cfg

_jwk_client = None


def _client():
    global _jwk_client
    if _jwk_client is None:
        import jwt  # PyJWT, lazy
        url = cfg.OIDC_JWKS_URL or (cfg.OIDC_ISSUER.rstrip("/") + "/protocol/openid-connect/certs")
        _jwk_client = jwt.PyJWKClient(url)
    return _jwk_client


async def require_auth(authorization: str = Header(default="")):
    if not cfg.AUTH_ENABLED:
        return None
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        import jwt
        signing_key = _client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, signing_key, algorithms=cfg.OIDC_ALGS,
            audience=cfg.OIDC_AUDIENCE or None,
            issuer=cfg.OIDC_ISSUER or None,
            options={"verify_aud": bool(cfg.OIDC_AUDIENCE)})
        return claims
    except Exception as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token: %s" % e)
