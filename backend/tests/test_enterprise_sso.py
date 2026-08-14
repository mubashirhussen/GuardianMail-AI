import pytest
from httpx import AsyncClient
from app.models.organization_domain import OrganizationDomain
from app.models.identity_provider import IdentityProvider
from app.security.password import verify_password
from app.database.cache import cache_manager
import json

@pytest.mark.asyncio
async def test_domain_normalization():
    """Test that domain names are correctly normalized to lowercase and stripped."""
    record = OrganizationDomain(
        organization_id="org_123",
        domain="  Company.COM  ",
        verified=False,
        verification_token="txt-token"
    )
    assert record.domain == "company.com"

@pytest.mark.asyncio
async def test_identity_provider_secrets_encryption():
    """Verify that client secrets and certificates are encrypted at rest."""
    provider = IdentityProvider(
        organization_id="org_123",
        provider_type="oidc",
        provider_name="Okta",
        client_id="client_id_val",
        client_secret="my_super_secret_value",
        certificate="my_secret_cert"
    )
    
    # Assert they are encrypted in the raw fields/dict representation
    doc = provider.model_dump(by_alias=True)
    assert doc["client_secret"] != "my_super_secret_value"
    assert doc["certificate"] != "my_secret_cert"
    
    # Assert properties decrypt them on access
    assert provider.client_secret == "my_super_secret_value"
    assert provider.certificate == "my_secret_cert"

@pytest.mark.asyncio
async def test_sso_discovery_and_login_flow(client: AsyncClient):
    """Test full cycle of discovery, login state generation, and JIT provisioning callback."""
    # 1. Setup mock org, domain, and IDP configurations in DB via endpoints
    # Register an admin user first to configure settings
    admin_email = "admin@guardianmail.ai"
    admin_password = "SuperAdminPassword123!"
    
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": admin_email,
            "password": admin_password,
            "full_name": "Admin User",
            "role": "admin"
        }
    )
    assert reg_resp.status_code == 201
    
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_email,
            "password": admin_password
        }
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Setup organization link
    org_id = "test_org_456"
    
    # Associate user membership to mock org
    from app.database.connection import db_manager
    from app.repositories.organization_membership_repo import OrganizationMembershipRepository
    from app.repositories.organization_domain_repo import OrganizationDomainRepository
    
    membership_repo = OrganizationMembershipRepository(db_manager.db)
    org_dom_repo = OrganizationDomainRepository(db_manager.db)
    
    await membership_repo.create({
        "organization_id": org_id,
        "user_id": str(reg_resp.json()["_id"]),
        "role": "admin"
    })
    
    # Register domain
    domain_resp = await client.post(
        f"/api/v1/organizations/{org_id}/domains",
        json={"domain": "enterprise-test.com"},
        headers=headers
    )
    assert domain_resp.status_code == 200
    domain_data = domain_resp.json()
    domain_id = domain_data.get("_id") or domain_data.get("id")
    
    # Verify domain
    verify_resp = await client.post(
        f"/api/v1/organizations/{org_id}/domains/{domain_id}/verify",
        headers=headers
    )
    assert verify_resp.status_code == 200
    
    # Register Identity Provider
    idp_resp = await client.post(
        f"/api/v1/organizations/{org_id}/identity-providers",
        json={
            "provider_type": "oidc",
            "provider_name": "Entra ID",
            "issuer": "https://login.microsoftonline.com/tenant-id/v2.0",
            "client_id": "entra-client-id",
            "client_secret": "entra-client-secret",
            "authorization_url": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
            "allowed_domains": ["enterprise-test.com"]
        },
        headers=headers
    )
    assert idp_resp.status_code == 200
    idp_id = idp_resp.json().get("_id") or idp_resp.json().get("id")
    
    # Update domain record with identity_provider_id
    await org_dom_repo.collection.update_one(
        {"_id": org_dom_repo._to_oid(domain_id)},
        {"$set": {"identity_provider_id": idp_id}}
    )
    
    # Check List IDP (Client credentials should be masked/omitted in result)
    list_resp = await client.get(
        f"/api/v1/organizations/{org_id}/identity-providers",
        headers=headers
    )
    assert list_resp.status_code == 200
    assert "client_secret" not in list_resp.json()[0]
    
    # Check Domain test connection diagnostics
    test_resp = await client.post(
        f"/api/v1/organizations/{org_id}/identity-providers/{idp_id}/test",
        headers=headers
    )
    assert test_resp.status_code == 200
    assert test_resp.json()["connection_status"] == "SUCCESS"

    # Test Discovery Endpoint
    disc_resp = await client.post(
        "/api/v1/auth/sso/discover",
        json={"email": "user@enterprise-test.com"}
    )
    assert disc_resp.status_code == 200
    assert disc_resp.json()["sso_available"] is True
    assert disc_resp.json()["provider_name"] == "Entra ID"

    # Test Login Endpoint
    login_sso_resp = await client.post(
        "/api/v1/auth/sso/login",
        json={"email": "user@enterprise-test.com"}
    )
    assert login_sso_resp.status_code == 200
    assert "auth_url" in login_sso_resp.json()
    assert "state" in login_sso_resp.json()

    # Test Callback and JIT User creation
    state_val = login_sso_resp.json()["state"]
    callback_resp = await client.get(
        f"/api/v1/auth/sso/callback?code=mock_sso_user@enterprise-test.com&state={state_val}"
    )
    assert callback_resp.status_code == 200
    assert "access_token" in callback_resp.json()

    # Verify user JIT created in DB
    from app.repositories.user_repo import UserRepository
    user_repo = UserRepository(db_manager.db)
    jit_user = await user_repo.get_by_email("mock_sso_user@enterprise-test.com")
    assert jit_user is not None
    assert jit_user["role"] == "user"

@pytest.mark.asyncio
async def test_tenant_isolation_unauthorized_access(client: AsyncClient):
    """Test that unauthorized users are blocked from organization security config endpoints."""
    bad_headers = {"Authorization": "Bearer badtoken"}
    resp = await client.get(
        "/api/v1/organizations/test_org_456/identity-providers",
        headers=bad_headers
    )
    assert resp.status_code == 401
