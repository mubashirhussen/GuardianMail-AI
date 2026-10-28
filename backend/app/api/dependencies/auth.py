from typing import List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.config.settings import settings
from app.database.connection import db_manager
from app.security.jwt import decode_token_async
from app.models.user import UserInDB, UserRole
from app.repositories.user_repo import UserRepository
from app.repositories.device_repo import DeviceRepository
from app.exceptions.custom import AuthError, TokenExpiredError

from app.repositories.identity_provider_repo import IdentityProviderRepository
from app.repositories.organization_domain_repo import OrganizationDomainRepository
from app.repositories.organization_membership_repo import OrganizationMembershipRepository

from app.repositories.verification_repo import VerificationRepository

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"/api/v1/auth/login"
)

async def get_user_repo() -> UserRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return UserRepository(db_manager.db)

async def get_device_repo() -> DeviceRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return DeviceRepository(db_manager.db)

async def get_verification_repo() -> VerificationRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return VerificationRepository(db_manager.db)

async def get_idp_repo() -> IdentityProviderRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return IdentityProviderRepository(db_manager.db)

async def get_org_domain_repo() -> OrganizationDomainRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return OrganizationDomainRepository(db_manager.db)

async def get_org_membership_repo() -> OrganizationMembershipRepository:
    if db_manager.db is None:
         raise RuntimeError("Database connection not ready.")
    return OrganizationMembershipRepository(db_manager.db)

async def get_current_user(
    token: str = Depends(reusable_oauth2),
    user_repo: UserRepository = Depends(get_user_repo),
    device_repo: DeviceRepository = Depends(get_device_repo)
) -> UserInDB:
    """Dependency to decode access token, fetch user from DB and verify session status."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = await decode_token_async(token)
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token signature has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
        
    if not payload or payload.get("type") != "access":
        raise credentials_exception
        
    user_id: str = payload.get("sub")
    token_id: Optional[str] = payload.get("jti")
    
    if user_id is None:
        raise credentials_exception
        
    # Check if session is active/revoked in DB
    if token_id and not await device_repo.is_session_active(token_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked or logged out"
        )
        
    user = await user_repo.get(user_id)
    if not user:
        raise credentials_exception
        
    return UserInDB(**user)

def get_current_active_user(
    current_user: UserInDB = Depends(get_current_user),
) -> UserInDB:
    """Verify that the user account is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user"
        )
    return current_user

class RequireRole:
    """Role-based Access Control authorization policy enforcer dependency checker."""
    
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: UserInDB = Depends(get_current_active_user)) -> UserInDB:
        # Normalize and map roles checking
        user_role_str = str(current_user.role.value if hasattr(current_user.role, 'value') else current_user.role).lower().strip()
        allowed_normalized = [r.lower().strip() for r in self.allowed_roles]
        
        if user_role_str not in allowed_normalized:
             raise HTTPException(
                 status_code=status.HTTP_403_FORBIDDEN,
                 detail="You do not have sufficient permissions to access this resource."
             )
        return current_user
