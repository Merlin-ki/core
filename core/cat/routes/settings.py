from fastapi import Depends, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from cat.db import models
from cat.db import crud
from .schemas import TokenData, User
from .authentication import get_user
import os

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = os.environ.get("CCAT_JWT_SECRET")
ALGORITHM = "HS256"

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",   
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)   
    if user is None:
        raise credentials_exception
    return user   

@router.get("/")
def get_settings(
    search: str = "",
    current_user: User = Depends(get_current_user),
):
    """Get the entire list of settings available in the database"""

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )

    settings = crud.get_settings(search=search)
    return {"settings": settings}

@router.post("/")
def create_setting(
    payload: models.SettingBody,
    current_user: User = Depends(get_current_user),
):
    """Create a new setting in the database"""

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )

    # complete the payload with setting_id and updated_at
    payload = models.Setting(**payload.model_dump())

    # save to DB
    new_setting = crud.create_setting(payload)

    return {"setting": new_setting}

@router.get("/{settingId}")
def get_setting(
    settingId: str,
    current_user: User = Depends(get_current_user),
):
    """Get the a specific setting from the database"""

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )

    setting = crud.get_setting_by_id(settingId)
    if not setting:
        raise HTTPException(
            status_code=404,
            detail={
                "error": f"No setting with this id: {settingId}",
            },
        )
    return {"setting": setting}

@router.put("/{settingId}")
def update_setting(
    settingId: str,
    payload: models.SettingBody,
    current_user: User = Depends(get_current_user),
):
    """Update a specific setting in the database if it exists"""

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )

    # does the setting exist?
    setting = crud.get_setting_by_id(settingId)
    if not setting:
        raise HTTPException(
            status_code=404,
            detail={
                "error": f"No setting with this id: {settingId}",
            },
        )

    # complete the payload with setting_id and updated_at
    payload = models.Setting(**payload.model_dump())
    payload.setting_id = settingId

    # save to DB
    updated_setting = crud.update_setting_by_id(payload)
    return {"setting": updated_setting}

@router.delete("/{settingId}")
def delete_setting(
    settingId: str,
    current_user: User = Depends(get_current_user),
):
    """Delete a specific setting in the database"""

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )

    # does the setting exist?
    setting = crud.get_setting_by_id(settingId)
    if not setting:
        raise HTTPException(
            status_code=404,
            detail={
                "error": f"No setting with this id: {settingId}",
            },
        )

    # delete
    crud.delete_setting_by_id(settingId)
    return {"deleted": settingId}