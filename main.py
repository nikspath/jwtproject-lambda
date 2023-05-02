from fastapi import FastAPI,Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from mangum import Mangum
from passlib.hash import md5_crypt
app = FastAPI()


pwd_context= CryptContext(schemes = ["bcrypt"], deprecated = "auto")
ACCESS_TOKEN_EXPIRE_MINUTES=30
SECRET_KEY = '1234'
ALGORITHM = 'HS256'
oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "token")

fake_user_db={
    "nikhil" :{
        "username":"nikhil",
        "full_name":"nikhil patil",
        "email":"n@t.com",
        "hashed_password":"$1$aRJe40kX$6PFkP2xDnkDuh2mpOb./n.",
        "disabled":False,
    }
}

class Token(BaseModel):
    access_token : str
    token_type : str

class TokenData(BaseModel):
    username: str or None = None

class User(BaseModel):
    username: str
    email : str or None = None
    full_name : str or None = None
    disabled : bool or None = None

class UserInDB(User):
    hashed_password : str

def get_user(db , username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def verify_password(password: str , hashed_password: str):
    return md5_crypt.verify(password, hashed_password)

def get_password_hash(password):
    return md5_crypt.hash(password)


def authenticate_user(fake_db, username:str, password:str):
    user = get_user(fake_db,username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta :timedelta or None = None):
    to_encode = data.copy()
    if expires_delta :
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp":expires_delta})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY, algorithm=ALGORITHM )
    return encoded_jwt

async def get_current_user(token : str = Depends(oauth2_scheme)):
    credentials_exception= HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="username and password authorized",
                headers={"WWW-Authenticate":"Bearer"},)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_user_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user : User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive usrr")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_user_db, form_data.username , form_data.password)
    print(user)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="username and password authorized",
            headers={"WWW-Authenticate":"Bearer"}
        )
    access_token_expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token=create_access_token(
        data = {"sub":user.username},
        expires_delta= access_token_expire
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me" , response_model= User)
async def read_users_me(current_user : User = Depends(get_current_active_user)):
    return current_user


# pwt=get_password_hash("test")
# print(pwt)

handler = Mangum(app)

