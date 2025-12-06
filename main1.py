from fastapi import FastAPI,Request,HTTPException,status,Depends 
from pydantic import BaseModel, EmailStr, field_validator, Field
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime,timedelta
from jose import jwt,JWTError
from client import supabase
import os

SECRRET_KEY = os.getenv("SECRRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "login")




app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://demo1-wine-psi.vercel.app/"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # TEMP: allow all origins
    allow_credentials=False,      # must be False if using "*"
    allow_methods=["*"],
    allow_headers=["*"],
)


# ======================================
#        MODEL
# ======================================
class LeadIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    phone: str = Field(pattern=r'^(\+91|0)?[6-9]\d{9}$')
    vec_type : str = Field(min_length = 2,max_length=100)

    @field_validator('phone')
    @classmethod
    def normalize_phone(cls, v: str) -> str:
        digits = ''.join(filter(str.isdigit, v))
        if len(digits) == 12:
            digits = digits[2:]  # Remove country code
        elif len(digits) == 11:
            digits = digits[1:]  # Remove leading 0
        # assuming remaining is 10 digits
        return f"+91{digits}"


class Lead(LeadIn):
    id: int  # for id storage


class LoginInput(BaseModel):
    username: str
    password: str

# =====================================
#          STORAGE
# =====================================
leads_db: list[Lead] = []
next_id = 1


# =====================================
#          FUNCTIONS 
# =====================================

def create_access_token(data:dict,expires_delta:timedelta | None=None):
    """
    CREATING A SIGNED JWT ACESS TOKEN
    data : dict with claims like e.g. { "sub": "admin@example.com", "role": "admin" }
    expires_delta : how long before token expires (timedelta)
    """
    #copying the input data so we dont mutate the original
    to_encode = data.copy()
    #calculate the expiry time (UTC)
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode["exp"] = expire # "exp" is a standard JWT CLAIM FOR EXPIRY
    #ENCODING THE PAYLOAD
    encoded_jwt = jwt.encode(to_encode,SECRRET_KEY,algorithm=ALGORITHM)

    return encoded_jwt

def get_current_admin(token:str = Depends(oauth2_scheme)):
    """
    Dependency that:
    -extracts jwt from author : bearer <token>
    -verifies signature + expiry
    -checks that role == "admin"
    - returns user info if valid
    """
    print("⚙️ Raw token from header:", repr(token)) #debug
    try:
        # Decode token 
        payload = jwt.decode(token,SECRRET_KEY,algorithms=[ALGORITHM])
        print("✅ Decoded payload:", payload)  # DEBUG

        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")

        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing subject",
            )
        if role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
            )
        return {"username": username, "role": role}
    except JWTError as e:
        # This includes expired token, invalid signature, etc.
        print("JWT decode error:", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    
    

        





# =====================================
#          ENDPOINTS
# =====================================
#+++++++++++++++ HOMEPAGE +++++++++++++
@app.get("/")
def home():
    return {"message": "Insurance API running"}

#+++++++++++++++++++ LOGIN +++++++++++++++++++++++
@app.post("/login")
def login(payload:LoginInput):
    #checking username and password
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="Admin credentials not configured")

    if payload.username != ADMIN_USERNAME or payload.password != ADMIN_PASSWORD:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "INVALID CREDENTIALS",
        )
    #TOKEN DATA
    token_data = {
        "sub" : payload.username, # sub = who this token is about
        "role": "admin",
    }
    # CREATING JWT
    access_token = create_access_token(
        data=token_data,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {
        "access_token" : access_token,
        "token_type" : "bearer",
    }




#+++++++++++++++++++ FORM INPUT ++++++++++++++++++++
@app.post("/lead")
def submit_lead(lead_in: LeadIn):

    payload = lead_in.model_dump()
    result = supabase.table("submissions").insert(payload).execute()
    

    print(f"lead captured: {lead_in.name}, {lead_in.email}, {lead_in.phone},{lead_in.vec_type}")

    return {
        "message": "thanks we will contact you soon",
        "data": lead_in.model_dump()
    }

#+++++++++++++++++ TABLE FROM DB ++++++++++++++++++++++
@app.get("/leads")
def get_all_leads(current_admin = Depends(get_current_admin)):
    """
    Only accessible if :
    - a valid JWT is sent in Authorization header
    - token is not expired
    - role == "admin"

    """
    result = supabase.table("submissions").select("*").execute()
    return {"count": len(result.data), "leads": result.data}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main1:app", reload=True)
