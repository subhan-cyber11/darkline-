from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import Dict

SECRET_KEY = "supersecretkey123"  # Change this in production
ALGORITHM = "HS256"

app = FastAPI()
templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory user storage (for testing)
users_db: Dict[str, str] = {}  # username -> hashed_password

# Active websocket connections per user
active_connections: Dict[str, WebSocket] = {}

# ------------------- Auth Functions -------------------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    if username in users_db:
        if verify_password(password, users_db[username]):
            return username
    return False

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

# ------------------- Routes -------------------
@app.get("/", response_class=HTMLResponse)
async def get(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...)):
    if username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    users_db[username] = get_password_hash(password)
    return {"msg": "User registered successfully"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user})
    return {"access_token": token, "token_type": "bearer"}

# ------------------- WebSocket -------------------
@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != username:
            await websocket.close()
            return
    except:
        await websocket.close()
        return

    await websocket.accept()
    active_connections[username] = websocket

    try:
        while True:
            data = await websocket.receive_text()
            target_user, message = data.split(":", 1)  # format -> target_user:message
            if target_user in active_connections:
                await active_connections[target_user].send_text(f"{username}: {message}")
    except WebSocketDisconnect:
        active_connections.pop(username)
