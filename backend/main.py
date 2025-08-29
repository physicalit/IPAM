import os
from fastapi import FastAPI, Request, Depends, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from datetime import datetime

from .database import engine, Base, get_db
from . import models
from .auth import router as auth_router
from .tasks import start_scheduler

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SECRET_KEY", "changeme"))
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(auth_router)

templates = Jinja2Templates(directory="templates")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    # ensure default user
    db = next(get_db())
    if not db.query(models.User).filter_by(username="admin").first():
        import bcrypt

        hashed = bcrypt.hashpw(os.environ.get("ADMIN_PASSWORD", "admin").encode(), bcrypt.gensalt()).decode()
        user = models.User(username="admin", hashed_password=hashed)
        db.add(user)
        db.commit()
    db.close()
    if os.environ.get("DISABLE_SCHEDULER") != "1":
        start_scheduler()


@app.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    hosts = db.query(models.Host).all()
    return templates.TemplateResponse("index.html", {"request": request, "hosts": hosts})


@app.post("/hosts")
def add_host(request: Request, ip: str = Form(...), subnet_id: int = Form(None), db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    host = models.Host(ip=ip, subnet_id=subnet_id)
    db.add(host)
    db.commit()
    return RedirectResponse("/", status_code=302)


@app.post("/subnets")
def add_subnet(request: Request, cidr: str = Form(...), name: str = Form(...), db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    subnet = models.Subnet(cidr=cidr, name=name)
    db.add(subnet)
    db.commit()
    return RedirectResponse("/", status_code=302)
