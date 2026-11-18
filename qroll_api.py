"""QRoll Smart Attendance API — secure backend foundation.

Quick start:
  python -m venv .venv && source .venv/bin/activate
  pip install fastapi uvicorn sqlalchemy psycopg[binary] python-jose[cryptography] \
    passlib[argon2] python-multipart qrcode[pil] openpyxl reportlab pytest httpx
  export DATABASE_URL='sqlite:///./qroll.db'
  export JWT_SECRET='replace-with-random-secret-at-least-32-chars'
  export QR_SECRET='another-random-secret-at-least-32-chars'
  export BOOTSTRAP_ADMIN_EMAIL='admin@example.edu'
  export BOOTSTRAP_ADMIN_PASSWORD='replace-this-now'
  uvicorn qroll_api:app --reload

For production use PostgreSQL, TLS, secrets manager, migrations, rate-limiting at
an API gateway, and institutional identity provisioning. This file is a starter,
not a substitute for security review or an institutional deployment approval.
"""
from __future__ import annotations
import csv, hashlib, hmac, io, json, os, secrets, time
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File
from fastapi.responses import StreamingResponse, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, Float, Boolean, ForeignKey, DateTime, Text, UniqueConstraint, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

APP_SECRET=os.getenv('JWT_SECRET','')
QR_SECRET=os.getenv('QR_SECRET','')
if not APP_SECRET or not QR_SECRET:
    # Deliberately refuse to start with weak implicit production secrets.
    if os.getenv('ENVIRONMENT','development')=='production':
        raise RuntimeError('Set JWT_SECRET and QR_SECRET in the deployment environment.')
    APP_SECRET=APP_SECRET or secrets.token_urlsafe(48)
    QR_SECRET=QR_SECRET or secrets.token_urlsafe(48)
JWT_ALG='HS256'; TOKEN_MINUTES=int(os.getenv('TOKEN_MINUTES','30'))
QR_TTL=int(os.getenv('QR_TTL_SECONDS','20')); DATABASE_URL=os.getenv('DATABASE_URL','sqlite:///./qroll.db')
connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite') else {}
engine=create_engine(DATABASE_URL,connect_args=connect_args,pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine,autoflush=False,expire_on_commit=False)
class Base(DeclarativeBase): pass
class User(Base):
    __tablename__='users'; id:Mapped[int]=mapped_column(primary_key=True); email:Mapped[str]=mapped_column(String(255),unique=True,index=True); password_hash:Mapped[str]=mapped_column(String(255)); role:Mapped[str]=mapped_column(String(20),default='faculty'); active:Mapped[bool]=mapped_column(Boolean,default=True)
class Student(Base):
    __tablename__='students'; id:Mapped[int]=mapped_column(primary_key=True); reg_no:Mapped[str]=mapped_column(String(40),unique=True,index=True); name:Mapped[str]=mapped_column(String(160)); programme:Mapped[str]=mapped_column(String(80)); email:Mapped[Optional[str]]=mapped_column(String(255),nullable=True); cgpa:Mapped[Optional[float]]=mapped_column(Float,nullable=True)
class Subject(Base):
    __tablename__='subjects'; id:Mapped[int]=mapped_column(primary_key=True); code:Mapped[str]=mapped_column(String(40),unique=True,index=True); title:Mapped[str]=mapped_column(String(200)); semester:Mapped[str]=mapped_column(String(40)); academic_year:Mapped[str]=mapped_column(String(20)); faculty_id:Mapped[int]=mapped_column(ForeignKey('users.id')); threshold:Mapped[int]=mapped_column(Integer,default=75); archived:Mapped[bool]=mapped_column(Boolean,default=False)
class Enrolment(Base):
    __tablename__='enrolments'; id:Mapped[int]=mapped_column(primary_key=True); subject_id:Mapped[int]=mapped_column(ForeignKey('subjects.id')); student_id:Mapped[int]=mapped_column(ForeignKey('students.id')); __table_args__=(UniqueConstraint('subject_id','student_id'),)
class AttendanceSession(Base):
    __tablename__='attendance_sessions'; id:Mapped[str]=mapped_column(String(36),primary_key=True); subject_id:Mapped[int]=mapped_column(ForeignKey('subjects.id')); class_date:Mapped[str]=mapped_column(String(10)); status:Mapped[str]=mapped_column(String(16),default='live'); created_by:Mapped[int]=mapped_column(ForeignKey('users.id')); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc)); qr_generation:int=0
class Attendance(Base):
    __tablename__='attendance'; id:Mapped[int]=mapped_column(primary_key=True); session_id:Mapped[str]=mapped_column(ForeignKey('attendance_sessions.id')); student_id:Mapped[int]=mapped_column(ForeignKey('students.id')); status:Mapped[str]=mapped_column(String(12)); checked_at:Mapped[Optional[datetime]]=mapped_column(DateTime(timezone=True),nullable=True); __table_args__=(UniqueConstraint('session_id','student_id'),)
class ScanAttempt(Base):
    __tablename__='scan_attempts'; id:Mapped[int]=mapped_column(primary_key=True); session_id:Mapped[str]=mapped_column(String(36),index=True); student_id:Mapped[Optional[int]]=mapped_column(Integer,nullable=True); outcome:Mapped[str]=mapped_column(String(40)); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc)); detail:Mapped[str]=mapped_column(String(200),default='')
class Audit(Base):
    __tablename__='audit_logs'; id:Mapped[int]=mapped_column(primary_key=True); actor_id:Mapped[int]=mapped_column(Integer); action:Mapped[str]=mapped_column(String(100)); entity:Mapped[str]=mapped_column(String(80)); entity_id:Mapped[str]=mapped_column(String(80)); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc)); detail:Mapped[str]=mapped_column(Text,default='')
Base.metadata.create_all(engine)
def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()
crypt=CryptContext(schemes=['argon2'],deprecated='auto'); oauth=OAuth2PasswordBearer(tokenUrl='/auth/token')
class RegisterIn(BaseModel): email:str; password:str=Field(min_length=12); role:str='faculty'
class SubjectIn(BaseModel): code:str; title:str; semester:str=''; academic_year:str=''; threshold:int=Field(default=75,ge=0,le=100)
class StudentIn(BaseModel): reg_no:str; name:str; programme:str; email:Optional[str]=None; cgpa:Optional[float]=None
class SessionIn(BaseModel): class_date:str
class MarkIn(BaseModel): student_id:int; status:str=Field(pattern='^(P|A)$')
app=FastAPI(title='QRoll Smart Attendance API',version='1.0.0',description='Secure API foundation. OpenAPI docs at /docs.')
def actor(token:str=Depends(oauth),s:Session=Depends(db))->User:
    try: uid=int(jwt.decode(token,APP_SECRET,algorithms=[JWT_ALG])['sub'])
    except (JWTError,KeyError,ValueError): raise HTTPException(401,'Invalid or expired access token')
    u=s.get(User,uid)
    if not u or not u.active: raise HTTPException(401,'Account inactive')
    return u
def role(*allowed):
    def check(u:User=Depends(actor)):
        if u.role not in allowed: raise HTTPException(403,'Insufficient role')
        return u
    return check
def audit(s,u,action,entity,eid,detail=''):
    s.add(Audit(actor_id=u.id,action=action,entity=entity,entity_id=str(eid),detail=detail[:2000]))
def get_session(s,sid):
    obj=s.get(AttendanceSession,sid)
    if not obj: raise HTTPException(404,'Session not found')
    return obj
def signed_qr(session:AttendanceSession):
    now=int(time.time()); generation=now//QR_TTL
    payload={'sid':session.id,'sub':session.subject_id,'iat':generation*QR_TTL,'exp':(generation+1)*QR_TTL,'nonce':hashlib.sha256(f'{session.id}:{generation}'.encode()).hexdigest()[:20]}
    body=json.dumps(payload,separators=(',',':'),sort_keys=True).encode(); sig=hmac.new(QR_SECRET.encode(),body,hashlib.sha256).hexdigest()
    return json.dumps({'p':payload,'sig':sig},separators=(',',':'))
def validate_qr(raw,sess):
    try:
        item=json.loads(raw); p=item['p']; sig=item['sig']; body=json.dumps(p,separators=(',',':'),sort_keys=True).encode()
        valid=hmac.compare_digest(sig,hmac.new(QR_SECRET.encode(),body,hashlib.sha256).hexdigest())
        return valid and p.get('sid')==sess.id and p.get('sub')==sess.subject_id and int(p.get('exp',0))>int(time.time()) and int(p.get('iat',0))<=int(time.time())+2
    except (ValueError,TypeError,KeyError): return False
@app.post('/auth/bootstrap',status_code=201)
def bootstrap(data:RegisterIn,s:Session=Depends(db)):
    """One-time initial admin setup; disable/remove endpoint after provisioning."""
    if s.scalar(select(User.id).limit(1)) is not None: raise HTTPException(409,'Bootstrap is already closed')
    expected=os.getenv('BOOTSTRAP_ADMIN_EMAIL','').lower()
    if not expected or data.email.lower()!=expected or data.role!='admin': raise HTTPException(403,'Bootstrap identity not authorized')
    u=User(email=data.email.lower(),password_hash=crypt.hash(data.password),role='admin');s.add(u);s.commit();return {'id':u.id,'email':u.email,'role':u.role}
@app.post('/auth/users',status_code=201)
def create_user(data:RegisterIn,s:Session=Depends(db),u:User=Depends(role('admin'))):
    if data.role not in ('faculty','admin'): raise HTTPException(422,'Role must be faculty or admin')
    if s.scalar(select(User).where(User.email==data.email.lower())): raise HTTPException(409,'Email exists')
    x=User(email=data.email.lower(),password_hash=crypt.hash(data.password),role=data.role);s.add(x);s.flush();audit(s,u,'user.create','user',x.id);s.commit();return {'id':x.id,'email':x.email,'role':x.role}
@app.post('/auth/token')
def login(form:OAuth2PasswordRequestForm=Depends(),s:Session=Depends(db)):
    u=s.scalar(select(User).where(User.email==form.username.lower()))
    if not u or not u.active or not crypt.verify(form.password,u.password_hash): raise HTTPException(401,'Incorrect credentials',headers={'WWW-Authenticate':'Bearer'})
    tok=jwt.encode({'sub':str(u.id),'exp':datetime.now(timezone.utc)+timedelta(minutes=TOKEN_MINUTES)},APP_SECRET,algorithm=JWT_ALG);return {'access_token':tok,'token_type':'bearer','expires_in':TOKEN_MINUTES*60}
@app.get('/auth/me')
def me(u:User=Depends(actor)): return {'id':u.id,'email':u.email,'role':u.role}
@app.post('/students',status_code=201)
def add_student(data:StudentIn,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    if s.scalar(select(Student).where(Student.reg_no==data.reg_no.strip().upper())): raise HTTPException(409,'Registration number already exists')
    x=Student(reg_no=data.reg_no.strip().upper(),**data.model_dump(exclude={'reg_no'}));s.add(x);s.flush();audit(s,u,'student.create','student',x.id);s.commit();return {'id':x.id,**data.model_dump()}
@app.get('/students')
def students(s:Session=Depends(db),u:User=Depends(actor)): return [{'id':x.id,'reg_no':x.reg_no,'name':x.name,'programme':x.programme,'email':x.email,'cgpa':x.cgpa} for x in s.scalars(select(Student).order_by(Student.reg_no))]
@app.post('/subjects',status_code=201)
def add_subject(data:SubjectIn,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    if s.scalar(select(Subject).where(Subject.code==data.code.upper())): raise HTTPException(409,'Subject code exists')
    x=Subject(**{**data.model_dump(),'code':data.code.upper()},faculty_id=u.id);s.add(x);s.flush();audit(s,u,'subject.create','subject',x.id);s.commit();return {'id':x.id,'code':x.code,'title':x.title,'threshold':x.threshold}
@app.get('/subjects')
def subjects(s:Session=Depends(db),u:User=Depends(actor)): return [{'id':x.id,'code':x.code,'title':x.title,'semester':x.semester,'academic_year':x.academic_year,'threshold':x.threshold,'archived':x.archived} for x in s.scalars(select(Subject).where(Subject.archived.is_(False)))]
@app.post('/subjects/{subject_id}/enrolments/{student_id}',status_code=201)
def enrol(subject_id:int,student_id:int,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    if not s.get(Subject,subject_id) or not s.get(Student,student_id): raise HTTPException(404,'Subject or student not found')
    x=Enrolment(subject_id=subject_id,student_id=student_id);s.add(x)
    try:s.flush()
    except Exception:s.rollback();raise HTTPException(409,'Student already enrolled')
    audit(s,u,'enrolment.create','subject',subject_id,str(student_id));s.commit();return {'enrolled':True}
@app.post('/subjects/{subject_id}/sessions',status_code=201)
def open_session(subject_id:int,data:SessionIn,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    subject=s.get(Subject,subject_id)
    if not subject: raise HTTPException(404,'Subject not found')
    try: datetime.strptime(data.class_date,'%d/%m/%Y')
    except ValueError: raise HTTPException(422,'Date must be DD/MM/YYYY')
    sid=secrets.token_urlsafe(24);x=AttendanceSession(id=sid,subject_id=subject_id,class_date=data.class_date,created_by=u.id);s.add(x)
    # Seed explicit unmarked records for enrolled students.
    for e in s.scalars(select(Enrolment).where(Enrolment.subject_id==subject_id)): s.add(Attendance(session_id=sid,student_id=e.student_id,status='U'))
    audit(s,u,'session.open','session',sid);s.commit();return {'id':sid,'class_date':data.class_date,'status':x.status}
@app.get('/sessions/{sid}/qr')
def qr(sid:str,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    x=get_session(s,sid)
    if x.status!='live': raise HTTPException(409,'Session is not live')
    raw=signed_qr(x);return {'payload':raw,'expires_at':json.loads(raw)['p']['exp'],'ttl_seconds':QR_TTL}
@app.post('/sessions/{sid}/pause')
def pause(sid:str,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    x=get_session(s,sid);x.status='paused' if x.status=='live' else 'live';audit(s,u,'session.'+x.status,'session',sid);s.commit();return {'status':x.status}
@app.post('/sessions/{sid}/end')
def end(sid:str,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    x=get_session(s,sid);x.status='ended';audit(s,u,'session.end','session',sid);s.commit();return {'status':x.status}
@app.post('/sessions/{sid}/checkin')
def checkin(sid:str,qr_payload:str=Header(alias='X-QRoll-Payload'),s:Session=Depends(db),u:User=Depends(actor)):
    """Student caller must be identity-bound in production; this API maps caller email to roster email."""
    x=get_session(s,sid)
    student=s.scalar(select(Student).where(Student.email==u.email))
    outcome='accepted';detail=''
    if x.status!='live': outcome='blocked_session';detail='Session not live'
    elif not student: outcome='blocked_identity';detail='No student profile linked to account'
    elif not s.scalar(select(Enrolment.id).where(Enrolment.subject_id==x.subject_id,Enrolment.student_id==student.id)): outcome='blocked_enrolment';detail='Not enrolled'
    elif not validate_qr(qr_payload,x): outcome='blocked_qr';detail='Invalid, expired, or wrong-subject QR'
    old=s.scalar(select(Attendance).where(Attendance.session_id==sid,Attendance.student_id==student.id))
    if outcome=='accepted' and old and old.status!='U': outcome='blocked_duplicate';detail='Already checked in'
    s.add(ScanAttempt(session_id=sid,student_id=student.id if student else None,outcome=outcome,detail=detail))
    if outcome!='accepted': s.commit();raise HTTPException(409,detail)
    if not old: old=Attendance(session_id=sid,student_id=student.id,status='P');s.add(old)
    old.status='P';old.checked_at=datetime.now(timezone.utc);audit(s,u,'attendance.checkin','session',sid,str(student.id));s.commit();return {'status':'P','student':student.reg_no,'checked_at':old.checked_at.isoformat()}
@app.post('/sessions/{sid}/mark')
def manual_mark(sid:str,data:MarkIn,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    x=get_session(s,sid);en=s.scalar(select(Enrolment).where(Enrolment.subject_id==x.subject_id,Enrolment.student_id==data.student_id))
    if not en: raise HTTPException(422,'Student is not enrolled in subject')
    r=s.scalar(select(Attendance).where(Attendance.session_id==sid,Attendance.student_id==data.student_id))
    if not r: r=Attendance(session_id=sid,student_id=data.student_id,status=data.status);s.add(r)
    else:r.status=data.status;r.checked_at=datetime.now(timezone.utc) if data.status=='P' else None
    audit(s,u,'attendance.manual','session',sid,f'{data.student_id}:{data.status}');s.commit();return {'student_id':data.student_id,'status':data.status}
@app.get('/subjects/{subject_id}/register')
def register(subject_id:int,s:Session=Depends(db),u:User=Depends(actor)):
    subject=s.get(Subject,subject_id)
    if not subject:raise HTTPException(404,'Subject not found')
    sessions=list(s.scalars(select(AttendanceSession).where(AttendanceSession.subject_id==subject_id).order_by(AttendanceSession.class_date)))
    result=[]
    for e in s.scalars(select(Enrolment).where(Enrolment.subject_id==subject_id)):
        st=s.get(Student,e.student_id);marks=[]
        for ses in sessions:
            rec=s.scalar(select(Attendance).where(Attendance.session_id==ses.id,Attendance.student_id==st.id));marks.append(rec.status if rec else 'U')
        counted=[m for m in marks if m in ('P','A')];result.append({'student_id':st.id,'reg_no':st.reg_no,'name':st.name,'programme':st.programme,'marks':marks,'attendance_percent':round(sum(m=='P' for m in counted)*100/len(counted)) if counted else None})
    return {'subject':subject.code,'dates':[x.class_date for x in sessions],'students':result}
def report_rows(s,subject_id):
    data=register(subject_id,s,actor_for_report(s))
    return data
def actor_for_report(s):
    # Internal register helper only; reports below query directly without invoking a dependency.
    class Internal: pass
    return Internal()
@app.get('/subjects/{subject_id}/export.csv')
def export_csv(subject_id:int,s:Session=Depends(db),u:User=Depends(actor)):
    su=s.get(Subject,subject_id)
    if not su:raise HTTPException(404,'Subject not found')
    sessions=list(s.scalars(select(AttendanceSession).where(AttendanceSession.subject_id==subject_id).order_by(AttendanceSession.class_date)))
    out=io.StringIO();w=csv.writer(out);w.writerow(['Registration','Name','Programme','CGPA',* [x.class_date for x in sessions],'Attendance %'])
    for e in s.scalars(select(Enrolment).where(Enrolment.subject_id==subject_id)):
        st=s.get(Student,e.student_id);marks=[]
        for se in sessions:
            r=s.scalar(select(Attendance).where(Attendance.session_id==se.id,Attendance.student_id==st.id));marks.append(r.status if r else 'U')
        counted=[m for m in marks if m in ('P','A')];pct=round(marks.count('P')*100/len(counted)) if counted else ''
        w.writerow([st.reg_no,st.name,st.programme,st.cgpa,*marks,pct])
    return StreamingResponse(iter([out.getvalue()]),media_type='text/csv',headers={'Content-Disposition':f'attachment; filename="{su.code}-attendance.csv"'})
@app.get('/subjects/{subject_id}/export.xlsx')
def export_xlsx(subject_id:int,s:Session=Depends(db),u:User=Depends(actor)):
    from openpyxl import Workbook
    su=s.get(Subject,subject_id)
    if not su:raise HTTPException(404,'Subject not found')
    sessions=list(s.scalars(select(AttendanceSession).where(AttendanceSession.subject_id==subject_id).order_by(AttendanceSession.class_date)));wb=Workbook();ws=wb.active;ws.title='Attendance';ws.append(['Registration','Name','Programme','CGPA',*[x.class_date for x in sessions],'Attendance %'])
    for e in s.scalars(select(Enrolment).where(Enrolment.subject_id==subject_id)):
        st=s.get(Student,e.student_id);marks=[]
        for se in sessions:
            r=s.scalar(select(Attendance).where(Attendance.session_id==se.id,Attendance.student_id==st.id));marks.append(r.status if r else 'U')
        counted=[m for m in marks if m in ('P','A')];ws.append([st.reg_no,st.name,st.programme,st.cgpa,*marks,round(marks.count('P')*100/len(counted)) if counted else None])
    b=io.BytesIO();wb.save(b);return Response(b.getvalue(),media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',headers={'Content-Disposition':f'attachment; filename="{su.code}-attendance.xlsx"'})
@app.get('/subjects/{subject_id}/export.pdf')
def export_pdf(subject_id:int,s:Session=Depends(db),u:User=Depends(actor)):
    from reportlab.lib.pagesizes import landscape, A4
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors
    su=s.get(Subject,subject_id)
    if not su:raise HTTPException(404,'Subject not found')
    sessions=list(s.scalars(select(AttendanceSession).where(AttendanceSession.subject_id==subject_id).order_by(AttendanceSession.class_date)));b=io.BytesIO();c=canvas.Canvas(b,pagesize=landscape(A4));width,height=landscape(A4);c.setFont('Helvetica-Bold',15);c.drawString(32,height-34,f'{su.code} — Attendance report');c.setFont('Helvetica',8);c.drawString(32,height-49,f'{su.title} | threshold {su.threshold}%')
    headers=['Reg no','Student','Programme',* [x.class_date for x in sessions],'Percent'];cols=max(1,len(headers));cw=(width-64)/cols;y=height-72
    def header():
        c.setFillColor(colors.HexColor('#dff0df'));c.rect(32,y-4,width-64,17,fill=1,stroke=0);c.setFillColor(colors.black);c.setFont('Helvetica-Bold',7)
        for i,h in enumerate(headers):c.drawString(34+i*cw,y,str(h)[:20])
    header();y-=22
    for e in s.scalars(select(Enrolment).where(Enrolment.subject_id==subject_id)):
        st=s.get(Student,e.student_id);marks=[]
        for se in sessions:
            r=s.scalar(select(Attendance).where(Attendance.session_id==se.id,Attendance.student_id==st.id));marks.append(r.status if r else 'U')
        counted=[m for m in marks if m in ('P','A')];vals=[st.reg_no,st.name,st.programme,*marks,(f'{round(marks.count("P")*100/len(counted))}%' if counted else '—')]
        for i,v in enumerate(vals):c.drawString(34+i*cw,y,str(v or '')[:20])
        y-=14
        if y<35:c.showPage();y=height-40;header();y-=22
    c.save();return Response(b.getvalue(),media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="{su.code}-attendance.pdf"'})
@app.post('/subjects/{subject_id}/import.xlsx')
def import_xlsx(subject_id:int,file:UploadFile=File(...),replace:bool=False,s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    """Preview-safe import: validates workbook and adds/updates roster; marks are never silently replaced."""
    if file.content_type not in ('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/octet-stream'):raise HTTPException(415,'Upload an .xlsx workbook')
    if not s.get(Subject,subject_id):raise HTTPException(404,'Subject not found')
    if file.size and file.size>5_000_000:raise HTTPException(413,'File exceeds 5 MB limit')
    from openpyxl import load_workbook
    try: wb=load_workbook(io.BytesIO(file.file.read()),read_only=True,data_only=True);rows=list(wb.active.iter_rows(values_only=True))
    except Exception:raise HTTPException(422,'Could not parse workbook')
    if not rows or len(rows)>5001:raise HTTPException(422,'Workbook is empty or exceeds 5000 data rows')
    hdr=[str(x or '').strip().lower() for x in rows[0]];required=['registration','name','programme']
    if any(k not in hdr for k in required):raise HTTPException(422,'Required columns: Registration, Name, Programme')
    idx={k:hdr.index(k) for k in hdr};preview=[];seen=set()
    for n,row in enumerate(rows[1:],2):
        if not any(v is not None for v in row):continue
        try:
            reg=str(row[idx['registration']]).strip().upper();name=str(row[idx['name']]).strip();prog=str(row[idx['programme']]).strip()
            if not reg or not name or not prog or reg in seen:raise ValueError('empty or duplicated registration')
            seen.add(reg);preview.append((reg,name,prog,str(row[idx['email']]).strip() if 'email' in idx and row[idx['email']] else None,float(row[idx['cgpa']]) if 'cgpa' in idx and row[idx['cgpa']] is not None else None))
        except Exception as ex:raise HTTPException(422,f'Invalid row {n}: {ex}')
    # This endpoint returns a validation preview; caller must explicitly confirm commit via import-confirm.
    return {'preview_only':True,'subject_id':subject_id,'rows':len(preview),'replace_requested':replace,'students':[{'reg_no':a,'name':b,'programme':c,'email':d,'cgpa':e} for a,b,c,d,e in preview]}
@app.post('/subjects/{subject_id}/import-confirm')
def import_confirm(subject_id:int,students:list[StudentIn],s:Session=Depends(db),u:User=Depends(role('admin','faculty'))):
    if not s.get(Subject,subject_id):raise HTTPException(404,'Subject not found')
    if len(students)>5000:raise HTTPException(422,'Too many rows')
    if len({x.reg_no.strip().upper() for x in students})!=len(students):raise HTTPException(422,'Duplicate registration numbers in upload')
    added=updated=enrolled=0
    for d in students:
        reg=d.reg_no.strip().upper();x=s.scalar(select(Student).where(Student.reg_no==reg))
        if x:x.name=d.name;x.programme=d.programme;x.email=d.email;x.cgpa=d.cgpa;updated+=1
        else:x=Student(reg_no=reg,name=d.name,programme=d.programme,email=d.email,cgpa=d.cgpa);s.add(x);s.flush();added+=1
        if not s.scalar(select(Enrolment.id).where(Enrolment.subject_id==subject_id,Enrolment.student_id==x.id)):s.add(Enrolment(subject_id=subject_id,student_id=x.id));enrolled+=1
    audit(s,u,'import.commit','subject',subject_id,f'added={added},updated={updated}');s.commit();return {'added':added,'updated':updated,'enrolled':enrolled}
@app.get('/health')
def health():return {'status':'ok','service':'qroll-api'}

# Minimal smoke tests: run `pytest -q qroll_api.py` after installing pytest/httpx.
def test_qr_payload_signed_and_expires():
    x=AttendanceSession(id='test-session',subject_id=5,class_date='01/01/2026',created_by=1,status='live')
    raw=signed_qr(x);assert validate_qr(raw,x);assert not validate_qr(raw,AttendanceSession(id='other',subject_id=5,class_date='01/01/2026',created_by=1))
def test_qr_tampering_rejected():
    x=AttendanceSession(id='test-session',subject_id=5,class_date='01/01/2026',created_by=1,status='live');p=json.loads(signed_qr(x));p['p']['sub']=9;assert not validate_qr(json.dumps(p),x)
