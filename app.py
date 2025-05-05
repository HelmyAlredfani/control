# app.py - Simple Student Results Management System

import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import io

# --- App Configuration ---
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_key_12345")

# --- Database Configuration (SQLite) ---
instance_path = os.path.join(os.path.dirname(app.instance_path), "instance")
os.makedirs(instance_path, exist_ok=True)
db_path = os.path.join(instance_path, "results_simple.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# --- Login Manager Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "الرجاء تسجيل الدخول للوصول إلى هذه الصفحة."
login_manager.login_message_category = "info"

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=\"teacher\") # Roles: admin, teacher

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class School(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    teachers = db.relationship(\"Teacher\", backref=\"school\", lazy=True)
    students = db.relationship(\"Student\", backref=\"school\", lazy=True)

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(\"user.id\"), unique=True, nullable=True) # Link to User model for login
    school_id = db.Column(db.Integer, db.ForeignKey(\"school.id\"), nullable=False)
    user = db.relationship(\"User\", backref=db.backref(\"teacher_profile\", uselist=False))
    subjects = db.relationship(\"Subject\", secondary=\"teacher_subject\", backref=db.backref(\"teachers\", lazy=\"dynamic\"))

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    results = db.relationship(\"Result\", backref=\"subject\", lazy=True)

# Association table for Teacher and Subject (Many-to-Many)
teacher_subject = db.Table(\"teacher_subject\",
    db.Column(\"teacher_id\", db.Integer, db.ForeignKey(\"teacher.id\"), primary_key=True),
    db.Column(\"subject_id\", db.Integer, db.ForeignKey(\"subject.id\"), primary_key=True)
)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    secret_code = db.Column(db.String(50), unique=True, nullable=False) # For public search
    school_id = db.Column(db.Integer, db.ForeignKey(\"school.id\"), nullable=False)
    results = db.relationship(\"Result\", backref=\"student\", lazy=True)

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey(\"student.id\"), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey(\"subject.id\"), nullable=False)
    grade = db.Column(db.Float, nullable=False)

# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Decorators for Role-Based Access ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != \"admin\":
            flash("أنت غير مصرح لك بالوصول لهذه الصفحة.", "danger")
            return redirect(url_for(\"index\"))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Allow admin access to teacher routes as well
        if not current_user.is_authenticated or current_user.role not in [\"admin\", \"teacher\"]:
            flash("أنت غير مصرح لك بالوصول لهذه الصفحة.", "danger")
            return redirect(url_for(\"index\"))
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == \"admin\":
            return redirect(url_for(\"admin_dashboard\"))
        elif current_user.role == \"teacher\":
            return redirect(url_for(\"teacher_dashboard\"))
        else:
             return redirect(url_for(\"index\")) # Should not happen with roles

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash("تم تسجيل الدخول بنجاح.", "success")
            if user.role == \"admin\":
                return redirect(url_for(\"admin_dashboard\"))
            elif user.role == \"teacher\":
                return redirect(url_for(\"teacher_dashboard\"))
            else:
                return redirect(url_for(\"index\")) # Fallback
        else:
            flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "danger")

    return render_template("login.html") # Need to create this template

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("تم تسجيل الخروج بنجاح.", "success")
    return redirect(url_for(\"index\"))

# --- Admin Routes ---
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    # Placeholder for admin dashboard - Add links to manage sections
    return render_template("admin_dashboard.html") # Need to create this template

# TODO: Add CRUD routes for School, Teacher, Subject, Student under /admin/

# --- Teacher Routes ---
@app.route("/teacher")
@login_required
@teacher_required
def teacher_dashboard():
    teacher_profile = getattr(current_user, \"teacher_profile\", None)
    assigned_subjects = []
    if teacher_profile:
        assigned_subjects = teacher_profile.subjects
    elif current_user.role == \"admin\": # Admin can see all subjects
        assigned_subjects = Subject.query.all()
    return render_template("teacher_dashboard.html", subjects=assigned_subjects) # Need to create this template

@app.route("/teacher/manage_grades/<int:subject_id>", methods=["GET", "POST"])
@login_required
@teacher_required
def manage_grades(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    # Optional: Add check if teacher is assigned to this subject (already in decorator)

    # For simplicity, assume teacher teaches students in their school
    teacher_profile = getattr(current_user, \"teacher_profile\", None)
    students = []
    if teacher_profile:
        students = Student.query.filter_by(school_id=teacher_profile.school_id).order_by(Student.name).all()
    elif current_user.role == \"admin\": # Admin can manage grades for any student
        students = Student.query.order_by(Student.name).all()

    if request.method == "POST":
        for student in students:
            grade_input = request.form.get(f"grade_{student.id}")
            if grade_input:
                try:
                    grade = float(grade_input)
                    # Find existing result or create new one
                    result = Result.query.filter_by(student_id=student.id, subject_id=subject.id).first()
                    if result:
                        result.grade = grade
                    else:
                        result = Result(student_id=student.id, subject_id=subject.id, grade=grade)
                        db.session.add(result)
                except ValueError:
                    flash(f"قيمة غير صالحة للدرجة للطالب {student.name}", "warning")
                    continue # Skip this student if grade is invalid
        try:
            db.session.commit()
            flash(f"تم تحديث درجات مادة {subject.name} بنجاح.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"حدث خطأ أثناء تحديث الدرجات: {e}", "danger")
        return redirect(url_for(\"manage_grades\", subject_id=subject_id))

    # Get existing grades for the form
    existing_results = {res.student_id: res.grade for res in Result.query.filter_by(subject_id=subject.id).all()}
    return render_template("manage_grades.html", subject=subject, students=students, results=existing_results) # Need to create this template

# --- Public Routes ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        search_query = request.form.get("search_query", "").strip()
        results = []
        if search_query:
            # Search by secret code OR name (case-insensitive)
            results = Student.query.filter(
                (Student.secret_code == search_query) |
                (Student.name.ilike(f"%{search_query}%"))
            ).all()
            if not results:
                flash("لم يتم العثور على طلاب مطابقين.", "info")
        else:
            flash("الرجاء إدخال اسم الطالب أو الرقم السري للبحث.", "warning")
        return render_template("search_results.html", results=results, search_query=search_query)

    # GET request shows the search form
    return render_template("search_results.html", results=None)

@app.route("/results/<string:secret_code>")
def view_result_details(secret_code):
    student = Student.query.filter_by(secret_code=secret_code).first_or_404()
    # Fetch results for this student, joining with Subject to get subject names
    student_results = db.session.query(Result, Subject).join(Subject).filter(Result.student_id == student.id).all()
    return render_template("view_result_details.html", student=student, results=student_results) # Need to create this template

@app.route("/results/<string:secret_code>/download")
def download_result(secret_code):
    student = Student.query.filter_by(secret_code=secret_code).first_or_404()
    student_results = db.session.query(Result, Subject).join(Subject).filter(Result.student_id == student.id).all()
    
    # Render a specific template designed for printing/downloading
    rendered_html = render_template("result_download.html", student=student, results=student_results) # Need to create this template
    
    response = make_response(rendered_html)
    # Suggest a filename for the download
    response.headers["Content-Disposition"] = f"attachment; filename=result_{student.secret_code}.html"
    response.headers["Content-Type"] = "text/html"
    return response

# --- Database Initialization Function ---
def initialize_database():
    with app.app_context():
        print("Initializing database...")
        db.create_all() # Create tables if they don\\\"t exist
        print("Database tables checked/created.")

        # Seed admin user if not exists
        ADMIN_USERNAME = "alredfani"
        ADMIN_PASSWORD = "73345"
        admin_user = User.query.filter_by(username=ADMIN_USERNAME).first()
        if not admin_user:
            admin_user = User(username=ADMIN_USERNAME, role=\"admin\")
            admin_user.set_password(ADMIN_PASSWORD)
            db.session.add(admin_user)
            try:
                db.session.commit()
                print(f"Admin user \t{ADMIN_USERNAME}\t created.")
            except Exception as e:
                db.session.rollback()
                print(f"Error creating admin user: {e}")
        else:
            print(f"Admin user \t{ADMIN_USERNAME}\t already exists.")

# --- Run the App ---
if __name__ == "__main__":
    initialize_database()
    # Use host=\"0.0.0.0\" to be accessible externally if needed for testing
    # debug=True is helpful during development but should be False in production
    app.run(host=\"0.0.0.0\", port=5002, debug=True) # Using a different port 5002


