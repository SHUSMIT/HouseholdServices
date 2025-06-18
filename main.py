from flask import Flask, render_template, flash, request, redirect, url_for
from datetime import datetime 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

from sqlalchemy import case
from werkzeug.security import generate_password_hash, check_password_hash 

from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from flask_wtf import FlaskForm

from wtforms import StringField, SubmitField, PasswordField, BooleanField,TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, EqualTo, Length

from sqlalchemy.orm import relationship
from sqlalchemy.exc import IntegrityError, OperationalError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 5
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 10
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = 'secretkey'


# ---- Models ----
# Creating Tables

class Admin(db.Model, UserMixin):
    __tablename__ = 'admin'
    username = db.Column(db.String(10), primary_key=True)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)  

    def get_id(self):
        return self.username



class Customer(db.Model, UserMixin):
    __tablename__ = 'customer'
    c_username = db.Column(db.String(15), primary_key=True)
    password = db.Column(db.String(128), nullable=False)
    flagged = db.Column(db.Boolean, default=False)
    pincode = db.Column(db.Integer, nullable=False)
    service_requests = relationship('ServiceRequest', back_populates='customer', cascade='all, delete-orphan')

    @property
    def password_hash(self):
        raise AttributeError('Error Rouse')

    @password_hash.setter
    def hashed(self, password):
        self.password = generate_password_hash(password)
    
    def verify(self, password):
        return check_password_hash(self.password, password)
    
    def get_id(self):
        return self.c_username
    
    @property
    def is_admin(self):  
        return False



class Service_Proffessional(db.Model, UserMixin):
    __tablename__ = 'service_proffessional'
    sp_username = db.Column(db.String, primary_key=True)
    password = db.Column(db.String(128), nullable=False)
    flagged = db.Column(db.Boolean, default=False)
    approved = db.Column(db.Boolean, default=False)  # New field for admin approval
    pincode = db.Column(db.Integer, nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.service_id', ondelete='SET NULL'), nullable=True)
    service_name = db.Column(db.String(50))
    service = relationship('Service', back_populates='professionals', passive_deletes=True)
    service_requests = relationship('ServiceRequest', back_populates='professional', cascade='all, delete-orphan')
    ratings = relationship('Rating', back_populates='professional', cascade='all, delete-orphan')

    @property
    def password_hash(self):
        raise AttributeError('Error Rouse')

    @password_hash.setter
    def hashed(self, password):
        self.password = generate_password_hash(password)
    
    def verify(self, password):
        return check_password_hash(self.password, password)
    
    def get_id(self):
        return self.sp_username
    
    @property
    def is_admin(self):  
        return False


class Service(db.Model):
    __tablename__ = 'service'
    service_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(50), nullable=False, unique=True)
    price = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text)
    professionals = relationship('Service_Proffessional', back_populates='service', passive_deletes=True)
    service_requests = relationship('ServiceRequest', back_populates='service', cascade='all, delete-orphan')


class ServiceRequest(db.Model):
    __tablename__ = 'service_request'
    service_request_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    customer_username = db.Column(db.String(15), db.ForeignKey('customer.c_username', ondelete='CASCADE'), nullable=False)
    professional_username = db.Column(db.String, db.ForeignKey('service_proffessional.sp_username', ondelete='SET NULL'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.service_id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(50), default='Pending')  # 'Pending', 'Accepted', 'Completed'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    accepted = db.Column(db.Boolean, default=False)

    customer = relationship('Customer', back_populates='service_requests', passive_deletes=True)
    professional = relationship('Service_Proffessional', back_populates='service_requests', passive_deletes=True)
    service = relationship('Service', back_populates='service_requests', passive_deletes=True)


class Rating(db.Model):
    __tablename__ = 'Rating'
    rating_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    professional_username = db.Column(db.String, db.ForeignKey('service_proffessional.sp_username'))
    customer_username = db.Column(db.String(15), db.ForeignKey('customer.c_username'))
    rating = db.Column(db.Integer, nullable=False)
    review = db.Column(db.Text, nullable=True)  # Optional field for textual reviews
    professional = relationship('Service_Proffessional', back_populates='ratings')

# ---- Forms ----

# A form class with fields so that it can be re-used, with validators, so that if not filled, raises
class SignForm(FlaskForm):
    username = StringField("Enter Username", validators=[DataRequired()])
    password = PasswordField("Enter Your Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password')])
    pincode = IntegerField("Enter Pincode", validators=[DataRequired()])  # Added pincode field
    submit = SubmitField("Register")

class ProfessionalSignForm(FlaskForm):
    username = StringField("Enter Username", validators=[DataRequired()])
    password = PasswordField("Enter Your Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password')])
    service_id = SelectField("Select Service", coerce=int, validators=[DataRequired()])
    pincode = IntegerField("Enter Pincode", validators=[DataRequired()])
    submit = SubmitField("Register")

class LogForm(FlaskForm):
    username = StringField("Enter Username", validators=[DataRequired()])
    password = PasswordField("Enter Your Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

class ServiceRequestForm(FlaskForm):
    service_id = StringField("Service ID", validators=[DataRequired()])
    professional_username = StringField("Professional Username", validators=[DataRequired()])
    title = StringField("Request Title", validators=[DataRequired()])
    budget = StringField("Budget", validators=[DataRequired()])
    content = TextAreaField("Request Description", validators=[DataRequired()])
    submit = SubmitField("Submit Request")

class FlagUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit_flag = SubmitField('Flag User')
    submit_unflag = SubmitField('Unflag User')

class CloseRequestForm(FlaskForm):
    request_id = StringField("Request ID", validators=[DataRequired()])
    submit_close = SubmitField('Close Request')

class EditServiceForm(FlaskForm):
    title = StringField("Service Title", validators=[DataRequired()])
    price = StringField("Service Price", validators=[DataRequired()])
    content = TextAreaField("Service Description", validators=[DataRequired()])
    submit = SubmitField("Update Service")

class SearchForm(FlaskForm):
    search = StringField("Search", validators=[DataRequired()])
    submit = SubmitField("Search")



class DeleteUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit_delete = SubmitField('Delete User')

class PincodeSearchForm(FlaskForm):
    pincode = StringField("Enter Pincode", validators=[DataRequired()])
    submit = SubmitField("Search")

class ReviewForm(FlaskForm):
    rating = StringField("Rating (1-5)", validators=[DataRequired()])
    review = TextAreaField("Review", validators=[DataRequired()])
    submit = SubmitField("Submit Review")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

# Assuming the admin will have a separate form for creating services
class ServiceForm(FlaskForm):
    title = StringField("Service Title", validators=[DataRequired()])
    price = StringField("Service Price", validators=[DataRequired()])
    content = TextAreaField("Service Description", validators=[DataRequired()])
    submit = SubmitField("Create Service")






with app.app_context():
    db.create_all()





@app.route('/')
def start():
    return render_template('home.html')

#-- login and signup routes --


@app.route('/log_admin', methods=['GET', 'POST'])
def log_admin():
    form = LogForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        # Directly compare the stored password with the input password
        if admin and admin.password == form.password.data:
            flash("Logged In")
            login_user(admin)
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid username or password")
    
    return render_template('admin_login.html', form=form)


@app.route('/signup_professional', methods=['GET', 'POST'])
def signup_professional():
    form = ProfessionalSignForm()
    form.service_id.choices = [(service.service_id, service.title) for service in Service.query.all()]

    if form.validate_on_submit():
        # Get the service to access both id and name
        service = Service.query.get(form.service_id.data)
        
        new_professional = Service_Proffessional(
            sp_username=form.username.data,
            password=generate_password_hash(form.password.data),
            service_id=service.service_id,
            service_name=service.title,  # Set the service name
            pincode=form.pincode.data,
            approved=False
        )
        db.session.add(new_professional)
        db.session.commit()
        flash("Professional account created. Awaiting admin approval.")
        return redirect(url_for('login_professional'))
    return render_template('signup_professional.html', form=form)


@app.route('/signup_customer', methods=['GET', 'POST'])
def signup_customer():
    form = SignForm()
    if form.validate_on_submit():
        # Check if the username already exists
        existing_customer = Customer.query.filter_by(c_username=form.username.data).first()
        if existing_customer:
            flash("Username already exists. Please choose a different one.")
            return redirect(url_for('signup_customer'))
        
        # Create a new customer if the username is unique
        new_customer = Customer(
            c_username=form.username.data,
            password=generate_password_hash(form.password.data),  # Hashing the password
            pincode=form.pincode.data  # Ensure pincode is included
        )
        db.session.add(new_customer)
        db.session.commit()
        flash("Customer account created successfully.")
        return redirect(url_for('login_customer'))
    return render_template('signup_customer.html', form=form)


@app.route('/login_customer', methods=['GET', 'POST'])
def login_customer():
    form = LogForm()
    if form.validate_on_submit():
        customer = Customer.query.filter_by(c_username=form.username.data).first()
        if customer and check_password_hash(customer.password, form.password.data):
            flash("Logged In")
            login_user(customer)
            return redirect(url_for('customer_dashboard'))
        else:
            flash("Invalid username or password")
    return render_template('login_customer.html', form=form)

@app.route('/login_professional', methods=['GET', 'POST'])
def login_professional():
    form = LogForm()
    if form.validate_on_submit():
        professional = Service_Proffessional.query.filter_by(sp_username=form.username.data).first()
        if professional and check_password_hash(professional.password, form.password.data) and professional.approved:
            flash("Logged In")
            login_user(professional)
            return redirect(url_for('professional_dashboard'))
        else:
            flash("Invalid username or password or account not approved")
    return render_template('login_professional.html', form=form)





@login_manager.user_loader
def load_user(user_id):
    # Attempt to load the user as an Admin
    admin = Admin.query.get(user_id)
    if admin:
        return admin
    
    # Attempt to load the user as a Customer
    customer = Customer.query.get(user_id)
    if customer:
        return customer
    
    # Attempt to load the user as a Service_Professional
    professional = Service_Proffessional.query.get(user_id)
    if professional:
        return professional
    
    # Return None if no user is found
    return None




@app.route('/customer_dashboard/logout', methods=["GET", "POST"])
@login_required
def customer_logout():
    logout_user()
    flash("Logged out")
    return redirect(url_for("start"))

@app.route('/professional_dashboard/logout', methods=["GET", "POST"])
@login_required
def professional_logout():
    logout_user()
    flash("Logged out")
    return redirect(url_for("start"))

@app.route('/admin_dashboard/logout', methods=["GET", "POST"])
@login_required
def admin_logout():
    logout_user()
    flash("Logged out")
    return redirect(url_for("start"))




@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    # Handle service creation
    service_form = ServiceForm()
    if service_form.validate_on_submit() and 'create_service' in request.form:
        try:
            # Check if service already exists
            existing_service = Service.query.filter_by(title=service_form.title.data).first()
            if existing_service:
                flash(f"Service '{service_form.title.data}' already exists.")
                return redirect(url_for('admin_dashboard'))

            new_service = Service(
                title=service_form.title.data,
                price=service_form.price.data,
                content=service_form.content.data
            )
            db.session.add(new_service)
            db.session.commit()

            # Find and reassign professionals
            professionals = Service_Proffessional.query.filter_by(
                service_name=service_form.title.data,
                service_id=None  # Only update those without a current service_id
            ).all()
            
            if professionals:
                for prof in professionals:
                    prof.service_id = new_service.service_id
                db.session.commit()
                flash(f"Service created and {len(professionals)} professionals reassigned.")
            else:
                flash("Service created successfully.")

        except IntegrityError:
            db.session.rollback()
            flash(f"Service '{service_form.title.data}' already exists.")
        except Exception:
            db.session.rollback()
            flash("An unexpected error occurred. Please try again.")

    # Handle service deletion
    if request.method == 'POST' and 'delete_service' in request.form:
        try:
            service_id = request.form['delete_service']
            service_to_delete = Service.query.get(service_id)
            if service_to_delete:
                # Store service name for professionals
                service_name = service_to_delete.title
                
                # Update professionals to keep their service_name but set service_id to None
                Service_Proffessional.query.filter_by(service_id=service_id).update(
                    {"service_id": None}
                )
                
                db.session.delete(service_to_delete)
                db.session.commit()
                flash(f"Service {service_name} deleted.")
            else:
                flash("Service not found.", "error")
        except Exception as e:
            db.session.rollback()
            flash("Error deleting service. Please try again.")

    # Approve or reject professionals
    if request.method == 'POST':
        if 'approve' in request.form:
            professional = Service_Proffessional.query.get(request.form['approve'])
            if professional:
                professional.approved = True
                # Ensure service_name is set if not already
                if not professional.service_name and professional.service_id:
                    service = Service.query.get(professional.service_id)
                    if service:
                        professional.service_name = service.title
                db.session.commit()
                flash(f"Professional {professional.sp_username} approved.")
        elif 'reject' in request.form:
            professional = Service_Proffessional.query.get(request.form['reject'])
            if professional:
                db.session.delete(professional)
                db.session.commit()
                flash(f"Professional {professional.sp_username} rejected.")

    # Flag/unflag/delete users and professionals
    flag_form = FlagUserForm()
    delete_form = DeleteUserForm()
    
    if flag_form.validate_on_submit():
        try:
            user = Customer.query.filter_by(c_username=flag_form.username.data).first() or \
                   Service_Proffessional.query.filter_by(sp_username=flag_form.username.data).first()
            if user:
                user.flagged = not user.flagged
                db.session.commit()
                flash(f"User {user.get_id()} {'flagged' if user.flagged else 'unflagged'}.")
            else:
                flash("User not found.")
        except Exception:
            db.session.rollback()
            flash("Error updating user flag status.")

    if delete_form.validate_on_submit():
        try:
            user = Customer.query.filter_by(c_username=delete_form.username.data).first() or \
                   Service_Proffessional.query.filter_by(sp_username=delete_form.username.data).first()
            
            if user:
                if isinstance(user, Service_Proffessional):
                    # Delete ratings first
                    Rating.query.filter_by(professional_username=user.sp_username).delete()
                    # Update service requests
                    ServiceRequest.query.filter_by(professional_username=user.sp_username).update(
                        {"professional_username": None, "status": "Pending"}
                    )
                elif isinstance(user, Customer):
                    # Delete customer's ratings
                    Rating.query.filter_by(customer_username=user.c_username).delete()
                
                db.session.commit()  # Commit the related records changes
                
                # Now delete the user
                db.session.delete(user)
                db.session.commit()
                flash(f"User {user.get_id()} deleted successfully.")
            else:
                flash("User not found.")
                
        except Exception as e:
            db.session.rollback()
            flash("Error deleting user. Please ensure all related records are handled.")

    # Fetch data for template
    services = Service.query.all()
    pending_professionals = Service_Proffessional.query.filter_by(approved=False).all()
    
    # Handle search
    search_form = SearchForm()
    professionals = []
    customers = []
    if search_form.validate_on_submit():
        search_query = search_form.search.data
        professionals = Service_Proffessional.query.filter(
            Service_Proffessional.sp_username.contains(search_query)
        ).all()
        customers = Customer.query.filter(
            Customer.c_username.contains(search_query)
        ).all()

    return render_template('admin_dashboard.html', 
                         service_form=service_form, 
                         pending_professionals=pending_professionals, 
                         services=services,
                         search_form=search_form,
                         professionals=professionals,
                         customers=customers,
                         flag_form=flag_form,
                         delete_form=delete_form)





@app.route('/professional_dashboard', methods=['GET', 'POST'])
@login_required
def professional_dashboard():
    if not isinstance(current_user, Service_Proffessional) or not current_user.approved:
        flash("Access denied.")
        return redirect(url_for('start'))
    
    if current_user.flagged:
        flash("Your account has been flagged. Please contact admin for assistance.")
        return render_template('professional_dashboard.html', 
                             service_requests=[],  # Empty list since flagged
                             accepted_requests=[])  # Empty list since flagged
    # Fetch pending requests for this professional's service
    
    service_requests = ServiceRequest.query.filter_by(
        service_id=current_user.service_id,
        status='Pending',
        professional_username=None  # Only show unassigned requests
    ).all()

    # Fetch accepted requests for this professional
    accepted_requests = ServiceRequest.query.filter_by(
        professional_username=current_user.sp_username,
        status='Accepted'
    ).all()

    if request.method == 'POST':
        request_id = request.form.get('request_id')
        action = request.form.get('action')
        service_request = ServiceRequest.query.get(request_id)

        if service_request and service_request.status == 'Pending':
            if action == 'accept':
                service_request.professional_username = current_user.sp_username
                service_request.status = 'Accepted'
                service_request.accepted = True
                db.session.commit()
                flash("Service request accepted successfully.")
                return redirect(url_for('professional_dashboard'))
            elif action == 'reject':
                service_request.status = 'Rejected'
                db.session.commit()
                flash("Service request rejected successfully.")
                return redirect(url_for('professional_dashboard'))

    return render_template('professional_dashboard.html', 
                         service_requests=service_requests, 
                         accepted_requests=accepted_requests)



@app.route('/customer_dashboard', methods=['GET', 'POST'])
@login_required
def customer_dashboard():
    if not isinstance(current_user, Customer):
        flash("Access denied.")
        return redirect(url_for('start'))

    # Instantiate the form for searching professionals by pincode
    pincode_search_form = PincodeSearchForm()


    if current_user.flagged:
        flash("Your account has been flagged. Please contact admin for assistance.")
        return render_template('customer_dashboard.html', 
                             service_requests=[], 
                             services=[],
                             professionals_info={},
                             pincode_search_form=PincodeSearchForm(),
                             professionals=[])



    # Handle pincode search form submission
    professionals = []
    professionals_info = {}
    if pincode_search_form.validate_on_submit():
        pincode = pincode_search_form.pincode.data
        professionals = Service_Proffessional.query.filter_by(pincode=pincode).all()
        
        # Calculate average ratings for found professionals
        for professional in professionals:
            avg_rating = db.session.query(func.avg(Rating.rating)).filter_by(
                professional_username=professional.sp_username
            ).scalar()
            professionals_info[professional.sp_username] = {
                'average_rating': round(float(avg_rating), 2) if avg_rating else 'No ratings yet'
            }

    # Fetch all available services
    services = Service.query.all()

    # Handle service request creation
    if request.method == 'POST' and 'service_id' in request.form:

        if current_user.flagged:
            flash("Your account is flagged. Cannot create new requests.")
            return redirect(url_for('customer_dashboard'))


        service_id = request.form['service_id']
        service = Service.query.get(service_id)
        if not service:
            flash("Selected service does not exist.")
            return redirect(url_for('customer_dashboard'))

        new_request = ServiceRequest(
            service_id=service_id,
            customer_username=current_user.c_username,
            status='Pending',
            timestamp=datetime.utcnow(),
            accepted=False
        )
        
        db.session.add(new_request)
        db.session.commit()
        flash("Service request created successfully.")
        return redirect(url_for('customer_dashboard'))

    # Fetch all service requests for the current customer
    service_requests = ServiceRequest.query.filter_by(customer_username=current_user.c_username).all()

    # Add professional details and ratings for service requests
    for req in service_requests:
        if req and req.professional_username:
            professional = Service_Proffessional.query.filter_by(sp_username=req.professional_username).first()
            if professional and professional.sp_username not in professionals_info:
                # Use SQLAlchemy's func to calculate the average directly in the database
                average_rating = db.session.query(func.avg(Rating.rating)).filter_by(
                    professional_username=professional.sp_username
                ).scalar() or 0
                professionals_info[professional.sp_username] = {
                    'professional': professional,
                    'average_rating': round(average_rating, 2)  # Round to 2 decimal places
                }

    return render_template('customer_dashboard.html', 
                         service_requests=service_requests, 
                         services=services,
                         professionals_info=professionals_info,
                         pincode_search_form=pincode_search_form,
                         professionals=professionals)



# -- service routes -> create, delete, edit --


@app.route('/create_service', methods=['GET', 'POST'])
@login_required
def create_service():
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    form = ServiceForm()
    if form.validate_on_submit():
        service_title = form.title.data
        
        # Check if service already exists
        existing_service = Service.query.filter_by(title=service_title).first()
        if existing_service:
            flash(f"Service '{service_title}' already exists.")
            return redirect(url_for('admin_dashboard'))
        
        # Create new service only if it doesn't exist
        new_service = Service(
            title=service_title,
            price=form.price.data,
            content=form.content.data
        )
        
        try:
            db.session.add(new_service)
            db.session.commit()

            # Find professionals who had this service name
            professionals = Service_Proffessional.query.filter_by(
                service_name=service_title
            ).all()

            if professionals:
                # Update their service_id to the new service
                for prof in professionals:
                    prof.service_id = new_service.service_id
                db.session.commit()
                flash(f"Service created and {len(professionals)} professionals reassigned.")
            else:
                flash("Service created successfully.")
                
        except IntegrityError:
            db.session.rollback()
            flash(f"Service '{service_title}' already exists.")
        except Exception:
            db.session.rollback()
            flash("An unexpected error occurred. Please try again.")
            # You might want to log the actual error for debugging
            # current_app.logger.error(f"Error creating service: {str(e)}")
            
        return redirect(url_for('admin_dashboard'))
            
    return render_template("create_service.html", form=form)



@login_required
@app.route('/delete_service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    if current_user.is_admin:
        db.session.delete(service)
        db.session.commit()
        flash("Service Deleted")
        return redirect(url_for('admin_dashboard'))
    else:
        flash("Not Authorized to delete this service")
        return redirect(url_for('start'))

@login_required
@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    service = Service.query.get_or_404(service_id)
    form = EditServiceForm(obj=service)
    if form.validate_on_submit():
        service.title = form.title.data
        service.price = form.price.data
        service.content = form.content.data
        db.session.commit()
        flash("Service Updated")
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_service.html', form=form, service=service)


@app.route('/close_service_request/<int:request_id>', methods=['POST'])
@login_required
def close_service_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)

    if service_request.customer_username != current_user.c_username:
        flash("You are not authorized to close this request.")
        return redirect(url_for('customer_dashboard'))

    try:
        # If the request has a professional assigned, redirect to review first
        if service_request.professional_username:
            return redirect(url_for('submit_review', request_id=request_id))
        
        # If no professional assigned, just delete the request
        db.session.delete(service_request)
        db.session.commit()
        flash("Service request closed successfully.")
        return redirect(url_for('customer_dashboard'))
            
    except Exception as e:
        db.session.rollback()
        flash(f"Error closing service request: {str(e)}")
        return redirect(url_for('customer_dashboard'))





# -- flag and  unflag delete routes --

@app.route('/flag_professional/<string:username>', methods=['POST'])
@login_required
def flag_professional(username):
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    professional = Service_Proffessional.query.filter_by(sp_username=username).first_or_404()
    professional.flagged = True
    db.session.commit()
    flash(f"Professional {username} flagged.")
    return redirect(url_for('admin_dashboard'))

@app.route('/unflag_professional/<string:username>', methods=['POST'])
@login_required
def unflag_professional(username):
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    professional = Service_Proffessional.query.filter_by(sp_username=username).first_or_404()
    professional.flagged = False
    db.session.commit()
    flash(f"Professional {username} unflagged.")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_professional/<string:username>', methods=['POST'])
@login_required
def delete_professional(username):
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    professional = Service_Proffessional.query.filter_by(sp_username=username).first_or_404()
    db.session.delete(professional)
    db.session.commit()
    flash(f"Professional {username} deleted.")
    return redirect(url_for('admin_dashboard'))

@app.route('/flag_user/<string:username>', methods=['POST'])
@login_required
def flag_user(username):
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    user = Service_Proffessional.query.filter_by(sp_username=username).first() or Customer.query.filter_by(c_username=username).first()
    if user:
        user.flagged = True
        db.session.commit()
        flash(f"User {username} flagged.")
    else:
        flash("User not found.")
    return redirect(url_for('admin_dashboard'))

@app.route('/unflag_user/<string:username>', methods=['POST'])
@login_required
def unflag_user(username):
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    user = Service_Proffessional.query.filter_by(sp_username=username).first() or Customer.query.filter_by(c_username=username).first()
    if user:
        user.flagged = False
        db.session.commit()
        flash(f"User {username} unflagged.")
    else:
        flash("User not found.")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<string:username>', methods=['POST'])
@login_required
def delete_user(username):
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    user = Service_Proffessional.query.filter_by(sp_username=username).first() or Customer.query.filter_by(c_username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {username} deleted.")
    else:
        flash("User not found.")
    return redirect(url_for('admin_dashboard'))




# -- search routes --



@app.route('/search_user', methods=["GET", "POST"])
@login_required
def search_user():
    if not current_user.is_admin:
        flash("Access denied.")
        return redirect(url_for('start'))

    form = SearchForm()
    flag_form = FlagUserForm()
    delete_form = DeleteUserForm()
    service_form = ServiceForm()
    professionals = []
    customers = []

    if form.validate_on_submit():
        search_query = form.search.data
        professionals = Service_Proffessional.query.filter(
            Service_Proffessional.sp_username.contains(search_query)
        ).all()
        customers = Customer.query.filter(
            Customer.c_username.contains(search_query)
        ).all()

    # Get all services for the dashboard
    services = Service.query.all()
    # Get pending professionals
    pending_professionals = Service_Proffessional.query.filter_by(approved=False).all()

    return render_template('admin_dashboard.html', 
                         professionals=professionals, 
                         customers=customers, 
                         form=form, 
                         flag_form=flag_form, 
                         delete_form=delete_form,
                         service_form=service_form, 
                         services=services, 
                         pending_professionals=pending_professionals, 
                         search_form=form)

@app.route('/search_professional_by_pincode', methods=["GET", "POST"])
@login_required
def search_professional_by_pincode():
    if not isinstance(current_user, Customer):
        flash("Access denied.")
        return redirect(url_for('start'))

    form = PincodeSearchForm()
    professionals = []
    professionals_info = {}  # Add this dictionary for ratings

    if form.validate_on_submit():
        search_pincode = form.pincode.data
        professionals = Service_Proffessional.query.filter_by(pincode=search_pincode).all()
        
        # Calculate average rating for each professional
        for professional in professionals:
            average_rating = db.session.query(func.avg(Rating.rating)).filter_by(
                professional_username=professional.sp_username
            ).scalar() or 0
            
            professionals_info[professional.sp_username] = {
                'professional': professional,
                'average_rating': round(average_rating, 2)
            }

    return render_template('customer_dashboard.html', 
                         professionals=professionals,
                         professionals_info=professionals_info,  # Add this
                         pincode_search_form=form)



# -- review routes --



@app.route('/submit_review/<int:request_id>', methods=['GET', 'POST'])
@login_required
def submit_review(request_id):
    if not isinstance(current_user, Customer):
        flash("Access denied.")
        return redirect(url_for('start'))

    service_request = ServiceRequest.query.get_or_404(request_id)
    
    if service_request.customer_username != current_user.c_username:
        flash("You are not authorized to review this request.")
        return redirect(url_for('customer_dashboard'))

    form = ReviewForm()
    if form.validate_on_submit():
        try:
            # First create the review
            new_rating = Rating(
                professional_username=service_request.professional_username,
                customer_username=current_user.c_username,
                rating=int(form.rating.data),
                review=form.review.data
            )
            db.session.add(new_rating)
            
            # Then delete the service request
            db.session.delete(service_request)
            db.session.commit()
            
            flash("Review submitted and service request closed successfully.")
            return redirect(url_for('customer_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error submitting review: {str(e)}")
    
    return render_template('submit_review.html', 
                         form=form, 
                         service_request=service_request)






if __name__ == "__main__":
    app.run(debug=True)


