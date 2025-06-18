# Household Services Application

A comprehensive multi-user platform for household services that enables seamless service booking and management through role-based access control.

## 🏠 Overview

This application connects customers with service professionals through an intuitive platform that supports three distinct user roles: Admin, Service Professional, and Customer. The system streamlines the entire service lifecycle from booking to completion, ensuring efficient service management and secure user interactions.

## ✨ Features

### Core Functionality
- **Multi-role user system** - Admin, Service Professional, and Customer access levels
- **Service request management** - Complete booking lifecycle tracking
- **Professional approval system** - Quality control through admin verification
- **Rating and review system** - Service quality assurance and feedback
- **Location-based matching** - Pincode-based service professional assignment

### Security & Access Control
- **Role-based authentication** - Secure access control for different user types
- **Password security** - Industry-standard encryption with Werkzeug Security
- **User flagging system** - Platform safety and moderation capabilities

## 🛠️ Technology Stack

### Backend
- **Flask** - Lightweight and flexible web framework
- **Flask-SQLAlchemy** - Powerful ORM for database operations
- **Werkzeug Security** - Robust authentication and password management
- **Flask-WTF** - Comprehensive form handling and validation

### Frontend
- **HTML with Jinja2** - Dynamic templating for responsive web pages
- **Server-side rendering** - Optimized performance through Flask

### Database
- **SQLite** - Efficient lightweight database for all application data

## 📊 Database Architecture

The application features a well-structured relational database with six core entities:

| Entity | Purpose | Key Features |
|--------|---------|--------------|
| **customer** | Customer profiles | Location data, account management |
| **service_professional** | Professional profiles | Approval status, specialization |
| **admin** | Administrative accounts | Platform oversight, user management |
| **service_request** | Booking management | Status tracking, assignment |
| **service** | Service catalog | Pricing, availability |
| **rating** | Review system | Quality feedback, professional ratings |

### Key Relationships
- One-to-many: Customers → Service Requests
- Many-to-one: Service Requests → Service Professionals
- One-to-many: Service Professionals → Specializations
- One-to-many: Completed Services → Ratings


### First Run
1. Start the application
2. Access the platform through your web browser
3. Register as a customer or service professional
4. Begin exploring the features!

## 👥 User Workflows

### 🛍️ For Customers
1. **Register** with your location details (pincode)
2. **Browse** available services in your area
3. **Create** service requests with specific requirements
4. **Track** request status in real-time
5. **Rate and review** completed services

### 🔧 For Service Professionals
1. **Register** with your service specializations
2. **Wait** for admin approval to activate your account
3. **Accept** assigned service requests
4. **Complete** services and update status
5. **Build** your reputation through customer ratings

### ⚙️ For Administrators
1. **Review** and approve professional applications
2. **Manage** user accounts and handle flagging
3. **Oversee** platform operations and quality control
4. **Monitor** service completion and user satisfaction


## 🔮 Future Roadmap

### Planned Enhancements
- **💳 Payment Integration** - Secure payment processing for completed services
- **⭐ Enhanced Review System** - Detailed feedback categories and analytics
- **📱 Mobile Application** - Native iOS and Android apps
- **🔔 Real-time Notifications** - Instant updates and messaging system
- **📈 Analytics Dashboard** - Performance insights for professionals and admins

## 🎥 Demo

A comprehensive video demonstration showcases the complete user workflow and administrative features, highlighting the platform's intuitive design and robust functionality.

## 👨‍💻 Author

**Shusmit Sarkar**  
📧 Email: 23f3002196@ds.study.iitm.ac.in  
🎓 IIT Madras

## 📄 License

This project is developed as part of an academic program at the Indian Institute of Technology Madras.

---

⭐ **Star this repository** if you find it helpful!  
🐛 **Report issues** or suggest improvements through GitHub Issues  
🤝 **Contributions** are welcome - please read our contributing guidelines


