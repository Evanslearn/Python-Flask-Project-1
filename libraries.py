from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import time
from werkzeug.security import generate_password_hash, check_password_hash  # Hashing password
from werkzeug.wrappers.response import Response
from flask_login import UserMixin, login_required, LoginManager, login_user, logout_user, current_user
